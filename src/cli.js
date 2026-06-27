#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { scanText, shouldScan, summarize, redact, severityLevel } = require('./scanner.js');

function walk(dir, ignorePatterns, results = []) {
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(process.cwd(), fullPath);

    if (entry.isDirectory()) {
      if (shouldScan(relPath + '/', ignorePatterns)) {
        walk(fullPath, ignorePatterns, results);
      }
    } else if (entry.isFile()) {
      if (shouldScan(relPath, ignorePatterns)) {
        results.push(fullPath);
      }
    }
  }
  return results;
}

function parseArgs(argv) {
  const args = { paths: [], ci: false, json: false, verbose: false, allow: [], quiet: false, severity: 'low', help: false };
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--ci') args.ci = true;
    else if (arg === '--json') args.json = true;
    else if (arg === '--verbose' || arg === '-v') args.verbose = true;
    else if (arg === '--quiet' || arg === '-q') args.quiet = true;
    else if (arg === '--help' || arg === '-h') args.help = true;
    else if (arg === '--allow') { args.allow.push(argv[++i]); }
    else if (arg === '--severity') { args.severity = argv[++i] || 'low'; }
    else if (arg.startsWith('--allow=')) { args.allow.push(arg.slice(8)); }
    else if (arg.startsWith('--severity=')) { args.severity = arg.slice(11); }
    else if (!arg.startsWith('-')) args.paths.push(arg);
  }
  return args;
}

function help() {
  console.log(`
secret-scan — Scan files for hardcoded secrets

USAGE:
  secret-scan [path...] [options]

OPTIONS:
  --ci              Exit code 1 if any findings (for CI pipelines)
  --json            Output findings as JSON
  --severity <s>    Minimum severity to report: low, medium, high, critical
  --allow <regex>   Allowlist values matching this regex (repeatable)
  --verbose, -v     Show full secret values (default: redacted)
  --quiet, -q       Only show summary, suppress details
  --help, -h        Show this help

EXAMPLES:
  secret-scan .
  secret-scan src/ --ci
  secret-scan --json .
  secret-scan . --severity high
  secret-scan . --allow "^DEV_KEY_"
`);
}

async function main() {
  const args = parseArgs(process.argv);

  if (args.help) {
    help();
    return;
  }

  const targets = args.paths.length > 0 ? args.paths : ['.'];

  // Collect files
  const files = [];
  for (const target of targets) {
    const resolved = path.resolve(target);
    const stat = fs.statSync(resolved, { throwIfNoEntry: false });
    if (!stat) {
      console.error(`Path not found: ${target}`);
      process.exit(2);
    }
    if (stat.isDirectory()) {
      walk(resolved, null, files);
    } else {
      files.push(resolved);
    }
  }

  // Scan each file
  const allFindings = [];
  for (const file of files) {
    let content;
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch {
      continue; // Skip binary/unreadable
    }

    const findings = scanText(content, { allowValues: args.allow });

    for (const f of findings) {
      if (severityLevel(f.severity) < severityLevel(args.severity)) continue;
      allFindings.push({ ...f, file: path.relative(process.cwd(), file) });
    }
  }

  // Output
  if (args.json) {
    const output = {
      findings: allFindings.map((f) => ({
        ...f,
        value: args.verbose ? f.value : redact(f.value),
      })),
      summary: summarize(allFindings),
    };
    console.log(JSON.stringify(output, null, 2));
  } else {
    const summary = summarize(allFindings);

    if (allFindings.length === 0) {
      if (!args.quiet) console.log('✓ No secrets found');
    } else {
      if (!args.quiet) {
        // Group by file
        const byFile = {};
        for (const f of allFindings) {
          if (!byFile[f.file]) byFile[f.file] = [];
          byFile[f.file].push(f);
        }

        for (const [file, fileFindings] of Object.entries(byFile)) {
          console.log(`\n📄 ${file}`);
          for (const f of fileFindings) {
            const sev = f.severity.toUpperCase().padEnd(8);
            const val = args.verbose ? f.value : redact(f.value);
            console.log(`  ${sev} ${f.name} (line ${f.line})`);
            console.log(`           ${val}`);
          }
        }
      }

      console.log(`\n${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low — ${summary.total} total`);
    }
  }

  // Exit code for CI
  if (args.ci && allFindings.length > 0) {
    process.exit(1);
  }
}

main();
