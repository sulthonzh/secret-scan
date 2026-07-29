'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const CLI_PATH = path.resolve(__dirname, '../src/cli.js');

// Helper: run CLI as subprocess and capture stdout/stderr/exit
function runCli(args = [], options = {}) {
  try {
    const stdout = execFileSync(process.execPath, [CLI_PATH, ...args], {
      encoding: 'utf8',
      timeout: 10000,
      maxBuffer: 1024 * 1024,
      ...options,
    });
    return { stdout, stderr: '', exitCode: 0 };
  } catch (err) {
    return { stdout: err.stdout || '', stderr: err.stderr || '', exitCode: err.status || 1 };
  }
}

// Helper: create temp dir with files
function createTempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secret-scan-test-'));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(dir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  return dir;
}

// ─── parseArgs (indirectly via CLI) ─────────────────────

test('--help shows usage information', () => {
  const { stdout, exitCode } = runCli(['--help']);
  assert.equal(exitCode, 0);
  assert.match(stdout, /secret-scan/);
  assert.match(stdout, /USAGE:/);
  assert.match(stdout, /--ci/);
  assert.match(stdout, /--json/);
  assert.match(stdout, /--severity/);
});

test('-h shows same help', () => {
  const { stdout, exitCode } = runCli(['-h']);
  assert.equal(exitCode, 0);
  assert.match(stdout, /USAGE:/);
});

test('no path defaults to current directory', () => {
  const dir = createTempProject({
    'clean.txt': 'no secrets here',
  });
  const { stdout, exitCode } = runCli([], { cwd: dir });
  assert.equal(exitCode, 0);
  assert.match(stdout, /No secrets found/);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ─── Scanning via CLI ───────────────────────────────────

test('detects secret in file and reports it', () => {
  const dir = createTempProject({
    'config.env': 'AWS_KEY=AKIAIOSFODNN7EXAMPLE',
  });
  const { stdout, exitCode } = runCli([dir]);
  assert.equal(exitCode, 0);
  assert.match(stdout, /aws-access-key|AWS Access Key/i);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--ci exits with code 1 when secrets found', () => {
  const dir = createTempProject({
    'config.env': 'AWS_KEY=AKIAIOSFODNN7EXAMPLE',
  });
  const { exitCode } = runCli([dir, '--ci']);
  assert.equal(exitCode, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--ci exits with code 0 when no secrets found', () => {
  const dir = createTempProject({
    'clean.txt': 'just some text',
  });
  const { exitCode } = runCli([dir, '--ci']);
  assert.equal(exitCode, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--json outputs valid JSON with findings', () => {
  const dir = createTempProject({
    'config.env': 'token = ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd',
  });
  const { stdout, exitCode } = runCli([dir, '--json']);
  const output = JSON.parse(stdout);
  assert.ok(output.findings.length > 0);
  assert.ok(output.summary);
  assert.equal(exitCode, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--json output has redacted values by default', () => {
  const dir = createTempProject({
    'config.env': 'token = ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd',
  });
  const { stdout } = runCli([dir, '--json']);
  const output = JSON.parse(stdout);
  const val = output.findings[0].value;
  assert.ok(val.includes('*'), 'value should contain redaction asterisks');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--verbose shows full secret values', () => {
  const dir = createTempProject({
    'config.env': 'token = ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd',
  });
  const { stdout } = runCli([dir, '--json', '--verbose']);
  const output = JSON.parse(stdout);
  const val = output.findings[0].value;
  assert.ok(!val.includes('*'), 'value should NOT be redacted with --verbose');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--quiet suppresses detailed output', () => {
  const dir = createTempProject({
    'config.env': 'AWS_KEY=AKIAIOSFODNN7EXAMPLE',
  });
  const { stdout } = runCli([dir, '--quiet']);
  // With --quiet, only summary line should appear, no per-file details
  assert.doesNotMatch(stdout, /📄/);
  assert.match(stdout, /critical/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--severity filters findings', () => {
  const dir = createTempProject({
    'config.env': [
      'AWS_KEY=AKIAIOSFODNN7EXAMPLE',  // critical
      'password = "somepassword123"',   // medium
    ].join('\n'),
  });
  const { stdout: lowOut } = runCli([dir, '--json', '--severity', 'low']);
  const lowOutput = JSON.parse(lowOut);
  // At least 2 findings with low threshold
  assert.ok(lowOutput.findings.length >= 2);

  const { stdout: highOut } = runCli([dir, '--json', '--severity', 'high']);
  const highOutput = JSON.parse(highOut);
  // Only critical and high severity
  for (const f of highOutput.findings) {
    assert.ok(['high', 'critical'].includes(f.severity), `expected high/critical, got ${f.severity}`);
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--allow filters values matching regex', () => {
  const dir = createTempProject({
    'config.env': 'api_key = "AKIAIOSFODNN7EXAMPLE"',
  });
  const { stdout: withoutAllow } = runCli([dir, '--json']);
  const withoutOutput = JSON.parse(withoutAllow);
  assert.ok(withoutOutput.findings.length > 0);

  const { stdout: withAllow } = runCli([dir, '--json', '--allow', 'AKIA']);
  const withOutput = JSON.parse(withAllow);
  assert.equal(withOutput.findings.length, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--allow=value syntax works', () => {
  const dir = createTempProject({
    'config.env': 'api_key = "AKIAIOSFODNN7EXAMPLE"',
  });
  const { stdout } = runCli([dir, '--json', '--allow=AKIA']);
  const output = JSON.parse(stdout);
  assert.equal(output.findings.length, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('--severity=value syntax works', () => {
  const dir = createTempProject({
    'config.env': 'password = "somepassword123"',  // medium severity
  });
  const { stdout } = runCli([dir, '--json', '--severity=high']);
  const output = JSON.parse(stdout);
  assert.equal(output.findings.length, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ─── Error handling ─────────────────────────────────────

test('nonexistent path exits with code 2', () => {
  const { stderr, exitCode } = runCli(['/nonexistent/path/xyz123']);
  assert.equal(exitCode, 2);
  assert.match(stderr, /Path not found/);
});

test('scans single file (not just directories)', () => {
  const dir = createTempProject({});
  const filePath = path.join(dir, 'test.env');
  fs.writeFileSync(filePath, 'AWS_KEY=AKIAIOSFODNN7EXAMPLE');
  const { stdout, exitCode } = runCli([filePath, '--json']);
  const output = JSON.parse(stdout);
  assert.ok(output.findings.length > 0);
  assert.equal(exitCode, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ─── walk function ──────────────────────────────────────

test('walk recursively scans subdirectories', () => {
  const dir = createTempProject({
    'top.env': 'AWS_KEY=AKIAIOSFODNN7EXAMPLE',
    'sub/nested.env': 'token = ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd',
    'sub/deep/deep.env': 'password = "supersecret123"',
  });
  const { stdout } = runCli([dir, '--json']);
  const output = JSON.parse(stdout);
  const files = new Set(output.findings.map((f) => f.file));
  assert.ok(files.size >= 3, `expected files from 3+ paths, got ${files.size}`);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('walk skips node_modules and .git', () => {
  const dir = createTempProject({
    'real.env': 'AWS_KEY=AKIAIOSFODNN7EXAMPLE',
    'node_modules/pkg/index.env': 'token = ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd',
    '.git/config.env': 'password = "supersecret123"',
  });
  const { stdout } = runCli([dir, '--json']);
  const output = JSON.parse(stdout);
  const files = output.findings.map((f) => f.file);
  // Should find the real.env file
  assert.ok(files.some((f) => f.includes('real.env')));
  // Should NOT find node_modules or .git
  assert.ok(!files.some((f) => f.includes('node_modules')), 'should skip node_modules');
  assert.ok(!files.some((f) => f.includes('.git/')), 'should skip .git');
  fs.rmSync(dir, { recursive: true, force: true });
});

// ─── Output format ──────────────────────────────────────

test('text output format includes file, severity, and line', () => {
  const dir = createTempProject({
    'config.env': 'AWS_KEY=AKIAIOSFODNN7EXAMPLE',
  });
  const { stdout } = runCli([dir]);
  assert.match(stdout, /config\.env/);
  assert.match(stdout, /CRITICAL|AWS/);
  assert.match(stdout, /line/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('summary line shows counts by severity', () => {
  const dir = createTempProject({
    'config.env': [
      'AWS_KEY=AKIAIOSFODNN7EXAMPLE',
      'password = "somepassword123"',
    ].join('\n'),
  });
  const { stdout } = runCli([dir]);
  assert.match(stdout, /\d+ critical.*\d+ high.*\d+ medium.*\d+ low.*total/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('clean directory shows ✓ message', () => {
  const dir = createTempProject({
    'clean.txt': 'just clean code',
  });
  const { stdout, exitCode } = runCli([dir]);
  assert.match(stdout, /No secrets found/);
  assert.equal(exitCode, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ─── Edge cases ─────────────────────────────────────────

test('binary/unreadable files are skipped gracefully', () => {
  const dir = createTempProject({});
  const binFile = path.join(dir, 'binary.dat');
  // Write invalid UTF-8
  const buf = Buffer.alloc(256, 0xff);
  fs.writeFileSync(binFile, buf);
  const { exitCode } = runCli([dir]);
  assert.equal(exitCode, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('multiple paths can be specified', () => {
  const dir1 = createTempProject({ 'a.env': 'AWS_KEY=AKIAIOSFODNN7EXAMPLE' });
  const dir2 = createTempProject({ 'b.env': 'password = "somepass123"' });
  const { stdout } = runCli([dir1, dir2, '--json']);
  const output = JSON.parse(stdout);
  const files = new Set(output.findings.map((f) => f.file));
  assert.ok(files.size >= 2);
  fs.rmSync(dir1, { recursive: true, force: true });
  fs.rmSync(dir2, { recursive: true, force: true });
});

test('--ci --json together works', () => {
  const dir = createTempProject({
    'config.env': 'AWS_KEY=AKIAIOSFODNN7EXAMPLE',
  });
  const { stdout, exitCode } = runCli([dir, '--ci', '--json']);
  const output = JSON.parse(stdout);
  assert.ok(output.findings.length > 0);
  assert.equal(exitCode, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('unknown flags are ignored (treated as paths if no dash)', () => {
  const dir = createTempProject({
    'clean.txt': 'no secrets',
  });
  // Unknown flags starting with - are silently skipped
  const { exitCode } = runCli([dir, '--unknown-flag']);
  assert.equal(exitCode, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});
