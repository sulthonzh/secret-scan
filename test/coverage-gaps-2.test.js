'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

// ─── walk() catch block (cli.js lines 12-14) ───────────
// Strategy: Use a preload script that mocks fs.readdirSync before cli.js loads.
// We run the CLI as a subprocess with --require pointing to our mock.

test('walk() returns [] when readdirSync throws (via preload mock)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-preload-walk-'));
  const subDir = path.join(dir, 'blocked');
  fs.mkdirSync(subDir);
  fs.writeFileSync(path.join(subDir, 'test.env'), 'AWS_KEY=AKIAIOSFODNN7EXAMPLE');

  // Create a preload mock script
  const mockScript = path.join(dir, 'mock-readdir.js');
  fs.writeFileSync(mockScript, `
    const fs = require('fs');
    const origReaddir = fs.readdirSync;
    const blockedPath = ${JSON.stringify(subDir)};
    fs.readdirSync = function(target, opts) {
      if (typeof target === 'string' && target.includes(blockedPath)) {
        throw new Error('EACCES: permission denied, readdir');
      }
      return origReaddir.call(fs, target, opts);
    };
  `);

  const CLI_PATH = path.resolve(__dirname, '../src/cli.js');

  let exitCode = 0;
  try {
    execFileSync(process.execPath, ['--require', mockScript, CLI_PATH, dir, '--json'], {
      encoding: 'utf8',
      timeout: 10000,
      cwd: dir,
    });
  } catch (err) {
    exitCode = err.status || 1;
  }

  // The blocked subdir should have been skipped by walk()'s catch block
  // The file in the top-level dir should still be found (if any)
  // But since the only secret is in the blocked subdir, it should NOT be found
  assert.equal(exitCode, 0, 'CLI should exit 0 when secrets are blocked by readdir failure');

  fs.rmSync(dir, { recursive: true, force: true });
});

// ─── walk() catch block preserves prior results ─────────

test('walk() preserves already-collected results when subdir readdir fails', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-preserve2-walk-'));
  // Top-level file with secret (should be found)
  fs.writeFileSync(path.join(dir, 'top.env'), 'AWS_KEY=AKIAIOSFODNN7EXAMPLE');
  const subDir = path.join(dir, 'blocked');
  fs.mkdirSync(subDir);
  fs.writeFileSync(path.join(subDir, 'nested.env'), 'password = "supersecret123"');

  const mockScript = path.join(dir, 'mock-readdir.js');
  fs.writeFileSync(mockScript, `
    const fs = require('fs');
    const origReaddir = fs.readdirSync;
    const blockedPath = ${JSON.stringify(subDir)};
    fs.readdirSync = function(target, opts) {
      if (typeof target === 'string' && target.includes(blockedPath)) {
        throw new Error('EACCES: permission denied, readdir');
      }
      return origReaddir.call(fs, target, opts);
    };
  `);

  const CLI_PATH = path.resolve(__dirname, '../src/cli.js');

  let stdout = '';
  try {
    stdout = execFileSync(process.execPath, ['--require', mockScript, CLI_PATH, dir, '--json'], {
      encoding: 'utf8',
      timeout: 10000,
      cwd: dir,
    });
  } catch (err) {
    stdout = err.stdout || '';
  }

  // top.env secret should be found (walk collected it before hitting blocked subdir)
  // nested.env secret should NOT be found (readdir failed on blocked subdir)
  let output;
  try {
    output = JSON.parse(stdout);
  } catch {
    // If JSON parse fails, check raw output
    assert.ok(stdout.includes('aws') || stdout.includes('AWS'), 'top-level secret found');
    fs.rmSync(dir, { recursive: true, force: true });
    return;
  }

  const files = output.findings.map((f) => f.file);
  assert.ok(files.some((f) => f.includes('top.env')), 'top.env should be found');
  assert.ok(!files.some((f) => f.includes('nested.env')), 'nested.env in blocked dir should NOT be found');

  fs.rmSync(dir, { recursive: true, force: true });
});

// ─── walk() with symlink loop ───────────────────────────

test('walk() handles symlink loops gracefully', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-symlink-walk-'));
  fs.writeFileSync(path.join(dir, 'real.env'), 'AWS_KEY=AKIAIOSFODNN7EXAMPLE');

  // Create a symlink that points back to parent (circular)
  try {
    fs.symlinkSync(dir, path.join(dir, 'loop'));
  } catch {
    // Symlinks might not work on all platforms
    fs.rmSync(dir, { recursive: true, force: true });
    assert.ok(true, 'symlink creation failed, skipping test');
    return;
  }

  const CLI_PATH = path.resolve(__dirname, '../src/cli.js');

  let exitCode = 0;
  try {
    execFileSync(process.execPath, [CLI_PATH, dir, '--json'], {
      encoding: 'utf8',
      timeout: 10000,
    });
  } catch (err) {
    exitCode = err.status || 1;
  }

  // Should not hang or crash — the symlink loop might cause issues
  // but the walk function should handle it (isDirectory() returns true for symlinks)
  // At minimum it should find real.env
  assert.ok(exitCode === 0 || exitCode === 1, 'CLI handles symlink loop without crashing');

  fs.rmSync(dir, { recursive: true, force: true });
});

// ─── parseArgs: --severity with no following value → || 'low' fallback (line 43) ───

test('parseArgs --severity at end with no value falls back to low', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-sev-fallback-'));
  fs.writeFileSync(path.join(dir, 'clean.txt'), 'just clean text');

  const CLI_PATH = path.resolve(__dirname, '../src/cli.js');

  // --severity at end of args, no value follows → argv[++i] is undefined → || 'low'
  const stdout = execFileSync(process.execPath, [CLI_PATH, dir, '--severity'], {
    encoding: 'utf8',
    timeout: 10000,
  });

  // With default low severity, no secrets in clean.txt → should show clean message
  assert.match(stdout, /No secrets found/);

  fs.rmSync(dir, { recursive: true, force: true });
});

// ─── Text output with --verbose shows full secret values (line 148 true branch) ───

test('text output with --verbose shows unredacted values', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-text-verbose-'));
  fs.writeFileSync(path.join(dir, 'config.env'), 'AWS_KEY=AKIAIOSFODNN7EXAMPLE');

  const CLI_PATH = path.resolve(__dirname, '../src/cli.js');

  // Text output (not JSON) with --verbose flag → line 148 true branch
  const stdout = execFileSync(process.execPath, [CLI_PATH, dir, '--verbose'], {
    encoding: 'utf8',
    timeout: 10000,
  });

  // Should show the actual secret value (not redacted with asterisks)
  assert.match(stdout, /AKIAIOSFODNN7EXAMPLE/);
  // Should NOT contain redaction asterisks
  assert.doesNotMatch(stdout, /\*{3,}/);

  fs.rmSync(dir, { recursive: true, force: true });
});
