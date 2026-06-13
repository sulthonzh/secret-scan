'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  scanLine,
  scanText,
  shouldScan,
  severityLevel,
  summarize,
  redact,
  isAllowValue,
  PATTERNS,
  DEFAULT_IGNORE_PATTERNS,
} = require('../src/scanner.js');

// ─── scanLine ────────────────────────────────────────────

test('scanLine detects AWS Access Key ID', () => {
  const findings = scanLine('key = "AKIAIOSFODNN7EXAMPLE"');
  assert.ok(findings.some((f) => f.patternId === 'aws-access-key'));
  assert.equal(findings[0].severity, 'critical');
});

test('scanLine detects AWS Secret Access Key', () => {
  const findings = scanLine('aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
  assert.ok(findings.some((f) => f.patternId === 'aws-secret'));
});

test('scanLine detects GitHub classic token', () => {
  const findings = scanLine('token: ghp_1234567890abcdefghijklmnopqrstuvwxyzAB');
  assert.ok(findings.some((f) => f.patternId === 'github-token'));
});

test('scanLine detects GitHub fine-grained token', () => {
  const findings = scanLine('token = github_pat_11ABCDEf0gHiJkLmNoPqRsTuVwXyZ1234567890');
  assert.ok(findings.some((f) => f.patternId === 'github-token'));
});

test('scanLine detects Google API Key', () => {
  const findings = scanLine('API_KEY = AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY');
  assert.ok(findings.some((f) => f.patternId === 'google-api-key'));
  assert.equal(findings[0].severity, 'high');
});

test('scanLine detects Google OAuth Client ID', () => {
  const findings = scanLine('client_id: 123456789-abcdefghijklmnop.apps.googleusercontent.com');
  assert.ok(findings.some((f) => f.patternId === 'google-oauth-id'));
});

test('scanLine detects Slack bot token', () => {
  const findings = scanLine('SLACK_TOKEN=xoxb-1234567890-1234567890123-abcdefghij');
  assert.ok(findings.some((f) => f.patternId === 'slack-token'));
});

test('scanLine detects Slack webhook URL', () => {
  const findings = scanLine('url = https://hooks.slack.com/services/T000AAA/B000AAA/XYZabcdefghij');
  assert.ok(findings.some((f) => f.patternId === 'slack-webhook'));
});

test('scanLine detects Stripe live secret key', () => {
  const sk = 'sk_' + 'live_' + 'a'.repeat(28); // assembled to avoid push protection
  const findings = scanLine(`stripe_key = ${sk}`);
  assert.ok(findings.some((f) => f.patternId === 'stripe-key'));
  assert.equal(findings[0].severity, 'critical');
});

test('scanLine detects Stripe test publishable key', () => {
  const pk = 'pk_' + 'test_' + 'a'.repeat(28);
  const findings = scanLine(`key: ${pk}`);
  assert.ok(findings.some((f) => f.patternId === 'stripe-publishable'));
  assert.equal(findings[0].severity, 'low');
});

test('scanLine detects PEM private key block', () => {
  const line = '-----BEGIN RSA PRIVATE KEY-----';
  const findings = scanLine(line);
  assert.ok(findings.some((f) => f.patternId === 'private-key'));
});

test('scanLine detects EC private key block', () => {
  const line = '-----BEGIN EC PRIVATE KEY-----';
  const findings = scanLine(line);
  assert.ok(findings.some((f) => f.patternId === 'private-key'));
});

test('scanLine detects OpenSSH private key', () => {
  const line = '-----BEGIN OPENSSH PRIVATE KEY-----';
  const findings = scanLine(line);
  assert.ok(findings.some((f) => f.patternId === 'private-key'));
});

test('scanLine detects JWT', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const findings = scanLine(`Authorization: Bearer ${jwt}`);
  assert.ok(findings.some((f) => f.patternId === 'jwt'));
});

test('scanLine detects Bearer token', () => {
  const findings = scanLine('Authorization: Bearer dGhpcyBpcyBhIHRlc3QgdG9rZW5fMTIzNDU2');
  assert.ok(findings.some((f) => f.patternId === 'bearer-token'));
});

test('scanLine detects NPM token', () => {
  const findings = scanLine('//registry.npmjs.org/:_authToken=npm_1234567890abcdef1234567890abcdef');
  assert.ok(findings.some((f) => f.patternId === 'npm-token'));
});

test('scanLine detects MongoDB connection string with credentials', () => {
  const findings = scanLine('DB_URL = mongodb://admin:s3cr3tP@ss@cluster.example.com/db');
  assert.ok(findings.some((f) => f.patternId === 'database-url'));
});

test('scanLine detects PostgreSQL connection string', () => {
  const findings = scanLine('DATABASE_URL=postgresql://user:password@localhost:5432/mydb');
  assert.ok(findings.some((f) => f.patternId === 'database-url'));
});

test('scanLine detects generic API key assignment', () => {
  const findings = scanLine('api_key: "sk_test_1234567890abcdef"');
  assert.ok(findings.some((f) => f.patternId === 'generic-api-key'));
});

test('scanLine detects password assignment', () => {
  const findings = scanLine('password = "supersecret123"');
  assert.ok(findings.some((f) => f.patternId === 'password-assignment'));
});

test('scanLine detects Twilio API Key SID', () => {
  const findings = scanLine('TWILIO_KEY = SK00000000000000000000000000000000');
  assert.ok(findings.some((f) => f.patternId === 'twilio-key'));
});

// ─── Allowlist / False Positive Filtering ────────────────

test('scanLine skips example values', () => {
  const findings = scanLine('api_key: "example_1234567890abcdef"');
  assert.equal(findings.length, 0);
});

test('scanLine skips placeholder values like <YOUR_KEY>', () => {
  const findings = scanLine('api_key: "<YOUR_API_KEY>"');
  assert.equal(findings.length, 0);
});

test('scanLine skips ${ENV_VAR} references', () => {
  const findings = scanLine('api_key: ${API_KEY_SECRET}');
  assert.equal(findings.length, 0);
});

test('scanLine skips "your_" prefixed values', () => {
  const findings = scanLine('api_key: "your_api_key_here_12345678"');
  assert.equal(findings.length, 0);
});

test('scanLine skips test_ prefixed values', () => {
  const findings = scanLine('password = "test_password_value"');
  assert.equal(findings.length, 0);
});

test('isAllowValue detects dummy values', () => {
  assert.ok(isAllowValue('dummy_key_12345678'));
});

test('isAllowValue detects replace_ values', () => {
  assert.ok(isAllowValue('replace_this_secret'));
});

// ─── scanText ────────────────────────────────────────────

test('scanText returns line numbers', () => {
  const content = 'const x = 1;\nconst key = "AKIAIOSFODNN7EXAMPLE"\nconst y = 2;';
  const findings = scanText(content);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);
});

test('scanText handles multiple findings across lines', () => {
  const content = [
    'const aws = "AKIAIOSFODNN7EXAMPLE";',
    'const gh = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB";',
    'const safe = "hello";',
  ].join('\n');
  const findings = scanText(content);
  assert.equal(findings.length, 2);
});

test('scanText handles empty content', () => {
  assert.deepEqual(scanText(''), []);
});

test('scanText with custom allow values', () => {
  const content = 'key = "AKIAIOSFODNN7EXAMPLE"';
  const findings = scanText(content, { allowValues: ['^AKIA'] });
  assert.equal(findings.length, 0);
});

test('scanText includes lineContent in findings', () => {
  const content = 'api_key: "sk_test_1234567890abcdef12345"';
  const findings = scanText(content);
  assert.ok(findings[0].lineContent.includes('api_key'));
});

// ─── shouldScan ──────────────────────────────────────────

test('shouldScan returns true for regular source files', () => {
  assert.ok(shouldScan('src/index.js'));
  assert.ok(shouldScan('lib/utils.ts'));
});

test('shouldScan returns false for node_modules', () => {
  assert.ok(!shouldScan('node_modules/express/index.js'));
});

test('shouldScan returns false for .git directory', () => {
  assert.ok(!shouldScan('.git/config'));
});

test('shouldScan returns false for lockfiles', () => {
  assert.ok(!shouldScan('package-lock.json'));
  assert.ok(!shouldScan('yarn.lock'));
  assert.ok(!shouldScan('pnpm-lock.yaml'));
});

test('shouldScan returns false for .env.example', () => {
  assert.ok(!shouldScan('.env.example'));
  assert.ok(!shouldScan('.env.sample'));
  assert.ok(!shouldScan('.env.template'));
});

test('shouldScan returns false for minified JS', () => {
  assert.ok(!shouldScan('dist/bundle.min.js'));
});

test('shouldScan with custom ignore patterns', () => {
  const custom = [/vendor\//];
  assert.ok(!shouldScan('vendor/jquery.js', custom));
  assert.ok(shouldScan('src/app.js', custom));
});

// ─── severityLevel ───────────────────────────────────────

test('severityLevel returns correct numeric levels', () => {
  assert.equal(severityLevel('critical'), 4);
  assert.equal(severityLevel('high'), 3);
  assert.equal(severityLevel('medium'), 2);
  assert.equal(severityLevel('low'), 1);
  assert.equal(severityLevel('unknown'), 0);
});

// ─── summarize ───────────────────────────────────────────

test('summarize counts findings by severity', () => {
  const findings = [
    { severity: 'critical' },
    { severity: 'critical' },
    { severity: 'high' },
    { severity: 'medium' },
    { severity: 'low' },
  ];
  const summary = summarize(findings);
  assert.equal(summary.critical, 2);
  assert.equal(summary.high, 1);
  assert.equal(summary.medium, 1);
  assert.equal(summary.low, 1);
  assert.equal(summary.total, 5);
});

test('summarize handles empty findings', () => {
  const summary = summarize([]);
  assert.equal(summary.total, 0);
  assert.equal(summary.critical, 0);
});

// ─── redact ──────────────────────────────────────────────

test('redact masks middle of long values', () => {
  const result = redact('AKIAIOSFODNN7EXAMPLE');
  assert.ok(result.startsWith('AKIA'));
  assert.ok(result.endsWith('MPLE'));
  assert.ok(result.includes('*'));
});

test('redact fully masks short values', () => {
  const result = redact('short');
  assert.ok(!result.includes('s'));
  assert.ok(result.includes('*'));
});

test('redact preserves first and last 4 chars for long values', () => {
  const result = redact('ghp_1234567890abcdefghijklmnopqrstuvwxyzAB');
  assert.equal(result.slice(0, 4), 'ghp_');
  assert.equal(result.slice(-4), 'yzAB');
});

// ─── Multiple patterns on one line ───────────────────────

test('scanLine detects multiple secrets on same line', () => {
  const line = 'aws_key=AKIAIOSFODNN7EXAMPLE gh_token=ghp_1234567890abcdefghijklmnopqrstuvwxyzAB';
  const findings = scanLine(line);
  assert.ok(findings.length >= 2);
});

// ─── No false positives on clean code ────────────────────

test('scanLine returns no findings for normal code', () => {
  const lines = [
    'const result = a + b;',
    'console.log("hello world");',
    'import { readFile } from "fs/promises";',
    'export function add(a, b) { return a + b; }',
  ];
  for (const line of lines) {
    assert.equal(scanLine(line).length, 0, `Unexpected finding in: ${line}`);
  }
});

// ─── PATTERNS integrity ──────────────────────────────────

test('PATTERNS has expected structure', () => {
  assert.ok(Array.isArray(PATTERNS));
  assert.ok(PATTERNS.length >= 15);
  for (const p of PATTERNS) {
    assert.ok(p.id, 'Pattern missing id');
    assert.ok(p.name, 'Pattern missing name');
    assert.ok(p.pattern instanceof RegExp, `${p.id} pattern is not RegExp`);
    assert.ok(['critical', 'high', 'medium', 'low'].includes(p.severity));
  }
});

test('DEFAULT_IGNORE_PATTERNS includes node_modules', () => {
  assert.ok(DEFAULT_IGNORE_PATTERNS.some((p) => p.test('node_modules/express')));
});

test('DEFAULT_IGNORE_PATTERNS includes .git', () => {
  assert.ok(DEFAULT_IGNORE_PATTERNS.some((p) => p.test('.git/config')));
});

// ─── Edge cases ──────────────────────────────────────────

test('scanLine handles empty string', () => {
  assert.deepEqual(scanLine(''), []);
});

test('scanText handles Windows line endings', () => {
  const content = 'const x = 1;\r\nconst key = "AKIAIOSFODNN7EXAMPLE"\r\n';
  const findings = scanText(content);
  assert.equal(findings.length, 1);
});

test('scanText detects generic secret env var', () => {
  const content = 'API_TOKEN=abcdef1234567890abcdef';
  const findings = scanText(content);
  assert.ok(findings.length >= 1);
});
