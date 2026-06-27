# secret-scan

**Catch leaked API keys before they hit git.** Zero-dependency scanner that finds 20+ secret types — AWS, GitHub, Stripe, private keys, database URLs — in milliseconds.

## Quick Start

```bash
# Scan your project right now
npx secret-scan . --ci
```

That's it. Exit code 1 means secrets found. Add it to CI in 30 seconds.

## Why

Credentials in git history is one of the most common security incidents. Once pushed, they're practically impossible to fully remove. `secret-scan` catches them **before** they reach your repo — in a pre-commit hook, CI pipeline, or ad-hoc audit.

## Real-World Examples

### 1. Git Pre-commit Hook (catch secrets before push)

```bash
# .git/hooks/pre-commit
#!/bin/sh
npx secret-scan --ci --quiet
```

Every commit now blocks if a secret is detected. No more leaked keys in git history.

### 2. GitHub Actions CI Pipeline

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx secret-scan . --ci --json > scan-results.json
      - run: cat scan-results.json
        if: always()
```

### 3. Programmatic Scanning in Node.js

```javascript
const { scanText } = require('secret-scan');

const code = `
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB";
`;

const findings = scanText(code);
console.log(findings);
// [
//   { patternId: 'aws-access-key', severity: 'critical', line: 2, ... },
//   { patternId: 'github-token', severity: 'critical', line: 3, ... }
// ]
```

## Install

```bash
npm install -g secret-scan
```

Or use without installing:

```bash
npx secret-scan .
```

## Usage

### Scan current directory

```bash
secret-scan .
```

### CI mode (exits 1 if secrets found)

```bash
secret-scan src/ --ci
```

### JSON output

```bash
secret-scan . --json
```

### Filter by severity

```bash
# Only high and above
secret-scan . --severity high
```

### Allowlist false positives

```bash
# Regex pattern for values to ignore
secret-scan . --allow "^DEV_KEY_"
```

### Show full secret values (for debugging)

```bash
secret-scan . --verbose
```

## What It Detects

| Pattern | Severity | Example |
|---------|----------|---------|
| AWS Access Key ID | Critical | `AKIA...` |
| AWS Secret Access Key | Critical | `aws_secret_access_key=...` |
| GitHub Token | Critical | `ghp_...`, `github_pat_...` |
| Slack Token | Critical | `xox[baprs]-...` |
| Stripe Secret Key | Critical | `sk_live_...` |
| NPM Auth Token | Critical | `npm_...` |
| Private Key Block | Critical | `-----BEGIN RSA PRIVATE KEY-----` |
| Google API Key | High | `AIza...` |
| Slack Webhook | High | `hooks.slack.com/services/...` |
| Twilio API Key | High | `SK...` |
| Database URL | High | `mongodb://user:pass@host/db` |
| Google OAuth Client ID | Medium | `...apps.googleusercontent.com` |
| JWT Token | Medium | `eyJ...` |
| Generic API Key | Medium | `api_key: "..."` |
| Password Assignment | Medium | `password: "..."` |
| Bearer Token | Medium | `Bearer eyJ...` |
| Stripe Publishable Key | Low | `pk_test_...` |
| Generic Secret Env Var | Low | `SECRET_TOKEN=...` |

## Smart Filtering

Automatically skips:

- **Files**: `node_modules/`, `.git/`, lockfiles, `.env.example`, `.min.js`
- **Values**: placeholders like `example_...`, `<YOUR_KEY>`, `${ENV_VAR}`, `test_...`, `dummy_...`

## Programmatic API

```javascript
const { scanText, scanLine } = require('secret-scan');

// Scan a string
const findings = scanText('api_key = "sk_test_aaaa" + "aaaaaaaaaaaaaaaaaaaaaaaa"');
// [{ patternId: 'generic-api-key', severity: 'medium', line: 1, ... }]

// Scan a single line
const hits = scanLine('const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"');
// [{ patternId: 'github-token', severity: 'critical', ... }]
```

## Git Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/sh
secret-scan --ci --quiet
```

Or with husky:

```json
{
  "scripts": {
    "precommit": "secret-scan --ci --quiet"
  }
}
```

## How It Compares

| Feature | secret-scan | gitleaks | truffleHog | detect-secrets |
|---------|------------|----------|------------|---------------|
| Dependencies | Zero | Go binary | Python + deps | Python + deps |
| Install | `npx` — no install | Download binary | `pip install` | `pip install` |
| CI integration | 1 line (`--ci` flag) | Config file | Config file | Config file |
| Programmatic API | Yes (Node.js) | No | No | No |
| Custom patterns | Yes (JS regex) | Yes (TOML) | Yes (JSON) | Yes (YAML) |
| False-positive filtering | Built-in | Manual | Manual | Manual |
| Speed | <1ms per file | Fast | Slow (entropy) | Medium |

`gitleaks` and `truffleHog` are excellent tools, but they require installation and configuration. `secret-scan` is the zero-friction option for Node.js projects — `npx` and you're done.

## License

MIT
