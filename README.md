# secret-scan

Scan files for hardcoded secrets before they leak. Detects API keys, tokens, passwords, private keys, and database URLs in your source code.

## Why

Credentials in git history is one of the most common security incidents. Once pushed, they're practically impossible to fully remove. `secret-scan` catches them **before** they reach your repo — in a pre-commit hook, CI pipeline, or ad-hoc audit.

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

## CI Pipeline

```yaml
# GitHub Actions
- name: Scan for secrets
  run: npx secret-scan . --ci --quiet
```

## License

MIT
