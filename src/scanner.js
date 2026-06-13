'use strict';

// Built-in secret detection patterns
const PATTERNS = [
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    severity: 'critical',
    pattern: /AKIA[0-9A-Z]{16}/g,
    description: 'AWS Access Key ID',
  },
  {
    id: 'aws-secret',
    name: 'AWS Secret Access Key',
    severity: 'critical',
    pattern: /aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi,
    description: 'AWS Secret Access Key assignment',
  },
  {
    id: 'github-token',
    name: 'GitHub Token',
    severity: 'critical',
    pattern: /(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{36,255}/g,
    description: 'GitHub personal access token (classic, fine-grained, OAuth, refresh, or server)',
  },
  {
    id: 'google-api-key',
    name: 'Google API Key',
    severity: 'high',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    description: 'Google API Key',
  },
  {
    id: 'google-oauth-id',
    name: 'Google OAuth Client ID',
    severity: 'medium',
    pattern: /[0-9]+-[0-9A-Za-z_]{10,}\.apps\.googleusercontent\.com/g,
    description: 'Google OAuth 2.0 Client ID',
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    severity: 'critical',
    pattern: /xox[baprs]-[A-Za-z0-9-]{10,72}/g,
    description: 'Slack bot/user/refresh token',
  },
  {
    id: 'slack-webhook',
    name: 'Slack Webhook URL',
    severity: 'high',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g,
    description: 'Slack incoming webhook URL',
  },
  {
    id: 'stripe-key',
    name: 'Stripe API Key',
    severity: 'critical',
    pattern: /sk_(?:live|test)_[A-Za-z0-9]{24,99}/g,
    description: 'Stripe secret key',
  },
  {
    id: 'stripe-publishable',
    name: 'Stripe Publishable Key',
    severity: 'low',
    pattern: /pk_(?:live|test)_[A-Za-z0-9]{24,99}/g,
    description: 'Stripe publishable key (less sensitive)',
  },
  {
    id: 'private-key',
    name: 'Private Key Block',
    severity: 'critical',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    description: 'PEM-encoded private key',
  },
  {
    id: 'jwt',
    name: 'JWT Token',
    severity: 'medium',
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/g,
    description: 'JSON Web Token',
  },
  {
    id: 'generic-api-key',
    name: 'Generic API Key Assignment',
    severity: 'medium',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']/gi,
    description: 'Generic API key or secret assignment with quoted value',
  },
  {
    id: 'password-assignment',
    name: 'Password Assignment',
    severity: 'medium',
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{6,})["']/gi,
    description: 'Hardcoded password in assignment',
  },
  {
    id: 'bearer-token',
    name: 'Bearer Token',
    severity: 'medium',
    pattern: /Bearer\s+[A-Za-z0-9_\-\.=]{20,}/g,
    description: 'Bearer token in authorization header',
  },
  {
    id: 'discord-token',
    name: 'Discord Token',
    severity: 'critical',
    pattern: /(?:discord|bot)\s*(?:api[_-]?key|token)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{50,72})["']/gi,
    description: 'Discord bot/user token',
  },
  {
    id: 'twilio-key',
    name: 'Twilio API Key',
    severity: 'high',
    pattern: /SK[0-9a-fA-F]{32}/g,
    description: 'Twilio API Key SID',
  },
  {
    id: 'npm-token',
    name: 'NPM Auth Token',
    severity: 'critical',
    pattern: /npm_[A-Za-z0-9]{32,}/g,
    description: 'NPM authentication token',
  },
  {
    id: 'database-url',
    name: 'Database Connection URL',
    severity: 'high',
    pattern: /(?:mongodb|postgresql|postgres|mysql|redis|amqp):\/\/[^\s"']+:[^\s"']+@[^\s"']+/gi,
    description: 'Database URL with credentials',
  },
  {
    id: 'generic-secret-env',
    name: 'Generic Secret in Env',
    severity: 'low',
    pattern: /(?:SECRET|TOKEN|CREDENTIAL|AUTH)[A-Z_]*\s*=\s*([A-Za-z0-9_\-\/+]{16,})/g,
    description: 'Generic secret-like environment variable',
  },
];

// Default allowlist patterns (files and values to skip)
const DEFAULT_IGNORE_PATTERNS = [
  /\.env\.example$/i,
  /\.env\.sample$/i,
  /\.env\.template$/i,
  /node_modules\//,
  /\.git\//,
  /package-lock\.json$/,
  /yarn\.lock$/,
  /pnpm-lock\.yaml$/,
  /\.min\.js$/,
];

// Default allowlist for values that look like secrets but aren't
const DEFAULT_ALLOW_VALUES = [
  /^example/i,
  /^your[_-]?/i,
  /^replace[_-]?/i,
  /^dummy/i,
  /^test[_-]?/i,
  /^sample/i,
  /^placeholder/i,
  /^changeme/i,
  /^xxx+/i,
  /^<+.+>+$/,  // <YOUR_API_KEY>
  /^\$\{.+\}$/,  // ${ENV_VAR}
  /^process\.env\./,
];

function isAllowValue(value) {
  return DEFAULT_ALLOW_VALUES.some((p) => p.test(value));
}

/**
 * Scan a single line of text for secrets.
 * @param {string} line - Line to scan
 * @param {object[]} [patterns=PATTERNS] - Custom patterns (defaults to built-in)
 * @returns {object[]} Array of findings
 */
function scanLine(line, patterns = PATTERNS) {
  const findings = [];

  for (const p of patterns) {
    const regex = new RegExp(p.pattern.source, p.pattern.flags);
    let match;
    while ((match = regex.exec(line)) !== null) {
      const matchedValue = match[1] || match[0];

      // Skip allowlisted values
      if (isAllowValue(matchedValue)) continue;

      // Skip if the captured group looks like a placeholder
      if (match[1] && isAllowValue(match[1])) continue;

      findings.push({
        patternId: p.id,
        name: p.name,
        severity: p.severity,
        value: matchedValue,
        startIndex: match.index,
        endIndex: match.index + matchedValue.length,
        description: p.description,
      });
    }
  }

  return findings;
}

/**
 * Scan a text string (multiple lines) for secrets.
 * @param {string} content - Full text content
 * @param {object} [opts] - Options
 * @param {object[]} [opts.patterns] - Custom patterns
 * @param {string[]} [opts.allowValues] - Additional allowlist regex strings
 * @returns {object[]} Array of findings with line numbers
 */
function scanText(content, opts = {}) {
  const { patterns, allowValues = [] } = opts;
  const lines = content.split('\n');
  const findings = [];

  // Compile additional allow values
  const extraAllow = allowValues.map((s) => new RegExp(s, 'i'));

  for (let i = 0; i < lines.length; i++) {
    const lineFindings = scanLine(lines[i], patterns || PATTERNS);

    for (const f of lineFindings) {
      // Check extra allow values
      const isExtraAllowed = extraAllow.some((r) => r.test(f.value));
      if (isExtraAllowed) continue;

      findings.push({
        ...f,
        line: i + 1,
        lineContent: lines[i].trim(),
      });
    }
  }

  return findings;
}

/**
 * Determine if a file should be scanned based on path.
 * @param {string} filePath - File path to check
 * @param {string[]} [ignorePatterns=DEFAULT_IGNORE_PATTERNS] - Ignore regex patterns
 * @returns {boolean} Whether the file should be scanned
 */
function shouldScan(filePath, ignorePatterns) {
  const patterns = ignorePatterns || DEFAULT_IGNORE_PATTERNS;
  return !patterns.some((p) => {
    if (typeof p === 'string') return new RegExp(p).test(filePath);
    return p.test(filePath);
  });
}

/**
 * Get severity level as numeric for sorting.
 * @param {string} severity - Severity name
 * @returns {number} Numeric level (higher = more severe)
 */
function severityLevel(severity) {
  const levels = { low: 1, medium: 2, high: 3, critical: 4 };
  return levels[severity] || 0;
}

/**
 * Summarize findings by severity.
 * @param {object[]} findings - Array of findings
 * @returns {object} Counts per severity
 */
function summarize(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, total: findings.length };
  for (const f of findings) {
    if (summary[f.severity] !== undefined) summary[f.severity]++;
  }
  return summary;
}

/**
 * Redact a secret value for safe display.
 * Shows first 4 and last 4 characters.
 * @param {string} value - Secret value
 * @returns {string} Redacted value
 */
function redact(value) {
  if (value.length <= 12) return '*'.repeat(value.length);
  return value.slice(0, 4) + '*'.repeat(Math.min(value.length - 8, 20)) + value.slice(-4);
}

module.exports = {
  PATTERNS,
  DEFAULT_IGNORE_PATTERNS,
  DEFAULT_ALLOW_VALUES,
  scanLine,
  scanText,
  shouldScan,
  severityLevel,
  summarize,
  redact,
  isAllowValue,
};
