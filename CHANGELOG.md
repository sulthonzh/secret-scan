# Changelog

## v1.1.0 — 2026-06-19

### Fixed
- **Critical**: Test script `node --test test/` failed on Node.js v22+ (resolved `test/` as module path). Fixed to `node --test test/*.test.js`.

### Added
- 12 new edge-case tests (54 → 66 total):
  - Discord token detection
  - MySQL and Redis connection string detection
  - `scanText` with custom patterns
  - `redact` boundary tests (exactly 12 chars, 13 chars)
  - `scanLine` with no patterns match
  - `shouldScan` for `.env.sample`, `.env.template`, `yarn.lock`, `pnpm-lock.yaml`
  - `summarize` with only-critical findings
  - `isAllowValue` for `changeme`, `${VAR}`, `<TOKEN>`
- CHANGELOG.md
- Three real-world examples in README (pre-commit hook, CI pipeline, programmatic scan)
- `prepublishOnly` script to run tests before publish
- `exports` field for clean CJS/ESM interop
- `repository` and `homepage` fields in package.json

### Improved
- README: added "Quick Start" section for <2-minute onboarding
- README: added programmatic API examples with expected output
- Version bump: 1.0.0 → 1.1.0

## v1.0.0 — 2026-06-13

### Initial Release
- 20 built-in secret detection patterns (AWS, GitHub, Google, Slack, Stripe, JWT, private keys, database URLs, etc.)
- Smart false-positive filtering (placeholders, example values, env var references)
- File ignore patterns (node_modules, .git, lockfiles, .env.example, minified JS)
- CLI with `--ci`, `--json`, `--severity`, `--allow`, `--verbose`, `--quiet` options
- Programmatic API: `scanLine`, `scanText`, `shouldScan`, `summarize`, `redact`, `severityLevel`
- Zero dependencies, Node.js 18+
- 54 tests, all passing
