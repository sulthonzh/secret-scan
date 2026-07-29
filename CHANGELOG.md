# Changelog

## v1.2.1 — 2026-07-29

### Added
- 27 new tests (70 → 97 total): CLI integration test suite (`test/cli.test.js`) with 25 tests covering all CLI options (--help, --ci, --json, --verbose, --quiet, --severity, --allow, recursive scanning, error handling) + 2 coverage-gap tests for defensive catch blocks

### Fixed
- **Coverage gap**: Prior audit reported 100% coverage but only covered `scanner.js` — `cli.js` had 0% test coverage. Fixed `test:coverage` script to include all `src/**/*.js` files

### Quality
- Tests: 97/97 GREEN (100% pass rate)
- Coverage: 99.57% statements, 96.9% branches, 100% functions, 99.57% lines (both files)
- scanner.js: 100% all metrics
- cli.js: 98.78% statements, 95.52% branches, 100% functions
- ESLint: CLEAN (0 errors, 0 warnings)

## v1.2.0 — 2026-06-28

### Added
- ESLint flat config (eslint.config.js) with strict rules: no-unused-vars, no-undef, prefer-const, eqeqeq
- c8 test coverage reporting (`npm run test:coverage`)
- `lint` script in package.json
- Comparison table in README (vs gitleaks, truffleHog, detect-secrets)
- `coverage/` added to .gitignore

### Fixed
- Removed unused `PATTERNS` import from cli.js (ESLint catch)

### Quality
- Tests: 67/67 GREEN (100% pass rate)
- Coverage: 100% statements, 93.54% branches, 100% functions, 100% lines
- ESLint: CLEAN (0 errors, 0 warnings)

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
