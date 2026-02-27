# Changelog

All notable changes to the Voidly Community Probe are documented here.

## [1.0.12] - 2026-02-26

### Fixed
- **Windows PATH issue**: Added `python -m voidly_probe` instructions for Windows users whose Scripts folder isn't on PATH
- Error messages now show Windows-friendly alternative command
- README and website install instructions updated with Windows note
- Fixed missing `--consent` flag in llms.txt install instructions

## [1.0.11] - 2026-02-26

### Security
- **Submission replay prevention**: Each submission now includes a unique nonce (`submissionId`) to prevent replay attacks
- **Risk advisory**: Automatic warning for users in high-censorship countries (CN, IR, RU, etc.) with VPN recommendation

### Added
- **Manual country override**: Set `VOIDLY_COUNTRY` and `VOIDLY_CITY` environment variables to skip ipinfo.io entirely
- **Third-party disclosure**: Consent text now explicitly discloses ipinfo.io and Cloudflare DoH usage
- **SECURITY.md**: Comprehensive security policy with third-party service documentation
- **CHANGELOG.md**: This file

### Changed
- Enhanced consent text with full third-party service disclosure
- `setup.py` now includes Security and Changelog project URLs

## [1.0.10] - 2026-02-25

### Security
- Safe integer parsing for environment variables (prevents crash on malformed input)
- Config validation: nodeId (8-64 chars) and nodeToken (16-256 chars) checked on load
- Interval clamping with user warning (minimum 300s enforced)

### Changed
- Dockerfile: Split ENTRYPOINT/CMD for easier CLI override
- Healthcheck: Validates local `node.json` exists
- `.dockerignore`: Added `node.json`, `pending_results.json`, IDE configs
- `setup.py`: UTF-8 encoding for README.md

## [1.0.9] - 2026-02-25

### Security
- Token file permissions set to `0600` (owner-only read/write)
- Registration validates nodeId and nodeToken format from API response
- HTTPS enforced for API URL (refuses plain HTTP)
- Error messages truncated to 200 chars to prevent information leakage

## [1.0.8] - 2026-02-24

### Added
- SIGTERM/SIGHUP signal handling for graceful Docker shutdown
- Exponential backoff on API failures (5s → 60s, reset on success)
- Disk cache for failed submissions (retried next cycle)
- DNS-over-HTTPS poisoning detection via Cloudflare DoH

### Changed
- Probe results now flush on Ctrl+C before exiting

## [1.0.7] - 2026-02-24

### Fixed
- User-Agent header format updated to pass Cloudflare WAF rules
- Docker build now works with slim Python base image
