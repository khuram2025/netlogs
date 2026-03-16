# Changelog

All notable changes to Zentryc SOAR/SIEM Platform will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-02-16

### Added
- First-run setup wizard with 4-step guided onboarding
- HTTPS/TLS enforcement with auto-generated self-signed certificates
- CSRF protection middleware on all state-changing requests
- Session security: JWT ID tracking, token revocation on logout, idle timeout
- Version tracking system (`__version__.py`, health endpoint, UI footer)
- Favicon for browser tab identification
- Security headers via nginx (HSTS, X-Frame-Options, CSP, etc.)

### Changed
- Session cookie `secure` flag now auto-enabled in production (non-debug) mode
- Health endpoint returns component-level status and version info
- Upgraded app version from 2.0.0 to 3.0.0

### Security
- CSRF tokens required on all POST/PUT/DELETE requests
- Session cookies marked Secure when not in debug mode
- Password complexity enforced: min 8 chars
- JWT tokens include unique `jti` claim for revocation support

## [2.0.0] - 2026-02-10

### Added
- Threat intelligence: 4 built-in feeds, real-time IOC matching, auto-block EDL
- Correlation engine: 5 pre-built multi-stage rules, MITRE ATT&CK mapping
- Custom dashboard builder: 6 widget types
- NQL (Zentryc Query Language) parser with aggregation pipelines
- Saved searches with sharing and use-count tracking

## [1.0.0] - 2026-02-08

### Added
- User authentication with JWT session tokens
- RBAC: ADMIN, ANALYST, VIEWER roles
- Alert engine: threshold, pattern, absence, anomaly rules
- 10 pre-built alert rules with MITRE ATT&CK mapping
- Notification service: email, Telegram, webhook channels
- Audit logging to ClickHouse with 1-year retention
- API key management with rate limiting (100/min)
- Docker appliance: 5-service compose deployment
