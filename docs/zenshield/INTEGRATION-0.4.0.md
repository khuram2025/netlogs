# ZenShield 0.4.0 source consolidation

The appliance source is now maintained together with the full application in `khuram2025/netlogs`.

## Included histories

| Branch | Integrated tip | Relationship |
|---|---|---|
| main | da8a87bc | Original appliance application base |
| claude/unruffled-cori | d1b6ba05 | Already contained in main |
| feat/zenai-ota-updates | b3d1d6b7 | Contained in the correlation feature branch |
| feat/policy-lookup-config-match | 5d0d9115 | Contained in the correlation feature branch |
| feat/correlation-engine-phase0 | bf7db5cb | All 55 upstream commits since main |
| Local appliance history | 181456c | Appliance controls, installer, storage, DNS, licensing and signed updates |

Git merge ancestry preserves all these commits. Feature branches remain available; none are deleted.

## Resolved overlaps

- Keep ZenShield's signed container update and rollback system. The upstream update implementation remains available for standalone installations; appliance navigation uses the host updater.
- Keep the deployed HTTPS Windows DNS agent, source enrollment, DNS workspace, filters, resolved IPs, pagination and CSV export. Add upstream Web Activity with its firewall/syslog DNS analysis as an additional view.
- Combine source approval and fail-closed collection with upstream event/ingest timestamps and per-device timezones. Refresh the global source timezone from PostgreSQL because web and collector have separate containers.
- Retain host storage metrics and disk expansion alongside upstream System Time settings and analytics.
- Preserve existing correlation rule definitions, including renamed or locally edited built-ins. New upstream rules are seeded without deleting existing rules by name; administrators can review overlap in Correlation.
- Preserve local cookie, CSRF, RBAC, bootstrap-password and five-character password policies.
- Remove embedded credential keys from the source and build. During OTA, the host copies the old key privately into the backed-up credentials volume before replacing the old container. Startup re-encrypts saved device credentials with a unique persistent key. New installs generate their own key.

## Upgrade/build corrections

- Apply PostgreSQL migrations before querying new columns. Adopt pre-Alembic appliance databases at the known baseline instead of incorrectly stamping the newest revision. Additive migrations tolerate tables already created by earlier application startup.
- Create the correlation table before its ClickHouse column migrations. Migration failures block startup and therefore the OTA health gate.
- Add the typed session, byte, interface, user, country and IPv4 columns required by NQL and traffic analytics; these were absent from upstream schema creation. Wait for asynchronous ClickHouse inserts before acknowledging writes or reading/dropping analytics scratch tables.
- Include Alembic configuration in the image, install the PDF renderer and its Chromium runtime, and store compliance proof uploads in backed-up application storage with authenticated retrieval.
- Build every application file and frontend asset from this merged checkout. Python runtime dependencies are locked with hashes in `appliance/requirements.lock`; the appliance version is `appliance/VERSION`.

## Source acceptance

- 154 upstream correlation/NQL unit tests passed. Two outdated CIDR SQL assertions were updated for the upstream numeric IPv4 implementation; a real ClickHouse CIDR/counter test verifies behavior.
- 53 upgrade checks and 49 fresh-install checks passed against isolated PostgreSQL, ClickHouse and Redis, including preserved credentials/events, real collector writes, source approval, pages/API filters, compliance proof access, PDF generation and time settings.
- 40 DNS integration checks passed in each installation path.
- 29 installer resource/recovery checks, 11 password-prompt checks and 19 signed OTA package tests passed.
- A synthetic 100,000-event DNS benchmark produced median queries of 21–23 ms and a summary query of 39.47 ms on the local disposable VM. This measures database queries, not an end-to-end sustained EPS capacity.

Public identifiers and canary acceptance are recorded separately after signed OTA deployment.
