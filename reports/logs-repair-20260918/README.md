# Log explorer and Time & NTP repair

This change incorporates the r3–r8 appliance repairs into the current repository
without replacing newer 0.4.4 storage/update changes. Application sources and
migrations are under `fastapi_app`, NTP host code is in `appliance/control`, and
regression tests are in `tests`. The reports here preserve measured results and
known limitations, including the broad 24-hour aggregate memory-pressure case.

The `*.patch` files and derived Dockerfile are historical deployment artifacts
against image 0.4.3. Use the canonical repository sources for new full builds.
Appliance-only reproduction/staging helpers are in `scripts/logs-maintenance`;
they read ignored root `.env.local`. `fetch_source.py` downloads an ignored
snapshot; it never replaces canonical repository source. Remote scripts and
`tests/finish_index_backfill.py` are manual maintenance tools, not CI steps.
The historical index materializations have already completed on the appliance.

Validation: run the log regression, performance, range/time, timestamp-display
and background-responsiveness Python tests in the application environment;
run `tests/test_ntp.py`, `node tests/test_ntp_ui.cjs` and
`node tests/test_autocomplete.cjs`. Live scripts query an explicitly configured
appliance and should run sequentially. Never expose credentials in output.

## Release integration

The new host module `code/control/ntp.py` is included in control installation,
signed-package building, current verifier allowlists and host-code switching.
The native installer accepts both older packages without the module and new
packages with it. The NTP template is mirrored into full/incremental image paths.

Existing 0.4.3/0.4.4 package verifiers have a fixed payload allowlist and do not
accept the new NTP module. Before publishing a signed release to those clients,
provide a verifier bridge/update or bundle the host implementation into an
already-allowed file. Do not advertise a direct OTA upgrade as compatible until
that upgrade path has been tested. No release/package was published by this
source commit. The appliance hotfix was deployed directly as described in the
historical reports.

`REPORT-r8.md` is the latest deployed state: web r8, syslog r5, with NTP status
synchronized and the system timezone `Asia/Riyadh`. No historical log timestamps
were rewritten. Branch integration does not redeploy or restart that appliance.

## Repository integration verification

38 application/host Python checks passed against this branch in an isolated
process using the application's Linux dependencies. The 22 existing signed
package checks passed with their temporary directory on a filesystem meeting
the suite's 1 GiB free-space requirement. Both Node.js suites passed. No running
application source or settings were changed by this integration verification.
