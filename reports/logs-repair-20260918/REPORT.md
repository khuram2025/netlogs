# IP range, event time and NTP management — 18 September 2026

Latest: r8 makes Time & NTP honor the appliance timezone; see
[REPORT-r8.md](REPORT-r8.md). r7 changes the log table to device-reported timestamps;
see [REPORT-r7.md](REPORT-r7.md). The following records the r5/r6 deployment.

Web now runs `zenshield:0.4.3-logfix-20260918-r6`; syslog runs
`zenshield:0.4.3-logfix-20260918-r5`. All six services are healthy.
The collector was recreated for the r5 timestamp parser fix.
Previous performance work is in [REPORT-r4.md](REPORT-r4.md).

## System → Time & NTP

The new `/system/#time` panel shows actual Chrony synchronization state separately
from service activity, selected source, UTC clock, last reference time, stratum,
clock offset and per-source reachability. It refreshes every ten seconds without
discarding unsaved edits. Administrators can save up to eight additional IPv4,
IPv6 or hostname sources and retry source discovery/sampling.

The existing authenticated administrator/CSRF bridge exposes only three fixed
host operations. Server input is validated before writing the managed Chrony
sources file. A failed reload restores the old file. System/DHCP sources remain
unchanged. Retry does not force a clock step. The user's `10.10.192.10` was preserved.

Seven host unit tests and the JavaScript UI behavior check passed. Authenticated,
certificate-validated HTTPS verified the deployed panel and live status, rejected
an invalid server with HTTP 400, and confirmed configuration was unchanged.
Multiple-server saving and rollback were tested using temporary files, without
replacing the user's live NTP settings. Browser visual verification remains
blocked by the browser's certificate warning; it was not bypassed.

During deployment, several containers were unexpectedly observed stopped/created
(the nginx stop preceded the host-agent restart). The cause was not established.
Compose services were restored using the existing configuration and data volumes;
all six are healthy. This recovery also restarted the database services.
Post-recovery HTTPS smoke tests passed: range 3.245 s, reported seven-day query
2.947 s, one minute 0.476 s, TCP/443 seven days 0.920 s. All 100 range rows were
inside the requested bounds. See `https-r6.jsonl`.

## Findings and fixes

The reported range was `10.10.190.12-10.10.193.13` with denied Internet traffic over one hour. A fresh browser load before this patch returned 100 rows from `10.10.190.14` and `10.10.190.15`, both legitimately inside the range. The reported `10.10.199.15` was not reproduced. Do not describe its appearance as a confirmed, diagnosed parser defect.

Range filtering now uses validated, inclusive bounds on the native IPv4 columns. Reversed, malformed, or invalid ranges fail explicitly. Source/destination aliases, exclusions and comma-separated ranges retain numeric semantics. Live SQL boundary tests explicitly exclude `10.10.199.15`, values just outside either endpoint, and addresses whose string ordering differs from numeric ordering.

A separate ingestion bug was confirmed. FortiGate supplied a nanosecond epoch and `tz=+0300`, but the collector preferred its naive local date/time string and assigned UTC. Events were stored three hours ahead. The parser now prefers a valid epoch, supports seconds/milliseconds/microseconds/nanoseconds, and honors an explicit vendor offset when parsing a naive string. Palo Alto device-zone handling and the implausible-time fallback are retained.

After deployment, a live FortiGate event reported `17:35:56 +0300` and was stored as `14:35:56.379 UTC`, with ingestion at `14:36:02.551 UTC`. This confirms the conversion on newly received data.

Relative ranges now use exact durations instead of rounding the lower bound down by up to 59 seconds. The page visibly shows its timezone and effective start/end. The existing display setting remains UTC pending the user's timezone preference.

## Verification

- 29 Python checks passed: 9 new range/time tests plus 20 existing route/performance tests.
- Four live SQL boundary sets passed: source and destination, each included and excluded.
- The deployed full route returned 100 records; every IP and stored timestamp was within the requested bounds. Full HTML render: 2.653 seconds.
- Authenticated HTTPS returned HTTP 200 in 2.277 seconds, with 100 in-range source IPs and the UTC label present. Metrics are in `https-r5.jsonl`.
- The earlier seven-day query still completed in 1.150 seconds; one-minute page 0.322 seconds; TCP/443 seven-day page 0.493 seconds.
- Initial reproduction was verified in Chrome. The final browser reconnection encountered an untrusted-certificate error; it was not bypassed. Final deployed HTML was instead checked via authenticated HTTPS with the appliance certificate validated, plus direct route tests.

## Outstanding time issues

Previously stored, incorrectly dated records were not rewritten. The collector fix applies to new ingestion; historical event-time repair requires a separate data migration because timestamp participates in the table's sorting key. Historical records can retain their old three-hour error.

The appliance's own clock is also unsynchronized. `chronyc tracking` reports stratum 0 / Not synchronised; all configured NTP sources, including the user's `10.10.192.10`, have reach 0. The new panel accurately reports this. The clock service is active but has received no valid time samples. The NTP server/network path must become available before synchronization can succeed. No manual clock jump or NTP source replacement was made. Correct timezone conversion does not itself fix device or appliance clock drift.

The earlier broad 24-hour aggregation memory-pressure limitation remains as documented in the r4 report.

## Rollback

The pre-r5 override is saved at `/opt/zensheild/logfix-20260917/compose.update.before-r5.yaml`. It restores the prior r4 web image and original collector image; doing so also restores the old timestamp parsing bug.

```sh
cp /opt/zensheild/logfix-20260917/compose.update.before-r5.yaml /opt/zensheild/compose.update.yaml
cd /opt/zensheild
docker compose -f compose.yaml -f compose.update.yaml up -d --no-deps web syslog
docker exec zensheild-nginx-1 nginx -s reload
```

For an NTP-only rollback, restore `compose.update.before-r6.yaml` from the same
staging directory, recreate only web and reload nginx. Restore the saved
`agent.before-ntp.py` to `/usr/local/lib/zenshield/agent.py` and restart
`zenshield-agent` after checking that no management jobs or network changes are
pending. Preserve the managed NTP configuration file.

`logs-fix.patch` contains thirteen application source files against the original
0.4.3 image. `host-ntp.patch` contains the host-agent change and new NTP module.
The image recipe is `../deployment/Dockerfile.logs-fix`.
