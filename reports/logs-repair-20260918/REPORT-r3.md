# Logs repair â€” 17 September 2026

Deployed to `https://10.10.124.25/logs/` as web image
`zenshield:0.4.3-logfix-20260917-r3`. The original image and compose override
are retained on the server for rollback. Syslog ingestion was not restarted.

## Changes

- Replaced repeated raw-log device scans with an incrementally maintained
  ClickHouse device catalog, a cache, and one concurrent refresh per process.
- Removed redundant summary queries from the logs page. A device-list failure
  no longer discards successfully retrieved logs.
- Bounded explorer query threads, block sizes, memory, and aggregation/sort
  spill thresholds.
- Added an upper time bound to relative ranges. Future-dated events previously
  inflated the one-minute count from about 98,000 to over 16 million.
- Unified custom-date parsing, converted display-zone input to UTC, and
  rejected invalid/reversed ranges. Labels identify the configured timezone.
- Forwarded all toolbar/sidebar filters to facets and export, including IP/port
  exclusions, protocol, zones, session-end reason, and threat ID. Vendor action
  facets now actually filter the main table. Choosing a facet clears its NOT flag.
- Rendered query errors explicitly, retained filter state, and distinguished
  a proven capped count from an unavailable count. Failed counts retain results
  and permit pagination without claiming a fabricated minimum.
- Prevented stale facet responses from replacing newer results and rendered
  facet values as text rather than injecting them into HTML/event attributes.
- Restored pruned form controls when navigating back to a cached page.

## Verification

- 12 regression tests passed in the application's Python environment.
- 72 read-only route/database cases passed without a log-result error:
  all six presets (1m, 5m, 1h, 24h, 7d, 30d) crossed with all seven available
  device/VDOM entries plus All devices; representative network, policy, zone,
  application, protocol, action and session filters; exclusions; combinations;
  pagination; log and aggregate modes; custom UTC dates; and empty results.
- Median query-path time: **0.1115 seconds**; slowest: **7.694 seconds**.
  These are server-side route timings, not full browser navigation timings.
- Device-catalog reads measured **18â€“29 ms**, reading 10â€“19 catalog rows
  instead of millions of syslog rows.
- Browser checks exercised all six preset buttons and all seven device
  selections. TCP + destination port 443 returned matching rows. A custom
  11:00â€“11:05 UTC range returned rows inside that range. Reversed dates disabled
  Apply. A nonexistent source IP produced both an empty table and empty facets.
- The two additional registered IPs, `192.168.100.102` and `192.168.100.202`,
  have no stored syslog rows and therefore no log-source dropdown entries.

## Remaining operational limits

The ClickHouse container remains under substantial memory pressure from its
broader workload. Four of the 72 cases could not compute a total within the
budget; they returned logs successfully and displayed **Count unavailable**.
This patch does not claim to eliminate every database-wide memory error.

The device catalog was seeded from recent records and is maintained for new
inserts. A full historical catalog backfill hit the server-wide memory limit;
historical-only VDOMs outside that seed are not guaranteed to be discovered.
The currently visible seven sources were all tested. Existing log records were
not rewritten, including records with future timestamps.

## Files and rollback

- `live-matrix.json`: per-case timings and results, excluding raw log content.
- `logs-fix.patch`: portable source patch against the deployed 0.4.3 snapshot.
- `../tests/test_logs_regression.py`: regression tests.
- `../deployment/Dockerfile.logs-fix`: image recipe.

Server rollback (requires the same administrative access used for deployment):

```sh
cp /opt/zensheild/logfix-20260917/compose.update.before.yaml /opt/zensheild/compose.update.yaml
cd /opt/zensheild
docker compose -f compose.yaml -f compose.update.yaml up -d --no-deps web
```

The additive catalog and materialized view may remain in place on rollback;
they do not change or delete original logs.
