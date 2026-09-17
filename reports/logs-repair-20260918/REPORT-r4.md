# Logs performance repair — 17 September 2026

Deployed web image: `zenshield:0.4.3-logfix-20260917-r4`.
Target: `https://10.10.124.25/logs/`.
Web, nginx, ClickHouse, PostgreSQL, Redis and syslog containers are healthy.
ClickHouse and syslog ingestion were not restarted. Existing logs were not deleted.

## Changes

- Fetch recent log rows in disjoint, progressively older windows, reusing rows already fetched instead of repeatedly scanning expanding ranges for counts.
- Bound optional total counts to one second. Results remain usable when totals are unavailable; pagination does not invent a final page or a capped count.
- Add a materialized public-destination flag and compound source/action/scope indexes, including a VDOM variant. Historical materialization completed (`mutation_103251.txt`, zero remaining parts). Original predicates remain the correctness check; hints only skip data. OR/NOT branches cannot accidentally become mandatory index conditions.
- Compile named protocols such as TCP and UDP against the native numeric column.
- Bound autocomplete samples before applying prefix filters, exclude future timestamps, debounce requests, cancel superseded requests, and prevent stale responses from overwriting newer suggestions. Counts are labeled sampled.
- Move synchronous scheduled correlation and IOC database work off the web event loop. Security rules and their enabled state were preserved.
- Add one smaller-memory retry for database memory contention, sharing the original deadline. Queries never return a truncated scan as complete.
- Bound previous-period aggregate enrichment; missing history displays unknown rather than a false anomaly classification.
- Enable gzip for the exact `/logs/` HTML route. Authentication routes retain their previous configuration.
- Retain the earlier device catalog, UTC time bounds, facet/export filter forwarding, error handling and safe facet rendering fixes described in [the r3 report](REPORT-r3.md).

## Measurements

The supplied query combines source `172.20.30.46`, denied actions, Internet scope, seven days, 100 rows, and the default grouping fields.

| Measurement | Observed result |
| --- | --- |
| Before r4: supplied query, full server HTML render | 5.378 s |
| After r4: supplied query, authenticated HTTPS | 0.493–1.245 s |
| After r4: unfiltered one-minute page, authenticated HTTPS | 0.079–0.180 s |
| After r4: TCP/443/allow, seven days, authenticated HTTPS | 0.170–0.622 s |
| Supplied query HTML transfer | approximately 905 KB → 58 KB with gzip |
| Browser-submitted supplied query | 1,026 ms shown by page |

HTTPS timings include authenticated request processing, full HTML rendering and network transfer. They exclude browser painting. Browser timing is the page's server-reported duration. Results vary with incoming data and background load.

## Verification and scope

- 21 Python tests pass: 12 route/filter regressions, 8 performance/correctness checks, and an event-loop responsiveness test with a deliberately slow scan.
- JavaScript autocomplete cancellation and cached-response race checks pass.
- Nine live count comparisons agree with and without compound index hints: Internet/internal/inbound scopes crossed with All/Campus/WAN.
- The original 72-case query-path sweep is retained in `live-matrix.json`.
- The new 50-case sweep renders complete HTML. It covers every preset, every available device with the reported query, TCP/UDP, ports, action, Internet scope, CIDR/OR, exclusions, empty results, pagination, 200 rows, custom dates, NQL stats and aggregate views. This is representative combination coverage, not an exhaustive Cartesian product of arbitrary NQL expressions.
- In the post-materialization sweep (`performance-matrix-r4-complete.json`), **49/50 cases returned successfully**, median **0.628 s**, slowest successful case **3.017 s**. All seven reported-query device combinations completed in **0.490–1.486 s**, versus up to 30 seconds or a timeout during diagnosis.
- Browser checks verified the supplied filter state, returned source/action values, live IP suggestions, selecting a suggestion and submitting it.

## Remaining limit

The broad, unfiltered 24-hour aggregation by destination port still hit ClickHouse's **server-wide 5.4 GiB memory ceiling** in the post-materialization sweep. Its own recorded memory use was only tens of MB. This is not fixed merely by reducing the selected grouping fields. The deployment cannot honestly be described as passing every combination under all background loads.

An additional 50-case run with smaller background merge blocks also passed 49/50 and did not resolve this failure; that trial setting was reverted. The server reports that memory-worker correction and background merge-memory limits require a database restart, so those settings were not changed. Further work on this case needs a separately validated database resource/configuration change; repeatedly relaxing query limits would not resolve the shared memory ceiling.

Thirteen cases in that sweep returned their rows while displaying **Count unavailable** because the optional total exceeded its one-second budget. Autocomplete intentionally samples recent records. Historical-only device/VDOM catalog coverage retains the limitation documented in the r3 report.

## Artifacts and rollback

- `https-r4.jsonl`: authenticated HTTPS measurements, without cookies or log rows.
- `performance-matrix-r4-*.json`: per-case metrics, including failed checks.
- `logs-fix.patch`: nine-file portable source patch against image 0.4.3.
- `../deployment/Dockerfile.logs-fix`: derived image recipe.
- `../deployment/nginx.logs-fix.conf`: scoped compression configuration.

The temporary index-build compaction restrictions were restored to their original values after completion. The scratch index-test table was dropped.

To restore the previous r3 web image on the appliance:

```sh
cp /opt/zensheild/logfix-20260917/compose.update.before-r4.yaml /opt/zensheild/compose.update.yaml
cd /opt/zensheild
docker compose -f compose.yaml -f compose.update.yaml up -d --no-deps web
docker exec zensheild-nginx-1 nginx -s reload
```

To restore the previous nginx configuration, copy `/opt/zensheild/logfix-20260917/nginx.before-r4.conf` to `/opt/zensheild/nginx.conf`, validate with `nginx -t` inside the nginx container, then reload it. The additive columns/indexes/catalog may remain after rollback. The original 0.4.3 compose override is also retained as `compose.update.before.yaml`.
