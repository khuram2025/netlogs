# URL / Domain Search Plan — Log Explorer (`/logs/`)

**Status:** Approved plan — _not yet implemented_
**Date:** 2026-06-07
**Owner:** Khuram
**Branch context:** `feat/correlation-engine-phase0`
**Related docs:** [`PALOALTO_THREAT_URL_PLAN.md`](./PALOALTO_THREAT_URL_PLAN.md), [`FASTVUE_GAP_ANALYSIS_AND_PLAN.md`](./FASTVUE_GAP_ANALYSIS_AND_PLAN.md)

---

## 1. Goal (user request)

On the Log Explorer (`http://<host>:8002/logs/`), destination **IP** search already works. We want the same destination search to also accept a **URL / domain**: when an analyst types a domain (e.g. `bing.com`) or a URL, the explorer should return the log records where that domain/URL appears — exactly like IP search does. Not every log carries a domain (only web/UTM/URL-filtering/DNS logs do), but those that do should be searchable. The search should also be able to tell whether the typed token is a **valid URL/domain** (vs an IP or free text) and route the query accordingly.

Logs are from **Fortinet (FortiGate)** and **Palo Alto (PAN-OS)** firewalls.

### Scope decisions (confirmed 2026-06-07)
| Decision | Choice |
|---|---|
| Approach | **Full integration** — promote indexed `hostname` / `url` / `domain` columns onto the `syslogs` table + backfill history, so domain behaves exactly like IP in the main view (not an `url_logs`-only MVP). |
| Match semantics | **Registrable-domain inclusive** — searching `bing.com` also matches `www.bing.com`, `cdn.bing.com`. Implemented via an eTLD+1 `domain` column. |
| Palo Alto gap | **In scope** — investigate and restore the broken PA URL-filtering ingestion (dead since 2026-04-22) so domain search covers both vendors. |

---

## 2. Executive summary

The Log Explorer searches the ClickHouse **`syslogs`** table. IP search is fast because `srcip`/`dstip` are **first-class, bloom-filter-indexed columns**. Domain/URL search does not work today because:

1. The NQL allow-list (`VALID_FIELDS`) does not include `url` / `hostname` / `domain`, so those terms are rejected before reaching SQL.
2. There is **no indexed `hostname`/`url`/`domain` column** on `syslogs`. The data exists only inside the unindexed `parsed_data` Map — searching it means a full scan of ~711M rows (too slow for interactive use).
3. The UI has no Domain/URL search field.

The fix mirrors the **proven `srcip`/`dstip` pattern** already used in this codebase: add dedicated indexed columns, populate them at ingest, backfill history with a mutation, and wire them through NQL + the UI. The registrable-domain (`bing.com` matches `www.bing.com`) requirement is satisfied natively by ClickHouse's built-in `cutToFirstSignificantSubdomain()` — **no `tldextract`/external dependency needed**. A separate, real issue must be fixed in the same effort: **Palo Alto URL-filtering logs stopped arriving on 2026-04-22**, so without that fix domain search would silently only cover Fortinet.

Because the live `syslogs` table only retains **~7 daily partitions** (Jun 1–7; older data lives in `syslogs_old`), the historical backfill is small (~7 mutations) and low-risk.

---

## 3. Current-state findings (research)

### 3.1 Search pipeline (codebase)
- Route + filter assembly: `fastapi_app/api/views.py` → `log_list()` (~lines 1044–1231). Accepts `q`, `srcip`, `dstip`, `srcport`, `dstport`, `protocol`, `application`, `action`, `policyname`, `log_type`, `threat_id`, zones, time range, and `*_not` negation flags. Helpers `_nql_term()` / `_explorer_search_query()` (~lines 4799–4836) compose an NQL string.
- NQL parse → compile: `fastapi_app/services/nql_parser.py`. Every field term is gated against **`VALID_FIELDS`** (line 137). Current set: `srcip, dstip, srcport, dstport, proto, protocol, action, severity, device, device_ip, policyname, log_type, application, app, src_zone, dst_zone, session_end_reason, threat_id, message, raw, facility, timestamp`. **No `url`/`hostname`/`domain`.**
- Field → SQL: `fastapi_app/db/clickhouse.py` → `_build_field_condition()` (line 1222). IP fields get special CIDR/range/wildcard/multi-value handling against the indexed `srcip`/`dstip` columns (line 1241+). Indexed string columns use a fast path via `_INDEXED_STRING_COLUMNS` (line 1120). Everything else falls through to `field_mapping` (line 1392), and unmapped names default to **`parsed_data['<field>']`** (line 1470) — correct but **unindexed**.

### 3.2 `syslogs` schema (live)
- DDL: `fastapi_app/db/clickhouse.py` lines 109–168. Dedicated indexed columns: `srcip, dstip, srcport, dstport, action, policyname, log_type, application, src_zone, dst_zone, session_end_reason, threat_id` + `parsed_data Map(String,String)` catch-all + `raw` (full original line).
- **No `url` / `hostname` / `domain` / `fqdn` column exists.**
- Live partitioning: `partition_key = toDate(timestamp)` (**daily**), `sorting_key = (device_ip, timestamp)`, `TTL 3 MONTH`.
  - ⚠️ **Drift to note:** the source DDL says `PARTITION BY toYYYYMM(timestamp)` (line 161) but the live table is partitioned **daily** (`toDate`). The migration must `ALTER` the live table; the DDL string only governs fresh installs. Reconcile the two so new installs match production (recommend daily).

### 3.3 Live data volumes & domain coverage (measured 2026-06-07)
| Table | Rows | Span | Notes |
|---|---|---|---|
| `syslogs` | **711,179,853** | Jun 1 00:08 → Jun 7 14:41 | Only ~7 daily partitions live (older → `syslogs_old`). |
| `url_logs` (fortinet) | 28,702,383 | Mar 17 → **Jun 7 (current)** | Indexed `hostname` (bloom) + `url` (tokenbf); 478k/day. |
| `url_logs` (paloalto) | 30,492,008 | Mar 17 → **2026-04-22 (STALE)** | 🔴 No new PA URL rows for ~6 weeks. |

Domain coverage inside `syslogs.parsed_data` (last 1h sample of 7.78M rows): `hostname` present **229,338 (~3%)**, `url` 159,288, `qname` 35,469, `misc` 11,769, `dstname` 0. → Domains exist but are sparse and **must be indexed** to search at this scale.

### 3.4 Palo Alto URL gap (root-cause direction)
- Per [`PALOALTO_THREAT_URL_PLAN.md`](./PALOALTO_THREAT_URL_PLAN.md): **PA URL Filtering logs are THREAT logs with `log_subtype = "url"`** (not a separate type).
- Live check (last 6h) of PA THREAT subtypes returned: `end, drop, deny, vulnerability, start, spyware` — **no `url` subtype at all**. PA TRAFFIC + THREAT are flowing heavily, so the firewalls are reachable; only **URL-filtering logs are absent**.
- Likely causes (to confirm during Phase D): (a) PA **log-forwarding profile** no longer forwards URL Filtering logs (firewall-side config; fits the clean 2026-04-22 cutoff), or (b) a **PAN-OS field/format change** broke the parser's `subtype=url` routing in `services/parsers.py`. Determines whether the fix is code or firewall config.

---

## 4. Vendor field semantics (confirmed against vendor docs + live data)

| Concept | Fortinet (FortiGate) | Palo Alto (PAN-OS) |
|---|---|---|
| Bare host / FQDN | `hostname` = `odc.officeapps.live.com` | host portion of URL field 31 (`host[:port]/path`), parser extracts `hostname` |
| Path / full URL | `url` = path only (`/filestreamingservice/...`) | URL field 31 = `host[:port]/path` (no scheme) |
| DNS query name | `qname` (utm/dns) | `qname` (spyware/dns subtype) |
| Registrable domain | _not provided_ — derive | _not provided_ — derive |

**Implication:** "domain" is **not** a single native field. We synthesize three normalized columns:
- **`hostname`** — full FQDN (Fortinet `hostname`; PA host extracted from URL field; DNS `qname`).
- **`url`** — best-effort full URL/host+path (Fortinet `hostname + path`; PA URL field as-is).
- **`domain`** — registrable domain / eTLD+1, derived from `hostname` via ClickHouse `cutToFirstSignificantSubdomain()`.

> Verified ClickHouse behavior: `cutToFirstSignificantSubdomain('www.bing.com')` → `bing.com`; `('odc.officeapps.live.com')` → `live.com`; `('foo.co.uk')` → `foo.co.uk` (correct eTLD+1). For an IP it mangles (`10.11.160.53` → `160.53`), so **IP hostnames must be guarded** (`isIPv4String(...)`).

**Sources:**
- FortiGate webfilter `hostname` vs `url` — LogRhythm device guide & FortiOS Log Reference (key/value `hostname` = domain, `url` = path).
- Palo Alto URL Filtering log fields (field 31 = "URL/Filename") — [docs.paloaltonetworks.com – URL Filtering Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/url-filtering-log-fields).

---

## 5. Gap analysis — "what we are missing"

| # | Missing piece | Where |
|---|---|---|
| 1 | `url` / `hostname` / `domain` not in NQL allow-list → unsearchable | `services/nql_parser.py:137` (`VALID_FIELDS`) |
| 2 | No indexed `hostname` / `url` / `domain` columns on `syslogs` (data trapped in unindexed `parsed_data`) | `db/clickhouse.py:109` (DDL) |
| 3 | No `field_mapping` / `_INDEXED_STRING_COLUMNS` entries; no IP-vs-domain input detection | `db/clickhouse.py:1120, 1392` |
| 4 | No Domain/URL search field in the UI; results don't surface host/url | `templates/logs/log_list.html:~3053` |
| 5 | Palo Alto URL ingestion dead since 2026-04-22 (no `subtype=url`) | `services/parsers.py` (PA URL routing) + PA firewall config |
| 6 | No domain normalization (lowercase, strip scheme/port, eTLD+1 derivation, IP guard) | ingest + schema |
| 7 | No backfill of historical rows | new ClickHouse migration / backfill step |

---

## 6. Target design

### 6.1 Schema — add three columns to `syslogs`
```sql
-- New dedicated columns
hostname  String DEFAULT '' CODEC(ZSTD(1)),     -- full FQDN
url       String DEFAULT '' CODEC(ZSTD(3)),     -- full URL / host+path
domain    String MATERIALIZED                    -- registrable domain (eTLD+1), auto-derived
            if(hostname = '' OR isIPv4String(hostname), '', cutToFirstSignificantSubdomain(hostname)),

-- New skip indexes
INDEX idx_hostname hostname TYPE bloom_filter(0.01) GRANULARITY 4,
INDEX idx_domain   domain   TYPE bloom_filter(0.01) GRANULARITY 4,
INDEX idx_url      url      TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
```
Design notes:
- **`domain` is `MATERIALIZED`**, not inserted: ClickHouse derives it from `hostname` on every insert, and `ALTER TABLE ... MATERIALIZE COLUMN domain` derives it for historical parts. This guarantees ingest/backfill consistency with one function and removes any `tldextract`/PSL dependency (good for the air-gapped appliance).
- `hostname` / `domain` → **bloom_filter** (exact-match lookups, like `dstip`). `url` → **tokenbf_v1** (token/substring search, same params as the existing `message` index).
- IP-hostname guard prevents PA private-IP "hostnames" from polluting `domain`.

### 6.2 Ingest — populate `hostname` + `url` (domain auto-derives)
Add a single vendor-aware helper (recommended location: `services/parsers.py`, consumed by `syslog_collector.py`):

```
derive_web_fields(parsed_data, log_type) -> (hostname, url):
  # Fortinet: hostname = parsed_data['hostname']; path = parsed_data['url']
  #           url = hostname + path  (when both present)
  # Palo Alto: field 31 → url = 'host[:port]/path'; hostname = host part (strip :port and /path)
  # DNS (utm/dns, spyware/dns): hostname = parsed_data['qname']
  # Normalize: lowercase host, strip trailing dot, cap length
```
Wire-up:
- `services/syslog_collector.py` → `parse_syslog_message()` (~lines 206–253): compute `(hostname, url)`, append to the row tuple (~line 1113).
- `db/clickhouse.py` → `insert_logs()` `column_names` (~lines 918–923): add `hostname`, `url` (**not** `domain` — it's materialized). Keep tuple order in sync.
- Gate the derivation on web-bearing `log_type`s (utm/webfilter, utm/app-ctrl, utm/ssl, utm/dns, PA THREAT `subtype=url`, PA spyware/dns) so the ~97% non-web rows pay ~zero cost.

### 6.3 NQL + field mapping
- `services/nql_parser.py:137` — add `"hostname", "url", "domain"` to `VALID_FIELDS` (all text fields; not numeric).
- `db/clickhouse.py:1120` — add to `_INDEXED_STRING_COLUMNS`: `'hostname': 'hostname'`, `'domain': 'domain'` (enables the fast indexed path incl. `~` contains and `|` OR). Map `'url'` here too, but document that `url:` typically uses the `~`/contains operator (tokenbf).
- `db/clickhouse.py:1392` — add `field_mapping` fallbacks for safety on the un-backfilled tail:
  - `'hostname'`: `if(hostname != '', hostname, parsed_data['hostname'])`
  - `'url'`: `if(url != '', url, parsed_data['url'])`
  - `'domain'`: `if(domain != '', domain, if(parsed_data['hostname'] != '' AND NOT isIPv4String(parsed_data['hostname']), cutToFirstSignificantSubdomain(parsed_data['hostname']), ''))`

### 6.4 "Smart destination" detection (the "valid URL or not" piece)
Add a classifier used by the Explorer:
```
classify_token(s) -> 'ip' | 'cidr' | 'ip_range' | 'wildcard_ip' | 'url' | 'domain' | 'text'
  - IPv4 / CIDR / a.b.c.d-e.f.g.h / 1.2.3.* → IP family (existing dstip path)
  - starts with http(s):// OR contains '/'         → url
  - matches FQDN regex (labels + valid TLD, has dot) → domain
  - else                                            → free text (message search)
```
- The **Dst** field auto-routes: IP-family → `dstip:` term (unchanged); `domain`/`url` → `domain:`/`url:` term.
- Add an explicit **"Domain / URL"** field for unambiguous use.
- Surface validity inline (e.g. greys out / hints "not a valid domain or IP") — satisfies the user's "valid URL or not" requirement.

### 6.5 UI
- `templates/logs/log_list.html` (~line 3053): add a **"Domain / URL"** search field beside Dst IP, reusing the existing label + **NOT** toggle pattern; bind to new `domain`/`url` query params.
- Results: show `hostname` (and `url` on row expand / detail). Optionally add a "Domain" column and a one-click **"Expand to all traffic to this domain's dst IPs"** pivot (domain → dst IPs via the indexed columns → existing `dstip` filter) for the IP-parity power case.
- `api/views.py` `log_list()`: accept `domain` / `url` (+ `_not`) params; run them through `classify_token`; include in `_explorer_search_query()` / `_nql_term()`.

---

## 7. Backfill plan (history)

**Magnitude:** live `syslogs` = ~7 daily partitions (Jun 1–7, ~100M rows/day). One mutation per partition; sequential, oldest → newest, off-peak.

Per partition (example `2026-06-07`):
```sql
ALTER TABLE syslogs
UPDATE
  hostname = lower(
    if(parsed_data['hostname'] != '', parsed_data['hostname'],
    if(parsed_data['qname']    != '', parsed_data['qname'],
    if(parsed_data['url'] != '' AND NOT startsWith(parsed_data['url'], '/'),
       domain(concat('//', parsed_data['url'])),       -- PA: host from 'host:port/path'
       '')))),
  url = if(parsed_data['url'] != '',
           if(parsed_data['hostname'] != '' AND startsWith(parsed_data['url'], '/'),
              concat(parsed_data['hostname'], parsed_data['url']),  -- Fortinet host + /path
              parsed_data['url']),                                  -- PA already host+path
           '')
WHERE log_date = '2026-06-07'
  AND (parsed_data['hostname'] != '' OR parsed_data['url'] != '' OR parsed_data['qname'] != '');
```
Then derive `domain` + populate the new indexes for old parts:
```sql
ALTER TABLE syslogs MATERIALIZE COLUMN domain   IN PARTITION '2026-06-07';
ALTER TABLE syslogs MATERIALIZE INDEX idx_hostname IN PARTITION '2026-06-07';
ALTER TABLE syslogs MATERIALIZE INDEX idx_domain   IN PARTITION '2026-06-07';
ALTER TABLE syslogs MATERIALIZE INDEX idx_url      IN PARTITION '2026-06-07';
```
**Monitoring & safety:**
- Watch `SELECT * FROM system.mutations WHERE table='syslogs' AND is_done=0`.
- Mutations rewrite whole parts → I/O heavy and compete with live ingest (~1100 EPS). Run one partition at a time, off-peak; verify free disk ≥ size of the largest partition before each.
- `syslogs_old` (older history) is **out of scope** for backfill by default — decide per need.

---

## 8. Palo Alto restoration (Phase D)

1. **Triage** what the firewalls are actually sending now:
   ```sql
   SELECT parsed_data['subtype'] subtype, count()
   FROM syslogs
   WHERE log_type='THREAT' AND timestamp >= now() - INTERVAL 1 DAY
   GROUP BY subtype ORDER BY 2 DESC;        -- confirm 'url' is absent
   ```
   Pull a few raw PA THREAT lines (`SELECT raw FROM syslogs WHERE log_type='THREAT' ... LIMIT 20`) and compare field layout to `services/parsers.py` PA URL/THREAT field maps.
2. **Decide fix path:**
   - If PA is **not forwarding** URL Filtering logs → firewall-side fix (re-enable URL logging in the Security Policy / Log Forwarding profile). Document the required PAN-OS config.
   - If PA **is forwarding** but the parser misroutes `subtype=url` (PAN-OS field/format drift) → fix `PaloAltoParser` URL detection + `build_paloalto_url_row()` and re-enable the `url_logs` dual-write; align with [`PALOALTO_THREAT_URL_PLAN.md`](./PALOALTO_THREAT_URL_PLAN.md).
3. Once PA URL rows flow again, the same ingest path (§6.2) populates `hostname`/`url`/`domain` for PA automatically.

---

## 9. Implementation task list (ordered)

| Phase | Task | Files | Effort |
|---|---|---|---|
| **A. Schema** | ClickHouse migration: `ALTER ADD COLUMN hostname,url`; `ADD COLUMN domain MATERIALIZED ...`; `ADD INDEX` (bloom hostname/domain, tokenbf url). Reconcile DDL partition drift. | new `db/clickhouse_migrations/0XX_add_url_domain_columns.py`; `db/clickhouse.py:109` | M |
| **B. Ingest** | `derive_web_fields()` helper; populate `hostname`/`url` per row; extend `insert_logs()` column list + collector tuple | `services/parsers.py`, `services/syslog_collector.py:~206/1113`, `db/clickhouse.py:918` | M |
| **C. Query** | Add fields to `VALID_FIELDS`, `_INDEXED_STRING_COLUMNS`, `field_mapping`; `classify_token()` IP-vs-domain detection | `services/nql_parser.py:137`, `db/clickhouse.py:1120/1392`, `api/views.py` | M |
| **D. PA fix** | Triage + restore PA URL ingestion (config or parser); re-enable `url_logs` dual-write | `services/parsers.py` (+ firewall config note) | M–L |
| **E. UI** | "Domain / URL" field + NOT toggle; show hostname/url; optional domain→dstIP pivot | `templates/logs/log_list.html:~3053`, `api/views.py:~1044/4803` | M |
| **F. Backfill** | Per-partition `UPDATE` + `MATERIALIZE COLUMN/INDEX`; monitor `system.mutations` | ops / migration step | S (≈7 partitions) |
| **G. Verify** | Timed queries + UI checks (§11) | — | S |

---

## 10. Risks & mitigations
- **Mutation load on live ingest** → run sequentially per daily partition, off-peak; monitor `system.mutations` + disk. Small (~7 partitions).
- **DDL vs live partition drift** (`toYYYYMM` vs `toDate`) → migration targets the live table; fix the source DDL for fresh installs.
- **IP-shaped hostnames** (PA private IPs) → guarded with `isIPv4String()` so `domain` stays clean.
- **`url` cardinality / index tuning** → tokenbf params matched to the proven `message` index; revisit if false-positive rate is high.
- **PA fix may be firewall-side** (out of our code) → if so, deliver Fortinet coverage + a documented PAN-OS config change rather than a code fix.
- **Ingest CPU** at ~1100 EPS → derivation gated to web-bearing `log_type`s (~3% of rows); `domain` computed in-DB, not Python.

---

## 11. Verification / acceptance
- `domain:bing.com` on a 24h window returns rows for `www.bing.com`, `cdn.bing.com`, etc., and is **fast** (uses `idx_domain`; check `EXPLAIN indexes=1`).
- `hostname:www.msftconnecttest.com` and `url:connecttest` (contains) return expected Fortinet rows.
- Typing an **IP** in the Dst field still uses the existing `dstip` path (no regression).
- Typing an invalid token is flagged ("not a valid domain or IP").
- Palo Alto: after Phase D, a known PA-visited domain returns rows; `url_logs` PA resumes growing.
- Negation (`-domain:...`) and combination with other filters (action/port/time) work.

---

## 12. What we need to enable (summary)
1. New indexed columns on `syslogs`: `hostname`, `url`, `domain` (materialized eTLD+1).
2. Ingest derivation of host/url for Fortinet + Palo Alto (+ DNS qname).
3. NQL allow-list + field-mapping + IP-vs-domain detection.
4. UI Domain/URL field (+ optional domain→IP pivot).
5. Restore Palo Alto URL-filtering ingestion (dead since 2026-04-22).
6. One-time backfill of the ~7 live daily partitions.

---

## Appendix A — Evidence queries (run 2026-06-07, host ClickHouse `localhost:8123`)
- `syslogs`: 711,179,853 rows; Jun 1 00:08 → Jun 7 14:41; `PARTITION BY toDate(timestamp)`, `ORDER BY (device_ip, timestamp)`, `TTL 3 MONTH`.
- Last-1h domain coverage: hostname 229,338 / url 159,288 / qname 35,469 / misc 11,769 of 7,778,946 (~3%).
- `url_logs`: fortinet 28,702,383 (current); paloalto 30,492,008 (last row **2026-04-22**).
- PA THREAT subtypes (last 6h): end, drop, deny, vulnerability, start, spyware — **no `url`**.
- `cutToFirstSignificantSubdomain`: `www.bing.com→bing.com`, `odc.officeapps.live.com→live.com`, `foo.co.uk→foo.co.uk`, `10.11.160.53→160.53` (IP must be guarded).

## Appendix B — Key code anchors
- `api/views.py` — `log_list()` ~1044–1231; `_nql_term()`/`_explorer_search_query()` ~4799–4836.
- `services/nql_parser.py` — `VALID_FIELDS` line 137.
- `db/clickhouse.py` — `syslogs` DDL 109–168; `insert_logs()` ~918; `_INDEXED_STRING_COLUMNS` 1120; `_build_field_condition()` 1222; `field_mapping` 1392; `url_logs` DDL 672.
- `services/syslog_collector.py` — `parse_syslog_message()` ~206–253; insert tuple ~1113.
- `services/parsers.py` — `FortinetParser`, `PaloAltoParser`, `build_paloalto_url_row()`.
- `templates/logs/log_list.html` — filter toolbar ~3053.
