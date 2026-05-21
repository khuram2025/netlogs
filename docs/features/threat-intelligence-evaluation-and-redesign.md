# Threat Intelligence — Evaluation & Redesign Plan
### Feeds · IOCs · Matches

**Author:** Security Architecture review
**Date:** 2026-05-21
**Scope:** `/threat-intel/` — the Feeds, IOCs and Matches pages, their backend, and the IOC matching engine.
**Method:** Live walkthrough of the running system (`10.12.50.77:8002`), full source review (`models/threat_intel.py`, `services/threat_intel_service.py`, `services/ioc_matcher.py`, `api/threat_intel.py`, 3 templates ≈ 4,400 LOC), and competitive research against MISP, OpenCTI, Anomali, ThreatConnect, ThreatQ and Recorded Future.

---

## 1. Executive Summary

The Threat Intelligence module is a **functional IOC feed aggregator**, not yet a **threat intelligence capability**. It ingests well, but it under-detects, over-alerts, and gives the analyst nowhere to think.

**The headline problem — proven on the live system:**

> The platform holds **163,588 IOCs** but the matcher only loads **81,281**, and **every one of the 348 matches in the last 24h is an IP match**. The **82,307 URL IOCs and ~79,000 hash IOCs are never evaluated against any log.** Half the intelligence we pay to collect, parse, store and refresh produces **zero detections.**

That single gap defines the priority order. Three more findings shape the rest of the plan:

1. **Match output is noise, not signal.** The 348 "matches" are a handful of scanner IPs logged once per packet — the same IP `58.16.114.232` repeats dozens of times. There is no grouping, no case, no status, no triage workflow.
2. **IOCs have no lifecycle.** No decay/aging, no expiry enforcement, no enrichment, no allowlist/warning-list, no de-duplication across feeds. An IOC is a static row that lives forever.
3. **No retrospective hunting.** A new IOC is matched only against *future* traffic. With **2.4 billion logs already in ClickHouse**, the moment a feed adds a known-bad IP we should be sweeping history — and we don't.

The redesign below is sequenced so the **highest-ROI, lowest-risk work lands first** (detect the IOCs we already own), then signal quality (sightings, allowlists, decay), then platform depth (STIX/TAXII, enrichment, relationships).

**Current maturity vs. the market:** roughly a **3/10 IOC feed manager**. After P0–P1 it becomes a credible **6–7/10 operational TIP**; after P2–P3 it is genuinely competitive with MISP for an embedded SIEM use case.

---

## 2. Current State

### 2.1 What exists (and works)

| Area | State |
|---|---|
| Feed ingestion | CSV and JSON over HTTP, configurable parser, 5 built-in abuse.ch / Emerging Threats feeds, 30-min scheduler |
| IOC store | PostgreSQL `iocs` table, unique `(type,value)`, severity/confidence/threat_type/tags |
| Matcher | In-memory singleton, O(1) IP set + CIDR list, 5-min cache refresh, <1 ms/log |
| Matches | ClickHouse `ioc_matches` table, monthly partitions, 6-month TTL |
| Auto-block | High-confidence IP matches queued to an EDL list, 24h expiry |
| UI | 3 pages (Feeds / IOCs / Matches), tabbed, dark theme, metric cards |

The ingestion and matching *plumbing* is sound and fast. The architecture is not the problem.

### 2.2 Page-by-page (live observations)

**Feeds page** — 5 feeds, all `csv_url`, all abuse.ch / ET. Hero cards: `163,588 IOCs · Loaded in matcher: 81,281 · 348 matches · Matcher Engine: 0 checks`. Feed cards show IOC count, last fetch, interval, and Detail / IOCs / Matches / Fetch / Disable / Delete actions. **Bug:** "Match Severity Breakdown (24h)" shows `critical 0 / high 0 / medium 0 / low 0` while the Matches page reports `medium: 348` — the breakdown query is broken. **Bug:** "Logs checked: 0 / 0 checks completed" — matcher counters are in-memory only and read 0 after any restart.

**IOCs page** — a flat table paginated **1 of 3,272 pages** (50/row). Columns: Type, Value, Severity, Confidence, Threat Type, Source, Matches, Added, Actions. Filters: type / severity / feed / text search. Per-row actions: "Logs", "Remove" only. No row selection, no column sort, no IOC detail view, no enrichment, no bulk action beyond import. It is a spreadsheet, not an investigation surface.

**Matches page** — flat list, 100 rows. Columns: Time, Severity, IOC Type, IOC Value, Threat, Matched Field, Source IP, Dest IP, Dest Port, Feed, Actions. Every visible row is the *same* scanner IP at 1–5 second intervals. Hero: `Total 348 · all medium · By Type: IP 348 · Critical+High 0`. There is no concept of a distinct "sighting", no de-duplication, no status, no assignment, no link to an alert or incident.

---

## 3. Competitive Analysis

How the leading platforms frame the same three surfaces. (Sources in the Appendix.)

| Capability | Zentryc (today) | MISP | OpenCTI | Commercial TIP (Anomali / RF / ThreatConnect) |
|---|---|---|---|---|
| Feed formats | CSV, JSON | CSV, MISP, **STIX/TAXII**, freetext | **STIX 2.1 / TAXII 2.1**, 100+ connectors | STIX/TAXII, MISP, hundreds of feeds |
| STIX/TAXII | ❌ (enum stub) | ✅ | ✅ (native data model) | ✅ |
| IOC enrichment | ❌ | partial | ✅ (connectors) | ✅ (PDNS, WHOIS, ASN, geo, sandbox) |
| Decay / aging | ❌ | ✅ **decaying models** | ✅ | ✅ (e.g. RF 60-day decay) |
| Allow / warning lists | ❌ | ✅ **warninglists** (a flagship feature) | ✅ | ✅ |
| Cross-feed de-dup & scoring | ❌ | ✅ | ✅ | ✅ (multi-source corroboration) |
| Domain / URL / hash detection | ❌ (IP only) | n/a (sharing tool) | n/a | ✅ |
| Retro-hunt / historical sweep | ❌ | partial | partial | ✅ |
| Sightings model | ❌ | ✅ | ✅ (STIX Sighting SRO) | ✅ |
| Relationships (IOC↔malware↔actor↔campaign) | ❌ | ✅ galaxies | ✅ **knowledge graph** | ✅ |
| MITRE ATT&CK mapping | ❌ | ✅ | ✅ | ✅ |
| TLP marking | ❌ | ✅ | ✅ | ✅ |
| IOC detail / pivot page | ❌ | ✅ | ✅ (graph pivot) | ✅ |

**What the market teaches us (the principles worth stealing):**

- **MISP — warninglists & decaying models.** The single most effective false-positive control in the industry is a curated allowlist of "things that look bad but aren't" (CDNs, cloud ranges, public DNS, Alexa/Tranco top sites, your own ASNs). And IOCs *expire on a curve* — DNS/URL indicators decay fast, file hashes slowly.
- **OpenCTI — everything is an object with relationships.** An indicator is not a string; it links to malware, to a threat actor, to a campaign, to ATT&CK techniques. The value is the *pivot*.
- **Recorded Future / Anomali — confidence is computed, not declared.** Score from source reliability + recency + **number of independent sightings** + your own internal sightings. One feed saying "bad" ≠ five feeds saying "bad".
- **All of them — the unit of work is a *sighting/observation*, not a feed entry.** Detection happens when intel meets *your* telemetry; that intersection is what an analyst triages.

---

## 4. Gap Analysis (prioritised)

| # | Gap | Impact | Priority |
|---|---|---|---|
| G1 | URL / domain / hash IOCs never matched against logs | ~50% of all IOCs produce zero value | **P0** |
| G2 | Match output is raw events, not de-duplicated sightings | Analysts cannot triage; 348 rows ≈ ~10 real things | **P0** |
| G3 | Severity-breakdown bug; matcher counters reset on restart | Dashboards lie | **P0** |
| G4 | No allowlist / warninglist | Scanner/CDN/cloud noise floods matches | **P1** |
| G5 | No retro-hunt on new IOCs | Miss already-present compromise across 2.4 B logs | **P1** |
| G6 | No IOC decay / expiry enforcement | Stale IOCs accumulate, FP rate climbs | **P1** |
| G7 | No sighting status / case workflow / alert escalation | Matches go nowhere | **P1** |
| G8 | No IOC detail / pivot page | No place to investigate a single indicator | **P1** |
| G9 | No enrichment (geo, ASN, WHOIS, rDNS, reputation) | No context for a triage decision | **P2** |
| G10 | No STIX/TAXII or MISP feed support | Can't connect to standards-based sharing | **P2** |
| G11 | No cross-feed de-dup; confidence is static/declared | Duplicate rows; can't trust the score | **P2** |
| G12 | No feed health/quality scoring | Can't tell a good feed from a noisy one | **P2** |
| G13 | No relationships, threat actors, campaigns, ATT&CK | Not an intelligence platform, just a list | **P3** |
| G14 | Feed `auth_config` secrets stored in plaintext JSON | Security finding | **P2** |
| G15 | UI: flat 3,272-page table, no sort/bulk/saved views | Unusable at 163 k IOCs | woven through P1–P2 |

---

## 5. Redesign — Functionality

### 5.0 Foundation: data-model changes

These underpin everything else.

```
-- IOCs: lifecycle, scoring, dedup
ALTER TABLE iocs ADD COLUMN base_confidence   INT;      -- as declared by source
ALTER TABLE iocs ADD COLUMN score             INT;      -- computed, decayed, 0-100
ALTER TABLE iocs ADD COLUMN decay_at          TIMESTAMP;-- when score hits floor
ALTER TABLE iocs ADD COLUMN source_count      INT DEFAULT 1;  -- # feeds asserting it
ALTER TABLE iocs ADD COLUMN tlp               VARCHAR(10);    -- clear/green/amber/red
ALTER TABLE iocs ADD COLUMN status            VARCHAR(20);    -- active/expired/allowlisted/in_review
ALTER TABLE iocs ADD COLUMN kill_chain        VARCHAR(40);    -- recon/c2/exfil/...
ALTER TABLE iocs ADD COLUMN mitre_techniques  JSON;
ALTER TABLE iocs ADD COLUMN enrichment        JSON;     -- geo/asn/whois/rdns cache
ALTER TABLE iocs ADD COLUMN enriched_at       TIMESTAMP;
ALTER TABLE iocs ADD COLUMN internal_sightings INT DEFAULT 0;

-- New: feed↔IOC many-to-many (kills cross-feed duplication, G11)
CREATE TABLE ioc_feed_sources (ioc_id, feed_id, first_seen, last_seen,
                               feed_confidence, PRIMARY KEY (ioc_id, feed_id));

-- New: allow / warning lists (G4)
CREATE TABLE ti_allowlist (id, list_name, entry_type, value, is_cidr,
                           reason, source, created_by, created_at);

-- New: curated relationships (G13)
CREATE TABLE ti_entities  (id, kind, name, aliases, description, mitre_id);
                           -- kind: malware | threat_actor | campaign | tool
CREATE TABLE ti_relations (src_kind, src_id, rel, dst_kind, dst_id);

-- ClickHouse: a sighting roll-up beside the raw ioc_matches table (G2)
CREATE TABLE ioc_sightings (
  sighting_key String,            -- hash(ioc_value, internal_asset)
  ioc_value String, ioc_type String, internal_asset String,
  direction String,               -- inbound/outbound/lateral
  hit_count UInt32, first_seen DateTime64(3), last_seen DateTime64(3),
  severity String, status String, -- new/investigating/resolved/false_positive
  ...) ENGINE = ReplacingMergeTree ORDER BY sighting_key;
```

### 5.1 Detection engine — close G1 (the P0 priority)

The matcher already loads domains and hashes into memory; it just never checks them. Wire the existing log streams in:

| IOC type | Match against | Column |
|---|---|---|
| `ip` / CIDR | `syslogs` (live) | srcip / dstip — *already done* |
| `domain` | `dns_logs` (6.6 M rows) | `qname` — and `url_logs.hostname` |
| `url` | `url_logs` (55 M rows) | `url` |
| `hash_*` | `pa_threat_logs` | `file_hash` |

- Extend `ioc_matcher.check_log()` to accept and test `domain`, `url`, `hash`.
- Call it from the DNS / URL / PA-threat ingestion paths (the syslog path already calls it).
- For URLs: match on exact URL **and** on the URL's host against domain IOCs.
- **Expected outcome:** the 82 k URL + 79 k hash IOCs that are dead weight today start producing detections; the "Loaded in matcher 81,281 / Total 163,588" gap closes.

### 5.2 Sightings — close G2 / G7

Stop showing raw match events. Roll them up:

- A **sighting** = one `(IOC, internal asset, direction)` tuple. The 348 raw rows collapse to a handful of sightings, each with `hit_count`, `first_seen`, `last_seen`, an activity sparkline.
- Sighting **lifecycle:** `new → investigating → resolved | false_positive`. A "false positive" verdict offers a one-click **"add to allowlist"**.
- **Escalation:** a sighting on a `critical`/`high` IOC, or any *outbound* sighting (internal host → known-bad = likely compromise), auto-creates a **correlation incident** / alert. Inbound scanner hits do not — the firewall already dropped them.
- Drill-down: a sighting expands to its raw `ioc_matches` rows, each linking to the rule-aware log viewer.

### 5.3 Allowlists & warninglists — close G4

- Ship **built-in warninglists** (MISP-style), refreshable: RFC1918/bogons, major CDN ranges, cloud provider ranges (AWS/Azure/GCP/Cloudflare), public DNS resolvers, Tranco top-10k domains, your own ASNs/zones.
- On import: an IOC matching a warninglist is flagged `in_review`, not silently activated.
- On match: a hit on an allowlisted value is suppressed (still recorded, shown muted).
- The scanner IP `58.16.114.232` dominating today's matches is the textbook case — a "known mass-scanner" warninglist plus inbound-vs-outbound weighting removes most of the noise.

### 5.4 IOC lifecycle: decay, confidence, expiry — close G6 / G11

- **Computed score**, not declared. `score = f(base_confidence, source_count, recency, internal_sightings)`. Five feeds asserting an IOC and one of our own hosts touching it ⇒ high; one stale feed ⇒ low.
- **Type-aware decay curves:** URLs/domains decay fast (~14–30 days), IPs medium (~60–90 days), hashes slowly (months) — file hashes are immutable, infrastructure rotates.
- A nightly job applies decay, sets `status='expired'` past the floor, and **the matcher only loads `status='active'`**.
- Cross-feed **de-dup**: one row in `iocs`, N rows in `ioc_feed_sources`.

### 5.5 Retro-hunt — close G5

- When a feed import adds genuinely new IOCs, queue a **retrospective sweep** of ClickHouse (last 30/90 days, configurable) for those values.
- Surface results as sightings tagged `retro`, with a banner: *"New IOC X was already seen in your traffic 6 days ago."* This is where a TIP earns its keep — finding the compromise that predates the intel.
- Also expose **on-demand retro-hunt**: any IOC detail page → "Hunt last 90 days".

### 5.6 Enrichment — close G9

- On import (and on demand) enrich IOCs: **geo + ASN** (IP), **rDNS/PTR**, **WHOIS** age & registrar (domain), **passive-DNS** style resolution history from our own `dns_logs`, and a reputation roll-up.
- Cache in `iocs.enrichment` JSON with `enriched_at`; refresh on a schedule.
- Enrichment feeds both the analyst (context) and the score (a 10-year-old registrar domain ≠ a domain registered yesterday).

### 5.7 Feeds: formats, health, security — close G10 / G12 / G14

- **STIX 2.1 / TAXII 2.1** ingestion (the interoperability standard) and **MISP feed** format. Implement the `stix_taxii` enum that is currently a stub.
- **Feed health score** per feed: freshness (on-schedule %), volume trend, **hit rate** (IOCs that ever matched), **FP rate** (matches later marked false-positive), and **overlap** (uniqueness vs other feeds). A feed that only produces noise should be visibly bad.
- **Encrypt `auth_config`** at rest (G14) — feed API keys must not sit in plaintext JSON.

### 5.8 Relationships & ATT&CK — close G13 (P3)

- Lightweight STIX-shaped objects: `malware`, `threat_actor`, `campaign`, linked to IOCs and to MITRE techniques.
- IOC → ATT&CK technique → existing **MITRE coverage map** (already in the correlation module) — unifies the two features.
- A pivot graph on the IOC detail page: indicator ↔ feeds ↔ related IOCs ↔ malware ↔ actor.

---

## 6. Redesign — UI / UX

Design language stays consistent with the rest of Zentryc (dark theme, the existing CSS variables, the `localdt` / display-timezone work already shipped). Three pages, re-thought around the analyst's job.

### 6.1 Feeds — from "cards" to a feed *operations* console

```
┌─ Threat Intelligence ───────────────[ Feeds | IOCs | Sightings ]──[+ Add Feed]─┐
│                                                                                │
│  ┌ Coverage ─────┐ ┌ Detections 24h ┐ ┌ Matcher ───────┐ ┌ Feed Health ─────┐ │
│  │ 163,588 IOCs  │ │ 41 sightings   │ │ 163,588 loaded │ │ 4 healthy        │ │
│  │ ip·dom·url·hsh│ │ ▲ 12 outbound  │ │ 2.1 M logs/min │ │ 1 noisy ⚠        │ │
│  └───────────────┘ └────────────────┘ └────────────────┘ └──────────────────┘ │
│                                                                                │
│  FEEDS                                              [ Healthy ▾ ] [ search ]   │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ ● URLhaus — Malicious URLs           csv  ·  every 60m  ·  fetched 12m ago│  │
│  │   82,307 IOCs   Health 91 ███████████░  hit-rate 4.2%  FP 0.1%  uniq 88% │  │
│  │   [Detail] [IOCs] [Sightings] [Fetch] [Disable]                          │  │
│  ├────────────────────────────────────────────────────────────────────────┤  │
│  │ ⚠ Emerging Threats — Compromised IPs  csv ·  every 360m ·  fetched 1h ago│  │
│  │   2,133 IOCs    Health 38 ████░░░░░░░  hit-rate 71%  FP 64% ⚠  uniq 30%  │  │
│  │   → 64% of this feed's matches were marked false-positive. Review.        │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────┘
```

Changes: a real **health score** per feed (freshness · hit-rate · FP-rate · uniqueness); inline warnings on bad feeds; "Add Feed" supports CSV/JSON **and STIX-TAXII / MISP** with format-specific fields; the Detail modal becomes a feed analytics view (IOC type/severity mix, match trend, top matched IOCs, overlap with other feeds).

### 6.2 IOCs — from spreadsheet to investigation surface

```
┌─ Threat Intelligence ─────────────[ Feeds | IOCs | Sightings ]──[Import][+ IOC]─┐
│ ┌ Facets ────────┐  ┌──────────────────────────────────────────────────────┐  │
│ │ TYPE           │  │ [ search value / tag / actor ]      [ Saved views ▾ ] │  │
│ │  url    82,307 │  ├──┬────────┬──────────────┬───────┬─────┬───────┬──────┤  │
│ │  hash   79,143 │  │☐ │ TYPE   │ VALUE        │ SCORE │ HITS│ SOURCES│ AGE  │  │
│ │  ip      2,138 │  ├──┼────────┼──────────────┼───────┼─────┼───────┼──────┤  │
│ │ STATUS         │  │☐ │ url    │ hxxp://...sh │ 86 ▼  │  3  │ ●●●   │ 52m  │  │
│ │  active        │  │☐ │ ip     │ 58.16.114.232│ 44 ▼  │ 211 │ ●     │ 9d   │  │
│ │  in_review  12 │  │☐ │ domain │ bad.example  │ 91 ▲  │  0  │ ●●    │ 2h   │  │
│ │  expired       │  └──┴────────┴──────────────┴───────┴─────┴───────┴──────┘  │
│ │ SCORE  [▓▓▓──] │  3 selected → [ Allowlist ] [ Expire ] [ Tag ] [ Export ]   │
│ │ FEED / TLP /…  │                                                              │
│ └────────────────┘                                                              │
└────────────────────────────────────────────────────────────────────────────────┘
```

Changes: left **facet rail** with live counts (replaces the four static metric cards); **sortable** columns; **score** column with a decay trend arrow; **multi-row select + bulk actions** (allowlist / expire / tag / export); **saved views**; row click opens the **IOC detail drawer**:

```
┌─ IOC · domain · bad.example ──────────────────────────────[ Hunt 90d ][ × ]─┐
│ Score 91 ▲   Severity HIGH   TLP:AMBER   Status ACTIVE   Decays in 21 days   │
│ Threat: c2     Kill-chain: command-and-control     ATT&CK: T1071             │
├─ Enrichment ────────────────┬─ Sources (2 feeds) ──────────────────────────┤
│ ASN  AS13335 Cloudflare      │ ● URLhaus        first 2h ago   conf 80      │
│ Registered 2026-05-19 (2d!)  │ ● OTX C2 domains first 2h ago   conf 75      │
│ rDNS  —    Geo  US           │ Internal sightings: 0                        │
├─ Activity in our traffic ───┴──────────────────────────────────────────────┤
│  retro-hunt: seen 0 times in last 90 days                                   │
│  [ ▁▁▁▂▁▁ ] no internal resolutions in dns_logs                             │
├─ Related ───────────────────────────────────────────────────────────────────┤
│  malware: AgentTesla   ·   2 sibling IOCs from same feed batch              │
│  Actions: [ Block via EDL ] [ Allowlist ] [ Expire now ] [ Add note ]       │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 6.3 Matches → "Sightings" — from noise to a triage queue

```
┌─ Threat Intelligence ───────────────────[ Feeds | IOCs | Sightings ]──────────┐
│ ┌ New 9 ┐┌ Investigating 3 ┐┌ Outbound ▲ 4 ┐┌ FP this wk 22 ┐  [ status ▾ ]  │
│                                                                                │
│  SIGHTINGS                                            grouped by IOC + asset   │
│  ┌──────────────────────────────────────────────────────────────────────────┐│
│  │ ⬤ HIGH  outbound ▲   10.40.2.15  →  bad.example (domain, c2)              ││
│  │   17 hits · first 6d ago · last 12m ago   ▁▂▃▅▇▅▃   [New]   → Incident #44 ││
│  │   ── likely C2 beacon from an internal host. Investigate.                  ││
│  ├──────────────────────────────────────────────────────────────────────────┤│
│  │ ○ MEDIUM inbound ▼   58.16.114.232 (scanner)  → 211 hosts                  ││
│  │   211 hits · firewall denied all   [Resolved · scanner]  [Allowlist this] ││
│  └──────────────────────────────────────────────────────────────────────────┘│
└────────────────────────────────────────────────────────────────────────────────┘
```

Changes: the page is renamed **Sightings** and becomes a **work queue**, not a log dump. Status tabs across the top; each row is a de-duplicated `(IOC, asset)` pair with hit-count + sparkline; **direction** is first-class (outbound = priority); one-click **promote to incident**, **resolve**, **mark false-positive → allowlist**; expanding a sighting shows raw events deep-linked to the (already rule-aware) log viewer.

---

## 7. Phased Roadmap

| Phase | Theme | Deliverables | Why this order |
|---|---|---|---|
| **P0** | *Detect what we already ingest* | Domain/URL/hash matching vs `dns_logs`/`url_logs`/`pa_threat_logs`; fix severity-breakdown bug; persist matcher counters | Highest ROI, low risk — turns ~50% dead IOCs into detections with no new data model |
| **P1** | *Signal quality* | Sightings roll-up + status workflow + incident escalation; allowlist/warninglists; IOC decay + expiry; retro-hunt on new IOCs; IOCs-page facet rail + sort + bulk + IOC detail drawer | Makes the output triagable and trustworthy |
| **P2** | *Platform depth* | STIX/TAXII + MISP feeds; IOC enrichment (geo/ASN/WHOIS/rDNS); cross-feed de-dup + computed confidence; feed health scoring; encrypt feed secrets; TLP | Brings us to parity with mainstream TIPs |
| **P3** | *Intelligence, not just indicators* | Relationships (malware/actor/campaign); MITRE mapping into the existing coverage map; pivot graph; STIX export/sharing | Turns a list into an intelligence platform |

Each phase is independently shippable and leaves the system in a better, consistent state.

---

## 8. Risks & Notes

- **P0 performance:** domain/URL matching runs on the DNS/URL ingestion path — keep it on the same in-memory O(1) dict design as IP matching; URL exact-match is a hashset lookup, host-of-URL is one parse. Negligible cost.
- **Retro-hunt cost:** sweeping 90 days of ClickHouse must be a **bounded background job** (batched by IOC, capped concurrency), never synchronous to a feed fetch.
- **Allowlist correctness:** an over-broad allowlist hides real detections — every suppression must still be *recorded* and visible (muted), never silently dropped.
- **Decay tuning:** start with conservative curves and expose them as settings; an IOC expiring too early is a missed detection.
- **Scope:** P3 (relationships/graph) is genuinely large — treat it as a separate initiative once P0–P2 are in production.

---

## 9. Appendix — Competitive Sources

- MISP — features, warninglists, decaying models, taxonomies/galaxies: <https://www.misp-project.org/features/>
- OpenCTI — STIX 2.1 data model & knowledge graph: <https://docs.opencti.io/latest/usage/data-model/>
- Commercial TIP comparison (Anomali / Recorded Future / ThreatConnect / ThreatQ): <https://www.peerspot.com/products/comparisons/anomali-threatstream_vs_recorded-future_vs_threatconnect-threat-intelligence-platform-tip>
- IOC confidence scoring & decay models: <https://www.cyware.com/resources/security-guides/what-is-confidence-scoring-in-threat-intelligence> · <https://arxiv.org/pdf/1803.11052>
- Building IOC pipelines (scoring, decay, allowlists): <https://ismalicious.com/posts/building-ioc-pipelines-operational-threat-intelligence>
- Retro-hunting / retrospective IOC matching in SIEM: <https://www.cycognito.com/learn/threat-intelligence/threat-intelligence-feeds/>
- IOC enrichment (PDNS, WHOIS, ASN, geo): <https://www.wiz.io/academy/threat-intel/enrichment-in-threat-intelligence>
- False-positive reduction & allowlists: <https://www.hunters.security/en/blog/optimizing-threat-intel>
- STIX/TAXII 2.1 standard & ingestion: <https://kravensecurity.com/stix-and-taxii-a-full-guide/>
