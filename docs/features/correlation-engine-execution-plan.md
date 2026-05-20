# Correlation Engine — Master Execution Plan & Task Tracker

> **Status:** Active — working document
> **Date opened:** 2026-05-20
> **Owner:** _unassigned_
> **Feature area:** `/correlation/` — Multi-Stage Attack Detection

---

## How to use this document

This is the **single source of truth** for executing the Correlation Engine
overhaul. It consolidates three analysis documents into one actionable plan:

| Source document | Role |
|-----------------|------|
| `correlation-engine-evaluation-and-roadmap.md` | Original assessment + competitive analysis |
| `correlation-engine-final-verdict.md` | Challenge review — found 2 extra P0 defects, re-sequenced roadmap |
| `correlation-engine-review-response.md` | Second opinion — concessions + 3 refinements |

**Workflow:**
1. Work tasks **top to bottom**. Do not start a phase until the previous phase's
   exit criteria are met (exception: **Phase 2b** runs in parallel — see note).
2. When a task is done, change `- [ ]` to `- [x]` and fill the **Done** column
   (date + commit/PR).
3. When every task in a phase is checked and exit criteria pass, mark the phase
   **✅ COMPLETE** in the Progress Summary, then proceed to the next phase.
4. Each task has an ID (e.g. `P0-3`) — use it in commit messages and PRs.

**Status legend:** `- [ ]` not started · `- [~]` in progress · `- [x]` done · `- [!]` blocked

---

## Progress Summary

| Phase | Theme | Effort | Status | Done |
|-------|-------|--------|--------|------|
| **0** | Correctness & safety hotfixes | 1.5–2 wk | ✅ Complete | 14 / 14 |
| **1** | Match identity, evidence, suppression | 2–3 wk | ✅ Complete | 10 / 10 |
| **2** | True sequence engine | 3–5 wk | ⬜ Not started | 0 / 11 |
| **2b** | Visual builder UI (parallel w/ 1–2) | ~3 wk | ⬜ Not started | 0 / 7 |
| **3** | Authoring polish & detection-eng UX | 1–2 wk | ⬜ Not started | 0 / 5 |
| **4** | Source registry & entity model | 4 wk | ⬜ Not started | 0 / 7 |
| **5** | Incident & risk output | 3–4 wk | ⬜ Not started | 0 / 8 |
| **6** | Templates, MITRE workflow, response, ML | 4 wk | ⬜ Not started | 0 / 10 |

**Overall: 24 / 72 tasks complete.**

> Update this table as phases progress: ⬜ Not started · 🟡 In progress · ✅ Complete

---

## Positioning gate (do not skip)

Until **Phase 2** is complete, the feature is described internally and externally
as **"staged correlation analytics over firewall/syslog data."** It may **not**
be marketed as "multi-stage attack detection" until the sequence engine proves
stage B followed stage A for the same entity within a bounded window.

- [ ] **GATE-1** — Positioning copy updated to "staged correlation analytics" until Phase 2 ships · _UI strings, marketing_

---

# Phase 0 — Correctness & Safety Hotfixes

**Goal:** Stop silently wrong or unsafe behavior. Make existing matches
trustworthy. Ship the edit capability so release 1 is analyst-visible.
**Effort:** 1.5–2 weeks · **Priority:** 🔴 P0 — do first · **Depends on:** nothing

### Tasks

| ☐ | ID | Task | File(s) | Done |
|---|----|------|---------|------|
| - [x] | **P0-1** | Fix duplicate-alert `ValueError`: replace `datetime.replace(minute=now.minute-5)` with `datetime.now(timezone.utc) - timedelta(minutes=5)` | `services/correlation_engine.py` → `create_correlation_alert()` | 2026-05-20 · branch `feat/correlation-engine-phase0` |
| - [x] | **P0-2** | Fix MITRE coverage `pct` inflation: compute `covered` over **detectable** techniques only, not all techniques | `api/correlation.py` → `compute_coverage_stats()` (extracted pure helper) | 2026-05-20 · verified live: max 67%, none >100% |
| - [x] | **P0-3** | Add per-source field + operator **allow-list** for `syslogs` columns; reject unknown identifiers | `core/correlation_fields.py` (new), `services/correlation_engine.py` → `_build_where_clause()` | 2026-05-20 |
| - [x] | **P0-4** | Parameterize ClickHouse query **values** (bind params) instead of f-string interpolation | `services/correlation_engine.py` (`_build_where_clause`/`_evaluate_stage`) | 2026-05-20 · `{pN:Type}` bound params |
| - [x] | **P0-5** | Validate `group_by` / identifier fields separately against the allow-list (structural injection vector) | `services/correlation_engine.py` → `_evaluate_stage()` | 2026-05-20 |
| - [x] | **P0-6** | Create Pydantic schemas: `CorrelationRuleCreate/Update`, `StageSchema` (name, filter, threshold, window, group_by, source) | new `schemas/correlation.py` | 2026-05-20 |
| - [x] | **P0-7** | Validate rule/stage payloads on create; return user-readable errors to the UI (no silent runtime failure) | `api/correlation.py` → `api_create_rule()` | 2026-05-20 · 422 on bad field/severity/sqli |
| - [x] | **P0-8** | Fail **closed** on unresolved `$stageN.field` variables — drop the *stage*, not the *condition*; optional vars (`$x?`) must be explicit | `services/correlation_engine.py` → `_resolve_variable()`/`_build_where_clause()` | 2026-05-20 |
| - [x] | **P0-9** | Surface **medium/low** severity match counts in stat cards | `api/correlation.py` → `correlation_rules_page()`, `templates/correlation/rules.html` | 2026-05-20 · 6 cards; Medium 94,730 was hidden |
| - [x] | **P0-10** | Make "View All Matches" pass rule context — filters the matches tab to the rule, with a filter banner + clear | `templates/correlation/rules.html` | 2026-05-20 · verified: banner + 10/20 rows filtered |
| - [x] | **P0-11** | Add `PUT /api/correlation/rules/{id}` update endpoint; preserve immutable rule identity; bump `updated_at` | `api/correlation.py` → `api_update_rule()` | 2026-05-20 · HTTP 200 verified |
| - [x] | **P0-12** | Add `POST /api/correlation/rules/{id}/clone` endpoint (clone created disabled) | `api/correlation.py` → `api_clone_rule()` | 2026-05-20 · HTTP 200 verified |
| - [x] | **P0-13** | Add explicit range limits/validation for `hours` and `limit` API query params | `api/correlation.py` (`Query(ge=, le=)`) | 2026-05-20 · 422 on `hours=99999` |
| - [x] | **P0-14** | Unit tests: where-clause building (incl. injection attempts), variable resolution fail-closed, alert dedup boundary, invalid-stage rejection, MITRE pct | new `tests/test_correlation.py`, `pytest.ini`, `requirements-dev.txt` | 2026-05-20 · 50 tests, all pass |

### Exit criteria — Phase 0
- [x] A malformed rule **cannot be saved** (validation rejects it with a clear message). — _422 verified for bad field, severity, injection_
- [x] A variable-resolution failure **cannot broaden** a later stage. — _`_resolve_variable` raises `StageEvalError`; unit-tested_
- [x] Query field names are restricted to an approved allow-list; values are bound parameters. — _`core/correlation_fields.py` + `{pN:Type}` binding_
- [x] Alert creation does **not** fail during the first five minutes of any hour. — _`_recent_alert_cutoff()` uses `timedelta`; unit-tested_
- [x] Rules can be **edited** and **cloned** via the API (analyst-visible win for release 1). — _PUT + clone endpoints, HTTP 200 verified_
- [x] MITRE coverage `%` is mathematically correct (cannot exceed 100%). — _verified live (max 67%) + unit test for worst case_
- [x] `tests/test_correlation.py` passes — _50 tests pass (`venv/bin/python3 -m pytest`)_

---

# Phase 1 — Match Identity, Evidence & Suppression

**Goal:** Make match records represent **unique security evidence**, not
scheduler ticks. Preserve enough context to investigate.
**Effort:** 2–3 weeks · **Priority:** 🔴 P0 · **Depends on:** Phase 0

> **Why:** Two rules show exactly 1440 matches/24h = one per 60s scheduler tick.
> Match counts currently measure *condition persistence*, not *discrete events*.

### Tasks

| ☐ | ID | Task | File(s) | Done |
|---|----|------|---------|------|
| - [x] | **P1-1** | Extend `correlation_matches`: add `rule_version`, `match_fingerprint`, `entity_type`, `entity_value`, `first_seen`, `last_seen`, `status` | `services/correlation_engine.py`, `db/clickhouse_migrations/003_*` | 2026-05-20 · 7 columns added & populated |
| - [x] | **P1-2** | Define `match_fingerprint` composition: SHA-1 of `rule_id` + `rule_version` + entity_type + entity_value | `services/correlation_engine.py` → `match_fingerprint()` | 2026-05-20 · unit-tested (6 tests) |
| - [x] | **P1-3** | Capture per-stage **evidence**: min/max event time, count, source, filter, 3 sample event rows | `services/correlation_engine.py` → `_evaluate_stage()`, `_fetch_stage_samples()` | 2026-05-20 · verified live |
| - [x] | **P1-4** | Add explicit rule mode: **`discrete`** (one record per chain) vs **`recurring`** (continuous monitor) | `models/correlation.py`, `schemas/correlation.py` | 2026-05-20 · `match_mode` column + schema |
| - [x] | **P1-5** | Suppress repeats for `discrete` mode — record a chain at most once per `suppress_window` (no N rows for one persistent condition) | `services/correlation_engine.py` → `evaluate_all_correlation_rules()`, `_is_match_suppressed()` | 2026-05-20 · verified: count stays 1 over 3+ cycles |
| - [x] | **P1-6** | Add configurable **suppression window** per rule (`suppress_window`) | `models/correlation.py`, `schemas/correlation.py` | 2026-05-20 · column default 3600s |
| - [x] | **P1-7** | Replace title-substring alert dedup with exact `rule + entity` title dedup | `services/correlation_engine.py` → `create_correlation_alert()` | 2026-05-20 |
| - [x] | **P1-8** | Rule detail modal shows **evidence windows** (first→last event) and **suppression state** (mode + window + version chips) | `templates/correlation/rules.html`, `api/correlation.py` | 2026-05-20 · verified in browser |
| - [x] | **P1-9** | ClickHouse migration for the `correlation_matches` schema change (versioned migration file) | `db/clickhouse_migrations/003_correlation_match_evidence.py` | 2026-05-20 · CH schema v3 |
| - [x] | **P1-10** | Tests: fingerprint stability, discrete-vs-recurring, suppression window, evidence capture | `tests/test_correlation.py` | 2026-05-20 · 65 tests pass (15 new) |

### Exit criteria — Phase 1
- [x] A condition true for 30 minutes does **not** create 30 independent attack-chain records (unless rule mode = `recurring`). — _verified: each fingerprint stayed at 1 row over 3+ cycles; logs show "0 recorded, 2 suppressed"_
- [x] An analyst can see **why each stage matched** without guessing from broad log links. — _per-stage evidence (event-time bounds, samples) + evidence-window column in the detail modal_
- [x] Every match carries `entity`, `match_fingerprint`, `rule_version`, stage windows, and sample evidence. — _verified in `correlation_matches` rows_

---

# Phase 2 — True Sequence Engine

**Goal:** Make "then" mean **event-time ordering**. Evaluate **all** candidate
entities, not just the top aggregate.
**Effort:** 3–5 weeks · **Priority:** 🟠 P1 · **Depends on:** Phase 0 (Phase 1 strongly recommended)

> **Why:** `evaluate_correlation_rule()` calls `_evaluate_stage()` without
> `reference_time`, so every stage queries `now()` independently — ordering is
> never proven. And only `rows[0]` (top entity) is carried forward, masking
> every other valid chain.

### Tasks

| ☐ | ID | Task | File(s) | Done |
|---|----|------|---------|------|
| - [ ] | **P2-1** | Add rule property `ordering`: `sequence` (strict order) \| `any_order` (legacy aggregate behavior) | `models/correlation.py`, `schemas/correlation.py` | |
| - [ ] | **P2-2** | Add `join_keys` as a first-class stage/rule property (replaces single-string IP key) | `models/correlation.py`, `schemas/correlation.py` | |
| - [ ] | **P2-3** | Thread `reference_time` through `evaluate_correlation_rule()` into every stage call | `services/correlation_engine.py` | |
| - [ ] | **P2-4** | For `sequence` mode: stage 1 captures event time bounds; stage N evaluates `timestamp BETWEEN prev_terminal_time AND prev_terminal_time + window` | `services/correlation_engine.py` → `_evaluate_stage()`, `evaluate_correlation_rule()` | |
| - [ ] | **P2-5** | Return **candidate sets** from each stage (key, count, event-time bounds) — not just the top group | `services/correlation_engine.py` → `_evaluate_stage()` | |
| - [ ] | **P2-6** | Join candidate sets between stages by **canonical entity** — emit one match per valid chain | `services/correlation_engine.py` → `evaluate_correlation_rule()` | |
| - [ ] | **P2-7** | Support **composite joins**: `srcip+dstip`, `user+host`, etc. | `services/correlation_engine.py` | |
| - [ ] | **P2-8** | Store stage **ordering proof** (per-stage event windows showing A-before-B) in `stage_details` | `services/correlation_engine.py` | |
| - [ ] | **P2-9** | Migrate the 5 seeded rules to v2 schema; set `ordering=sequence` on the "then" rules, re-baseline thresholds | `services/correlation_engine.py` → `seed_correlation_rules()` | |
| - [ ] | **P2-10** | Alembic migration for `correlation_rules` (add `ordering`, `schema_version`, `join_keys`, `suppress_window`) + v1→v2 stage converter | `db/migrations/` | |
| - [ ] | **P2-11** | Tests: ordered sequence fires only when B follows A; multiple entities produce separate matches; `any_order` back-compat preserved | `tests/test_correlation.py` | |

### Exit criteria — Phase 2
- [ ] "Reconnaissance then Access" fires **only** when access follows recon for the same entity inside the window.
- [ ] Multiple valid entities can produce **separate** matches in one scheduler run.
- [ ] `any_order` legacy mode still works for the aggregate-style seeded rules.
- [ ] **Positioning gate lifted** — feature may now be called "multi-stage attack detection."

---

# Phase 2b — Visual Builder UI *(runs in parallel with Phases 1–2)*

**Goal:** Eliminate raw-JSON authoring. **Frontend-only** work — no shared code
with the engine, so it can be built concurrently if a frontend engineer is
staffed. **The `test/preview` endpoint is the exception — it is gated on Phase 2
and lives in Phase 3.**
**Effort:** ~3 weeks · **Priority:** 🔴 P0 (UX) · **Depends on:** Phase 0 (`PUT` endpoint)

### Tasks

| ☐ | ID | Task | File(s) | Done |
|---|----|------|---------|------|
| - [ ] | **P2b-1** | Add `GET /api/correlation/schema` — field/operator catalog per data source | `api/correlation.py` | |
| - [ ] | **P2b-2** | Visual stage builder: stage cards with add / remove / **reorder** (drag handle) | `templates/correlation/rules.html` | |
| - [ ] | **P2b-3** | Per-stage inputs: field dropdown, operator dropdown, value, threshold, window (duration picker), source, group-by, join keys | `templates/correlation/rules.html` | |
| - [ ] | **P2b-4** | Variable picker — offer `$stageN.<field>` chips for fields captured upstream | `templates/correlation/rules.html` | |
| - [ ] | **P2b-5** | Inline validation in the UI (name uniqueness, threshold > 0, window sanity, unknown-field warnings) | `templates/correlation/rules.html` | |
| - [ ] | **P2b-6** | Keep a **synchronized advanced JSON editor** as a power-user escape hatch | `templates/correlation/rules.html` | |
| - [ ] | **P2b-7** | Edit mode — open any existing rule in the same builder (uses `PUT` from P0-11) | `templates/correlation/rules.html` | |

### Exit criteria — Phase 2b
- [ ] An analyst can build and edit a correlation rule **without writing JSON**.
- [ ] A power user can still inspect/edit the JSON representation, kept in sync.

---

# Phase 3 — Authoring Polish & Detection-Engineering UX

**Goal:** Add test/preview (now safe because the engine is correct) and rule
versioning. **Effort:** 1–2 weeks · **Priority:** 🟠 P1 · **Depends on:** Phase 2 + Phase 2b

### Tasks

| ☐ | ID | Task | File(s) | Done |
|---|----|------|---------|------|
| - [ ] | **P3-1** | Add `POST /api/correlation/rules/test` — run a draft rule against recent history **without persisting** | `api/correlation.py` | |
| - [ ] | **P3-2** | Preview output: stages matched, sample matches, event counts, **estimated fire frequency**, stage-by-stage failure reasons | `api/correlation.py`, `templates/correlation/rules.html` | |
| - [ ] | **P3-3** | Record `rule_version` in every match; bump version on each `PUT` update | `services/correlation_engine.py`, `api/correlation.py` | |
| - [ ] | **P3-4** | Wire builder → test → save into one flow ("Test before enable") | `templates/correlation/rules.html` | |
| - [ ] | **P3-5** | Tests: preview returns correct match shape; preview never writes to `correlation_matches` | `tests/test_correlation.py` | |

### Exit criteria — Phase 3
- [ ] An analyst can create, test, edit, and tune a rule end-to-end without writing JSON.
- [ ] Rule preview shows expected fire rate, sample matches, and per-stage failures.

---

# Phase 4 — Source Registry & Entity Model

**Goal:** Move from firewall-only to **cross-domain** correlation. Normalize
entities **before** adding many sources.
**Effort:** 4 weeks · **Priority:** 🟠 P1 · **Depends on:** Phase 2

### Tasks

| ☐ | ID | Task | File(s) | Done |
|---|----|------|---------|------|
| - [ ] | **P4-1** | Build a correlation **source registry**: table name, timestamp column, allowed fields, entity mappings, supported operators | new `services/correlation_sources.py` | |
| - [ ] | **P4-2** | Register sources: `syslogs`, `url_logs`, `ioc_matches`, `audit_logs`, `alerts`, `correlation_matches` | `services/correlation_sources.py` | |
| - [ ] | **P4-3** | Define **canonical entities**: `ip`, `user`, `host`, `domain`, `url`, `device` | `services/correlation_sources.py` | |
| - [ ] | **P4-4** | Map each source's native fields → canonical entities (enables cross-source joins) | `services/correlation_sources.py` | |
| - [ ] | **P4-5** | Engine reads `source` from stage config — remove hardcoded `FROM syslogs` | `services/correlation_engine.py` → `_evaluate_stage()` | |
| - [ ] | **P4-6** | Seed 3 cross-source rules: (a) IOC hit → allowed firewall connection same IP; (b) suspicious DNS/URL → high outbound volume; (c) repeated denials → admin/audit change same entity | `services/correlation_engine.py` → `seed_correlation_rules()` | |
| - [ ] | **P4-7** | Tests: cross-source join by canonical entity; new source addable without core-engine edits | `tests/test_correlation.py` | |

### Exit criteria — Phase 4
- [ ] At least **3 shipped rules span ≥2 data sources**.
- [ ] A new source can be added by registry config without modifying core engine logic.

---

# Phase 5 — Incident & Risk Output

**Goal:** Reduce alert fatigue. Produce **incident-quality** output, not a flat
alert stream. **Effort:** 3–4 weeks · **Priority:** 🟡 P2 · **Depends on:** Phase 4

### Tasks

| ☐ | ID | Task | File(s) | Done |
|---|----|------|---------|------|
| - [ ] | **P5-1** | Create `entity_risk` ClickHouse table (entity_type, entity_value, score, contributing rule, ts, decay) | `db/clickhouse_migrations/` | |
| - [ ] | **P5-2** | Per-rule configurable **risk contribution** (weight added to the implicated entity) | `models/correlation.py`, `services/correlation_engine.py` | |
| - [ ] | **P5-3** | Implement **time-decay** so stale risk ages out | new risk evaluator, `services/scheduler.py` | |
| - [ ] | **P5-4** | **Incident grouping** — collapse matches sharing entity + rule family + MITRE tactic + time proximity into one incident | new `services/incident_service.py` (or extend `Alert` w/ parent) | |
| - [ ] | **P5-5** | Derive incident **severity** from accumulated risk + rule severity + tactic kill-chain position | `services/incident_service.py` | |
| - [ ] | **P5-6** | Incident lifecycle states: `new`, `investigating`, `contained`, `resolved`, `suppressed` | model + UI | |
| - [ ] | **P5-7** | Keep raw matches available **as evidence under the incident** | `services/incident_service.py`, UI | |
| - [ ] | **P5-8** | Incident UI view + API | `api/correlation.py` (or new), templates | |

### Exit criteria — Phase 5
- [ ] Four related matches for one host become **one incident** with risk context and evidence — not four alerts.
- [ ] Entity risk **accumulates and decays** correctly.

---

# Phase 6 — Templates, MITRE Workflow, Response & ML

**Goal:** Scale detection content, connect ATT&CK gaps to rule creation, add
controlled response automation, and layer the differentiators.
**Effort:** 4 weeks · **Priority:** 🟡 P2 · **Depends on:** Phases 2b & 5

### Tasks

| ☐ | ID | Task | File(s) | Done |
|---|----|------|---------|------|
| - [ ] | **P6-1** | Curated **template library** — 30–50 parameterized, MITRE-mapped templates, grouped by tactic & source | new `api/correlation.py` endpoint + content | |
| - [ ] | **P6-2** | **Data-aware** template discovery — recommend templates matching sources actually ingested | `api/correlation.py`, UI | |
| - [ ] | **P6-3** | "Create rule from this technique" action on uncovered MITRE map cells → opens builder pre-seeded | `templates/correlation/mitre_map.html` | |
| - [ ] | **P6-4** | **Response actions** per rule + severity: notify (email/Telegram/webhook), add IP/domain to EDL/blocklist, create ticket/webhook | `models/correlation.py`, `services/correlation_engine.py`, `services/notification_service.py` | |
| - [ ] | **P6-5** | **Anomaly stages** — let a stage reference existing learning-mode baselines (volume anomalous vs baseline) | `services/correlation_engine.py` | |
| - [ ] | **P6-6** | _Differentiator:_ **attack-chain timeline visualization** — render a matched chain as a kill-chain timeline | `templates/correlation/` | |
| - [ ] | **P6-7** | _Differentiator:_ **rule health scorecard** — fire frequency, match-to-alert ratio, est. FP rate, last-tuned date | `api/correlation.py`, UI | |
| - [ ] | **P6-8** | _Differentiator:_ **Sigma rule import** — map single-source Sigma rules into Zentryc stages | new importer | |
| - [ ] | **P6-9** | _Differentiator:_ **backtest** — `POST /rules/{id}/backtest` over 7/30 days of history with a fire-frequency chart | `api/correlation.py`, UI | |
| - [ ] | **P6-10** | _Differentiator:_ **simulation / purple-team mode** — inject synthetic event sequences to validate rules fire, mapped to MITRE | new service | |

### Exit criteria — Phase 6
- [ ] An analyst can open an uncovered ATT&CK technique, pick a template, preview match volume, and deploy a rule in minutes.
- [ ] A critical incident can trigger a **controlled, audited** response action.

---

## Recommended Next Sprint

The first sprint should establish a **trustworthy detection foundation** before
any UX expansion. Pull these tasks into the first sprint:

- [x] **P0-1** — Fix alert-dedup time math
- [x] **P0-6 / P0-7** — Schema validation, reject malformed rules at save
- [x] **P0-8** — Fail-closed variable resolution
- [x] **P0-3 / P0-4 / P0-5** — Query allow-lists + parameterized values
- [x] **P1-1 / P1-2** — Match fingerprint / suppression **design** (design can start early)
- [ ] **P2-1 / P2-3 / P2-4** — Ordered sequence semantics for the seeded "then" rules
- [x] **P0-11 / P0-12** — `PUT` update + clone endpoints (so release 1 has an analyst-visible win)

> Rationale: this sequence makes the engine *correct* first. Once correct, the
> visual builder, multi-source correlation, templates, and risk-based incidents
> become high-value investments instead of UI built on ambiguous semantics.

---

## Decision Log

Record scope changes, deferrals, and disputes here as work proceeds.

| Date | Decision | By |
|------|----------|----|
| 2026-05-20 | Plan consolidated from 3 analysis docs; roadmap adopts the verdict's sequencing with 3 refinements (edit endpoint pulled into Phase 0; builder UI parallelized as Phase 2b; test/preview gated on Phase 2 as Phase 3). | Review |
| 2026-05-20 | **Phase 0 complete** (14/14 tasks). Implemented on branch `feat/correlation-engine-phase0`: new `core/correlation_fields.py` (source field allow-list), `schemas/correlation.py` (Pydantic validation), parameterized ClickHouse queries, fail-closed variable resolution, PUT/clone endpoints, 6 severity cards, filtered match view, `tests/test_correlation.py` (50 tests). Committed `4df7aa0`. | Eng |
| 2026-05-20 | **Phase 1 complete** (10/10 tasks). ClickHouse migration `003` (+7 columns on `correlation_matches`, schema v3); Alembic `f1a2b3c4d5e6` (+version/match_mode/suppress_window on `correlation_rules`). Match fingerprint + entity identity + event-chain evidence windows + 3 sample events per stage; discrete/recurring rule modes; suppression so a discrete rule records a chain once per `suppress_window` instead of once per 60s tick. Verified live: scheduler logs "0 recorded, 2 suppressed"; each fingerprint stayed at 1 row over 3+ cycles. 65 tests pass. | Eng |
| | | |

---

## Reference Documents

- `docs/features/correlation-engine-evaluation-and-roadmap.md` — original assessment, competitive analysis, feature matrix
- `docs/features/correlation-engine-final-verdict.md` — challenge review, 2 extra P0 findings, acceptance criteria
- `docs/features/correlation-engine-review-response.md` — second opinion, concessions, 3 refinements, conflict register

**Key source files (current implementation):**
- `fastapi_app/models/correlation.py`
- `fastapi_app/services/correlation_engine.py`
- `fastapi_app/api/correlation.py`
- `fastapi_app/templates/correlation/rules.html`
- `fastapi_app/templates/correlation/mitre_map.html`
- `fastapi_app/services/scheduler.py:426` (60s evaluation job)
