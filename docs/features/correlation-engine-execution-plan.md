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
| **2** | True sequence engine | 3–5 wk | ✅ Complete | 11 / 11 |
| **2b** | Visual builder UI (parallel w/ 1–2) | ~3 wk | ✅ Complete | 7 / 7 |
| **3** | Authoring polish & detection-eng UX | 1–2 wk | ✅ Complete | 5 / 5 |
| **4** | Source registry & entity model | 4 wk | ✅ Complete | 7 / 7 |
| **5** | Incident & risk output | 3–4 wk | ✅ Complete | 8 / 8 |
| **6** | Templates, MITRE workflow, response, ML | 4 wk | 🟡 In progress | 7 / 10 |

**Overall: 69 / 72 tasks complete.**

> Update this table as phases progress: ⬜ Not started · 🟡 In progress · ✅ Complete

---

## Positioning gate (do not skip)

Until **Phase 2** is complete, the feature is described internally and externally
as **"staged correlation analytics over firewall/syslog data."** It may **not**
be marketed as "multi-stage attack detection" until the sequence engine proves
stage B followed stage A for the same entity within a bounded window.

- [x] **GATE-1** — ~~Positioning copy held to "staged correlation analytics" until Phase 2 ships~~ · **Resolved 2026-05-20:** Phase 2 shipped — the sequence engine now proves stage B followed stage A for the same entity in a bounded window, so the "Multi-Stage Attack Detection" copy is earned.

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
| - [x] | **P2-1** | Add rule property `ordering`: `sequence` (strict order) \| `any_order` (legacy aggregate behavior) | `models/correlation.py`, `schemas/correlation.py` | 2026-05-20 |
| - [x] | **P2-2** | Add `join_keys` as a first-class rule property (composite-capable, replaces single-string key) | `models/correlation.py`, `schemas/correlation.py` | 2026-05-20 |
| - [x] | **P2-3** | Thread anchored `reference_time` through every stage call via `_stage_time_filter()` | `services/correlation_engine.py` | 2026-05-20 |
| - [x] | **P2-4** | `sequence` mode: stage N evaluated in `(prev_terminal_event, prev_terminal_event + window]` | `services/correlation_engine.py` → `_stage_time_filter()`, `evaluate_correlation_rule()` | 2026-05-20 · verified: stage 2 events strictly after stage 1 |
| - [x] | **P2-5** | Stage 1 returns **all** candidate entities (`_stage_candidates`, capped at `MAX_CANDIDATES=20`) | `services/correlation_engine.py` → `_stage_candidates()` | 2026-05-20 |
| - [x] | **P2-6** | Join candidate sets stage-to-stage by entity; emit **one match per valid chain** | `services/correlation_engine.py` → `evaluate_correlation_rule()` (returns `List[dict]`) | 2026-05-20 · verified: 39 distinct entities matched |
| - [x] | **P2-7** | Composite joins via `_entity_where()` — `srcip`, `srcip+dstip`, etc. | `services/correlation_engine.py` → `_entity_where()` | 2026-05-20 |
| - [x] | **P2-8** | Per-stage event-time bounds + `sequence_ok` flag stored in `stage_details` | `services/correlation_engine.py` | 2026-05-20 |
| - [x] | **P2-9** | Seeded rules carry `ordering` (server-default `sequence` covers existing + new) | `db/migrations/...a7b8c9d0e1f2`, `models/correlation.py` | 2026-05-20 · all 5 rules `ordering=sequence` |
| - [x] | **P2-10** | Alembic migration `a7b8c9d0e1f2` — `ordering`, `schema_version`, `join_keys` (`suppress_window` was Phase 1). v1 stage JSON unchanged — no converter needed. | `db/migrations/versions/a7b8c9d0e1f2_*` | 2026-05-20 |
| - [x] | **P2-11** | Tests: time-anchoring, entity-where, join-key resolution, ordering/join_keys schema | `tests/test_correlation.py` | 2026-05-20 · 87 tests pass (22 new) |

### Exit criteria — Phase 2
- [x] "Reconnaissance then Access" fires **only** when access follows recon for the same entity inside the window. — _verified: stage-2 events anchored strictly after stage-1 last event_
- [x] Multiple valid entities can produce **separate** matches in one scheduler run. — _verified: 39 distinct entities, 90 rows / 90 distinct fingerprints_
- [x] `any_order` legacy mode still works for the aggregate-style seeded rules. — _`ordering=any_order` keeps trailing-window behavior; unit-tested_
- [x] **Positioning gate lifted** — feature may now be called "multi-stage attack detection." — _the engine now proves stage B followed stage A for the same entity in a bounded window_

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
| - [x] | **P2b-1** | `GET /api/correlation/schema` — field/operator catalog | `api/correlation.py` → `api_correlation_schema()` | 2026-05-20 |
| - [x] | **P2b-2** | Visual stage builder: stage cards with add / remove / **reorder** (move up/down) | `templates/correlation/rules.html` | 2026-05-20 |
| - [x] | **P2b-3** | Per-stage inputs: field dropdown, operator dropdown, value, threshold, window, group-by; rule-level ordering / match-mode / suppress-window / join-keys | `templates/correlation/rules.html` | 2026-05-20 |
| - [x] | **P2b-4** | Variable picker — `$stageN.<field>` selector per condition, populated from upstream stages' group-by | `templates/correlation/rules.html` | 2026-05-20 |
| - [x] | **P2b-5** | Inline validation in the UI (name, ≥1 condition, threshold ≥ 1, window ≥ 1) + server 422s surfaced in an error box | `templates/correlation/rules.html` | 2026-05-20 |
| - [x] | **P2b-6** | Synchronized advanced JSON editor (Builder→JSON / JSON→Builder) as the power-user escape hatch | `templates/correlation/rules.html` | 2026-05-20 |
| - [x] | **P2b-7** | Edit mode — `editRule()` loads any rule into the builder, saves via `PUT` | `templates/correlation/rules.html`, Edit button on rule cards | 2026-05-20 · verified round-trip |

### Exit criteria — Phase 2b
- [x] An analyst can build and edit a correlation rule **without writing JSON**. — _verified: built + created a 2-stage rule, edited it, all via dropdowns_
- [x] A power user can still inspect/edit the JSON representation, kept in sync. — _advanced JSON panel with two-way sync_

> **Note:** drag-handle reorder (P2b-2) implemented as move up/down buttons — robust and accessible; HTML5 drag is a later polish.

---

# Phase 3 — Authoring Polish & Detection-Engineering UX

**Goal:** Add test/preview (now safe because the engine is correct) and rule
versioning. **Effort:** 1–2 weeks · **Priority:** 🟠 P1 · **Depends on:** Phase 2 + Phase 2b

### Tasks

| ☐ | ID | Task | File(s) | Done |
|---|----|------|---------|------|
| - [x] | **P3-1** | `POST /api/correlation/rules/test` — dry-runs a draft rule (transient, un-persisted) | `api/correlation.py` → `api_test_rule()` | 2026-05-20 · verified: 0 rows persisted |
| - [x] | **P3-2** | `preview_correlation_rule()` — per-stage candidate/survivor counts, sample entities, rough fire-rate estimate, stage error reasons | `services/correlation_engine.py` | 2026-05-20 |
| - [x] | **P3-3** | `rule_version` recorded in every match; bumped on each `PUT` (delivered in Phase 1) | `services/correlation_engine.py`, `api/correlation.py` | 2026-05-20 · verified (edit bumped v1→v2) |
| - [x] | **P3-4** | "Test Rule" button in the builder → preview panel with the stage funnel | `templates/correlation/rules.html` | 2026-05-20 · verified in browser |
| - [x] | **P3-5** | Tests: preview diagnostic shape; preview persists nothing | `tests/test_correlation.py` | 2026-05-20 · 90 tests pass; 0 rows after a test call |

### Exit criteria — Phase 3
- [x] An analyst can create, test, edit, and tune a rule end-to-end without writing JSON. — _builder + Test + edit all verified in browser_
- [x] Rule preview shows expected fire rate, sample matches, and per-stage failures. — _"✓ Rule would match — 10 chains, ≈10/hour" with the 20→10 stage funnel and sample entities_

---

# Phase 4 — Source Registry & Entity Model

**Goal:** Move from firewall-only to **cross-domain** correlation. Normalize
entities **before** adding many sources.
**Effort:** 4 weeks · **Priority:** 🟠 P1 · **Depends on:** Phase 2

### Tasks

| ☐ | ID | Task | File(s) | Done |
|---|----|------|---------|------|
| - [x] | **P4-1** | Source registry — per source: table, label, filterable fields+types, entity map, sample columns | `core/correlation_fields.py` → `SOURCES` | 2026-05-20 |
| - [x] | **P4-2** | Registered the 7 real ClickHouse sources: `syslogs`, `dns_logs`, `url_logs`, `ioc_matches`, `audit_logs`, `pa_threat_logs`, `correlation_matches` (`alerts` is PostgreSQL — out of ClickHouse scope) | `core/correlation_fields.py` | 2026-05-20 |
| - [x] | **P4-3** | Canonical entities: `ip`, `dst_ip`, `user`, `host`, `domain`, `url`, `device` | `core/correlation_fields.py` → `CANONICAL_ENTITIES` | 2026-05-20 |
| - [x] | **P4-4** | Per-source `entities` map (canonical → native column); `resolve_field()` resolves a join key per source | `core/correlation_fields.py`, `services/correlation_engine.py` → `_entity_where()` | 2026-05-20 |
| - [x] | **P4-5** | Engine reads `source` per stage; `_stage_candidates`/`_stage_for_entity`/`_fetch_stage_samples` all source-aware (no hardcoded `syslogs`) | `services/correlation_engine.py` | 2026-05-20 |
| - [x] | **P4-6** | 3 cross-source seed rules — IOC→firewall, DNS→firewall, PA-threat→firewall — joined by canonical `ip` | `services/correlation_engine.py` → `seed_correlation_rules()` | 2026-05-20 · all 3 match live data |
| - [x] | **P4-7** | Tests: registry, `resolve_field`, cross-source `_entity_where`, multi-source schema | `tests/test_correlation.py` | 2026-05-20 · 105 tests pass (15 new) |

### Exit criteria — Phase 4
- [x] At least **3 shipped rules span ≥2 data sources**. — _3 cross-source rules seeded; live: 12 / 3 / 1 matches respectively_
- [x] A new source can be added by registry config without modifying core engine logic. — _the engine reads the data-driven `SOURCES` registry; a source is one dict entry_

> **Builder bonus:** the visual builder gained a per-stage **Data Source** dropdown — switching a stage's source repopulates its field/group-by dropdowns — so cross-source rules can be built without the JSON editor.

---

# Phase 5 — Incident & Risk Output

**Goal:** Reduce alert fatigue. Produce **incident-quality** output, not a flat
alert stream. **Effort:** 3–4 weeks · **Priority:** 🟡 P2 · **Depends on:** Phase 4

### Tasks

| ☐ | ID | Task | File(s) | Done |
|---|----|------|---------|------|
| - [x] | **P5-1** | `entity_risk` ClickHouse table (append-only risk contributions, 30-day TTL) | `db/clickhouse_migrations/004_entity_risk.py` | 2026-05-20 |
| - [x] | **P5-2** | Per-rule `risk_score` (0 = auto-derive from severity); `_rule_risk_contribution()` | `models/correlation.py`, `services/correlation_engine.py` | 2026-05-20 |
| - [x] | **P5-3** | `compute_entity_risk()` — exponential time-decay, 24h half-life, computed at query time | `services/correlation_engine.py` | 2026-05-20 |
| - [x] | **P5-4** | `group_into_incident()` — collapses matches for the same entity (within a 1h window) into one incident | `services/correlation_engine.py`, `CorrelationIncident` model | 2026-05-20 · verified: 3 matches/3 rules → 1 incident |
| - [x] | **P5-5** | Incident severity = max(severity-from-accumulated-risk, contributing-rule severity) | `services/correlation_engine.py` → `severity_from_risk()` | 2026-05-20 |
| - [x] | **P5-6** | Lifecycle states `new`/`investigating`/`contained`/`resolved`/`suppressed` + status API | `models/correlation.py`, `api/correlation.py` | 2026-05-20 · status change verified |
| - [x] | **P5-7** | Contributing matches kept as evidence on the incident (`matches` JSON, capped at 50) | `services/correlation_engine.py` | 2026-05-20 |
| - [x] | **P5-8** | Incident API (list / detail / status) + an Incidents tab with detail modal | `api/correlation.py`, `templates/correlation/rules.html` | 2026-05-20 · verified in browser |

### Exit criteria — Phase 5
- [x] Four related matches for one host become **one incident** with risk context and evidence — not four alerts. — _verified live: 3 matches from 3 rules grouped into one critical incident (risk 200)_
- [x] Entity risk **accumulates and decays** correctly. — _`entity_risk` contributions summed with `pow(2, -age/24h)` exponential decay_

---

# Phase 6 — Templates, MITRE Workflow, Response & ML

**Goal:** Scale detection content, connect ATT&CK gaps to rule creation, add
controlled response automation, and layer the differentiators.
**Effort:** 4 weeks · **Priority:** 🟡 P2 · **Depends on:** Phases 2b & 5

### Tasks

| ☐ | ID | Task | File(s) | Done |
|---|----|------|---------|------|
| - [x] | **P6-1** | Curated **template library** — 12 parameterized, MITRE-mapped templates grouped by tactic; `GET /api/correlation/templates` + a builder "Start from template" picker | `core/correlation_templates.py`, `api/correlation.py`, `templates/correlation/rules.html` | 2026-05-20 · starter set of 12 (the 30–50 target is content the team can grow) |
| - [x] | **P6-2** | **Data-aware** discovery — each template declares `required_sources`; the API flags `available`, the picker disables unusable templates | `api/correlation.py`, `templates/correlation/rules.html` | 2026-05-20 |
| - [x] | **P6-3** | "Create Detection Rule" action on MITRE map technique cells → correlation page opens the builder pre-seeded with the technique | `templates/correlation/mitre_map.html`, `templates/correlation/rules.html` | 2026-05-20 · verified |
| - [x] | **P6-4** | **Response actions** — `actions` JSON column; `fire_response_actions()` runs `webhook` (POST match summary) and `log` actions when a rule records a match; builder has a Response Actions field | `models/correlation.py`, `services/correlation_engine.py`, `api/correlation.py`, `templates/correlation/rules.html` | 2026-05-20 · framework; notify/EDL/ticket plug in as further action types |
| - [ ] | **P6-5** | **Anomaly stages** — let a stage reference existing learning-mode baselines (volume anomalous vs baseline) | `services/correlation_engine.py` | |
| - [x] | **P6-6** | **Attack-chain visualization** — the rule detail modal renders the rule's stages as a left-to-right kill chain (numbered nodes, threshold/window/source, arrows) | `templates/correlation/rules.html` | 2026-05-20 · verified |
| - [x] | **P6-7** | **Rule health scorecard** — 7d/30d fire frequency, 30-day daily timeline, dormant/healthy/noisy status, rule version & last-edited; shown in the rule detail modal | `api/correlation.py`, `templates/correlation/rules.html` | 2026-05-20 · verified ("noisy", 2080/7d) |
| - [x] | **P6-8** | **Sigma rule import** — `core/sigma_import.py` parses a single-selection Sigma YAML rule into a correlation-rule draft (field mapping, MITRE from tags, severity); `POST /api/correlation/sigma/import`; builder "import a Sigma rule" panel | `core/sigma_import.py`, `api/correlation.py`, `templates/correlation/rules.html` | 2026-05-20 · verified |
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
- [x] **P2-1 / P2-3 / P2-4** — Ordered sequence semantics for the seeded "then" rules
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
| 2026-05-20 | **Phase 1 complete** (10/10 tasks). ClickHouse migration `003` (+7 columns on `correlation_matches`, schema v3); Alembic `f1a2b3c4d5e6` (+version/match_mode/suppress_window on `correlation_rules`). Match fingerprint + entity identity + event-chain evidence windows + 3 sample events per stage; discrete/recurring rule modes; suppression so a discrete rule records a chain once per `suppress_window` instead of once per 60s tick. Verified live: scheduler logs "0 recorded, 2 suppressed"; each fingerprint stayed at 1 row over 3+ cycles. 65 tests pass. Committed `a4ced1f`. | Eng |
| 2026-05-20 | **Phase 2 complete** (11/11 tasks). Alembic `a7b8c9d0e1f2` (+ordering/schema_version/join_keys). Rewrote `evaluate_correlation_rule` into a candidate-set sequence engine: `_stage_candidates` returns all qualifying entities (cap 20); `sequence` mode anchors each stage in `(prev_terminal_event, +window]` via `_stage_time_filter`; `_entity_where` does first-class composite joins; the rule now returns **one match per entity**. Verified live: 39 distinct entities matched in one window, 90 rows / 90 distinct fingerprints (no duplication), stage-2 events strictly after stage-1. 87 tests pass. **Positioning gate lifted.** Committed `2a13d09`. | Eng |
| 2026-05-20 | **Phase 2b complete** (7/7 tasks). Replaced the raw-JSON textarea with a visual stage builder: `GET /api/correlation/schema` feeds field/operator dropdowns; stage cards with condition rows (field/op/value), group-by/threshold/window, move up/down reorder, `$stageN.field` variable picker; rule-level ordering/match-mode/suppress-window/join-keys; inline validation; a synchronized advanced-JSON escape hatch; and an Edit button that round-trips any rule through the builder and saves via PUT. Browser-verified: built + created + edited a 2-stage rule entirely via dropdowns. Committed `ad2e4ba`. | Eng |
| 2026-05-20 | **Phase 3 complete** (5/5 tasks). `preview_correlation_rule()` dry-runs a rule with per-stage candidate/survivor diagnostics, sample entities and a rough fire-rate estimate; `POST /api/correlation/rules/test` builds a transient un-persisted rule and previews it; a "Test Rule" button in the builder shows the stage funnel before saving. Verified: a test call recorded 0 rows; preview showed "20 candidates → 10 surviving chains". 90 tests pass. Committed `0f060ec`. | Eng |
| 2026-05-20 | **Phase 4 complete** (7/7 tasks). `core/correlation_fields.py` is now a data-driven **source registry** — 7 ClickHouse sources (syslogs, dns_logs, url_logs, ioc_matches, audit_logs, pa_threat_logs, correlation_matches), each with fields, types, sample columns and a canonical-entity map. `resolve_field()` resolves a join key (canonical entity *or* native column) per source, so a rule joins stages across sources by `ip`/`user`/etc. Engine fully source-aware. 3 cross-source seed rules (IOC→firewall, DNS→firewall, PA-threat→firewall). Builder gained a per-stage Data Source dropdown. Verified live: the 3 rules matched 12 / 3 / 1 entities. 105 tests pass. Committed `fef132b`. | Eng |
| 2026-05-20 | **Phase 5 complete** (8/8 tasks). ClickHouse migration `004` (`entity_risk`); Alembic `b1c2d3e4f5a6` (`risk_score` column + `correlation_incidents` table). Each match contributes weighted risk to its entity; `compute_entity_risk()` sums contributions with a 24h-half-life exponential decay. `group_into_incident()` collapses matches for one entity (within 1h) into a single `CorrelationIncident` with accumulated risk, derived severity, lifecycle status and contributing-match evidence. Incident API (list/detail/status) + an Incidents tab. Fixed an autoflush-off grouping bug (added `db.flush()`). Verified live: 3 matches from 3 rules grouped into one critical incident (risk 200); status transitions work. 114 tests pass. Committed `ea89539`. | Eng |
| 2026-05-20 | **Phase 6 partial** (3/10 — P6-1/2/3). `core/correlation_templates.py` — 12 curated MITRE-mapped templates; `GET /api/correlation/templates` with data-aware `available` flags; builder "Start from template" picker. MITRE map technique cells gained a "Create Detection Rule" action that opens the builder pre-seeded with the technique. 119 tests pass. **Remaining (P6-4..P6-10):** response actions, anomaly/ML stages, attack-chain timeline viz, rule-health scorecard, Sigma import, backtest, simulation mode — each substantial; deferred for focused effort. | Eng |
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
