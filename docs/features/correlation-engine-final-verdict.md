# Correlation Engine - Expert Verdict, Challenge Review, and Roadmap

Author: Security Architecture and Product Design Review  
Date: 2026-05-20  
Reviewed area: `http://10.12.50.77/correlation/` and local implementation  
Input assessment reviewed: `docs/features/correlation-engine-evaluation-and-roadmap.md`  
Output status: Final verdict document

## 1. Final Verdict

The other team's assessment is directionally correct and should be accepted as
a strong first-pass review. The core conclusion is right: the current
Correlation Engine is live, useful, and demoable, but it is not yet a true
enterprise-grade correlation engine. Its largest gap is not UI polish or lack
of ML. Its largest gap is detection semantics: the engine currently evaluates
stages as independent rolling-window aggregations, not as ordered evidence
chains.

My final verdict is:

1. Accept the assessment's headline risk: the feature is operational but
   early-stage.
2. Elevate temporal sequence correctness to the top product and engineering
   blocker.
3. Add two critical findings the assessment underplays:
   - The engine returns only the top matched entity per stage, so it can miss
     valid matches and distort match counts.
   - Match records represent scheduler evaluations more than unique attack
     chains because there is no match fingerprint, event identity, or
     suppression model.
4. Refine the roadmap so the first investment is reliable evidence generation:
   ordered stages, all candidate entities, source allow-lists, validation,
   match deduplication, and investigable event context.
5. Defer ML/anomaly fusion until the entity model and sequence model are
   correct. ML on top of weak correlation semantics will amplify noise.

The current feature should be positioned internally as "staged detection and
analytics" until the sequence engine is fixed. Externally calling it
"multi-stage attack detection" is defensible only after the engine can prove
that stage B followed stage A for the same entity inside a bounded window.

## 2. Evidence Reviewed

### Local code and UI evidence

- Live `/correlation/` page observed on 2026-05-20 around 11:36 UTC:
  5 total rules, 5 active rules, 530455 total matches, 1413 matches today,
  95264 critical matches, and 340463 high matches. Counts will drift because
  the scheduler evaluates rules every 60 seconds.
- Rule detail modal confirmed per-rule analytics, top keys, recent matches,
  rule configuration breakdown, log links, and a "View All Matches" footer
  control.
- Add Rule modal confirmed raw JSON stage authoring, with no visual builder,
  no edit path, and no test/preview before save.
- Core engine reviewed in `fastapi_app/services/correlation_engine.py`.
- API and UI reviewed in `fastapi_app/api/correlation.py` and
  `fastapi_app/templates/correlation/rules.html`.

### Competitor references used

- Splunk Enterprise Security detections and finding-based/risk detection:
  https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.0/detections
- Splunk adaptive response actions:
  https://docs.splunk.com/Documentation/ES/8.1.0/Admin/SetupAdaptiveResponse
- Splunk event-based detection editing, trigger conditions, and throttling:
  https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.2/detections/create-event-based-detections-in-splunk-enterprise-security
- Microsoft Sentinel Fusion advanced multistage attack detection:
  https://learn.microsoft.com/en-us/azure/sentinel/configure-fusion-rules
- Microsoft Sentinel scheduled analytics, entity mappings, and alert grouping:
  https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom
- Elastic Security EQL event correlation rules:
  https://www.elastic.co/docs/solutions/security/detect-and-alert/eql
- Elastic validation and rule preview:
  https://www.elastic.co/docs/solutions/security/detect-and-alert/validate-and-test-rules
- Datadog Cloud SIEM signal correlation rules:
  https://docs.datadoghq.com/security/cloud_siem/detection_rules/signal_correlation_rules
- IBM QRadar rules, building blocks, and offenses:
  https://www.ibm.com/docs/SS42VS_7.4/com.ibm.qradar.doc/c_tuning_guide_tuning_rules_offenses.html
- IBM QRadar offense chaining:
  https://www.ibm.com/docs/SS42VS_7.4/com.ibm.qradar.doc/c_qradar_ug_offense_chaining.html
- CrowdStrike Falcon Next-Gen SIEM correlation rule template discovery:
  https://www.crowdstrike.com/content/crowdstrike-www/locale-sites/us/en-us/blog/boost-soc-detection-content-correlation-rule-template-discovery-dashboard.html

## 3. Point-by-Point Challenge of the Other Team Assessment

### 3.1 Executive summary

Assessment claim: Zentryc has a working, useful, but early-stage multi-stage
detection feature.

Verdict: Accept.

The live page and implementation support this. The product has seeded rules,
scheduled evaluation, ClickHouse match storage, a usable rules dashboard,
per-rule analytics, MITRE mapping, and generated alerts. This is more than a
prototype.

Challenge: the phrase "multi-stage attack detection" currently overstates the
engine. It is better described as "multi-stage rolling-window aggregation"
until temporal order and event evidence are fixed.

### 3.2 Structural weakness 1: stages do not enforce temporal order

Assessment claim: stages are evaluated independently against rolling windows
ending at `now()`.

Verdict: Accept and elevate to P0.

`_evaluate_stage()` has a `reference_time` parameter, but
`evaluate_correlation_rule()` calls it without passing any stage-specific
reference time. As a result, each stage uses the default `reference_time =
"now()"`. Stage 2 does not evaluate from the timestamp of stage 1. It evaluates
from current time.

Local evidence:

- `fastapi_app/services/correlation_engine.py:92` defines `_evaluate_stage()`
  with default `reference_time="now()"`.
- `fastapi_app/services/correlation_engine.py:108` builds
  `timestamp > reference_time - INTERVAL window SECOND`.
- `fastapi_app/services/correlation_engine.py:171` loops over stages.
- `fastapi_app/services/correlation_engine.py:175` calls `_evaluate_stage()`
  without passing a reference time.

Product impact:

- "Recon then Access" can mean "Recon and Access both existed in overlapping
  windows", not "Recon happened before Access".
- The engine cannot defend a detection with a precise attack timeline.
- Analysts may investigate false attack chains assembled from unrelated
  events.

Additional challenge: the assessment's proposed fix is directionally right but
under-specified. Capturing only a single `stage1_time` is not enough. The
engine must evaluate candidate sequences per entity, preserve all candidate
entities, and carry forward the terminal event time or event range for each
candidate. Otherwise, a high-volume top entity will hide lower-volume valid
chains.

### 3.3 Structural weakness 2: authoring is raw JSON only

Assessment claim: analysts must hand-write JSON; there is no visual builder,
field auto-complete, validation, edit, or test/preview.

Verdict: Accept.

The Add Rule modal exposes `Stages (JSON Array)` as a textarea. The API creates
rules from raw request JSON and persists `data["stages"]` directly. There is no
`PUT` endpoint for rule update in the correlation API.

Local evidence:

- `fastapi_app/api/correlation.py:143` defines only `POST
  /api/correlation/rules/` for creation.
- `fastapi_app/api/correlation.py:152` stores `stages=data["stages"]`.
- No update endpoint exists for correlation rules.
- Live UI shows create, toggle, detail, delete, but not edit or preview.

Challenge: keep the raw JSON option as an advanced escape hatch. Enterprise
detection engineers often want text-level control. The product gap is not that
JSON exists; the gap is that JSON is the only authoring path and the system
accepts invalid JSON schema silently until scheduler evaluation.

### 3.4 Structural weakness 3: single data source

Assessment claim: correlation evaluates only ClickHouse `syslogs`.

Verdict: Accept for the correlation engine, refine for the platform.

The engine currently queries only `syslogs` in `_evaluate_stage()`. That makes
the correlation feature firewall/syslog-centric.

Local evidence:

- `fastapi_app/services/correlation_engine.py:116` queries `FROM syslogs`.
- `fastapi_app/services/correlation_engine.py:143` queries `FROM syslogs`.

Challenge: the broader product already has useful security data that can feed
correlation later, including URL analytics, threat-intel matches, audit logs,
alerts, and parsed DNS-style fields. The roadmap should not describe this as a
platform limitation. It is an engine integration limitation.

Best product direction: build a source registry and canonical entity mapping
layer before adding many sources. Without that layer, cross-source correlation
will become one-off query glue.

### 3.5 Structural weakness 4: no RBA, ML/anomaly fusion, or response actions

Assessment claim: matches create generic alerts; there is no risk-based
alerting, incident grouping, ML/anomaly fusion, or SOAR playbook trigger.

Verdict: Accept, with priority adjustment.

The current implementation creates an `Alert` row from a match. It does not
group matches into incidents, score entity risk, or invoke response playbooks.

Local evidence:

- `fastapi_app/services/correlation_engine.py:236` creates alerts from
  correlation matches.
- `fastapi_app/services/correlation_engine.py:264` stores correlation details
  in alert JSON, not a richer incident model.

Challenge: ML/anomaly fusion should not be in the first two delivery phases.
The immediate competitor gap is not "no ML"; it is "no trustworthy sequence
evidence and no incident-quality output." Risk scoring and incident grouping
depend on entity normalization and match deduplication. Those must come first.

## 4. Feature Inventory Cross-Check

### Staged rule model

Verdict: Accept.

Rules contain ordered stage arrays. The UI displays stage flow and the engine
iterates through stages.

Challenge: "ordered list" in data structure does not mean ordered evaluation in
time. The stage array order is currently control-flow order, not event-time
order.

### Variable substitution

Verdict: Accept with concern.

`$stage1.srcip` style substitution exists and works for the seeded rules where
stage 1 returns the grouped field.

Critical concern: unresolved variables are skipped in `_build_where_clause()`.
Skipping an unresolved variable can broaden a later stage query instead of
failing closed. A safe engine should treat unresolved required variables as a
stage failure unless the rule explicitly marks the variable optional.

### Comparison operators

Verdict: Accept with concern.

Suffix operators such as `_gt`, `_lt`, `_gte`, `_lte`, and `_ne` exist.

Concern: they are implemented through raw string SQL assembly. Numeric
operators do not validate numeric values, and field names are not allow-listed.

### Scheduler-driven evaluation

Verdict: Accept.

The scheduler runs `evaluate_all_correlation_rules` every 60 seconds with
`max_instances=1`.

Challenge: this creates a polling detector, not a streaming correlation engine.
That is acceptable for v1, but the product must communicate evaluation
latency, late-arrival behavior, and deduplication rules.

### Match persistence

Verdict: Accept with important limitation.

Matches are persisted in ClickHouse `correlation_matches` with a 6-month TTL.

Limitation: the match timestamp is evaluation time, not the event-chain time.
`stage_details` stores aggregate counts and stage metadata, but not exact event
IDs or bounded event timestamps. This weakens investigation and auditability.

### Seeded rules

Verdict: Accept.

Five seeded rules are visible in the UI:

- Reconnaissance then Access
- Brute Force then Login
- Multi-Firewall Scan
- Denied then Allowed - Same Source
- High Volume Outbound Traffic

Challenge: rules named "then" should not be used in shipped content until
ordered semantics are implemented. Rename them internally or ship an
`ordering=any_order` compatibility flag until true sequence mode exists.

### Rules grid UI

Verdict: Accept.

The grid is useful and readable. It exposes severity, stages, MITRE mapping,
match counts, last triggered, last evaluated, and actions.

Challenge: the primary cards show only critical and high severity match totals.
Medium and low are omitted from the stats strip, which creates a reporting
blind spot for the medium seeded rule.

### Per-rule detail dashboard

Verdict: Accept.

This is one of the strongest parts of the feature. Top keys, timeline, recent
matches, configuration breakdown, and log pivots make the feature tangible.

Challenge: the log pivot is broad. It links by key value and time range, but it
does not pass exact contributing event identifiers because the engine does not
store them. The detail page is analytics-first, not evidence-first.

### Recent Matches tab

Verdict: Accept.

The feature exists and lists recent cross-rule matches.

Challenge: it needs filtering by rule, severity, key/entity, MITRE tactic, and
time window. "View All Matches" from a rule detail should land in a rule-filtered
view.

### MITRE ATT&CK coverage map

Verdict: Accept as a strength, refine the differentiator claim.

The map is valuable because it connects detection content to ATT&CK coverage in
a visible way. It is a strong product demo.

Challenge: competitors also expose ATT&CK-aligned content and detection
coverage. Zentryc's advantage is not uniqueness; it is the clarity of the
workflow and the opportunity to connect uncovered techniques directly to rule
templates.

Additional local concern: coverage percentage calculation should use
detectable techniques consistently in numerator and denominator. Today the code
computes `covered` across all techniques in a tactic, then divides by
`detectable`. If a non-detectable technique is mapped, the percentage can be
inflated.

### Alert generation

Verdict: Accept with major output-quality gap.

Each match can create an alert.

Challenge: the current duplicate check is title-based and time-window based,
not entity-aware. A noisy entity and a genuinely new entity can suppress each
other if they share the same rule name. Enterprise correlation needs
configurable suppression by rule and entity, plus incident grouping.

### RBAC

Verdict: Accept.

View routes require ANALYST and write operations require ADMIN.

Challenge: because correlation rules generate SQL, administrative access alone
is not a sufficient control. Rules still need schema validation and query
allow-lists.

## 5. Bug and Defect Review

### Finding A: temporal ordering is absent

Assessment severity: Critical  
My severity: P0 critical  
Verdict: Accept

This is the central correctness issue. A correlation engine must prove event
relationships in time. Current behavior proves only that each stage had enough
events in its own rolling window.

Required fix:

- Add explicit rule-level `ordering` mode:
  - `sequence`: stage N must occur after stage N-1 for the same join key.
  - `any_order`: current behavior, kept only for backward compatibility.
- Evaluate candidate chains, not just one top group.
- Carry forward per-candidate entity keys and event time bounds.
- Store matched event references or at least time ranges and query fingerprints
  in `stage_details`.

### Finding B: duplicate-alert check can throw `ValueError`

Assessment severity: High  
My severity: High  
Verdict: Accept

`datetime.replace(minute=datetime.now(...).minute - 5)` fails when the current
minute is 0-4. The surrounding `except` logs and drops alert creation.

Required fix:

- Replace with `datetime.now(timezone.utc) - timedelta(minutes=5)`.
- Stop using title substring as the dedupe key.
- Add a proper suppression key: `rule_id`, canonical entity, severity, and
  optional stage fingerprint.

### Finding C: SQL is built by string interpolation

Assessment severity: Medium  
My severity: High  
Verdict: Accept and elevate

This is a high-severity design issue because correlation rules are executable
query definitions. Admin-only write access lowers exposure but does not remove
the risk. Data-derived variable substitution can also carry tainted values into
later query strings.

Required fix:

- Maintain source-specific allow-lists for fields and operators.
- Use ClickHouse query parameters for values.
- Validate group-by fields separately from filter fields.
- Reject unresolved variables unless explicitly optional.
- Add range limits for `hours` and `limit` API parameters.

### Finding D: no stage-schema validation

Assessment severity: Medium  
My severity: High  
Verdict: Accept and elevate

Malformed rules should be rejected at save time. Runtime scheduler logs are not
acceptable analyst feedback.

Required fix:

- Add Pydantic schemas for rule and stage payloads.
- Validate severity, stage count, stage names, threshold, window, fields,
  operators, source, join keys, and MITRE technique format.
- Return user-readable validation errors in the UI.

### Finding E: "View All Matches" is dead

Assessment severity: Low  
My severity: Low, but assessment is partially wrong  
Verdict: Refine

The footer link has `href="#"`, but it also has an onclick handler that switches
to the Recent Matches tab and closes the modal. So it is not completely dead.
It is misleading because it does not filter the match list to the selected rule.

Required fix:

- Change it to a real filtered route or tab state:
  `/correlation/?tab=matches&rule_id=<id>` or equivalent client-side state.

### Finding F: no edit path

Assessment severity: Low  
My severity: Medium  
Verdict: Accept and elevate

No edit path is more than a convenience gap. It prevents safe tuning. Deleting
and recreating rules breaks lineage and makes historical match analysis harder.

Required fix:

- Add `PUT /api/correlation/rules/{id}`.
- Preserve immutable rule identity.
- Track `version`.
- Record the rule version in each match.

### Finding G: full-scan evaluation and no cursor

Assessment severity: Low  
My severity: Medium  
Verdict: Accept and elevate

Every enabled rule runs a window query every minute. This can be acceptable for
five short-window rules, but it will not scale cleanly with more rules, longer
windows, or higher EPS.

Required fix:

- Add rule evaluation watermarks.
- Add overlap/backfill policy for late events.
- Deduplicate by match fingerprint so overlapping windows do not create
  repeated matches.
- Track evaluation duration and ClickHouse query cost per rule.

### Finding H: medium/low severity omitted from stats

Assessment severity: Low  
My severity: Low  
Verdict: Accept

The API initializes `match_stats` with only total, today, critical, and high.
The UI renders only critical and high severity cards. Medium and low matches
are not surfaced in the top metrics.

Required fix:

- Add medium and low counts, or replace severity cards with a compact severity
  distribution.

## 6. Additional Findings Missing From the Assessment

### Additional P0: only the top matched entity is carried forward

Current `_evaluate_stage()` returns only the top group as the active result.
It also includes `all_matches`, but later stages use only the top group's
variables.

Impact:

- A rule can miss valid chains for non-top entities.
- Match volume can be artificially capped to one match per rule per scheduler
  run.
- A noisy IP can dominate correlation and hide other attacks.

Required fix:

- Return candidate sets from each stage.
- Join candidate sets between stages by canonical entity.
- Persist one match per unique chain/entity, subject to suppression.

### Additional P0: matches are repeated scheduler observations, not unique chains

The live UI shows rules such as Multi-Firewall Scan and High Volume Outbound
Traffic with 1440 matches over 24 hours, exactly consistent with one match per
minute. That is a strong signal that repeated scheduled evaluations are being
stored as matches while a condition remains true.

Impact:

- Match counts overstate unique security events.
- Analysts see persistence of condition as many matches.
- Risk scoring would be inflated if built directly on current match counts.

Required fix:

- Introduce `match_fingerprint`.
- Fingerprint should include rule id, rule version, entity key, stage evidence
  windows, and relevant dimensions.
- Suppress or update existing open match/incident while the same condition is
  active.

### Additional High: no event-level evidence trail

The engine stores aggregate counts but not the exact contributing event IDs,
stable event hashes, or exact stage event windows.

Impact:

- Analysts cannot prove why the match fired without re-querying approximate
  logs.
- Re-querying later can produce different results if data is late, aged out, or
  filtered differently.
- Auditability is weak for incident response and compliance.

Required fix:

- Capture representative event references for every stage.
- Store min/max event timestamps, sample event ids/hashes, and query
  conditions used.
- Let the detail modal open exact evidence, not just broad log search.

### Additional High: unresolved variables fail open

If a variable cannot be resolved, `_build_where_clause()` skips that condition.
For correlation, skipping a join condition is dangerous.

Impact:

- A malformed later stage can become broader than intended.
- A rule can match even when the entity relationship was not established.

Required fix:

- Unresolved required variables must fail the stage.
- Optional variables must be explicit in schema.

### Additional Medium: MITRE technique modeling is free text

MITRE tactic and technique fields are free text. This allows inconsistent
labels and weak coverage analytics.

Required fix:

- Store technique ID separately from display name.
- Validate against the platform's ATT&CK technique catalog.
- Allow multiple techniques per rule.

## 7. Competitive Analysis Verdict

The competitor comparison in the assessment is mostly accurate. The important
message is that mature SIEM/SOAR platforms do not treat correlation as only a
rule that emits another alert. They increasingly combine ordered sequences,
entity mapping, signal correlation, suppression, risk, and incidents.

### Splunk Enterprise Security

Assessment position: Splunk has detections/correlation searches, adaptive
response, throttling, and risk-based alerting.

Verdict: Accept.

Splunk's current Enterprise Security docs describe event-based and
finding-based detections. Finding-based detections aggregate findings and
intermediate findings in the risk/notable indexes into finding groups based on
risk associated with entities. Splunk adaptive response actions can create
findings, modify risk scores, send emails, run scripts, add threat intelligence,
and perform other actions.

Product lesson for Zentryc:

- Add response actions after match correctness.
- Build risk around entities, not raw match count.
- Add rule throttling/suppression as first-class rule configuration.

### Microsoft Sentinel

Assessment position: Fusion is advanced multistage attack detection that maps
entities and creates incidents.

Verdict: Accept.

Microsoft documents Fusion as multistage attack detection and requires entity
mapping for analytics rules. Sentinel scheduled analytics also supports alert
grouping into incidents based on entities and details.

Product lesson for Zentryc:

- Entity mapping is not optional for serious correlation.
- The desired output should be incident-quality grouping, not a flat alert row.

### Elastic Security

Assessment position: Elastic EQL supports ordered event sequences, shared join
fields, and absence-of-event detection.

Verdict: Accept.

Elastic's EQL documentation explicitly focuses on ordered sequences, shared
fields, and missing events in time windows. Elastic also documents historical
rule preview and validation.

Product lesson for Zentryc:

- Use Elastic EQL as the clearest benchmark for sequence semantics.
- "sequence by entity with maxspan" is the minimum mental model Zentryc should
  match.

### IBM QRadar

Assessment position: QRadar has rules, building blocks, and offense chaining.

Verdict: Accept.

IBM documents rules and building blocks in the Custom Rules Engine and offense
chaining to reduce the number of offenses analysts review.

Product lesson for Zentryc:

- Add reusable building blocks only after the basic stage schema is stable.
- Incident/offense grouping should be a core roadmap item, not a future luxury.

### CrowdStrike Falcon Next-Gen SIEM

Assessment position: CrowdStrike emphasizes correlation rule templates and
template discovery aligned to data sources and MITRE.

Verdict: Accept.

CrowdStrike's public material says the template discovery dashboard helps teams
find and operationalize detection content aligned to existing data sources, and
mentions more than 1000 correlation rule templates across cloud, endpoint,
network, identity, and third-party sources.

Product lesson for Zentryc:

- A template library matters, but template discovery should be data-aware.
- Zentryc should recommend templates based on sources actually ingested.

### Datadog Cloud SIEM

Assessment position: Datadog signal correlation rules correlate existing
signals into higher-value signals.

Verdict: Accept.

Datadog documents signal correlation rules that combine multiple security
signals to alert on more complex use cases and reduce alert fatigue.

Product lesson for Zentryc:

- Add "alert/signal as a source" so correlation can operate over existing
  Zentryc alerts and threat-intel hits, not only raw logs.

## 8. Revised Strategic Roadmap

The other team's six-phase roadmap is sensible, but the order should be
adjusted. Reliability, evidence, and entity semantics must come before visual
expansion and ML.

### Phase 0 - Correctness and Safety Hotfixes

Target: 1 to 2 engineering weeks

Goals:

- Stop silently wrong or unsafe rule behavior.
- Make current matches more trustworthy.
- Create a safe base for UI and multi-source work.

Required changes:

- Replace duplicate-alert time math with `timedelta(minutes=5)`.
- Add field and operator allow-lists for `syslogs`.
- Parameterize ClickHouse values.
- Validate rule/stage payloads with Pydantic before save.
- Fail closed on unresolved variables.
- Add medium/low severity statistics or severity distribution.
- Change "View All Matches" to a real filtered match view.
- Add unit tests for where-clause building, variable resolution, duplicate
  alert logic, and invalid stage rejection.

Exit criteria:

- A malformed rule cannot be saved.
- A variable resolution failure cannot broaden a later stage.
- Query field names are restricted to approved columns.
- Alert creation does not fail during the first five minutes of an hour.

### Phase 1 - Match Identity, Evidence, and Suppression

Target: 2 to 3 engineering weeks

Goals:

- Make match records represent unique security evidence, not scheduler ticks.
- Preserve enough context for investigation.

Required changes:

- Add `rule_version`, `match_fingerprint`, `entity_type`, `entity_value`,
  `first_seen`, `last_seen`, and `status` concepts to match storage.
- Capture per-stage evidence windows: min event time, max event time, count,
  source, filter, and sample event references.
- Add configurable suppression by rule and entity.
- Replace title-based alert dedupe with rule/entity/fingerprint suppression.
- Update existing detail modal to show evidence windows and suppression state.

Exit criteria:

- A condition that remains true for 30 minutes does not create 30 independent
  attack-chain records unless the rule explicitly wants recurring matches.
- An analyst can see why each stage matched without guessing from broad log
  links.

### Phase 2 - True Sequence Engine

Target: 3 to 5 engineering weeks

Goals:

- Make "then" mean event-time ordering.
- Evaluate all candidate entities, not only the top aggregate.

Required changes:

- Add `ordering` to rules: `sequence` or `any_order`.
- Add `join_keys` as a first-class stage/rule property.
- Return candidate sets from stages, including key, count, and event time
  bounds.
- For `sequence`, evaluate stage N after the prior stage's terminal timestamp
  and within stage N's window.
- Add composite joins such as `srcip + dstip`, `user + host`, and future
  canonical entity joins.
- Store stage ordering proof in `stage_details`.
- Keep `any_order` only for backward-compatible aggregate rules.

Exit criteria:

- "Reconnaissance then Access" fires only when access follows recon for the
  same entity inside the allowed window.
- Multiple valid entities can produce separate matches in the same scheduler
  run.

### Phase 3 - Authoring and Detection Engineering UX

Target: 3 engineering weeks

Goals:

- Make rule creation safe and usable for analysts.
- Preserve advanced control for detection engineers.

Required changes:

- Add `PUT /api/correlation/rules/{id}`.
- Add clone rule.
- Add a visual stage builder with field dropdowns, operators, threshold,
  window, source, join keys, and variable chips.
- Add `GET /api/correlation/schema` for source/field metadata.
- Add `POST /api/correlation/rules/test` to preview draft rules against recent
  historical data without persistence.
- Keep a synchronized advanced JSON editor.
- Version rules on update and record version in future matches.

Exit criteria:

- An analyst can create, test, edit, and tune a rule without manually writing
  JSON.
- A power user can still inspect and edit the JSON representation.

### Phase 4 - Source Registry and Entity Model

Target: 4 engineering weeks

Goals:

- Move from firewall-only correlation to cross-domain correlation.
- Normalize entities before adding many data sources.

Required changes:

- Add a correlation source registry with table name, timestamp column,
  allowed fields, entity mappings, and supported operators.
- Start with sources already present in the platform:
  - `syslogs`
  - `url_logs`
  - `ioc_matches`
  - `audit_logs`
  - existing `alerts`
  - `correlation_matches`
- Define canonical entities:
  - `ip`
  - `user`
  - `host`
  - `domain`
  - `url`
  - `device`
- Add source-specific field mapping to canonical entities.
- Seed at least three cross-source rules:
  - Threat-intel IOC hit followed by allowed firewall connection from the same
    IP.
  - Suspicious DNS or URL activity followed by high outbound volume.
  - Admin/audit change after repeated denied access from the same entity.

Exit criteria:

- At least three shipped rules span two or more sources.
- A source can be added without modifying the core engine logic.

### Phase 5 - Incident and Risk Output

Target: 3 to 4 engineering weeks

Goals:

- Reduce alert fatigue and produce incident-quality outputs.

Required changes:

- Add entity risk scoring with time decay.
- Let rules contribute configurable risk scores to entities.
- Group related matches into incidents by entity, rule family, MITRE tactic,
  and time proximity.
- Derive incident severity from accumulated risk and rule severity.
- Add lifecycle states: new, investigating, contained, resolved, suppressed.
- Keep raw matches available under the incident as evidence.

Exit criteria:

- Four related matches for one host become one incident with evidence and risk
  context, not four unrelated alerts.

### Phase 6 - Templates, MITRE Workflow, and Response Actions

Target: 4 engineering weeks

Goals:

- Scale detection content.
- Connect ATT&CK coverage gaps to rule creation.
- Add controlled response automation.

Required changes:

- Build a curated template library with parameters and expected data sources.
- Recommend templates based on sources actually ingested.
- Add "Create rule from this technique" actions in the MITRE map.
- Add response actions per rule and severity:
  - email or webhook notification
  - Telegram or existing notification channel where available
  - add IP/domain to EDL or blocklist workflow where supported
  - create ticket/webhook for ITSM integration
- Add anomaly stages only after entity and sequence foundations are stable.

Exit criteria:

- An analyst can open an uncovered ATT&CK technique, select a relevant
  template, preview expected match volume, and deploy the rule in minutes.
- A critical incident can trigger a controlled response action with audit
  history.

## 9. Recommended Acceptance Criteria

### Engine correctness

- Stage order is proven with event timestamps.
- All candidate entities can be evaluated.
- Rule matches include entity, fingerprint, rule version, stage windows, and
  sample evidence.
- Unresolved variables fail closed.

### Security and robustness

- ClickHouse SQL uses allow-listed identifiers and parameterized values.
- API inputs have explicit ranges.
- Rule schema validation blocks malformed rules at save time.
- Scheduler failures surface in rule health, not only logs.

### Analyst experience

- Create, edit, clone, disable, delete, and preview are all supported.
- Rule preview shows expected fire rate, sample matches, and stage-by-stage
  failures.
- Detail pages show evidence, not only aggregate analytics.
- Recent Matches supports filtering and deep links from rule detail.

### Enterprise output

- Matches can be suppressed by rule and entity.
- Related matches become incidents.
- Entity risk accumulates and decays.
- Response actions are configurable, audited, and severity-aware.

## 10. Product Positioning Recommendation

Until Phase 2 is complete, describe the feature as:

"Staged correlation rules over firewall/syslog data with MITRE mapping and
per-rule match analytics."

After Phase 2, describe it as:

"A sequence-aware correlation engine that detects ordered multi-stage attack
chains across entities and preserves evidence for investigation."

After Phase 5, describe it as:

"A risk-based, entity-aware correlation and incident engine that turns related
security signals into prioritized incidents and response actions."

## 11. Priority Decision

The next implementation sprint should not start with the visual rule builder.
The visual builder would make it easier to create rules, but it would also make
it easier to create rules on top of weak semantics.

Recommended next sprint:

1. Fix alert dedup time math.
2. Add schema validation and fail-closed variable resolution.
3. Add query allow-lists and parameterized values.
4. Add match fingerprint/suppression design.
5. Implement ordered sequence semantics for the seeded "then" rules.

This sequence creates a trustworthy detection foundation. Once that foundation
exists, the visual builder, multi-source correlation, templates, and risk-based
incidents become high-value product investments instead of UI built around an
ambiguous engine.
