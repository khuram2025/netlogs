# Policy Lookup — Config-Match Engine (P0)

## Why

Today `/policy-lookup/` is log-driven: it answers *"has this traffic been
seen?"*. If no logs exist for the flow, the page is silent even when an
allow rule would match. Competitors (FortiManager Policy Lookup, Panorama
Test Policy Match, Tufin, AlgoSec) answer the config question —
*"would this traffic match if it tried?"*. We already ingest the full
rule base, zones, routes, and address/service objects per device, so we
have everything needed to answer both questions in one screen.

## Scope of this change

Two P0 items from the improvement plan:

1. **Protocol selector + FQDN input** on the lookup form.
2. **Config-match engine** producing a "Would Match" result table
   alongside the existing Allowed / Denied tables, plus a Mode toggle
   (Logs+Config / Config-only / Logs-only).

Out of scope (later PRs): path-first device selection, shadow-rule
detection, bulk CSV, pre-change what-if, AI explanation, threat-intel
overlay.

## Match algorithm (per device+VDOM)

Input: `(src_ip?, src_zone?, dst_ip|fqdn, dst_port, protocol, user?, app?)`

For each policy in `FirewallPolicy` ordered by `position` ASC where
`enabled=True`, return the first policy whose every populated field matches:

1. **Protocol / service**: resolve the policy's `services[]` via
   `FirewallServiceObject` (expand groups recursively); match if any
   service has `protocol in (input_proto, tcp_udp, ip)` AND `ports`
   range contains `dst_port`. Special token `ALL` / `any` matches any.
2. **Source address**: resolve `src_addresses[]` via
   `FirewallAddressObject` (recurse groups); match if `src_ip` falls
   inside any `ipmask`/`iprange`, or the list contains `all`/`any`.
   Skip this check when `src_ip` was not provided.
3. **Destination address**: same, but also handle `kind=fqdn` —
   match if the user supplied a matching FQDN directly, or if the
   resolved IPs of that FQDN contain `dst_ip`.
4. **Zones**: if `src_zone`/`dst_zone` is known (from input or
   auto-resolved via routing+zone table) and the policy's
   `src_zones`/`dst_zones` is non-empty and doesn't contain `any`,
   require membership.
5. **User / app**: only enforce when the input provides them and the
   policy constrains them.

Return: `{policy_id, rule_id, name, position, action, matched_by:{...}, hit_count, last_hit_at}`.

A device can produce at most one match (first-match-wins, standard
FortiGate/PAN behavior). If no policy matches, the device's implicit
default applies (`deny` on Fortinet, explicit catch-all on PAN) — surface
this as `action='implicit-deny'`.

## Resolvers (new module pieces)

All live in `services/policy_match_engine.py`:

- `resolve_address_object(name, objects_by_name) -> list[IPNetwork|FQDN]`
  (recursive for groups, cached)
- `resolve_service_object(name, services_by_name) -> list[ServiceRange]`
  (recursive, cached)
- `resolve_zone_for_ip(ip, zones, routes) -> zone_name | None`
  (uses longest-prefix match on subnets, falls back to route next-hop
  interface → zone)
- `match_device(device_id, vdom, query) -> MatchResult`
- `match_all_devices(query) -> list[MatchResult]`

All reads go through the existing SQLAlchemy services
(`FirewallPolicyService`, `ZoneService`, `RoutingService`). No new DB
schema.

## View / API changes

`GET /policy-lookup/` gains query params:

- `proto` — `tcp` | `udp` | `icmp` | `any` (default `tcp`)
- `dst` — accepts IP **or** FQDN (renames `dstip` in the UI, param kept
  for back-compat)
- `mode` — `both` (default) | `config` | `logs`

View behavior:

- Run log query (existing) when `mode in (both, logs)`.
- Run config engine when `mode in (both, config)`.
- Merge: if a `(device, policy)` appears in both, annotate with
  `evidence=['config','logs']`. Config-only matches become the new
  "Would Match" section.

## Template changes (`logs/policy_lookup.html`)

- Form: add protocol radio, change dstip label to "Destination (IP or FQDN)",
  add Mode segmented control.
- New table section `Would Match (config, no traffic)` between Allowed
  and Denied, rendered when `results.would_match` is non-empty.
- Reuse existing `pl-section-badge` styling for consistency.

## Testing

- Unit tests for each resolver (`tests/services/test_policy_match_engine.py`):
  ipmask, iprange, nested groups, FQDN, ports range, `ALL`, implicit deny.
- Integration test against a seeded device snapshot (fixtures) covering:
  allow-by-subnet, deny-by-service, implicit deny, disabled rule skipped.
- Manual: run on device 4 (FortiGate, 46 policies already ingested) and
  compare first-match outcomes with FortiGate CLI
  `diag firewall iprope lookup`.

## Rollout

Feature-flagged behind `POLICY_LOOKUP_CONFIG_MATCH=1` env var (default
on in dev, off in prod until QA signoff). Falls back to existing
log-only lookup if the engine raises.
