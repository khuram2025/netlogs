# Device timestamp display — 18 September 2026

Deployed web image `zenshield:0.4.3-logfix-20260918-r7`. Only web was recreated;
all six services are healthy. The collector remains r5.

The user requested that the Timestamp column match the time in the log itself.
A newly ingested FortiGate event contained `2026-09-17 18:04:57`, `tz=+0300`;
its normalized timestamp was correctly stored as `2026-09-17 15:04:57.299 UTC`.
The table previously rendered the normalized UTC value, causing the visible
three-hour difference.

The table now displays the existing `log_time` string verbatim. Its heading is
“Timestamp (device)”; the hover text shows normalized time and timezone. The time
window explains that filtering and ordering use normalized time. Records without
a device time use the normalized fallback with an explicit timezone label.
Detail chips identify device time/offset, normalized time/zone and ingestion
time/zone. Lookup keys still use the normalized timestamp. No new database reads
or heavy columns were added, and no stored timestamps were modified.

## Verification

- A real-route rendering test passed with source timestamps ahead of and behind
  UTC, vendor date separators, missing source time, escaped untrusted content,
  and preservation of the normalized detail lookup key.
- Authenticated HTTPS on the exact requested one-minute URL returned 100 rows in
  0.212 seconds. Rows 1, 50 and 100 were fetched via the detail API and matched
  their raw device date/time. Expanded detail panels rendered the updated labels.
- `timestamp-r7.jsonl` records these metrics without raw log payloads.
- Browser access remains blocked by `ERR_CERT_AUTHORITY_INVALID`; the warning
  was not bypassed. HTTPS verification trusts the appliance public certificate
  retrieved over pinned SSH and retains hostname validation.

Historical rows ingested before r5 still have the previously reported storage
offset problem, and can appear in an incorrect filter window. r7 changes display
only; it does not repair historical storage or unsynchronized device clocks.

## Rollback

Restore `/opt/zensheild/logfix-20260917/compose.update.before-r7.yaml` to
`/opt/zensheild/compose.update.yaml`, recreate only web with the existing compose
files, then reload nginx. This returns to r6 while retaining NTP management and
the r5 ingestion fix.
