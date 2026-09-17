# Time & NTP display timezone

Deployed web image `zenshield:0.4.3-logfix-20260918-r8`. Only web was recreated;
all services are healthy. Backup: `/opt/zensheild/logfix-20260917/compose.update.before-r8.yaml`.

The Time & NTP panel was hard-coded to display UTC even after the appliance
timezone changed. Both the appliance clock and last synchronization now use
the timezone reported by `time.status`, with an explicit UTC offset. UTC API
timestamps remain unchanged. Invalid timezone data falls back to UTC with a
visible fallback label. NTP configuration was not changed.

UI tests cover Asia/Riyadh conversion and date rollover, UTC, winter/summer
offsets, invalid zones, unsaved server edits, saving and retry behavior.
Authenticated HTTPS retrieved the deployed script and live status. Executing
that script in the DOM test harness verified `18:26:46 UTC+03:00` for the actual
`15:26:46 UTC` last-reference time, and confirmed synchronized status.
See `ntp-timezone-r8.jsonl`. This is script/API verification; browser visual
verification remains unavailable due to the previously observed certificate
warning, which was not bypassed.
