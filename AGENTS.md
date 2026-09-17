# Repository agent instructions

- Keep real credentials in `.env.local`, which is ignored by Git.
- Read credentials only when required; never print, commit, or copy secret values.
- Maintenance variable names are documented in `.env.example`.
- Application source lives in `fastapi_app`; host management code lives in
  `appliance/control`. Keep its `api.py`, `system.html`, and `_ntp_panel.html`
  mirrors aligned with the corresponding application files.
- See `reports/logs-repair-20260918/README.md` for the log and NTP repair,
  validation evidence and release integration constraints.
