# Standalone ClickHouse container (`clickhouse-server`)

This is the **production** ClickHouse that the FastAPI app and syslog collector use
(`.env` → `CLICKHOUSE_HOST=localhost`, `CLICKHOUSE_PORT=8123`). It is a standalone
`docker run` container (NOT part of `docker-compose.yml`; the compose
`net-logs-clickhouse-1` on host port 8124 is a separate, near-empty instance).

- Data volume: `cd50d6d1c09b...` → `/var/lib/clickhouse` (the 1.7B-row `syslogs` table etc.)
- Restart policy: `always`
- Host ports: 8123 (HTTP), 9000 (native)

## 2026-06-18 incident — logs stopped ingesting after reboot

**Symptom:** After a server reboot, no logs were parsed/saved; `/devices/` showed
nothing new. `netlogs-syslog.service` was stuck in `activating (start-pre)` on an
endless restart loop.

**Root cause:** `config.d/disk-safety.xml` placed `max_partition_size_to_drop`
*inside* the `<merge_tree>` block. That is a **server-level** setting, not a
MergeTree setting. ClickHouse 25.10 hard-rejects unknown MergeTree settings:

```
Code: 115. DB::Exception: Unknown setting 'max_partition_size_to_drop': in MergeTree config.
```

So ClickHouse aborted on startup (exit 115, crash-loop). The syslog unit's
`ExecStartPre` health-gate (`curl http://localhost:8123/ping`, 30×2s then fail)
never passed → collector never started → nothing on UDP/514 → no logs saved.
The bad setting had been edited in earlier but only took effect when the reboot
restarted the container.

**Fix:** Move `max_partition_size_to_drop` (and `max_table_size_to_drop`) to the
top-level `<clickhouse>` element. Corrected file is `config.d/disk-safety.xml`
here; the broken original is `disk-safety.xml.BROKEN-bak`.

The corrected config was `docker cp`'d into the live container and it was
restarted — data volume untouched.

## If this container is ever recreated, re-apply the config

```bash
docker cp docker/clickhouse-standalone/config.d/disk-safety.xml \
    clickhouse-server:/etc/clickhouse-server/config.d/disk-safety.xml
docker restart clickhouse-server
```

(Or add `-v $(pwd)/docker/clickhouse-standalone/config.d:/etc/clickhouse-server/config.d`
as a bind mount when recreating, so the config is version-controlled and can never
drift inside the writable layer again.)
