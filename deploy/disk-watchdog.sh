#!/usr/bin/env bash
# =============================================================================
# Zentryc Disk Watchdog — Prevents ClickHouse from filling the disk
#
# Runs hourly via systemd timer. Checks disk usage and drops the oldest
# ClickHouse partition if usage exceeds the threshold.
#
# Safety layers:
#   Layer 1: ClickHouse TTL (30 days) — auto-expires old data during merges
#   Layer 2: ClickHouse keep_free_space_bytes (50 GB) — blocks writes early
#   Layer 3: This script — force-drops oldest partition as a last resort
# =============================================================================

set -euo pipefail

THRESHOLD_PCT=85       # Drop oldest partition when disk usage exceeds this %
CRITICAL_PCT=95        # Emergency: drop ALL but current month above this %
CH_CLIENT="docker exec clickhouse-server clickhouse-client"
LOG_TAG="zentryc-disk-watchdog"

log() { logger -t "$LOG_TAG" "$*"; echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

# Get current disk usage percentage
USAGE_PCT=$(df --output=pcent / | tail -1 | tr -dc '0-9')
log "Disk usage: ${USAGE_PCT}%"

if [[ "$USAGE_PCT" -lt "$THRESHOLD_PCT" ]]; then
    log "Below ${THRESHOLD_PCT}% threshold — no action needed"
    exit 0
fi

log "WARNING: Disk at ${USAGE_PCT}% (threshold: ${THRESHOLD_PCT}%)"

# Get the oldest partition
OLDEST_PARTITION=$($CH_CLIENT --query "
    SELECT partition
    FROM system.parts
    WHERE table = 'syslogs' AND database = 'default' AND active
    GROUP BY partition
    ORDER BY partition ASC
    LIMIT 1
" 2>/dev/null | tr -d '[:space:]')

if [[ -z "$OLDEST_PARTITION" ]]; then
    log "ERROR: No partitions found in syslogs table"
    exit 1
fi

# Count total partitions (don't drop if only 1 left)
PARTITION_COUNT=$($CH_CLIENT --query "
    SELECT count(DISTINCT partition)
    FROM system.parts
    WHERE table = 'syslogs' AND database = 'default' AND active
" 2>/dev/null | tr -d '[:space:]')

if [[ "$PARTITION_COUNT" -le 1 ]]; then
    log "WARNING: Only 1 partition left ($OLDEST_PARTITION) — cannot drop. Consider adding disk space."
    # Emergency: kill any pending mutations that might be consuming reserved space
    $CH_CLIENT --query "KILL MUTATION WHERE table='syslogs' AND NOT is_done" 2>/dev/null || true
    exit 1
fi

# Get partition size for logging
PARTITION_SIZE=$($CH_CLIENT --query "
    SELECT formatReadableSize(sum(bytes_on_disk))
    FROM system.parts
    WHERE table = 'syslogs' AND database = 'default' AND active AND partition = '$OLDEST_PARTITION'
" 2>/dev/null | tr -d '[:space:]')

log "Dropping oldest partition: $OLDEST_PARTITION ($PARTITION_SIZE)"

# Drop the partition
$CH_CLIENT --query "
    ALTER TABLE syslogs DROP PARTITION '$OLDEST_PARTITION'
    SETTINGS max_partition_size_to_drop = 0
" 2>&1 && log "SUCCESS: Partition $OLDEST_PARTITION dropped" \
         || log "ERROR: Failed to drop partition $OLDEST_PARTITION"

# If still critical, kill stale mutations to free reserved space
USAGE_AFTER=$(df --output=pcent / | tail -1 | tr -dc '0-9')
if [[ "$USAGE_AFTER" -ge "$CRITICAL_PCT" ]]; then
    log "CRITICAL: Still at ${USAGE_AFTER}% after drop — killing stale mutations"
    $CH_CLIENT --query "KILL MUTATION WHERE table='syslogs' AND NOT is_done" 2>/dev/null || true
fi

log "Disk usage after cleanup: ${USAGE_AFTER}%"
