"""Resumable history loading, separate from schema migration and live MVs.

The appliance updater stops all writers before schema initialization. Capture
immutable, hard-linked source parts during that maintenance window, then let
the scheduler process them after services are healthy. Live inserts only go to
the original tables; history goes to separate tables exposed by UNION views.
Each bounded batch is published using atomic REPLACE PARTITION. Replaying a
batch after a crash replaces its result instead of adding its counts again.
"""
import hashlib
import fcntl
import importlib
import json
import logging
import re
import time

logger = logging.getLogger(__name__)
TARGETS = ('policy_hits_daily', 'implicit_deny_daily', 'flow_pairs_daily', 'forti_utm_events')
BATCH_ROWS = 250_000
OPTIONS = {'async_insert': 0, 'max_threads': 1, 'max_insert_threads': 1,
           'max_block_size': 8192, 'max_insert_block_size': 8192,
           'max_memory_usage': 536870912, 'max_execution_time': 90,
           'max_bytes_before_external_sort': 67108864,
           'max_bytes_before_external_group_by': 67108864}
LEDGER = '_zenshield_analytics_backfill'


def ensure_ledger(c):
    c.command(f'''CREATE TABLE IF NOT EXISTS {LEDGER} (
        target String, revision UInt64, payload String
    ) ENGINE = ReplacingMergeTree(revision) ORDER BY target''')


def states(c):
    return {target: json.loads(payload) for target, payload in c.query(
        f'SELECT target,payload FROM {LEDGER} FINAL').result_rows}


def save(c, target, state):
    c.insert(LEDGER, [[target, time.time_ns(), json.dumps(state)]],
             column_names=['target', 'revision', 'payload'], settings={'async_insert': 0})


def names(target):
    assert target in TARGETS
    return (f'_zs_source_{target}', f'_zs_history_{target}', f'_zs_stage_{target}')


def ensure_history_view(c, target):
    _, history, stage = names(target)
    # Preserve the original engine, sorting key, codecs and retention rules.
    ddl = c.query(f'SHOW CREATE TABLE {target}').first_row[0]
    ddl = re.sub(r'^CREATE TABLE \S+', f'CREATE TABLE IF NOT EXISTS {history}', ddl, count=1)
    ddl = re.sub(r'PARTITION BY [^\n]+', 'PARTITION BY _backfill_batch', ddl, count=1)
    pos = ddl.index('\n)\nENGINE')
    ddl = ddl[:pos] + ',\n    `_backfill_batch` String' + ddl[pos:]
    c.command(ddl)
    c.command(f'CREATE TABLE IF NOT EXISTS {stage} AS {history}')
    columns = ','.join('`'+r[0]+'`' for r in c.query(f'DESCRIBE TABLE {target}').result_rows)
    c.command(f'CREATE VIEW IF NOT EXISTS {target}_all AS '
              f'SELECT {columns} FROM {target} UNION ALL SELECT {columns} FROM {history}')


def prepare(c, target):
    """Called before creating a new target/MV, with appliance writers stopped.

    A durable ready marker makes interrupted migration retries reuse the exact
    same source boundary. Existing installations retain their prior aggregates.
    """
    ensure_ledger(c)
    if target in states(c):
        return
    if c.query(f'EXISTS TABLE {target}').first_row[0]:
        save(c, target, {'status': 'existing', 'completed_rows': 0, 'total_rows': 0})
        return
    source, _, _ = names(target)
    # No ready marker: discard only our incomplete private snapshot and retry.
    c.command(f'DROP TABLE IF EXISTS {source} SYNC')
    c.command(f'CREATE TABLE {source} AS syslogs')
    c.command(f'ALTER TABLE {source} REMOVE TTL')
    c.command(f'ALTER TABLE {source} MODIFY SETTING '
              'max_bytes_to_merge_at_max_space_in_pool=0, max_bytes_to_merge_at_min_space_in_pool=0')
    c.command(f'SYSTEM STOP MERGES {source}')
    c.command(f'ALTER TABLE {source} ATTACH PARTITION ALL FROM syslogs')
    parts = [[r[0], int(r[1])] for r in c.query(
        'SELECT name,rows FROM system.parts WHERE active AND database=currentDatabase() '
        'AND table={table:String} ORDER BY name', parameters={'table': source}).result_rows]
    save(c, target, {'status': 'pending', 'parts': parts, 'part_index': 0, 'offset': 0,
                    'completed_rows': 0, 'total_rows': sum(r[1] for r in parts), 'error_code': None})


def extract(target):
    if target == 'forti_utm_events':
        mod = importlib.import_module('.clickhouse_migrations.006_forti_utm_events', __package__)
        return mod._EXTRACT_SELECT.strip()
    mod = importlib.import_module('.clickhouse_migrations.002_policy_analytics_aggregates', __package__)
    # Use the same per-event projection as the live MV. Streaming hits=1 avoids
    # retaining millions of distinct flow keys in a startup GROUP BY hash table.
    stmt = next(s for s in mod._STATEMENTS if f'{target}_mv TO' in s)
    return stmt.split(' AS\n', 1)[1].strip()


def run_batch(c):
    # Covers scheduler workers and operator/test invocations alike. A container
    # restart cannot leave a stale lease; the kernel releases this lock.
    with open('/tmp/zenshield-analytics-backfill.lock', 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return None
        return _run_batch(c)


def _run_batch(c):
    """Process at most one bounded batch; the scheduler supplies a single worker."""
    jobs = states(c)
    for target in TARGETS:
        state = jobs.get(target)
        if not state:
            continue
        source, history, stage = names(target)
        if state['status'] == 'complete':
            if not state.get('source_removed'):
                c.command(f'DROP TABLE IF EXISTS {source} SYNC')
                state['source_removed'] = True
                save(c, target, state)
            continue
        if state['status'] == 'existing':
            continue
        if state.get('retry_after', 0) > time.time():
            continue
        try:
            # STOP MERGES is not persisted across a ClickHouse restart.
            # Persisted parts must remain stable, so snapshot tables additionally
            # disable merges through their table settings (set during migration).
            if state['part_index'] >= len(state['parts']):
                state['status'] = 'complete'
                state['error_code'] = None
                save(c, target, state)
                c.command(f'DROP TABLE IF EXISTS {source} SYNC')
                return True
            part, rows = state['parts'][state['part_index']]
            actual = c.query('SELECT rows FROM system.parts WHERE active AND database=currentDatabase() '
                             'AND table={table:String} AND name={part:String}',
                             parameters={'table': source, 'part': part}).result_rows
            if actual != [(rows,)]:
                raise RuntimeError('Historical source part changed; operator recovery is required')
            start = state['offset']
            end = min(start+BATCH_ROWS, rows)
            batch = hashlib.sha256(f'{part}:{start}:{end}'.encode()).hexdigest()[:24]
            # A failed INSERT may leave partial stage parts. They are never visible
            # to analytics and are removed before every retry.
            c.command(f'TRUNCATE TABLE {stage}')
            sql = extract(target).replace('FROM syslogs', f'FROM {source}')
            sql += ' AND _part={part:String} AND _part_offset>={start:UInt64} AND _part_offset<{end:UInt64}'
            c.command(f'INSERT INTO {stage} SELECT *, {{batch:String}} FROM ({sql})',
                      parameters={'part': part, 'start': start, 'end': end, 'batch': batch}, settings=OPTIONS)
            present = c.query('SELECT count() FROM system.parts WHERE active AND database=currentDatabase() '
                              'AND table={table:String}', parameters={'table': stage}).first_row[0]
            if present:
                c.command(f'ALTER TABLE {history} REPLACE PARTITION {{batch:String}} FROM {stage}',
                          parameters={'batch': batch})
            state['completed_rows'] += end-start
            state['offset'] = end
            if end == rows:
                state['part_index'] += 1
                state['offset'] = 0
            state['status'] = 'running'
            state['error_code'] = None
            state['retry_after'] = 0
            state['attempts'] = 0
            save(c, target, state)
            c.command(f'TRUNCATE TABLE {stage}')
            return True
        except Exception as error:
            code = re.search(r'Code: (\d+)', str(error))
            state['status'] = 'retrying'
            state['error_code'] = int(code[1]) if code else None
            state['attempts'] = state.get('attempts', 0)+1
            state['retry_after'] = time.time()+min(300, 10*state['attempts'])
            save(c, target, state)
            logger.warning('Analytics history %s paused for retry (code=%s, type=%s)',
                           target, state['error_code'], type(error).__name__)
            return False
    return False


def scheduled_batch():
    from .clickhouse import ClickHouseClient
    return run_batch(ClickHouseClient.get_client())


def progress():
    """Public status contains no log records, internal part names or raw errors."""
    from .clickhouse import ClickHouseClient
    labels = dict(zip(TARGETS, ('Policy activity', 'Implicit denies', 'Flow pairs', 'FortiGate threats')))
    return [{'name': labels[target], 'status': state['status'],
             'processed': state['completed_rows'], 'total': state['total_rows'],
             'percent': 100 if state['status'] == 'complete' else round(100*state['completed_rows']/max(1, state['total_rows']), 1),
             'error_code': state.get('error_code')}
            for target, state in states(ClickHouseClient.get_client()).items() if target in labels]
