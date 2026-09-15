"""Executed inside the candidate web image with the ordered SQL ledger on stdin."""
import asyncio
import hashlib
import json
import os
import sys
import asyncpg
import clickhouse_connect
from urllib3.exceptions import NewConnectionError, ReadTimeoutError, ProtocolError
from urllib3.util import Timeout


def transient_connection_error(error):
    """Retry transport/startup failures only, never authentication or SQL errors."""
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        if getattr(error, 'code', None) is not None:
            return False  # ClickHouse returned a database error, not a transport failure.
        if isinstance(error, (ConnectionError, TimeoutError, asyncpg.CannotConnectNowError,
                              NewConnectionError, ReadTimeoutError, ProtocolError)):
            return True
        error = error.__cause__ or getattr(error, 'reason', None)
    return False


async def await_connection(factory, engine, timeout=60, interval=2):
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise RuntimeError(engine + ' readiness timed out before schema changes') from None
        try:
            return await asyncio.wait_for(factory(remaining), timeout=remaining)
        except Exception as error:
            if not transient_connection_error(error):
                raise
            await asyncio.sleep(min(interval, max(0, deadline - asyncio.get_running_loop().time())))


async def connect_postgres(remaining):
    return await asyncpg.connect(host=os.environ['POSTGRES_HOST'], port=int(os.environ['POSTGRES_PORT']),
        user=os.environ['POSTGRES_USER'], password=os.environ['POSTGRES_PASSWORD'],
        database=os.environ['POSTGRES_DB'], timeout=min(5, remaining))


async def connect_clickhouse(remaining):
    # Dedicated migration client: bounded transport waits, no SQL query retries.
    return await asyncio.to_thread(clickhouse_connect.get_client,
        host=os.environ['CLICKHOUSE_HOST'], port=int(os.environ['CLICKHOUSE_PORT']),
        username=os.environ['CLICKHOUSE_USER'], password=os.environ['CLICKHOUSE_PASSWORD'],
        database=os.environ['CLICKHOUSE_DB'], connect_timeout=min(3, remaining),
        send_receive_timeout=min(5, remaining), query_retries=0, compress=True)

async def main():
    migrations=json.load(sys.stdin)
    pg=await await_connection(connect_postgres, 'PostgreSQL')
    try:
        ch=await await_connection(connect_clickhouse, 'ClickHouse')
        ch.timeout = Timeout(connect=10, read=300)  # Normal timeout for the migration statements below.
    except BaseException:
        await pg.close()
        raise
    await pg.execute('CREATE TABLE IF NOT EXISTS zenshield_ota_migrations (id text PRIMARY KEY, sha256 text NOT NULL, ordinal integer NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())')
    ch.command('CREATE TABLE IF NOT EXISTS zenshield_ota_migrations (id String, sha256 String, ordinal UInt32, applied_at DateTime DEFAULT now()) ENGINE=MergeTree ORDER BY id')
    actual={'postgres':[(r['id'],r['ordinal']) for r in await pg.fetch('SELECT id,ordinal FROM zenshield_ota_migrations ORDER BY ordinal')],
            'clickhouse':ch.query('SELECT id,ordinal FROM zenshield_ota_migrations ORDER BY ordinal').result_rows}
    for engine,rows in actual.items():
        expected=[(m['path'],i) for i,m in enumerate(migrations) if m['path'].split('/')[2]==engine]
        if [tuple(r) for r in rows]!=expected[:len(rows)]:raise ValueError('Migration history must be an unchanged ordered prefix')
    ledgers={'postgres':{r['id']:r['sha256'] for r in await pg.fetch('SELECT id,sha256 FROM zenshield_ota_migrations')},
             'clickhouse':{row[0]:row[1] for row in ch.query('SELECT id,sha256 FROM zenshield_ota_migrations').result_rows}}
    declared={m['path']:m for m in migrations}
    for engine,ledger in ledgers.items():
        for name,checksum in ledger.items():
            if name not in declared or declared[name]['sha256']!=checksum:raise ValueError('Released migration was removed or modified')
    for ordinal,m in enumerate(migrations):
        engine=m['path'].split('/')[2]
        if hashlib.sha256(m['sql'].encode()).hexdigest()!=m['sha256']:raise ValueError('Migration checksum mismatch')
        if m['path'] in ledgers[engine]:continue
        if engine=='postgres':
            async with pg.transaction():
                await pg.execute(m['sql'])
                await pg.execute('INSERT INTO zenshield_ota_migrations (id,sha256,ordinal) VALUES ($1,$2,$3)',m['path'],m['sha256'],ordinal)
        else:
            ch.command(m['sql'])
            ch.insert('zenshield_ota_migrations',[[m['path'],m['sha256'],ordinal]],column_names=['id','sha256','ordinal'])
    assert await pg.fetchval("SELECT count(*) FROM information_schema.columns WHERE table_name='users' AND column_name IN ('id','username','password_hash','role')")>=4
    assert 'log_time' in {row[0] for row in ch.query('DESCRIBE TABLE syslogs').result_rows}
    await pg.close()
    ch.close()
    print('Schema ledger and required schema verified')

if __name__ == '__main__':
    asyncio.run(main())
