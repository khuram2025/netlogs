#!/usr/bin/python3
"""Read-only ClickHouse migration metadata; no event data or raw errors printed."""
import json,subprocess

CODE=r'''
import asyncio,json,re
from sqlalchemy import text
from fastapi_app.db.database import async_session_maker
from fastapi_app.db.clickhouse import ClickHouseClient

async def main():
    out={'diagnostic':'clickhouse-migrations-v1','read_only':True}
    async with async_session_maker() as db:
        value=(await db.execute(text("SELECT value FROM system_settings WHERE key='clickhouse_schema_version'"))).scalar_one_or_none()
        out['recorded_migration_version']=int(value) if value is not None and str(value).isdigit() else ('not_recorded' if value is None else 'invalid')
    c=ClickHouseClient.get_client()
    options={'readonly':1,'max_execution_time':15,'max_memory_usage':268435456,'max_threads':1}
    out['syslogs_parts']=[dict(zip(('active_parts','rows','compressed_bytes','uncompressed_bytes','partitions'),r)) for r in c.query("SELECT count(),sum(rows),sum(bytes_on_disk),sum(data_uncompressed_bytes),uniqExact(partition_id) FROM system.parts WHERE active AND database=currentDatabase() AND table='syslogs'",settings=options).result_rows]
    out['analytics_tables']=[dict(zip(('name','rows','compressed_bytes'),r)) for r in c.query("SELECT table,sum(rows),sum(bytes_on_disk) FROM system.parts WHERE active AND database=currentDatabase() AND table IN ('policy_hits_daily','implicit_deny_daily','flow_pairs_daily','forti_utm_events') GROUP BY table ORDER BY table",settings=options).result_rows]
    out['settings']={r[0]:r[1] for r in c.query("SELECT name,value FROM system.settings WHERE name IN ('max_memory_usage','max_bytes_before_external_group_by','max_partitions_per_insert_block','max_execution_time','max_threads')",settings={'readonly':1}).result_rows}
    out['recent_migration_query_errors']=[]
    exists=c.query("EXISTS TABLE system.query_log",settings=options).first_row[0]
    if exists:
        for table in ('policy_hits_daily','implicit_deny_daily','flow_pairs_daily','forti_utm_events','entity_risk','correlation_matches'):
            try:
                rows=c.query("SELECT exception_code,exception,query_duration_ms,read_rows,memory_usage,event_time FROM system.query_log WHERE event_time>now()-INTERVAL 2 DAY AND exception_code!=0 AND positionCaseInsensitive(query, {table:String})>0 ORDER BY event_time DESC LIMIT 5",parameters={'table':table},settings=options).result_rows
                for code,error,duration,read,memory,when in rows:
                    out['recent_migration_query_errors'].append({'table':table,'code':code,'error_names':sorted(set(re.findall(r'\(([A-Z][A-Z_0-9]+)\)',error)))[:8],'duration_ms':duration,'read_rows':read,'memory_bytes':memory,'time':str(when)})
            except Exception as error:
                out['query_log_read_error']=type(error).__name__
                break
    else:out['query_log_available']=False
    print(json.dumps(out,indent=2))

try:asyncio.run(main())
except Exception as error:print(json.dumps({'diagnostic':'clickhouse-migrations-v1','read_only':True,'error_type':type(error).__name__}))
'''

if __name__=='__main__':
    p=subprocess.run(['docker','exec','-i','zensheild-web-1','python'],input=CODE,capture_output=True,text=True,timeout=150)
    try:
        # Imported modules may log before the final JSON. Never relay raw logs.
        start=p.stdout.find('{')
        report=json.loads(p.stdout[start:])
    except (ValueError,TypeError):report={'diagnostic':'clickhouse-migrations-v1','read_only':True,'error_type':'DiagnosticExecutionFailed','exit_code':p.returncode}
    print(json.dumps(report,indent=2))
