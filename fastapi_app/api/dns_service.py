"""Windows DNS ingestion: per-source credentials, durable acknowledgements and bounded queries."""
import asyncio
import hashlib
import ipaddress
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from pathlib import Path
from pydantic import BaseModel, Field, ValidationError, ConfigDict
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from ..core.permissions import require_min_role, require_role
from ..db.database import async_session_maker, engine
from ..db.clickhouse import ClickHouseClient

router = APIRouter()

def device_storage_summary():
    """Physical storage totals and bounded, approximate per-source storage."""
    client = ClickHouseClient.get_client()
    totals = list(client.query("""SELECT
        formatReadableSize(sum(data_compressed_bytes)) AS compressed_size,
        formatReadableSize(sum(data_uncompressed_bytes)) AS uncompressed_size,
        sum(rows) AS total_rows,
        round(sum(data_uncompressed_bytes) / greatest(sum(data_compressed_bytes),1),2) AS compression_ratio
        FROM system.parts WHERE database=currentDatabase()
        AND table IN ('syslogs','windows_dns_events') AND active=1""",
        settings=QUERY_SETTINGS).named_results())[0]
    by_ip = {r['device_ip']: r for r in ClickHouseClient.get_per_device_storage()}
    average = client.query("""SELECT sum(data_uncompressed_bytes) / greatest(sum(rows),1)
        FROM system.parts WHERE database=currentDatabase()
        AND table='windows_dns_events' AND active=1""", settings=QUERY_SETTINGS).result_rows[0][0]
    recent = client.query("""SELECT device_ip,count() AS log_count,max(timestamp) AS newest_log
        FROM windows_dns_events FINAL WHERE timestamp > now() - INTERVAL 24 HOUR
        GROUP BY device_ip""", settings=QUERY_SETTINGS).named_results()
    for row in recent:
        entry = by_ip.setdefault(row['device_ip'], {'device_ip':row['device_ip'],'log_count':0,'total_raw_size':0})
        entry['log_count'] += row['log_count']
        entry['total_raw_size'] += int(average * row['log_count'])
        entry['newest_log'] = max(entry.get('newest_log') or row['newest_log'], row['newest_log'])
    return dict(totals), by_ip

UTC = timezone.utc
MAX_BODY = 2 * 1024 * 1024
PG_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS dns_sources (
        id UUID PRIMARY KEY, device_id INTEGER UNIQUE NOT NULL REFERENCES devices_device(id) ON DELETE CASCADE,
        token_hash VARCHAR(64) NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen TIMESTAMPTZ,
        agent_version VARCHAR(64) NOT NULL DEFAULT '', health JSONB NOT NULL DEFAULT '{}')""",
    """CREATE TABLE IF NOT EXISTS dns_batches (
        source_id UUID REFERENCES dns_sources(id) ON DELETE CASCADE, batch_id UUID,
        payload_hash VARCHAR(64) NOT NULL, accepted INTEGER NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(source_id,batch_id))""",
    "CREATE INDEX IF NOT EXISTS dns_batches_age ON dns_batches(created_at)",
]
CH_SCHEMA = """CREATE TABLE IF NOT EXISTS windows_dns_events (
    timestamp DateTime64(6,'UTC') CODEC(DoubleDelta,LZ4),
    received_at DateTime64(6,'UTC') CODEC(DoubleDelta,LZ4),
    expires_at DateTime('UTC'), source_id UUID, event_id UUID,
    device_ip String, device_name LowCardinality(String),
    event_code UInt16, event_type LowCardinality(String),
    src_ip String, dest_ip String, src_port UInt16, dest_port UInt16,
    transport LowCardinality(String), qname String CODEC(ZSTD(1)),
    qtype LowCardinality(String), response_code LowCardinality(String),
    action LowCardinality(String), resolved_ip String, transaction_id String,
    raw_fields String CODEC(ZSTD(3)),
    INDEX dns_time timestamp TYPE minmax GRANULARITY 1,
    INDEX dns_client src_ip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX dns_domain qname TYPE ngrambf_v1(3,32768,3,0) GRANULARITY 4,
    INDEX dns_type qtype TYPE set(128) GRANULARITY 4
) ENGINE=ReplacingMergeTree(received_at)
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (source_id,timestamp,event_id)
TTL expires_at DELETE
SETTINGS index_granularity=8192"""
COLUMNS = ['timestamp','received_at','expires_at','source_id','event_id','device_ip','device_name','event_code','event_type','src_ip','dest_ip','src_port','dest_port','transport','qname','qtype','response_code','action','resolved_ip','transaction_id','raw_fields']
EVENTS = {256:'query-received',257:'response-success',258:'response-failure',259:'query-ignored',260:'recursive-query',261:'recursive-response',262:'recursive-timeout'}
QTYPES = {1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',41:'OPT',43:'DS',46:'RRSIG',47:'NSEC',48:'DNSKEY',64:'SVCB',65:'HTTPS',255:'ANY'}
RCODES = {0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED',6:'YXDOMAIN',7:'YXRRSET',8:'NXRRSET',9:'NOTAUTH',10:'NOTZONE',16:'BADVERS',23:'BADCOOKIE'}

async def initialize():
    async with engine.begin() as conn:
        for statement in PG_SCHEMA: await conn.execute(text(statement))
    await run_in_threadpool(lambda: ClickHouseClient.get_client().command(CH_SCHEMA))

class Event(BaseModel):
    model_config = ConfigDict(extra='forbid')
    event_id: uuid.UUID
    timestamp: datetime
    event_code: int = Field(ge=256,le=262)
    fields: dict[str,str | int | bool | None] = Field(max_length=64)

class Batch(BaseModel):
    model_config = ConfigDict(extra='forbid')
    batch_id: uuid.UUID
    hostname: str = Field(max_length=255)
    agent_version: str = Field(default='',max_length=64)
    captured: int = Field(default=0,ge=0)
    dropped: int = Field(default=0,ge=0)
    parse_errors: int = Field(default=0,ge=0)
    etw_lost: int = Field(default=0,ge=0)
    spool_bytes: int = Field(default=0,ge=0)
    capture_running: bool = True
    events: list[Event] = Field(max_length=500)

def number(value, default=0):
    try:
        s=str(value);return int(s,16) if s.lower().startswith('0x') else int(s)
    except (ValueError,TypeError):return default

def ip(value):
    if not value:return ''
    try:return str(ipaddress.ip_address(str(value)))
    except ValueError:return ''

def answer_ips(packet):
    """Extract bounded A/AAAA answers without executing DNS lookups or expanding compressed names."""
    try:
        data=bytes.fromhex(packet.removeprefix('0x'))
        if len(data)<12:return ''
        def u16(i):return int.from_bytes(data[i:i+2],'big')
        def skip_name(i):
            for _ in range(128):
                size=data[i]
                if size&0xc0==0xc0:return i+2
                if size==0:return i+1
                if size>63:raise ValueError()
                i+=size+1
            raise ValueError()
        i=12
        for _ in range(min(u16(4),32)):i=skip_name(i)+4
        answers=[]
        for _ in range(min(u16(6),64)):
            i=skip_name(i);kind=u16(i);length=u16(i+8);i+=10
            if (kind,length) in ((1,4),(28,16)):
                value=str(ipaddress.ip_address(data[i:i+length]))
                if value not in answers:answers.append(value)
            i+=length
        return ', '.join(answers)
    except (ValueError,IndexError):return ''

def normalize(event: Event, source: dict, now: datetime):
    if event.timestamp.tzinfo is None: raise ValueError('Event timestamps must include a timezone')
    ts=event.timestamp.astimezone(UTC)
    if ts>now+timedelta(minutes=5) or ts<now-timedelta(days=30):raise ValueError('Event timestamp outside the 30-day intake window')
    f={k.lower():str(v if v is not None else '') for k,v in event.fields.items()}
    if any(len(k)>128 or len(v)>8192 for k,v in f.items()):raise ValueError('DNS field too large')
    domain=f.get('qname',f.get('queryname',''))
    domain='.' if domain=='.' else domain.rstrip('.').lower()
    if len(domain)>1024:raise ValueError('DNS name too long')
    code=event.event_code
    qtype=f.get('qtype',f.get('querytype',''))
    qtype=QTYPES.get(number(qtype,-1),qtype.upper())[:32]
    rcode=f.get('rcode',f.get('responsecode',''))
    rcode=RCODES.get(number(rcode,-1),rcode.upper())[:32]
    if code in (256,260):rcode=''
    if code==262:rcode='TIMEOUT'
    peer=ip(f.get('destination') if code in (257,258,260,262) else f.get('source'))
    peer=peer or ip(f.get('src_ip')) or ip(f.get('clientip'))
    outgoing=code in (260,261,262)
    src=source['ip_address'] if outgoing else peer
    dst=peer if outgoing else source['ip_address']
    if code in (257,261):action='response'
    elif code==258:action='failure'
    elif code==259:action='ignored'
    elif code==262:action='timeout'
    else:action='query'
    transport='tcp' if f.get('tcp','').lower() in ('1','true') else 'udp'
    port=max(0,min(65535,number(f.get('port'))))
    retention=source['retention_days']
    expiry=ts+timedelta(days=retention) if retention else datetime(2100,1,1,tzinfo=UTC)
    resolved=ip(f.get('resolved_ip','')) or answer_ips(f.get('packetdata',''))
    return [ts,now,expiry,source['id'],event.event_id,source['ip_address'],source['hostname'] or '',code,EVENTS[code],src,dst,port if not outgoing else 0,53,transport,domain,qtype,rcode,action,resolved,f.get('xid','')[:32],json.dumps(event.fields,separators=(',',':'))]

async def bounded_body(request):
    body=bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body)>MAX_BODY:raise HTTPException(413,'DNS batch exceeds 2 MiB')
    return bytes(body)

@router.post('/api/dns/ingest')
async def ingest(request: Request):
    # This exact endpoint has its own authentication; browser sessions never grant intake access.
    authorization=request.headers.get('authorization','')
    try:
        scheme,credential=authorization.split(' ',1)
        sid,token=credential.split('.',1)
        sid=uuid.UUID(sid)
        if scheme!='Bearer' or not 32<=len(token)<=128:raise ValueError()
    except ValueError:raise HTTPException(401,'A DNS source credential is required')
    raw=await bounded_body(request)
    digest=hashlib.sha256(raw).hexdigest()
    async with async_session_maker() as db:
        async with db.begin():
            source=(await db.execute(text('''SELECT s.*,d.ip_address,d.hostname,d.status,d.retention_days FROM dns_sources s
                JOIN devices_device d ON d.id=s.device_id WHERE s.id=:id FOR UPDATE OF s'''),{'id':sid})).mappings().first()
            if not source or not secrets.compare_digest(source['token_hash'],hashlib.sha256(token.encode()).hexdigest()):raise HTTPException(401,'Invalid DNS source credential')
            if not source['enabled'] or source['status']!='APPROVED':raise HTTPException(403,'DNS source is disabled or blocked')
            from ..core.cache import get_redis
            redis=await get_redis()
            # Atomic expiry: failed workers cannot leave a permanently exhausted counter.
            rate=await redis.eval("local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],60) end; return n",1,f'dns:rate:{sid}')
            if rate>600:raise HTTPException(429,'DNS intake rate exceeded',headers={'Retry-After':'10'})
            try:batch=Batch.model_validate_json(raw)
            except ValidationError:raise HTTPException(422,'Invalid DNS batch schema')
            prior=(await db.execute(text('SELECT payload_hash,accepted FROM dns_batches WHERE source_id=:s AND batch_id=:b'),{'s':sid,'b':batch.batch_id})).mappings().first()
            if prior:
                if prior['payload_hash']!=digest:raise HTTPException(409,'Batch identifier reused with different content')
                return {'batch_id':str(batch.batch_id),'accepted':prior['accepted'],'duplicate':True}
            if len({e.event_id for e in batch.events})!=len(batch.events):raise HTTPException(422,'Duplicate event identifiers in batch')
            now=datetime.now(UTC)
            try:rows=[normalize(e,source,now) for e in batch.events]
            except ValueError as e:raise HTTPException(422,str(e))
            if rows:
                # Await the actual ClickHouse commit. Default application async inserts do not acknowledge durability.
                await run_in_threadpool(lambda:ClickHouseClient.get_client().insert('windows_dns_events',rows,column_names=COLUMNS,settings={'async_insert':0}))
                await db.execute(text('UPDATE devices_device SET last_log_received=:now,updated_at=:now,log_count=coalesce(log_count,0)+:n WHERE id=:id'),{'now':now,'n':len(rows),'id':source['device_id']})
            health=batch.model_dump(exclude={'events','hostname','batch_id','agent_version'})
            await db.execute(text('UPDATE dns_sources SET last_seen=:now,agent_version=:version,health=CAST(:health AS jsonb) WHERE id=:id'),{'now':now,'version':batch.agent_version,'health':json.dumps(health),'id':sid})
            if rows:
                await db.execute(text('INSERT INTO dns_batches(source_id,batch_id,payload_hash,accepted) VALUES(:s,:b,:h,:n)'),{'s':sid,'b':batch.batch_id,'h':digest,'n':len(rows)})
            # A bounded daily purge keeps the idempotency ledger finite; events are accepted for at most 30 days.
            if await redis.set('dns:ledger-cleanup','1',nx=True,ex=86400):
                await db.execute(text("DELETE FROM dns_batches WHERE created_at < now()-interval '31 days'"))
    return {'batch_id':str(batch.batch_id),'accepted':len(rows),'duplicate':False}

class SourceInput(BaseModel):
    ip_address: str
    hostname: str = Field(min_length=1,max_length=255)
    retention_days: int = Field(default=90,ge=0,le=3650)

@router.post('/api/dns/sources',dependencies=[Depends(require_role('ADMIN'))])
async def enroll(body: SourceInput):
    try:address=str(ipaddress.ip_address(body.ip_address))
    except ValueError:raise HTTPException(422,'Enter a valid source IP address')
    token=secrets.token_urlsafe(32);sid=uuid.uuid4()
    async with async_session_maker() as db:
        async with db.begin():
            device=(await db.execute(text('SELECT id,status FROM devices_device WHERE ip_address=:ip FOR UPDATE'),{'ip':address})).mappings().first()
            if device:
                exists=(await db.execute(text('SELECT id FROM dns_sources WHERE device_id=:d'),{'d':device['id']})).first()
                if exists:raise HTTPException(409,'Source already enrolled. Rotate its credential instead.')
                if device['status']!='APPROVED':raise HTTPException(409,'Approve the existing device before enrolling it')
                did=device['id']
                await db.execute(text("UPDATE devices_device SET parser='WINDOWS_DNS',device_type='Windows DNS Server',hostname=:host WHERE id=:id"),{'id':did,'host':body.hostname})
            else:
                did=(await db.execute(text("""INSERT INTO devices_device(ip_address,hostname,status,parser,device_type,retention_days,log_count,created_at,updated_at)
                    VALUES(:ip,:host,'APPROVED','WINDOWS_DNS','Windows DNS Server',:days,0,now(),now()) RETURNING id"""),{'ip':address,'host':body.hostname,'days':body.retention_days})).scalar_one()
            await db.execute(text('INSERT INTO dns_sources(id,device_id,token_hash) VALUES(:id,:did,:hash)'),{'id':sid,'did':did,'hash':hashlib.sha256(token.encode()).hexdigest()})
    return JSONResponse({'source_id':str(sid),'token':token,'device_id':did},headers={'Cache-Control':'no-store'})

@router.post('/api/dns/sources/{source_id}/rotate',dependencies=[Depends(require_role('ADMIN'))])
async def rotate(source_id: uuid.UUID):
    token=secrets.token_urlsafe(32)
    async with async_session_maker() as db:
        result=await db.execute(text('UPDATE dns_sources SET token_hash=:hash WHERE id=:id'),{'id':source_id,'hash':hashlib.sha256(token.encode()).hexdigest()})
        if not result.rowcount:raise HTTPException(404,'Source not found')
        await db.commit()
    return JSONResponse({'source_id':str(source_id),'token':token},headers={'Cache-Control':'no-store'})

@router.get('/api/dns/sources',dependencies=[Depends(require_min_role('VIEWER'))])
async def sources():
    async with async_session_maker() as db:
        rows=(await db.execute(text('''SELECT s.id,s.device_id,s.enabled,s.last_seen,s.agent_version,s.health,
            d.ip_address,d.hostname,d.status,d.last_log_received,d.log_count,d.retention_days
            FROM dns_sources s JOIN devices_device d ON d.id=s.device_id ORDER BY d.hostname,d.ip_address'''))).mappings().all()
    now=datetime.now(UTC);result=[]
    for r in rows:
        item=dict(r);item['id']=str(item['id'])
        for key in ('last_seen','last_log_received'):item[key]=item[key].isoformat() if item[key] else None
        state='never-connected'
        if r['last_seen']:state='connected' if (now-r['last_seen']).total_seconds()<120 else 'offline'
        if state=='connected' and (not r['last_log_received'] or (now-r['last_log_received']).total_seconds()>300):state='idle'
        h=r['health'] or {}
        if state in ('connected','idle') and (h.get('dropped',0)>0 or h.get('etw_lost',0)>0 or h.get('parse_errors',0)>0 or h.get('spool_bytes',0)>5*1024*1024 or not h.get('capture_running',True)):state='degraded'
        if not r['enabled'] or r['status']!='APPROVED':state='blocked'
        item['connection_state']=state;result.append(item)
    return {'sources':result}

def filters(query):
    try:hours=int(query.get('hours','24'))
    except ValueError:raise HTTPException(422,'Invalid time window')
    if not 1<=hours<=744:raise HTTPException(422,'Choose a time window of 1–744 hours')
    end=datetime.now(UTC)
    try:
        if query.get('end'):end=datetime.fromisoformat(query['end'].replace('Z','+00:00')).astimezone(UTC)
        start=end-timedelta(hours=hours)
        if query.get('start'):start=datetime.fromisoformat(query['start'].replace('Z','+00:00')).astimezone(UTC)
    except ValueError:raise HTTPException(422,'Invalid custom time range')
    if not timedelta(0)<end-start<=timedelta(days=31):raise HTTPException(422,'Select a range up to 31 days')
    parts=['timestamp >= {start:DateTime64(6)}','timestamp <= {end:DateTime64(6)}'];params={'start':start,'end':end}
    for key in ('device_ip','src_ip','dest_ip','qtype','response_code','event_type','transport','action','vendor','severity'):
        value=query.get(key)
        if value:
            if len(value)>255:raise HTTPException(422,'Filter too long')
            parts.append(key+' = {'+key+':String}');params[key]=value
    if query.get('resolved_ip'):
        resolved=ip(query['resolved_ip'])
        if not resolved:raise HTTPException(422,'Enter a valid answer IP address')
        parts.append("has(splitByString(', ',resolved_ip),{answer:String})");params['answer']=resolved
    domain=query.get('domain','').strip().lower().rstrip('.')
    if domain:
        if len(domain)>255:raise HTTPException(422,'Domain filter too long')
        mode=query.get('domain_mode','contains')
        if mode=='exact':parts.append('qname = {domain:String}')
        elif mode=='suffix':parts.append("(qname = {domain:String} OR endsWith(qname,concat('.',{domain:String})))")
        elif mode=='contains':parts.append('positionCaseInsensitive(qname,{domain:String})>0')
        else:raise HTTPException(422,'Invalid domain match mode')
        params['domain']=domain
    search=query.get('search','').strip()
    if search:
        if len(search)>255:raise HTTPException(422,'Search too long')
        parts.append('(positionCaseInsensitive(qname,{search:String})>0 OR positionCaseInsensitive(src_ip,{search:String})>0 OR positionCaseInsensitive(device_name,{search:String})>0)');params['search']=search
    return ' AND '.join(parts),params

# The union retains existing firewall DNS history. Windows rows are deduplicated even before background merges.
RELATION = """(SELECT timestamp,received_at,toString(event_id) AS event_id,device_ip,device_name,
    'windows-dns' AS vendor,event_type,event_code,src_ip,dest_ip,src_port,dest_port,transport,qname,qtype,
    response_code,action,resolved_ip,transaction_id,raw_fields,'informational' AS severity,'' AS category
    FROM windows_dns_events FINAL
    UNION ALL SELECT toDateTime64(timestamp,6,'UTC'),toDateTime64(timestamp,6,'UTC'),
    toString(cityHash64(device_ip,toString(timestamp),qname,src_ip,event_type)),device_ip,device_name,vendor,
    event_type,0,src_ip,dest_ip,src_port,dest_port,transport,qname,qtype,'',action,resolved_ip,
    toString(session_id),msg,severity,category FROM dns_logs)"""
QUERY_SETTINGS={'max_execution_time':10,'max_memory_usage':268435456,'max_threads':2,'timeout_overflow_mode':'throw'}

@router.get('/api/dns/agent/{artifact}',dependencies=[Depends(require_role('ADMIN'))])
async def agent_artifact(artifact: str):
    files={'package':('ZenShield-DNS-Agent-1.0.0.zip','application/zip'),
           'manifest':('SHA256SUMS.txt','text/plain'),
           'guide':('README.md','text/plain')}
    if artifact not in files:raise HTTPException(404,'Artifact not found')
    name,media=files[artifact];path=Path('/app/dns-agent')/name
    if not path.is_file():raise HTTPException(503,'The DNS agent distribution has not been included in this appliance image')
    return FileResponse(path,media_type=media,filename=name,content_disposition_type='inline' if artifact=='guide' else 'attachment',headers={'Cache-Control':'private, no-store'})

def execute_search(query):
    where,params=filters(query)
    try:limit=int(query.get('limit','100'));offset=int(query.get('offset','0'))
    except ValueError:raise HTTPException(422,'Invalid pagination')
    if not 1<=limit<=500 or not 0<=offset<=10000:raise HTTPException(422,'Limit must be 1–500; narrow filters after 10,000 results')
    client=ClickHouseClient.get_client()
    q=f'SELECT * FROM {RELATION} WHERE {where} ORDER BY timestamp DESC,event_id DESC LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}'
    rows=list(client.query(q,parameters={**params,'limit':limit+1,'offset':offset},settings=QUERY_SETTINGS).named_results())
    more=len(rows)>limit
    for row in rows:
        for key in ('timestamp','received_at'):row[key]=row[key].replace(tzinfo=UTC).isoformat()
    return {'success':True,'events':rows[:limit],'has_more':more,'limit':limit,'offset':offset}

@router.get('/api/dns/events',dependencies=[Depends(require_min_role('ANALYST'))])
async def events(request: Request):
    try:return await run_in_threadpool(execute_search,dict(request.query_params))
    except HTTPException:raise
    except Exception:raise HTTPException(503,'DNS search is temporarily unavailable. Narrow the time range or try again.')

def execute_stats(query):
    where,params=filters(query);client=ClickHouseClient.get_client()
    summary=list(client.query(f'''SELECT count() AS total,uniqCombined64(qname) AS domains,
        uniqCombined64If(src_ip,event_code IN (0,256,257,258) AND src_ip!='') AS clients,uniqExact(device_ip) AS servers,
        countIf(response_code='NXDOMAIN') AS nxdomain,countIf(action IN ('failure','timeout')) AS failures,
        countIf(event_code=256) AS queries,countIf(event_code IN (257,258)) AS responses
        FROM {RELATION} WHERE {where}''',parameters=params,settings=QUERY_SETTINGS).named_results())[0]
    # One bounded scan supplies the investigation sidebar. All facets use the
    # same filters and time anchor as the result table, independent of its page.
    facets=list(client.query(f'''SELECT tupleElement(facet,1) AS kind,
        tupleElement(facet,2) AS value,count() AS count,countIf(event_code=256) AS queries
        FROM {RELATION} ARRAY JOIN [
            tuple('domains',qname),
            tuple('clients',if(event_code IN (0,256,257,258),src_ip,'')),
            tuple('record_types',qtype),tuple('response_codes',response_code)] AS facet
        WHERE {where} AND tupleElement(facet,2)!=''
        GROUP BY kind,value ORDER BY kind,count DESC,value LIMIT 8 BY kind''',
        parameters=params,settings=QUERY_SETTINGS).named_results())
    grouped={key:[] for key in ('domains','clients','record_types','response_codes')}
    for row in facets:
        grouped[row['kind']].append({'value':row['value'],'count':row['count'],'queries':row['queries']})
    top=[{'qname':r['value'],'count':r['count'],'queries':r['queries']} for r in grouped['domains']]
    return {'summary':summary,'top_domains':top,'top_clients':grouped['clients'],
            'record_types':grouped['record_types'],'response_codes':grouped['response_codes']}

@router.get('/api/dns/stats',dependencies=[Depends(require_min_role('ANALYST'))])
async def stats(request: Request):
    try:return await run_in_threadpool(execute_stats,dict(request.query_params))
    except HTTPException:raise
    except Exception:raise HTTPException(503,'DNS statistics are temporarily unavailable')
