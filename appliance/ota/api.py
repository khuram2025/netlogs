import time
from datetime import time as clocktime
from .common import *

def status():
    c=config()
    history=[read(p) for p in sorted((STATE/'history').glob('*.json'),key=lambda p:p.stat().st_mtime)[-20:]]
    offer=read(STATE/'offer.json')
    public_offer={k:offer[k] for k in ('release_id','version','min_version','arch','severity','changelog') if k in offer} if offer else None
    return {'version':current_version(),'portal_url':c['portal_url'],'provisioned':bool(c['contract_confirmed'] and c['product_id']),
       'registered':bool(c['appliance_id'] and c['api_key']),'key_installed':PUBLIC_KEY.exists(),
       'product_id':c['product_id'],'auto_update':c['auto_update'],'window_start':c['window_start'],'window_end':c['window_end'],
       'status':read(STATE/'status.json',{'phase':'not_configured'}),'offer':public_offer,'history':history,
       'pending_reports':len(list((STATE/'outbox').glob('*.json')))}

def dispatch(operation,body):
    if operation.startswith('licences.'):
        from .transport import licence_status,sync_licence
        if operation=='licences.status':return licence_status()
        if operation=='licences.refresh':return sync_licence()
        if operation=='licences.claim':
            code=body.get('registration_code','')
            if not isinstance(code,str) or not 1<=len(code)<=64:raise ValueError('Enter a valid subscription registration code')
            return sync_licence(code)
        raise ValueError('Unknown licence operation')
    if operation=='updates.status':return status()
    if operation=='updates.policy':
        with locked(STATE/'update.lock'):
            c=config()
            if not isinstance(body.get('auto_update'),bool):raise ValueError('Choose an automatic update policy')
            for field in ('window_start','window_end'):
                clocktime.fromisoformat(body[field])
                if len(body[field])!=5:raise ValueError('Use HH:MM in UTC')
            if body['window_start']==body['window_end']:raise ValueError('Maintenance window must have a nonzero duration')
            c.update({k:body[k] for k in ('auto_update','window_start','window_end')});write(CONFIG,c)
        return {'message':'Update policy saved (maintenance times are UTC)'}
    if operation=='updates.register':
        from .transport import register
        with locked(STATE/'update.lock'):register(body.get('token',''))
        return {'message':'ZenShield appliance registered'}
    if operation in ('updates.check','updates.apply'):
        with locked(STATE/'update.lock'):
            from .transport import ready
            c=config();ready(c)
            if operation=='updates.apply':
                offer=read(STATE/'offer.json')
                if not offer or body.get('release_id')!=offer['release_id']:raise ValueError('The offered release changed; check for updates again')
                confirmed=body.get('confirmed') is True and body.get('version')==offer['version']
                if not confirmed and body.get('confirmation')!='INSTALL '+offer['version']:raise ValueError('Confirm installation of the currently offered version')
                write(STATE/'request.json',{'release_id':offer['release_id'],'expires':time.time()+300})
            unit='zenshield-update-check' if operation=='updates.check' else 'zenshield-updater'
        run('systemctl','start','--no-block',unit)
        return {'message':'Update check started' if operation=='updates.check' else 'Update installation queued'}
    raise ValueError('Unknown update operation')
