import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile
from .common import *
from . import transport,package,transaction

def main():
    parser=argparse.ArgumentParser(description='ZenShield signed appliance updater')
    parser.add_argument('mode',choices=['scheduled','check','recover','register','apply-file','provision'])
    parser.add_argument('--file');parser.add_argument('--sha256');parser.add_argument('--release-id')
    args=parser.parse_args();os.umask(0o077);STATE.mkdir(parents=True,exist_ok=True)
    with locked(STATE/'update.lock'),locked('/var/lib/zenshield/operation.lock'):
        c=config()
        if args.mode=='scheduled' and not(c['contract_confirmed'] and c['product_id'] and c['api_key'] and PUBLIC_KEY.exists()):
            phase('not_configured',message='Release service setup is incomplete')
            return
        if args.mode=='provision':
            if not args.file:raise ValueError('Provide a reviewed platform configuration file')
            supplied=read(args.file);candidate={**DEFAULT,**supplied}
            transport.ready(candidate,False)
            for value in candidate['download_origins']:transport.origin(value)
            for value in candidate['routes'].values():
                if not value.startswith('/api/'):raise ValueError('Expected explicit API routes')
            write(CONFIG,candidate);print('ZenShield OTA configuration provisioned');return
        if args.mode=='register':
            import getpass
            transport.register(getpass.getpass('ZenShield registration token: '));print('Appliance registered');return
        if args.mode=='recover':
            recovered=transaction.recover_incomplete(c['health_timeout'])
            if recovered:
                import uuid
                outcome='success' if recovered['phase']=='committed' else 'failed'
                event=str(uuid.uuid5(uuid.NAMESPACE_URL,recovered['backup']+'/recovered'))
                transport.queue_report({'release_id':recovered['release_id'],'version':recovered['to_version']},outcome,recovered['from_version'],error='' if outcome=='success' else 'Interrupted installation recovered',recovery=recovered.get('recovery'),event=event)
                write(STATE/'history'/(event+'.json'),{**recovered,'status':outcome,'finished_at':now()})
                recovered['reported']=True;transaction.save_tx(recovered)
                phase(outcome,message='Interrupted transaction finalized',recovery=recovered.get('recovery'))
            return
        pending=read(STATE/'transaction.json')
        if pending and pending['phase'] not in ('committed','rolled_back','aborted'):
            raise ValueError('An incomplete transaction requires recovery before another update')
        transport.flush(c)
        selected=None;old=current_version();tx=None
        try:
            phase('checking')
            if args.mode=='apply-file':
                # Expert/offline installation still needs expected product, pinned key, and complete hash.
                if not args.file or not args.sha256 or not args.release_id:raise ValueError('Offline apply requires file, SHA256 and immutable release ID')
                if package.digest(args.file)!=args.sha256:raise ValueError('Offline archive hash mismatch')
                manifest=package.verify(args.file,PUBLIC_KEY,c['product_id'],old,max_age=c['max_manifest_age_days'])
                selected={k:manifest[k] for k in ('product_id','version','min_version','arch')}
                selected.update(release_id=args.release_id,package_sha256=args.sha256)
            else:
                selected=transport.offer(c)
                request=read(STATE/'request.json');(STATE/'request.json').unlink(missing_ok=True)
                if args.mode=='check' or selected is None:
                    phase('available' if selected else 'up_to_date');return
                manual=request and request.get('release_id')==selected['release_id'] and request.get('expires',0)>__import__('time').time()
                if request and not manual:raise ValueError('Requested release changed or confirmation expired')
                if not manual and not(c['auto_update'] and window_open(c)):
                    phase('available',message='Automatic installation is disabled or outside the UTC maintenance window');return
            if platform.machine()!='x86_64' or 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text():raise ValueError('Unsupported appliance OS or architecture')
            if not PUBLIC_KEY.exists():raise ValueError('ZenShield release verification key is not provisioned')
            phase('downloading',release_id=selected['release_id']);transport.queue_report(selected,'downloading',old)
            staging=Path(tempfile.mkdtemp(prefix='update-',dir=STATE))
            try:
                archive=Path(args.file) if args.mode=='apply-file' else staging/'package.zup'
                if args.mode!='apply-file':transport.download(c,selected,archive)
                phase('verifying',release_id=selected['release_id'])
                manifest=package.verify(archive,PUBLIC_KEY,c['product_id'],old,selected,staging/'verified',c['max_manifest_age_days'])
                transport.queue_report(selected,'applying',old)
                tx=transaction.apply(staging/'verified',manifest,selected,c['health_timeout'])
            finally:shutil.rmtree(staging)
            event=transport.queue_report(selected,'success',old)
            write(STATE/'history'/(event+'.json'),{**tx,'status':'success','finished_at':now()})
            tx['reported']=True;transaction.save_tx(tx)
            phase('success',version=current_version(),release_id=selected['release_id'])
        except Exception as exc:
            tx=read(STATE/'transaction.json',{})
            if not selected or tx.get('release_id')!=selected['release_id']:tx={}
            status='recovery_failed' if tx.get('phase')=='recovery_failed' else 'failed'
            message=str(exc) if isinstance(exc,(ValueError,RuntimeError)) else type(exc).__name__
            phase(status,message=message)
            if selected:
                event=transport.queue_report(selected,'failed',old,error=message,recovery=tx.get('recovery'))
                write(STATE/'history'/(event+'.json'),{'status':'failed','release_id':selected['release_id'],'from_version':old,'to_version':selected['version'],'recovery':tx.get('recovery'),'error':message,'finished_at':now()})
                if tx and tx.get('phase') in ('rolled_back','aborted'):
                    tx['reported']=True;transaction.save_tx(tx)
            print(message,file=sys.stderr)
            raise SystemExit(1)
        finally:transport.flush(c)

if __name__=='__main__':main()
