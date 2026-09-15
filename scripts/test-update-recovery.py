"""Exercise real backup/restore copies with a simulated Docker startup failure."""
import contextlib,io,json,shutil,subprocess,sys,tarfile,tempfile,unittest,uuid
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'appliance'))
from ota import api,transaction as tx,common,runner
from ota.common import write,read

class RetryAfterRecovery(unittest.TestCase):
    def test_failed_attempt_restores_data_and_same_release_can_retry(self):
        if not shutil.which('rsync'):self.skipTest('Linux rsync required')
        with tempfile.TemporaryDirectory() as tmp,contextlib.ExitStack() as stack:
            root=Path(tmp);base=root/'base';state=root/'state';stage=root/'stage'
            for p in (base,state,stage/'images',stage/'code/control'):p.mkdir(parents=True)
            (base/'.version').write_text('0.3.4\n');(base/'.env').write_text('TEST_FIXTURE=true\n')
            data=root/'datastore';data.mkdir();(data/'events').write_text('preserved event')
            host=root/'agent.py';host.write_text('previous host code')
            (stage/'code/control/agent.py').write_text('candidate host code')
            (stage/'code/migrations.json').write_text('[]')
            manifest={'update_id':str(uuid.uuid4()),'version':'0.4.2','image':'zenshield:0.4.2','image_id':'sha256:'+'a'*64}
            with tarfile.open(stage/'images/application.tar','w') as t:
                raw=json.dumps([{'RepoTags':[manifest['image']]}]).encode();info=tarfile.TarInfo('manifest.json');info.size=len(raw);t.addfile(info,io.BytesIO(raw))
            fail=[True]
            def run(*args,**kwargs):
                if args[:2]==('docker','image'):return manifest['image_id']
                if args[0] in ('du','rsync'):
                    if args[0]=='rsync':
                        for value in args[-2:]:self.assertTrue(Path(value).resolve().is_relative_to(root))
                    p=subprocess.run(args,capture_output=True,text=True,check=True);return p.stdout.strip()
                return ''
            def compose(*args,**kwargs):
                if args[:2]==('run','--rm') and fail[0]:
                    (data/'events').write_text('partially migrated event')
                    fail[0]=False;raise RuntimeError('simulated Docker migration startup failure')
                return ''
            replacements={'BASE':base,'STATE':state,'HOST_FILES':{'code/control/agent.py':host},'run':run,'compose':compose,'targets':lambda:{'test':str(data)},'metrics':lambda:{'users':1,'events':1},'health':lambda timeout:{'users':1,'events':1},'current_version':lambda:(base/'.version').read_text().strip(),'maintenance':lambda *a:None,'stop':lambda *a,**k:None,'start':lambda *a,**k:None,'phase':lambda *a,**k:None}
            for name,value in replacements.items():stack.enter_context(patch.object(tx,name,value))
            offer={'release_id':str(uuid.uuid4())}
            with self.assertRaisesRegex(RuntimeError,'simulated Docker'):tx.apply(stage,manifest,offer,30)
            first=read(state/'transaction.json')
            self.assertEqual(first['phase'],'rolled_back');self.assertEqual(first['recovery'],'verified')
            self.assertEqual(first['failure_phase'],'mutating')
            self.assertEqual((data/'events').read_text(),'preserved event');self.assertEqual(host.read_text(),'previous host code')
            self.assertTrue((Path(first['backup'])/'complete.json').exists())
            second=tx.apply(stage,manifest,offer,30)
            self.assertEqual(second['phase'],'committed');self.assertNotEqual(first['backup'],second['backup'])
            self.assertTrue((Path(first['backup'])/'complete.json').exists())
            self.assertTrue((Path(second['backup'])/'complete.json').exists())
            self.assertEqual(host.read_text(),'candidate host code')
            self.assertEqual((data/'events').read_text(),'preserved event')

class FailureDetails(unittest.TestCase):
    def test_preflight_failure_does_not_inherit_previous_recovery(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(runner,'STATE',Path(tmp)):
            previous={'release_id':'same-release','attempt_id':'previous-attempt','phase':'rolled_back','recovery':'verified'}
            write(Path(tmp)/'transaction.json',previous)
            self.assertEqual(runner.attempt_transaction({'release_id':'same-release'},'new-attempt'),{})
            self.assertEqual(runner.attempt_transaction({'release_id':'same-release'},'previous-attempt'),previous)
    def test_command_and_log_secrets_never_appear_in_summary(self):
        failure=subprocess.CompletedProcess([],1,'','password=private-test-secret: no space left on device')
        detail=common.failure_summary(('docker','load','--input','/private/package.tar'),failure)
        self.assertIn('docker load failed',detail);self.assertIn('disk space exhausted',detail)
        self.assertNotIn('private-test-secret',detail);self.assertNotIn('/private/',detail)
    def test_unhealthy_service_and_oom_are_reported_without_raw_logs(self):
        inspected=[{'Name':'/zensheild-web-1','State':{'Running':False,'ExitCode':137,'OOMKilled':True,'Health':{'Status':'unhealthy'}}}]
        responses=[subprocess.CompletedProcess([],0,json.dumps(inspected),''),subprocess.CompletedProcess([],0,'secret-password-here UndefinedColumn','')]
        with patch.object(common.subprocess,'run',side_effect=responses):
            detail=common.failure_summary(('docker','compose','-f','/private/config','up'),subprocess.CompletedProcess([],1,'',''))
        self.assertIn('web was killed',detail);self.assertIn('missing database column',detail)
        self.assertNotIn('secret-password-here',detail);self.assertNotIn('/private/config',detail)

class UpdateConfirmation(unittest.TestCase):
    def setUp(self):
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.state=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.object(api,'STATE',self.state))
        self.stack.enter_context(patch.object(api,'config',return_value={}))
        self.stack.enter_context(patch.object(api,'locked',side_effect=lambda *a:contextlib.nullcontext()))
        self.stack.enter_context(patch('ota.transport.ready'))
        self.run=self.stack.enter_context(patch.object(api,'run'))
        write(self.state/'offer.json',{'release_id':'release-A','version':'0.4.2'})
    def test_click_confirmation_queues_current_release(self):
        api.dispatch('updates.apply',{'release_id':'release-A','version':'0.4.2','confirmed':True})
        self.assertEqual(read(self.state/'request.json')['release_id'],'release-A');self.run.assert_called_once()
    def test_stale_release_rejected(self):
        with self.assertRaises(ValueError):api.dispatch('updates.apply',{'release_id':'release-B','version':'0.4.2','confirmed':True})
        self.run.assert_not_called();self.assertFalse((self.state/'request.json').exists())
    def test_stale_version_rejected(self):
        with self.assertRaises(ValueError):api.dispatch('updates.apply',{'release_id':'release-A','version':'0.4.1','confirmed':True})
        self.run.assert_not_called()
    def test_confirmation_must_be_boolean_true(self):
        for value in (False,'true',1,None):
            with self.assertRaises(ValueError):api.dispatch('updates.apply',{'release_id':'release-A','version':'0.4.2','confirmed':value})
        self.run.assert_not_called()
    def test_legacy_console_confirmation_still_supported(self):
        api.dispatch('updates.apply',{'release_id':'release-A','confirmation':'INSTALL 0.4.2'})
        self.run.assert_called_once()

if __name__=='__main__':unittest.main(verbosity=2)
