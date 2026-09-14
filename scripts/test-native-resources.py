"""Regression tests for resource warnings, without installing onto the test host.

Optional argument: extracted bootstrap directory, to test the published payload.
"""
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
SOURCE=Path(sys.argv.pop(1))/'native_install.py' if len(sys.argv)>1 else ROOT/'installer/native_install.py'
if sys.platform=='win32':
    sys.modules.setdefault('fcntl',types.SimpleNamespace(flock=Mock(),LOCK_EX=2,LOCK_NB=4))
    sys.modules.setdefault('pwd',types.SimpleNamespace(getpwnam=Mock(side_effect=KeyError)))
spec=importlib.util.spec_from_file_location('native_install',SOURCE)
installer=importlib.util.module_from_spec(spec)
original_read=Path.read_text
with patch.object(Path,'read_text',lambda p,*a,**kw: '{"version":"0.3.1"}' if p.name=='release.json' else original_read(p,*a,**kw)):
    spec.loader.exec_module(installer)

class ReachedPackageInstall(Exception):pass

class ResourcePolicyTests(unittest.TestCase):
    def setUp(self):
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        temp=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.object(installer,'BASE',temp/'appliance'))
        self.stack.enter_context(patch.object(installer,'STATE',temp/'state'))
        self.cpus=self.stack.enter_context(patch.object(installer.os,'cpu_count',return_value=4))
        self.disk=self.stack.enter_context(patch.object(installer.shutil,'disk_usage',return_value=types.SimpleNamespace(total=100*1024**3,free=40*1024**3)))
        self.mem='MemTotal: 16777216 kB\n'
        self.os_release='ID=ubuntu\nVERSION_ID="24.04"\n'
        self.stack.enter_context(patch.object(Path,'read_text',lambda p,*a,**kw:self.read_text(p,*a,**kw)))
        exists=Path.exists
        self.stack.enter_context(patch.object(Path,'exists',lambda p:False if p.as_posix()=='/.dockerenv' else exists(p)))
        self.arch=self.stack.enter_context(patch.object(installer.platform,'machine',return_value='x86_64'))
        self.stack.enter_context(patch.object(installer.shutil,'which',return_value=None))
        self.stack.enter_context(patch('pwd.getpwnam',side_effect=KeyError))
        self.socket=self.stack.enter_context(patch.object(installer.socket,'socket'))
        self.log=io.StringIO();self.stack.enter_context(contextlib.redirect_stdout(self.log))

    def read_text(self,p,*args,**kwargs):
        if p.as_posix()=='/etc/os-release':return self.os_release
        if p.as_posix()=='/proc/1/comm':return 'systemd\n'
        if p.as_posix()=='/proc/meminfo':return self.mem
        return original_read(p,*args,**kwargs)

    def low_resources(self):
        self.cpus.return_value=1;self.mem='MemTotal: 524288 kB\n'
        self.disk.return_value=types.SimpleNamespace(total=10*1024**3,free=1024**3)

    def test_recommended_host_passes_without_warning(self):
        self.assertFalse(installer.preflight());self.assertNotIn('WARNING:',self.log.getvalue())

    def test_cpu_warning_does_not_reject(self):
        self.cpus.return_value=1;self.assertFalse(installer.preflight())
        self.assertIn('1 logical CPU(s)',self.log.getvalue())

    def test_memory_warning_does_not_reject(self):
        self.mem='MemTotal: 524288 kB\n';self.assertFalse(installer.preflight())
        self.assertIn('0.5 GiB RAM',self.log.getvalue())

    def test_small_disk_warning_does_not_reject(self):
        self.disk.return_value=types.SimpleNamespace(total=10*1024**3,free=8*1024**3)
        self.assertFalse(installer.preflight());self.assertIn('10.0 GiB total',self.log.getvalue())

    def test_zero_free_space_is_advisory_at_preflight(self):
        self.disk.return_value=types.SimpleNamespace(total=100*1024**3,free=0)
        self.assertFalse(installer.preflight());self.assertIn('0.0 GiB free',self.log.getvalue())

    def test_all_low_resources_continue_into_installation(self):
        self.low_resources()
        with patch.object(installer,'run',side_effect=ReachedPackageInstall) as run:
            with self.assertRaises(ReachedPackageInstall):installer.install()
        self.assertEqual(run.call_args.args,('apt-get','update'))
        self.assertEqual(json.loads((installer.STATE/'state.json').read_text())['version'],'0.3.1')
        self.assertEqual(self.log.getvalue().count('WARNING:'),3)
        self.assertIn('Continuing automatically',self.log.getvalue())

    def test_check_mode_succeeds_with_low_resources_without_install(self):
        self.low_resources()
        with patch.object(sys,'argv',['native_install.py','--check']),patch.object(installer.os,'geteuid',return_value=0,create=True),patch.object(installer,'run') as run:
            installer.main();run.assert_not_called()
        self.assertFalse(installer.STATE.exists())

    def test_resume_keeps_existing_state_with_low_resources(self):
        self.low_resources();installer.STATE.mkdir();installer.BASE.mkdir()
        (installer.STATE/'state.json').write_text('{"retained":true}')
        self.assertTrue(installer.preflight())
        self.assertEqual((installer.STATE/'state.json').read_text(),'{"retained":true}')

    def test_unavailable_resource_inventory_is_advisory(self):
        self.cpus.return_value=None;self.mem='';self.disk.side_effect=OSError('unavailable')
        self.assertFalse(installer.preflight());self.assertEqual(self.log.getvalue().count('WARNING:'),3)

    def test_unsupported_os_still_rejected(self):
        self.os_release='ID=ubuntu\nVERSION_ID="22.04"\n'
        with self.assertRaisesRegex(RuntimeError,'24.04'):installer.preflight()

    def test_unsupported_architecture_still_rejected(self):
        self.arch.return_value='aarch64'
        with self.assertRaisesRegex(RuntimeError,'x86_64'):installer.preflight()

    def test_existing_unmanaged_appliance_still_protected(self):
        self.low_resources();installer.BASE.mkdir()
        with self.assertRaisesRegex(RuntimeError,'Existing appliance'):installer.preflight()

    def test_occupied_port_still_rejected(self):
        self.low_resources();self.socket.return_value.__enter__.return_value.bind.side_effect=OSError('in use')
        with self.assertRaisesRegex(RuntimeError,'port 80'):installer.preflight()

    def test_paused_setup_receives_updated_wizard_without_reinstall(self):
        installer.STATE.mkdir();installer.BASE.mkdir()
        (installer.STATE/'state.json').write_text('{}');(installer.STATE/'complete').write_text('0.3.1')
        (installer.BASE/'.version').write_text('0.3.1')
        (installer.BASE/'.env').write_text('retained test data')
        (installer.BASE/'native_setup.py').write_text('old wizard')
        original_exists=Path.exists
        with patch.object(Path,'exists',lambda p:False if p.as_posix()=='/var/lib/zenshield/setup-complete' else original_exists(p)),patch.object(installer,'console_access'),patch.object(installer,'run') as run:
            installer.install();run.assert_not_called()
        self.assertEqual((installer.BASE/'native_setup.py').read_bytes(),(installer.HERE/'native_setup.py').read_bytes())
        self.assertEqual((installer.BASE/'.env').read_text(),'retained test data')

    def test_configured_host_does_not_replace_setup(self):
        installer.STATE.mkdir();installer.BASE.mkdir()
        (installer.STATE/'state.json').write_text('{}');(installer.STATE/'complete').write_text('0.3.1')
        (installer.BASE/'.version').write_text('0.3.1')
        (installer.BASE/'native_setup.py').write_text('configured wizard')
        original_exists=Path.exists
        with patch.object(Path,'exists',lambda p:True if p.as_posix()=='/var/lib/zenshield/setup-complete' else original_exists(p)),patch.object(installer,'console_access'),patch.object(installer,'run') as run:
            installer.install();run.assert_not_called()
        self.assertEqual((installer.BASE/'native_setup.py').read_text(),'configured wizard')

    def test_older_uninitialized_install_refreshes_application(self):
        installer.STATE.mkdir();installer.BASE.mkdir()
        (installer.STATE/'state.json').write_text('{}');(installer.STATE/'complete').write_text('0.2.9')
        (installer.BASE/'.version').write_text('0.2.9')
        original_exists=Path.exists
        with patch.object(Path,'exists',lambda p:False if p.as_posix()=='/var/lib/zensheild/initialized' else original_exists(p)),patch.object(installer,'run',side_effect=ReachedPackageInstall) as run:
            with self.assertRaises(ReachedPackageInstall):installer.install()
        self.assertEqual(run.call_args.args,('apt-get','update'))

    def test_older_initialized_install_requires_updater(self):
        installer.STATE.mkdir();installer.BASE.mkdir()
        (installer.STATE/'state.json').write_text('{}');(installer.STATE/'complete').write_text('0.2.9')
        (installer.BASE/'.version').write_text('0.2.9')
        original_exists=Path.exists
        with patch.object(Path,'exists',lambda p:True if p.as_posix()=='/var/lib/zensheild/initialized' else original_exists(p)),patch.object(installer,'run') as run:
            with self.assertRaisesRegex(RuntimeError,'System > Updates'):installer.install()
            run.assert_not_called()

class DownloadRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.path=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))/'release.zup'
        self.payload=b'verified release test bytes';self.digest=hashlib.sha256(self.payload).hexdigest()
        self.urlopen=self.stack.enter_context(patch.object(installer.urllib.request,'urlopen'))
        self.sleep=self.stack.enter_context(patch.object(installer.time,'sleep'))
        self.log=io.StringIO();self.stack.enter_context(contextlib.redirect_stdout(self.log))

    def response(self,payload=None,url='https://zentryc.com/release.zup'):
        response=io.BytesIO(self.payload if payload is None else payload);response.url=url
        return response

    def dns_error(self):
        return installer.urllib.error.URLError(installer.socket.gaierror(installer.socket.EAI_AGAIN,'Temporary failure in name resolution'))

    def download(self):installer.download('https://zentryc.com/release.zup',self.path,self.digest)

    def test_dns_failure_after_package_restart_recovers(self):
        self.urlopen.side_effect=[self.dns_error(),self.dns_error(),self.response()]
        self.download();self.assertEqual(self.path.read_bytes(),self.payload)
        self.assertEqual([c.args for c in self.sleep.call_args_list],[(5,),(10,)])
        self.assertIn('Temporary DNS resolution failure',self.log.getvalue())

    def test_interrupted_body_restarts_without_partial_bytes(self):
        response=self.response();response.read=Mock(side_effect=[b'partial previous attempt',ConnectionResetError()])
        self.urlopen.side_effect=[response,self.response()]
        self.download();self.assertEqual(self.path.read_bytes(),self.payload)
        self.assertFalse(self.path.with_suffix('.part').exists())

    def test_persistent_dns_is_bounded_and_actionable(self):
        self.urlopen.side_effect=self.dns_error()
        with self.assertRaisesRegex(RuntimeError,'getent hosts zentryc.com'):self.download()
        self.assertEqual(self.urlopen.call_count,6);self.assertEqual(self.sleep.call_count,5)
        self.assertFalse(self.path.exists());self.assertFalse(self.path.with_suffix('.part').exists())

    def test_transient_http_recovers(self):
        self.urlopen.side_effect=[installer.urllib.error.HTTPError('https://zentryc.com',503,'unavailable',{},None),self.response()]
        self.download();self.assertEqual(self.path.read_bytes(),self.payload)

    def test_timeout_recovers(self):
        self.urlopen.side_effect=[installer.urllib.error.URLError(TimeoutError()),self.response()]
        self.download();self.assertEqual(self.path.read_bytes(),self.payload)

    def test_http_access_denied_not_retried(self):
        self.urlopen.side_effect=installer.urllib.error.HTTPError('https://zentryc.com',403,'forbidden',{},None)
        with self.assertRaises(installer.urllib.error.HTTPError):self.download()
        self.sleep.assert_not_called()

    def test_tls_certificate_error_not_retried(self):
        self.urlopen.side_effect=installer.urllib.error.URLError(installer.ssl.SSLCertVerificationError('invalid certificate'))
        with self.assertRaises(installer.urllib.error.URLError):self.download()
        self.sleep.assert_not_called()

    def test_checksum_mismatch_not_retried_or_installed(self):
        self.urlopen.return_value=self.response(b'tampered')
        with self.assertRaisesRegex(RuntimeError,'SHA256 mismatch'):self.download()
        self.sleep.assert_not_called();self.assertFalse(self.path.exists());self.assertFalse(self.path.with_suffix('.part').exists())

    def test_unapproved_redirect_not_retried(self):
        self.urlopen.return_value=self.response(url='https://example.com/release.zup')
        with self.assertRaisesRegex(RuntimeError,'Unapproved release redirect'):self.download()
        self.sleep.assert_not_called();self.assertFalse(self.path.exists())

    def test_disk_full_not_retried_as_network_error(self):
        self.urlopen.return_value=self.response()
        with patch.object(Path,'open',side_effect=OSError(errno.ENOSPC,'disk full')):
            with self.assertRaises(OSError):self.download()
        self.sleep.assert_not_called()

    def test_verified_cached_download_survives_dns_outage(self):
        self.path.write_bytes(self.payload);self.urlopen.side_effect=self.dns_error()
        self.download();self.urlopen.assert_not_called()
        self.assertEqual(self.path.read_bytes(),self.payload)

    def test_existing_file_retained_when_retry_exhausted(self):
        self.path.write_bytes(b'existing file');self.urlopen.side_effect=self.dns_error()
        with self.assertRaises(RuntimeError):self.download()
        self.assertEqual(self.path.read_bytes(),b'existing file')

    def test_full_analytics_release_above_old_500_mib_limit(self):
        block=b'x'*(1024**2)
        response=self.response();response.read=Mock(side_effect=[block]*537+[b''])
        self.urlopen.return_value=response
        digest=hashlib.sha256()
        for _ in range(537):digest.update(block)
        installer.download('https://zentryc.com/release.zup',self.path,digest.hexdigest())
        self.assertEqual(self.path.stat().st_size,537*1024**2)

    def test_oversized_release_is_rejected_and_partial_removed(self):
        # Simulate an oversized chunk without allocating a multi-GiB fixture.
        class Oversized(bytes):
            def __len__(self):return 2*1024**3+1
        response=self.response();response.read=Mock(return_value=Oversized(b'x'))
        self.urlopen.return_value=response
        with self.assertRaisesRegex(RuntimeError,'2 GiB'):self.download()
        self.assertFalse(self.path.exists());self.assertFalse(self.path.with_suffix('.part').exists())

if __name__=='__main__':unittest.main(verbosity=2)
