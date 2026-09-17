import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / 'appliance/control/ntp.py'
if not source.exists():
    source = Path('/tmp/logfix/host-agent/ntp.py')
spec = importlib.util.spec_from_file_location('host_ntp',source)
ntp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ntp)

class NtpTests(unittest.TestCase):
    def test_valid_multiple_servers_and_deduplication(self):
        self.assertEqual(ntp.validate_servers(['10.10.192.10','NTP.example.com','2001:db8::1','10.10.192.10']),
                         ['10.10.192.10','ntp.example.com','2001:db8::1'])

    def test_invalid_values_cannot_inject_configuration_or_commands(self):
        for value in ['foo\nallow all','-x','host;reboot','https://ntp.example.com','999.1.2.3','ntp.example.com:123','a..b','a'*64+'.com','']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                ntp.validate_servers([value])
        for values in ['server',None,['ntp.local']*9]:
            with self.assertRaises(ValueError):ntp.validate_servers(values)

    def test_service_active_is_not_proof_of_synchronization(self):
        def run(*args,**kwargs):
            if args[0]=='timedatectl':return 'NTPSynchronized=no\nTimezone=UTC'
            if args[0]=='systemctl':return 'active'
            if args[-1]=='tracking':return '00000000,,0,0,0,0,0,0,0,0,1,1,0,Not synchronised'
            return '^,?,10.10.192.10,0,6,0,4294967295,0,0,0'
        with patch.object(ntp,'configured',return_value=['10.10.192.10']):
            status=ntp.status(run)
        self.assertFalse(status['synchronized'])
        self.assertTrue(status['service_active'])
        self.assertIsNone(status['peers'][0]['last_sample_seconds'])
        self.assertIsNone(status['offset_seconds'])

    def test_tracking_and_peers_show_selected_source(self):
        def run(*args,**kwargs):
            if args[0]=='timedatectl':return 'NTPSynchronized=yes\nTimezone=UTC'
            if args[0]=='systemctl':return 'active'
            if args[-1]=='tracking':return '0A0AC00A,10.10.192.10,3,1789655000,0.001,0,0,0,0,0,0.02,0.03,64,Normal'
            return '^,*,10.10.192.10,2,6,377,4,0.002,0.001,0.03'
        with patch.object(ntp,'configured',return_value=[]):status=ntp.status(run)
        self.assertTrue(status['synchronized'])
        self.assertEqual(status['reference'],'10.10.192.10')
        self.assertEqual(status['peers'][0]['reach'],'377')
        self.assertEqual(status['peers'][0]['status'],'Selected')

    def test_missing_commands_mean_unknown_not_synchronized(self):
        with patch.object(ntp,'configured',return_value=[]):
            status=ntp.status(Mock(side_effect=OSError('missing')))
        self.assertIsNone(status['synchronized'])
        self.assertTrue(status['errors'])

    def test_update_and_clear_only_managed_file(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(ntp,'SOURCES',Path(directory)/'additional.sources'):
            run,record=Mock(),Mock()
            atomic=lambda p,s,m:p.write_text(s)
            ntp.update({'servers':['10.10.192.10','ntp.example.com']},run,atomic,record)
            self.assertEqual(ntp.configured(),['10.10.192.10','ntp.example.com'])
            run.assert_called_with('chronyc','reload','sources',timeout=10)
            ntp.update({'servers':[]},run,atomic,record)
            self.assertEqual(ntp.configured(),[])

    def test_failed_reload_restores_previous_configuration(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(ntp,'SOURCES',Path(directory)/'additional.sources'):
            ntp.SOURCES.write_text('server old.example.com iburst\n')
            run=Mock(side_effect=[RuntimeError('reload failed'),''])
            with self.assertRaises(RuntimeError):
                ntp.update({'servers':['new.example.com']},run,lambda p,s,m:p.write_text(s),Mock())
            self.assertEqual(ntp.configured(),['old.example.com'])

if __name__=='__main__':unittest.main()
