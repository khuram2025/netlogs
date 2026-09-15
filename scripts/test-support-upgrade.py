import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('support',Path(__file__).with_name('support-upgrade-0.4.2.py'))
support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)

class SupportDiagnostics(unittest.TestCase):
    def test_static_codes_do_not_include_log_values(self):
        output='password=SECRET_EXAMPLE user@example.invalid /customer/file.txt PermissionError: [Errno 13] Permission denied'
        self.assertEqual(support.diagnostic_codes(output),{'categories':['permission_denied'],'source_locations':[]})
    def test_known_source_location_retained_without_exception_message(self):
        output='File "/app/fastapi_app/models/credential.py", line 53, in rotate_legacy_credentials\nInvalidToken: SECRET_EXAMPLE'
        self.assertEqual(support.diagnostic_codes(output),{'categories':['encryption_key_mismatch'],'source_locations':['credential.py:53']})
    def test_steps_disambiguate_compose_failures(self):
        self.assertEqual(support.operation(('docker','compose','up','-d','postgres','clickhouse','redis')),'dependency startup')
        self.assertEqual(support.operation(('docker','compose','up','-d','--wait')),'application service startup')
        self.assertEqual(support.operation(('docker','compose','run','--rm','web','SECRET_EXAMPLE')),'candidate schema verification')

if __name__=='__main__':unittest.main()
