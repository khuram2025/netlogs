"""Regression for the signed legacy-updater bootstrap and safe diagnostics."""
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('support',Path(__file__).with_name('support-upgrade-0.4.3.py'))
support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)


class SupportDiagnostics(unittest.TestCase):
    def test_clickhouse_failure_identified_without_log_values(self):
        raw='File "/app/db/002_policy_analytics_aggregates.py", line 180\nCode: 241 (MEMORY_LIMIT_EXCEEDED) password=PRIVATE_VALUE (CUSTOMER_SECRET)'
        result=support.diagnostic_codes(raw)
        self.assertEqual(result['categories'],['memory_exhausted'])
        self.assertEqual(result['source_locations'],['002_policy_analytics_aggregates.py:180'])
        self.assertEqual(result['database_error_codes'],[241])
        self.assertEqual(result['database_error_names'],['MEMORY_LIMIT_EXCEEDED'])
        self.assertNotIn('PRIVATE',str(result));self.assertNotIn('CUSTOMER',str(result))

    def test_quiesced_scan_is_distinguished(self):
        self.assertEqual(support.operation(('du','-sb','/private/path')),'quiesced backup sizing')

    def test_report_does_not_return_customer_paths(self):
        result=support.diagnostic_codes('/private/customer: Permission denied')
        self.assertEqual(result['categories'],['permission_denied'])
        self.assertEqual(result['source_locations'],[])
        self.assertNotIn('customer',str(result))


if __name__=='__main__':unittest.main(verbosity=2)
