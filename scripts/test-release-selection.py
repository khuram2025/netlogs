import unittest
from types import SimpleNamespace
from zenshield_release_selection import newest_compatible_release

def release(version,minimum):return SimpleNamespace(version=version,min_version=minimum)

class Bridges(unittest.TestCase):
 def setUp(self):self.releases=[release('0.4.4','0.4.3'),release('0.4.3','0.2.0')]
 def test_old_client_keeps_bridge(self):self.assertEqual(newest_compatible_release(self.releases,'0.3.4').version,'0.4.3')
 def test_baseline_receives_latest(self):self.assertEqual(newest_compatible_release(self.releases,'0.4.3').version,'0.4.4')
 def test_current_has_no_offer(self):self.assertIsNone(newest_compatible_release(self.releases,'0.4.4'))
 def test_invalid_current_rejected(self):self.assertIsNone(newest_compatible_release(self.releases,'unknown'))
 def test_numeric_order(self):self.assertEqual(newest_compatible_release([release('0.4.9','0.4.3'),release('0.4.10','0.4.3')],'0.4.3').version,'0.4.10')
 def test_invalid_minimum_rejected(self):self.assertIsNone(newest_compatible_release([release('0.4.4','bad')],'0.4.3'))

if __name__=='__main__':unittest.main(verbosity=2)
