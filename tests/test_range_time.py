import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from fastapi_app.core.event_time import parse_event_time
from fastapi_app.db.clickhouse import ClickHouseClient as CH
from fastapi_app.services.nql_parser import compile_filter, NQLSyntaxError
from fastapi_app.api import views


class RangeTimeTests(unittest.TestCase):
    def test_ip_ranges_are_inclusive_native_numeric_bounds(self):
        for field in ['srcip', 'dstip', 'source_ip', 'destination_ip']:
            sql, _ = compile_filter(field+':10.10.190.12-10.10.193.13')
            self.assertIn("_v4 >= toIPv4('10.10.190.12')", sql)
            self.assertIn("_v4 <= toIPv4('10.10.193.13')", sql)
            self.assertNotIn('IPv4StringToNum', sql)

    def test_reversed_and_invalid_ranges_fail_closed(self):
        for value in ['10.10.193.13-10.10.190.12', '10.10.190.999-10.10.193.13',
                      '10.10.190.12-bad', '10.10.190.12-10.10.193.13-10.10.199.15']:
            with self.subTest(value=value), self.assertRaises(NQLSyntaxError):
                compile_filter('srcip:'+value)

    def test_lists_and_negation_keep_numeric_ranges(self):
        sql, _ = compile_filter('-srcip:10.10.190.12-10.10.193.13,10.10.199.15')
        self.assertIn('NOT', sql)
        self.assertIn(' OR ', sql)
        self.assertIn("srcip = '10.10.199.15'", sql)
        self.assertIn('srcip_v4', sql)

    def test_last_hour_is_exact_not_rounded_to_older_records(self):
        start, end = views._explorer_time_window('1h', None, None)
        self.assertEqual(end-start, timedelta(hours=1))

    def test_fortigate_nanoseconds_override_naive_local_time(self):
        ingest = datetime(2026, 9, 17, 14, 29, 25, tzinfo=timezone.utc)
        result, source = parse_event_time({'eventtime':'1789655359769432127',
            'log_datetime':'2026-09-17 17:29:20', 'tz':'+0300'}, None, 'UTC', ingest)
        self.assertEqual(result, datetime(2026,9,17,14,29,19,769432,tzinfo=timezone.utc))
        self.assertEqual(source, 'parsed_tzaware')

    def test_reported_offset_used_without_epoch(self):
        ingest = datetime(2026,9,17,14,29,25,tzinfo=timezone.utc)
        for tz in ['+0300', '+03:00']:
            result, _ = parse_event_time({'log_datetime':'2026-09-17 17:29:20','tz':tz},None,'UTC',ingest)
            self.assertEqual(result, ingest.replace(second=20))

    def test_epoch_precision_variants(self):
        ingest = datetime(2026,9,17,14,29,25,tzinfo=timezone.utc)
        for epoch in ['1789655359','1789655359000','1789655359000000','1789655359000000000']:
            result, _ = parse_event_time({'eventtime':epoch},None,'Asia/Riyadh',ingest)
            self.assertEqual(result, ingest.replace(second=19))

    def test_pa_local_time_still_uses_device_zone(self):
        ingest = datetime(2026,9,17,14,29,25,tzinfo=timezone.utc)
        result, _ = parse_event_time({'generated_time':'2026/09/17 17:29:20'},'Asia/Riyadh','UTC',ingest)
        self.assertEqual(result, ingest.replace(second=20))

    def test_bad_or_implausible_timestamp_uses_ingest(self):
        ingest = datetime(2026,9,17,14,29,25,tzinfo=timezone.utc)
        for data in [{'eventtime':'9999999999999999999'}, {'log_datetime':'bad'}, None]:
            self.assertEqual(parse_event_time(data,None,'UTC',ingest),(ingest,'fallback_ingest'))


if __name__ == '__main__':
    unittest.main()
