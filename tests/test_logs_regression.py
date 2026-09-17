"""Run in the deployed app's Python environment, using unittest only."""
import asyncio
import inspect
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timezone
from types import SimpleNamespace
from unittest.mock import patch

from fastapi_app.api import views
from fastapi_app.db.clickhouse import ClickHouseClient as CH


def defaults(fn, **values):
    out = {k: getattr(p.default, 'default', p.default)
           for k, p in inspect.signature(fn).parameters.items()}
    out.update(values)
    return out


class LogRegressionTests(unittest.TestCase):
    def setUp(self):
        CH._device_lists = {}

    def test_device_discovery_is_single_flight_and_formats_vdoms(self):
        fake = SimpleNamespace(result_rows=[('10.0.0.1', 'a_b'), ('10.0.0.2', '')])
        with patch.object(CH, 'get_client') as client:
            client.return_value.query.return_value = fake
            with ThreadPoolExecutor(8) as pool:
                result = list(pool.map(lambda _: CH.get_distinct_devices(), range(8)))
            self.assertTrue(all(r == ['10.0.0.1_a_b', '10.0.0.2'] for r in result))
            self.assertEqual(client.return_value.query.call_count, 1)

    def test_empty_device_lists_are_cached_and_windows_separate(self):
        with patch.object(CH, 'get_client') as client:
            client.return_value.query.return_value.result_rows = []
            CH.get_distinct_devices(1)
            CH.get_distinct_devices(1)
            CH.get_distinct_devices(24)
            self.assertEqual(client.return_value.query.call_count, 2)

    def test_timezone_offsets_and_display_local_match(self):
        with patch('fastapi_app.core.app_settings.get_display_timezone', return_value='Asia/Riyadh'):
            a = views._explorer_time_window('custom', '2026-09-17T12:00', '2026-09-17T13:00')
            b = views._explorer_time_window('custom', '2026-09-17T09:00Z', '2026-09-17T10:00Z')
            self.assertEqual(a, b)
            self.assertEqual(a[0].tzinfo, timezone.utc)

    def test_invalid_dates_and_ranges_fail_explicitly(self):
        for args in [('custom', 'bad', None), ('custom', '2026-09-18', '2026-09-17'),
                     ('0m', None, None), ('-1h', None, None), ('custom', None, None)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                views._explorer_time_window(*args)

    def test_all_relative_time_presets(self):
        for preset in ['1m', '5m', '1h', '24h', '7d', '30d']:
            start, end = views._explorer_time_window(preset, None, None)
            self.assertIsNotNone(start)
            self.assertIsNotNone(end)
            self.assertGreater(end, start)
            self.assertEqual(start.tzinfo, timezone.utc)

    def test_device_failure_does_not_discard_logs(self):
        with patch.object(CH, 'get_distinct_devices', side_effect=RuntimeError('unavailable')), \
             patch.object(CH, 'search_logs', return_value=[{'srcip': '10.0.0.1'}]), \
             patch.object(CH, 'count_logs', return_value=1), \
             patch.object(views, '_render', side_effect=lambda name, request, ctx: ctx):
            ctx = asyncio.run(views.log_list(**defaults(views.log_list, request=None, db=None, device='10.0.0.1')))
            self.assertEqual(len(ctx['logs']), 1)
            self.assertEqual(ctx['devices'], ['10.0.0.1'])
            self.assertIsNone(ctx['nql_error'])

    def test_query_failure_is_visible_without_nql_and_preserves_filters(self):
        with patch.object(CH, 'get_distinct_devices', return_value=[]), \
             patch.object(CH, 'search_logs', side_effect=RuntimeError('memory limit exceeded')), \
             patch.object(CH, 'count_logs', return_value=-1), \
             patch.object(views, '_render', side_effect=lambda name, request, ctx: ctx):
            ctx = asyncio.run(views.log_list(**defaults(views.log_list, request=None, db=None, srcip='10.0.0.1', srcip_not='1')))
            self.assertIn('memory', ctx['nql_error'])
            self.assertEqual(ctx['current_srcip'], '10.0.0.1')
            self.assertTrue(ctx['current_srcip_not'])

    def test_facets_forward_every_toolbar_filter(self):
        filters = dict(srcip='10.0.0.0/8', dstip='8.8.8.8', srcport='123', dstport='443',
                       protocol='TCP', srcip_not='1', dstip_not='1', srcport_not='1', dstport_not='1',
                       policyname='Example Policy', src_zone='trust', dst_zone='untrust',
                       session_end_reason='tcp-fin', threat_id='1234', action='deny')
        with patch.object(CH, 'get_field_facets', return_value={'values': []}) as call:
            asyncio.run(views.logs_facets(**defaults(views.logs_facets, field='action', **filters)))
            q = call.call_args.kwargs['query_text']
            for term in ['-srcip:', '-dstip:', '-srcport:', '-dstport:', 'proto:TCP',
                         'policyname:"Example Policy"', 'src_zone:trust', 'dst_zone:untrust',
                         'session_end_reason:tcp-fin', 'threat_id:1234', 'deny|drop|block|reject']:
                self.assertIn(term, q)

    def test_invalid_range_api_is_a_validation_error(self):
        response = asyncio.run(views.logs_facets(**defaults(views.logs_facets, field='action', time_range='0m')))
        self.assertEqual(response.status_code, 400)
        response = asyncio.run(views.logs_export(**defaults(views.logs_export, start='bad')))
        self.assertEqual(response.status_code, 400)

    def test_unknown_count_does_not_claim_one_hundred_thousand(self):
        with patch.object(CH, 'get_distinct_devices', return_value=[]), \
             patch.object(CH, 'search_logs', return_value=[{'srcip': '10.0.0.1'}] * 10), \
             patch.object(CH, 'count_logs', return_value=-2), \
             patch.object(views, '_render', side_effect=lambda name, request, ctx: ctx):
            ctx = asyncio.run(views.log_list(**defaults(views.log_list, request=None, db=None, per_page='10')))
            self.assertEqual(ctx['total_display'], 'Count unavailable')
            self.assertTrue(ctx['has_next'])

    def test_device_catalog_query_never_scans_raw_logs(self):
        with patch.object(CH, 'get_client') as client:
            client.return_value.query.return_value.result_rows = []
            CH.get_distinct_devices()
            sql = client.return_value.query.call_args.args[0]
            self.assertIn('FROM log_device_catalog', sql)
            self.assertNotIn('FROM syslogs', sql)

    def test_vendor_facet_action_is_not_silently_ignored(self):
        with patch.object(CH, 'get_distinct_devices', return_value=[]), \
             patch.object(CH, 'search_logs', return_value=[]) as search, \
             patch.object(CH, 'count_logs', return_value=0), \
             patch.object(views, '_render', side_effect=lambda name, request, ctx: ctx):
            asyncio.run(views.log_list(**defaults(views.log_list, request=None, db=None, action='drop')))
            self.assertEqual(search.call_args.kwargs['query_text'], 'action:drop')


if __name__ == '__main__':
    unittest.main()
