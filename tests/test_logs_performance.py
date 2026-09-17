import asyncio
import inspect
import re
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch
from fastapi_app.db.clickhouse import ClickHouseClient as CH
from fastapi_app.services import nql_schema
from fastapi_app.services.nql_parser import compile_filter


class PerformanceRegressionTests(unittest.TestCase):
    def test_memory_retry_is_smaller_and_shares_budget(self):
        with patch.object(CH, 'get_client') as client:
            result = object()
            client.return_value.query.side_effect = [RuntimeError('Code: 241 MEMORY_LIMIT_EXCEEDED'), result]
            query = 'SELECT 1 SETTINGS max_execution_time = 2, '+CH.EXPLORER_CACHE_SETTINGS
            self.assertIs(CH._execute_explorer_query(client.return_value, query), result)
            retry = client.return_value.query.call_args.args[0]
            self.assertIn('max_threads = 1', retry)
            self.assertIn('max_block_size = 2048', retry)
            self.assertLessEqual(float(re.search(r'max_execution_time = ([\d.]+)', retry)[1]), 2)
            client.return_value.query.reset_mock(side_effect=True)
            client.return_value.query.side_effect = ValueError('invalid syntax')
            with self.assertRaises(ValueError):
                CH._execute_explorer_query(client.return_value, query)
            client.return_value.query.assert_called_once()

    def test_compound_index_only_uses_mandatory_positive_terms(self):
        q = 'srcip:172.20.30.46 action:deny|drop scope:internet'
        hints = CH._scoped_ip_index_hint(q, ['192.168.47.1_Campus'])
        self.assertEqual(len(hints), 1)
        self.assertIn('srcip, action, dst_is_public, vdom', hints[0])
        self.assertIn("'Campus'", hints[0])
        self.assertIn('toUInt8(1)', hints[0])
        for query in ['('+q+') OR srcip:1.2.3.4',
                      '-srcip:172.20.30.46 action:deny scope:internet',
                      'srcip:172.20.30.0/24 action:deny scope:internet',
                      'srcip:172.20.30.46 (action:deny OR action:drop) scope:internet']:
            self.assertEqual(CH._scoped_ip_index_hint(query), [])

    def test_protocol_names_numbers_aliases_and_negation_agree(self):
        for name, number in [('TCP', '6'), ('udp', '17'), ('ICMP', '1'), ('TCP|udp', '6|17')]:
            for field in ['proto', 'protocol']:
                for negated in [False, True]:
                    self.assertEqual(CH._build_field_condition(field, name, negated),
                                     CH._build_field_condition(field, number, negated))
                    sql, prewhere = compile_filter(('-' if negated else '') + field + ':' + name)
                    self.assertNotIn('parsed_data', sql)
                    self.assertTrue(prewhere)

    def test_time_batches_match_full_sort_with_boundary_rows_and_offset(self):
        end = datetime(2026, 9, 17, 12, tzinfo=timezone.utc)
        data = [{'timestamp': end-timedelta(seconds=s), 'id': i}
                for i, s in enumerate([0, 59.999, 60, 60, 61, 299.999, 300, 301, 1799, 1800, 4000])]
        sqls = []
        def query(sql):
            sqls.append(sql)
            bounds = re.findall(r"timestamp (<=|<|>=) '([^']+)'", sql)
            selected = data[:]
            for op, value in bounds:
                dt = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
                selected = [r for r in selected if {'<=': r['timestamp'] <= dt,
                            '<': r['timestamp'] < dt, '>=': r['timestamp'] >= dt}[op]]
            cap = int(re.search(r'LIMIT (\d+)', sql)[1])
            return SimpleNamespace(named_results=lambda: selected[:cap])
        for offset, limit in [(0, 3), (2, 7), (0, 100), (10, 2)]:
            with self.subTest(offset=offset, limit=limit), patch.object(CH, 'get_client') as client:
                client.return_value.query.side_effect = query
                rows = CH.search_logs(limit=limit, offset=offset, start_time=end-timedelta(hours=2), end_time=end)
                self.assertEqual(rows, data[offset:offset+limit])
        self.assertTrue(all('count()' not in sql and 'max(timestamp)' not in sql for sql in sqls))

    def test_equal_start_end_is_inclusive(self):
        end = datetime(2026, 9, 17, 12, tzinfo=timezone.utc)
        with patch.object(CH, 'get_client') as client:
            client.return_value.query.return_value.named_results.return_value = [{'timestamp': end}]
            self.assertEqual(len(CH.search_logs(start_time=end, end_time=end)), 1)

    def test_custom_sort_uses_entire_range_once(self):
        with patch.object(CH, 'get_client') as client:
            client.return_value.query.return_value.named_results.return_value = []
            CH.search_logs(order_by='dstport DESC', limit=100, offset=100)
            client.return_value.query.assert_called_once()
            self.assertIn('ORDER BY dstport DESC LIMIT 100 OFFSET 100', client.return_value.query.call_args.args[0])

    def test_rare_prefix_is_applied_after_bounded_sample(self):
        nql_schema._value_cache.clear()
        with patch.object(CH, 'get_client') as client:
            client.return_value.query.return_value.result_rows = [('172.20.30.46', 2)]
            nql_schema.suggest_values('srcip', '172.20.30.46', minutes=10080)
            sql = client.return_value.query.call_args.args[0]
            self.assertLess(sql.index('LIMIT 400000'), sql.index('positionCaseInsensitive'))
            self.assertIn('timestamp <= now()', sql)
            self.assertIn('enable_optimize_predicate_expression = 0', sql)
            nql_schema.suggest_values('srcip', '172.20.30.46', minutes=10080)
            client.return_value.query.assert_called_once()

    def test_count_timeout_is_unknown_not_zero_or_lower_bound(self):
        with patch.object(CH, 'get_client') as client:
            client.return_value.query.side_effect = TimeoutError('budget')
            self.assertEqual(CH.count_logs(max_count=100000, max_execution_time=1), -2)
            self.assertIn('max_execution_time = 1', client.return_value.query.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
