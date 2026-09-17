"""Render the real logs route, preserving source time and normalized lookup keys."""
import asyncio
import inspect
import re
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from starlette.requests import Request
from fastapi_app.api import views
from fastapi_app.db.clickhouse import ClickHouseClient as CH
from fastapi_app.main import app


class TimestampDisplayTests(unittest.TestCase):
    def test_device_time_and_normalized_lookup_remain_distinct(self):
        normalized = datetime(2026, 9, 17, 15, 4, 57, tzinfo=timezone.utc)
        rows = [dict(timestamp=normalized, device_ip='192.0.2.1', log_time=value)
                for value in ['2026-09-17 18:04:57', '2026/09/17 11:04:57', '', '<script>bad</script>']]
        request = Request({'type':'http','method':'GET','path':'/logs/','headers':[],
                           'query_string':b'','scheme':'https','server':('localhost',443),
                           'app':app,'router':app.router})
        args = {k:getattr(p.default,'default',p.default) for k,p in inspect.signature(views.log_list).parameters.items()}
        args.update(request=request, db=None, time_range='1m')
        with patch.object(CH,'search_logs',return_value=rows), \
             patch.object(CH,'count_logs',return_value=len(rows)), \
             patch.object(CH,'get_distinct_devices',return_value=['192.0.2.1']), \
             patch('fastapi_app.core.app_settings.get_display_timezone',return_value='UTC'):
            response = asyncio.run(views.log_list(**args))
        html = response.body.decode()
        cells = re.findall(r'<td data-col="timestamp">(.*?)</td>',html,re.S)
        self.assertEqual(len(cells),4)
        texts = [re.search(r'<span[^>]*>(.*?)</span>',cell,re.S).group(1).strip() for cell in cells]
        self.assertEqual(texts[:3],['2026-09-17 18:04:57','2026/09/17 11:04:57','2026-09-17 15:04:57 UTC'])
        self.assertEqual(texts[3],'&lt;script&gt;bad&lt;/script&gt;')
        self.assertIn('Normalized time (UTC): 2026-09-17 15:04:57',cells[0])
        self.assertIn('Device time unavailable.',cells[2])
        self.assertIn('data-timestamp="2026-09-17T15:04:57+00:00"',html)
        self.assertIn('Filter timezone: <strong>UTC</strong>',html)


if __name__ == '__main__':
    unittest.main()
