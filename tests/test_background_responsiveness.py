"""A slow scheduled scan must leave the web event loop responsive."""
import asyncio
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi_app.services import correlation_engine as engine


class BackgroundResponsivenessTests(unittest.IsolatedAsyncioTestCase):
    async def test_slow_correlation_evaluation_does_not_block_other_requests(self):
        rule = SimpleNamespace(name='test', match_mode='discrete', suppress_window=60,
                               last_evaluated_at=None)
        session = AsyncMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = [rule]
        session.execute.return_value = result
        manager = MagicMock()
        manager.return_value.__aenter__.return_value = session
        loop_thread = threading.get_ident()
        worker_threads = []
        def slow_scan(_):
            worker_threads.append(threading.get_ident())
            time.sleep(0.2)
            return []
        ticks = 0
        async def heartbeat():
            nonlocal ticks
            for _ in range(8):
                await asyncio.sleep(0.015)
                ticks += 1
        with patch.object(engine, 'async_session_maker', manager), \
             patch.object(engine, 'evaluate_correlation_rule', side_effect=slow_scan):
            task = asyncio.create_task(engine.evaluate_all_correlation_rules())
            await heartbeat()
            self.assertFalse(task.done(), 'The event loop stalled until the blocking scan finished')
            await task
        self.assertEqual(ticks, 8)
        self.assertNotEqual(worker_threads, [loop_thread])
        session.commit.assert_awaited_once()
        self.assertIsNotNone(rule.last_evaluated_at)


if __name__ == '__main__':
    unittest.main()
