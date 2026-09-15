"""Readiness retries must end before the migration write boundary."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import AsyncMock
import asyncpg
from clickhouse_connect.driver.exceptions import OperationalError, DatabaseError
from urllib3.exceptions import NewConnectionError

spec = importlib.util.spec_from_file_location('schema', Path(__file__).resolve().parents[1] / 'appliance/ota/schema.py')
schema = importlib.util.module_from_spec(spec)
spec.loader.exec_module(schema)


class Readiness(unittest.IsolatedAsyncioTestCase):
    async def test_connection_refused_then_ready(self):
        connection = object()
        factory = AsyncMock(side_effect=[ConnectionRefusedError(), asyncpg.CannotConnectNowError(), connection])
        self.assertIs(await schema.await_connection(factory, 'PostgreSQL', timeout=1, interval=0), connection)
        self.assertEqual(factory.await_count, 3)

    async def test_transport_wrapper_then_ready(self):
        error = OperationalError('private connection details')
        error.__cause__ = NewConnectionError(None, 'connection refused')
        factory = AsyncMock(side_effect=[error, 'ready'])
        self.assertEqual(await schema.await_connection(factory, 'ClickHouse', timeout=1, interval=0), 'ready')

    async def test_persistent_failure_has_bounded_sanitized_timeout(self):
        factory = AsyncMock(side_effect=ConnectionRefusedError('private connection details'))
        with self.assertRaisesRegex(RuntimeError, '^PostgreSQL readiness timed out before schema changes$'):
            await schema.await_connection(factory, 'PostgreSQL', timeout=.02, interval=.005)

    async def test_authentication_and_sql_failures_are_not_retried(self):
        for error in (asyncpg.InvalidPasswordError(), asyncpg.UndefinedTableError(),
                      DatabaseError('authentication failed', code=516), OperationalError('invalid response')):
            factory = AsyncMock(side_effect=error)
            with self.assertRaises(type(error)):
                await schema.await_connection(factory, 'database', timeout=1, interval=0)
            self.assertEqual(factory.await_count, 1)


if __name__ == '__main__':
    unittest.main()
