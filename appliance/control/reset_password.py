"""Run inside the application container with the password on stdin, never argv."""
import asyncio
import json
import sys
from sqlalchemy import select
from fastapi_app.db.database import async_session_maker
from fastapi_app.models.user import User
from fastapi_app.core.cache import get_redis

async def main():
    value = json.load(sys.stdin)
    async with async_session_maker() as db:
        user = (await db.execute(select(User).where(User.username == 'admin'))).scalar_one()
        user.set_password(value['password'])
        user.failed_login_attempts = 0
        user.locked_until = None
        user.is_active = True
        redis = await get_redis()
        # Revocation must succeed before accepting the password change.
        async for key in redis.scan_iter(match='session:*', count=100):
            session = await redis.get(key)
            if isinstance(session, bytes): session = session.decode()
            if session and session.startswith(str(user.id) + ':'):
                await redis.delete(key)
        await db.commit()
    print('{"message":"GUI administrator password changed; previous sessions revoked"}')

if __name__ == '__main__': asyncio.run(main())
