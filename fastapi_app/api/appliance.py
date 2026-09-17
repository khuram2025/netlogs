"""Authenticated, same-origin bridge to fixed host appliance operations."""
import logging
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from ..core.permissions import require_role

router = APIRouter(prefix='/api/appliance', tags=['appliance'], dependencies=[Depends(require_role('ADMIN'))])
OPERATIONS = {'status', 'storage', 'storage.plan', 'storage.commit', 'network.apply',
              'time.status', 'time.update', 'time.retry',
              'network.confirm', 'network.rollback', 'settings.update', 'password.gui',
              'updates.status','updates.check','updates.apply','updates.policy','updates.register',
              'licences.status','licences.refresh','licences.claim'}
logger = logging.getLogger(__name__)

@router.post('/{operation}')
async def appliance_operation(operation: str, request: Request):
    if operation not in OPERATIONS: raise HTTPException(404, 'Unknown appliance operation')
    if getattr(request.state, 'api_key', None) is not None:
        raise HTTPException(403, 'Appliance management requires an administrator browser session')
    raw = await request.body()
    if len(raw) > 16384: raise HTTPException(413, 'Request too large')
    try: body = await request.json()
    except ValueError: raise HTTPException(400, 'Invalid JSON')
    if not isinstance(body, dict): raise HTTPException(400, 'Expected an object')
    if operation == 'password.gui':
        user = request.state.current_user
        if not user.verify_password(body.pop('current_password', '')):
            raise HTTPException(403, 'Current administrator password is incorrect')
    try:
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds='/run/zenshield/agent.sock'), timeout=120) as client:
            response = await client.post('http://localhost/rpc', json={'operation': operation, 'body': body})
        if operation not in {'status', 'storage', 'time.status'}:
            logger.info('Appliance operation=%s actor=%s result=%s', operation, request.state.current_user.username, response.status_code)
        return JSONResponse(response.json(), status_code=response.status_code)
    except httpx.HTTPError:
        raise HTTPException(503, 'Appliance management is temporarily unavailable; use the console to inspect services')

# Preserve upstream's named navigation route without enabling a second updater.
updates_compat_router = APIRouter(dependencies=[Depends(require_role('ADMIN'))])
@updates_compat_router.get('/system/updates/', name='updates_page')
async def appliance_updates_page(request: Request):
    from fastapi.responses import RedirectResponse
    return RedirectResponse('/system/#updates', status_code=303)
