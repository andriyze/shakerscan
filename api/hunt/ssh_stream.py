"""Streaming view of canonical ssh.exec; no alternate execution or approval path."""
from __future__ import annotations

import asyncio
import hashlib
import json
from uuid import UUID, uuid5
from types import SimpleNamespace

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import StreamingResponse, JSONResponse

from .ssh_routing import output_key, cancel_key, OUTPUT_TTL

router = APIRouter(tags=['hunts'])
_configured_runtime = None


def configure_ssh_stream(**collaborators):
    global _configured_runtime
    _configured_runtime = SimpleNamespace(**collaborators)


def _runtime():
    if _configured_runtime is None:
        raise HTTPException(503, 'SSH runtime is not ready')
    return _configured_runtime


async def _action(hunt_id, action_id):
    runtime = _runtime()
    try:
        run, action = UUID(hunt_id), UUID(action_id)
    except ValueError as exc:
        raise HTTPException(400, 'Invalid Hunt or action ID') from exc
    async with runtime._pool().acquire() as conn:
        row = await conn.fetchrow('SELECT status FROM hunt_actions WHERE hunt_run_id=$1 AND id=$2 '
                                  "AND capability_name='ssh.exec'", run, action)
    if row is None:
        raise HTTPException(404, 'SSH action not found in this Hunt')
    return row


@router.get('/hunts/{hunt_id}/ssh/actions/{action_id}/output')
async def ssh_action_output(hunt_id: str, action_id: str):
    row = await _action(hunt_id, action_id)
    raw = _runtime().get_redis().get(output_key(hunt_id, action_id))
    value = json.loads(raw) if raw else {'status': row['status'], 'output_available': False}
    return JSONResponse(value, headers={'Cache-Control': 'no-store'})


@router.post('/hunts/{hunt_id}/ssh/actions/{action_id}/cancel')
async def cancel_ssh_action(hunt_id: str, action_id: str):
    row = await _action(hunt_id, action_id)
    pending = row['status'] in {'reserved', 'running'}
    if pending:
        _runtime().get_redis().set(cancel_key(hunt_id, action_id), '1', ex=OUTPUT_TTL)
    return {'hunt_id': hunt_id, 'action_id': action_id, 'cancellation_requested': pending,
            'remote_termination_confirmed': False}


def _event(name, value):
    return 'event: ' + name + '\ndata: ' + json.dumps(value, separators=(',', ':')) + '\n\n'


@router.post('/hunts/{hunt_id}/ssh/exec')
async def stream_ssh_command(hunt_id: str, request: Request):
    """Accept exactly the canonical capability envelope and stream untrusted output.

    Authentication is the deployment/gateway's ordinary Hunt authentication.
    All operation validation and state changes occur in execute_hunt_capability.
    """
    from pydantic import ValidationError
    runtime = _runtime()
    try:
        body = bytearray()
        async for part in request.stream():
            body.extend(part)
            if len(body) > 32768:
                raise HTTPException(413, 'SSH request too large')
        command = runtime.HuntCapabilityRequest.model_validate_json(body)
        run_uuid = UUID(hunt_id)
    except (ValidationError, ValueError) as exc:
        raise HTTPException(422, 'Invalid SSH capability request') from exc
    async with runtime._pool().acquire() as conn:
        await runtime._hunt_run_or_404(conn, hunt_id)
    action_id = str(uuid5(run_uuid, f'hunt-capability:{command.idempotency_key}'))
    digest = hashlib.sha256(json.dumps(command.input, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

    async def events():
        task = asyncio.create_task(runtime.execute_hunt_capability(hunt_id, 'ssh.exec', command))
        previous = None
        try:
            yield _event('accepted', {'hunt_id': hunt_id, 'action_id': action_id})
            while not task.done():
                raw = runtime.get_redis().get(output_key(hunt_id, action_id))
                if raw and raw != previous:
                    value = json.loads(raw)
                    if value.get('input_sha256') == digest:
                        yield _event('output', value)
                    previous = raw
                yield ': heartbeat\n\n'
                await asyncio.sleep(0.1)
            yield _event('result', await task)
        except HTTPException as exc:
            yield _event('error', {'status_code': exc.status_code, 'detail': exc.detail})
        except Exception as exc:
            yield _event('error', {'status_code': 500, 'detail': type(exc).__name__})
        finally:
            if not task.done():
                runtime.get_redis().set(cancel_key(hunt_id, action_id), '1', ex=OUTPUT_TTL)
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    return StreamingResponse(events(), media_type='text/event-stream',
        headers={'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no'})
