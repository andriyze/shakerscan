"""Optional authenticated ASGI ingress exposing only one already-admitted Hunt.

Run with ``uvicorn hunt.planner_gateway:create_app --factory`` in the API image.
The ordinary operator listener and its credentials must be unreachable from the
planner environment. This entrypoint is never silently enabled on local OSS.
"""
from __future__ import annotations

import asyncio
import importlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Callable
from uuid import UUID

from .planner_lease import PlannerLease, load_lease

LOGGER = logging.getLogger('shakerscan.hunt.planner_access')
MAX_BODY_BYTES = 1024 * 1024
BODY_TIMEOUT_SECONDS = 30
_NAME = r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'
_UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
_DRAFT = r'[0-9a-f]{64}'
# These are existing route shapes, not capability or authority declarations.
# All capability names still resolve through the one server-owned registry.
# Every route is under the leased /hunts/{id} prefix, so each one acts on that Hunt only.
# Operator-only steps (budget amendments, shell-plan confirmation, /ai/targets boundary
# verification) are deliberately absent.
_ROUTES = {
    'GET': (r'', r'/record', r'/budget-amendments', r'/checkpoint', r'/coverage-angles',
            rf'/candidates/{_UUID}/boundary-context',
            rf'/authorization-investigations/{_UUID}',
            rf'/authorization-investigations/{_UUID}/reproduction', rf'/ssh/actions/{_UUID}/output'),
    'POST': (r'/ssh/exec', rf'/ssh/actions/{_UUID}/cancel', r'/query', r'/finish', r'/cancel', r'/resume',
             rf'/capabilities/{_NAME}', r'/candidates', r'/coverage-angles',
             rf'/candidates/{_UUID}/verify', rf'/candidates/{_UUID}/boundary-proposal',
             r'/boundary-discovery', rf'/boundary-discovery/{_DRAFT}/prepare',
             r'/skills/suggestions', rf'/skills/{_NAME}/(?:read|bind|usage)',
             r'/authorization-investigations', rf'/authorization-investigations/{_UUID}/skip'),
    'PATCH': (rf'/candidates/{_UUID}',),
    'DELETE': (rf'/candidates/{_UUID}', rf'/skills/{_NAME}'),
}
_CONTRACT_PATHS = frozenset({'/health', '/openapi.json', '/hunts/contract', '/scan/contracts'})


def route_allowed(method: str, path: str, hunt_id: str) -> bool:
    if method == 'GET' and path in _CONTRACT_PATHS:
        return True
    prefix = '/hunts/' + str(UUID(hunt_id))
    if not path.startswith(prefix):
        return False
    suffix = path[len(prefix):]
    return any(re.fullmatch(pattern, suffix) is not None for pattern in _ROUTES.get(method, ()))


def _token(scope: dict) -> str:
    values = [value for name, value in scope.get('headers', ()) if name.lower() == b'authorization']
    if len(values) != 1:
        return ''
    try:
        scheme, token = values[0].decode('ascii').split(' ', 1)
    except (ValueError, UnicodeDecodeError):
        return ''
    return token if scheme.lower() == 'bearer' else ''


def _secure_transport(scope: dict) -> bool:
    if scope.get('scheme') == 'https':
        return True
    try:
        return ipaddress.ip_address(scope['client'][0]).is_loopback
    except (KeyError, TypeError, ValueError):
        return False


async def _reject(send: Callable, status: int, code: str) -> None:
    body = json.dumps({'detail': {'error': code}}).encode()
    await send({'type': 'http.response.start', 'status': status, 'headers': [
        (b'content-type', b'application/json'), (b'cache-control', b'no-store'),
        (b'content-length', str(len(body)).encode()),
    ]})
    await send({'type': 'http.response.body', 'body': body})


class HuntPlannerGateway:
    def __init__(self, app: Any, grant_file: Path, *, loader: Callable = load_lease):
        self.app, self.grant_file, self.loader = app, grant_file, loader

    def _lease(self, token: str) -> PlannerLease | None:
        try:
            lease = self.loader(self.grant_file)
            return lease if lease.accepts(token) else None
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            return None  # Revoked, expired and invalid credentials share one answer.

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'lifespan':
            return await self.app(scope, receive, send)
        if scope['type'] != 'http':
            if scope['type'] == 'websocket':
                await send({'type': 'websocket.close', 'code': 1008})
            return
        token = _token(scope)
        lease = self._lease(token)
        if lease is None:
            return await _reject(send, 401, 'planner_lease_invalid_or_expired')
        if not _secure_transport(scope):
            return await _reject(send, 403, 'planner_transport_requires_https')
        path, method = scope.get('path', ''), scope.get('method', '')
        # Reject ambiguous encodings before the router or redirects normalize them.
        raw_path = scope.get('raw_path', path.encode('utf-8'))
        if raw_path != path.encode('utf-8') or not route_allowed(method, path, lease.hunt_id):
            LOGGER.info('planner_access_denied planner=%s hunt=%s', lease.planner_id, lease.hunt_id)
            return await _reject(send, 403, 'planner_route_not_delegated')
        body = bytearray()
        try:
            async with asyncio.timeout(BODY_TIMEOUT_SECONDS):
                while True:
                    message = await receive()
                    if message['type'] == 'http.disconnect':
                        return
                    if message['type'] != 'http.request':
                        return await _reject(send, 400, 'invalid_planner_request')
                    body.extend(message.get('body', b''))
                    if len(body) > MAX_BODY_BYTES:
                        return await _reject(send, 413, 'planner_request_too_large')
                    if not message.get('more_body', False):
                        break
        except TimeoutError:
            return await _reject(send, 408, 'planner_request_timeout')
        # Revocation while uploading must take effect before application dispatch.
        current = self._lease(token)
        if current != lease:
            return await _reject(send, 401, 'planner_lease_invalid_or_expired')
        forwarded = dict(scope)
        forwarded.pop('shakerscan.operator_identity', None)
        forwarded['shakerscan.planner_identity'] = lease.planner_id
        forwarded['shakerscan.planner_hunt_id'] = lease.hunt_id
        forwarded['headers'] = [(name, value) for name, value in scope.get('headers', ())
            if name.lower() not in {b'authorization', b'cookie', b'x-http-method-override'}
            and not name.lower().startswith((b'x-shakerscan-', b'x-operator-', b'x-planner-'))]
        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
            return await receive()

        async def audit_send(message):
            if message['type'] == 'http.response.start':
                LOGGER.info('planner_request planner=%s hunt=%s status=%s',
                            lease.planner_id, lease.hunt_id, message['status'])
            await send(message)

        # No prompt, token, request body, target content or raw path is logged.
        return await self.app(forwarded, replay_receive, audit_send)


def create_app() -> HuntPlannerGateway:
    path = Path(os.environ['SHAKERSCAN_HUNT_PLANNER_GRANT_FILE'])
    load_lease(path)  # Misconfiguration fails startup, never opens an unguarded API.
    core = importlib.import_module('api.api' if __package__ == 'api.hunt' else 'api')
    return HuntPlannerGateway(core.app, path)
