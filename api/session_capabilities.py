"""GET /session/capabilities: what the person using the UI may do (session-capabilities/v1).

The UI reads this once per page load to hide controls that would only end in a refusal. The
open-source engine has no roles, so it allows everything. A gateway in front of the engine answers
the same request itself for the signed-in person. This is a presentation hint, never an
authorization decision. Contract: docs/session-capabilities.md.
"""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(tags=['Session'])

SCHEMA_VERSION = 'session-capabilities/v1'
ACTIONS = (
    'targets.add', 'targets.edit', 'targets.check', 'scans.start',
    'findings.retest', 'findings.verify', 'findings.triage', 'findings.accept_risk',
    'hunts.manage', 'secrets.read', 'secrets.manage', 'secrets.decide', 'records.delete',
)


@router.get('/session/capabilities')
async def session_capabilities() -> JSONResponse:
    """Everything is allowed on the open-source engine."""
    return JSONResponse({
        'schema_version': SCHEMA_VERSION,
        'source': 'engine',
        'role': None,
        'default': 'allow',
        'actions': {name: True for name in ACTIONS},
        'pages': {},
        'reasons': {},
    }, headers={'Cache-Control': 'no-store'})
