"""Operator routes for a target's interpretations, negative results and finding dismissals.

These are the operator's surface. A Hunt writes interpretations only through the
``knowledge.record`` capability and reads them through its own query; the planner ingress never
forwards these paths, and each route also refuses a request that arrived through it. Dismissing a
finding is a person's decision: no Hunt capability, query or MCP tool can do it.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request

try:
    from hunt.interpretations import (DismissalInput, InterpretationInput, StatusNote, dismiss_finding,
                                      negative_results, operator_list, record_interpretation, reopen_finding,
                                      retract_interpretation, retract_run)
except ModuleNotFoundError:  # package import
    from ..hunt.interpretations import (DismissalInput, InterpretationInput, StatusNote, dismiss_finding,
                                        negative_results, operator_list, record_interpretation, reopen_finding,
                                        retract_interpretation, retract_run)
from .metadata_row import target_metadata_row

router = APIRouter(tags=['targets'])
LIST_LIMIT = 200

KindFilter = Literal['observation', 'hypothesis', 'explanation', 'next_step', 'note', 'negative_result']
StatusFilter = Literal['active', 'superseded', 'retracted', 'reopened']
StateFilter = Literal['experiment_completed_negative', 'experiment_inconclusive', 'hypothesis_refuted',
                      'finding_dismissed']
SourceFilter = Literal['interpretations', 'authorization_workflow', 'hypothesis_lifecycle',
                       'candidate_verification']


def _operator(request: Request) -> str:
    """The server-derived operator identity. A request through the planner ingress is never one."""
    if request.scope.get('shakerscan.planner_identity') or request.scope.get('shakerscan.planner_hunt_id'):
        raise HTTPException(403, {'error': 'operator_only', 'reason_code': 'operator_only',
                                  'message': 'This is an operator route; a Hunt planner cannot use it.'})
    actor = str(request.scope.get('shakerscan.operator_identity') or 'operator:interpretations-api')
    return (actor if actor.startswith('operator:') else f'operator:{actor}')[:200]


def pool():
    from .asset_router import pool as configured_pool
    return configured_pool()


@router.get('/targets/{target_id}/interpretations')
async def get_target_interpretations(target_id: str, request: Request, kind: KindFilter | None = None,
                                     status: StatusFilter | None = None,
                                     negative_state: StateFilter | None = None, hunt_id: str | None = None,
                                     limit: int = Query(100, ge=1, le=LIST_LIMIT)):
    _operator(request)
    async with pool().acquire() as conn:
        return await operator_list(conn, target_id, kind=kind, status=status, negative_state=negative_state,
                                   hunt_id=hunt_id, limit=limit)


@router.post('/targets/{target_id}/interpretations', status_code=201)
async def post_target_interpretation(target_id: str, entry: InterpretationInput, request: Request):
    """An operator's own entry; it is attributed to the operator and, like any entry, grants nothing."""
    actor = _operator(request)
    async with pool().acquire() as conn:
        return await record_interpretation(conn, target_id, entry, writer=actor)


@router.post('/targets/{target_id}/interpretations/{entry_id}/retract')
async def post_retract_interpretation(target_id: str, entry_id: str, body: StatusNote, request: Request):
    actor = _operator(request)
    async with pool().acquire() as conn:
        return await retract_interpretation(conn, target_id, entry_id, actor=actor, note=body.note)


@router.post('/targets/{target_id}/hunts/{hunt_id}/interpretations/retract')
async def post_retract_hunt_interpretations(target_id: str, hunt_id: str, body: StatusNote, request: Request):
    """Retract every active entry one Hunt wrote on this target."""
    actor = _operator(request)
    async with pool().acquire() as conn:
        return await retract_run(conn, target_id, hunt_id, actor=actor, note=body.note)


@router.get('/targets/{target_id}/negative-results')
async def get_target_negative_results(target_id: str, request: Request, state: StateFilter | None = None,
                                      source: SourceFilter | None = None, limit: int = Query(50, ge=1, le=50)):
    _operator(request)
    async with pool().acquire() as conn:
        row = await target_metadata_row(conn, target_id)
        return await negative_results(conn, row['id'], device=True, audience='operator', state=state,
                                      source=source, limit=limit)


@router.post('/targets/{target_id}/findings/{finding_id}/dismiss')
async def post_dismiss_finding(target_id: str, finding_id: str, body: DismissalInput, request: Request):
    """Dismiss a finding (false positive, accepted risk or duplicate) with a reason: an operator's decision."""
    actor = _operator(request)
    async with pool().acquire() as conn:
        return await dismiss_finding(conn, target_id, finding_id, body, actor=actor)


@router.post('/targets/{target_id}/findings/{finding_id}/reopen')
async def post_reopen_finding(target_id: str, finding_id: str, body: StatusNote, request: Request):
    actor = _operator(request)
    async with pool().acquire() as conn:
        return await reopen_finding(conn, target_id, finding_id, actor=actor, note=body.note)


__all__ = ['router']
