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
try:
    from hunt.release_markers import ReleaseMarkerInput, declare_release, list_releases
except ModuleNotFoundError:  # package import
    from ..hunt.release_markers import ReleaseMarkerInput, declare_release, list_releases
from .metadata_row import target_metadata_row

router = APIRouter(tags=['targets'])
LIST_LIMIT = 200

KindFilter = Literal['observation', 'hypothesis', 'explanation', 'next_step', 'note', 'negative_result']
StatusFilter = Literal['active', 'superseded', 'retracted', 'reopened']
StateFilter = Literal['experiment_completed_negative', 'experiment_inconclusive', 'hypothesis_refuted',
                      'finding_dismissed']
SourceFilter = Literal['interpretations', 'authorization_workflow', 'hypothesis_lifecycle',
                       'candidate_verification']


from .operator_identity import operator_identity as _operator


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
        from .decision_receipts import receipt_request
        recorded = await receipt_request(conn, request, target_id, 'retract', subject_id=entry_id, note=body.note,
            perform=lambda identity: retract_interpretation(conn, target_id, entry_id, actor=identity, note=body.note))
        if recorded is not None:
            return recorded
        return await retract_interpretation(conn, target_id, entry_id, actor=actor, note=body.note)


@router.post('/targets/{target_id}/hunts/{hunt_id}/interpretations/retract')
async def post_retract_hunt_interpretations(target_id: str, hunt_id: str, body: StatusNote, request: Request):
    """Retract every active entry one Hunt wrote on this target."""
    actor = _operator(request)
    async with pool().acquire() as conn:
        from .decision_receipts import receipt_request
        recorded = await receipt_request(conn, request, target_id, 'retract_hunt', subject_id=hunt_id, note=body.note,
            perform=lambda identity: retract_run(conn, target_id, hunt_id, actor=identity, note=body.note))
        if recorded is not None:
            return recorded
        return await retract_run(conn, target_id, hunt_id, actor=actor, note=body.note)


@router.get('/targets/{target_id}/negative-results')
async def get_target_negative_results(target_id: str, request: Request, state: StateFilter | None = None,
                                      source: SourceFilter | None = None, limit: int = Query(50, ge=1, le=50)):
    _operator(request)
    async with pool().acquire() as conn:
        row = await target_metadata_row(conn, target_id)
        return await negative_results(conn, row['id'], device=True, audience='operator', state=state,
                                      source=source, limit=limit)


@router.get('/targets/{target_id}/knowledge/changes')
async def get_target_knowledge_changes(target_id: str, request: Request,
                                       since: str = Query('last_hunt', max_length=100),
                                       limit: int = Query(25, ge=1, le=25)):
    """What changed on this target (and, for a host, its services) since a point, from existing records,
    and which interpretations it affects. Reads only; never sends traffic or starts a Scan."""
    _operator(request)
    try:
        from hunt.knowledge_changes import ChangeQueryError, target_changes
    except ModuleNotFoundError:  # package import
        from ..hunt.knowledge_changes import ChangeQueryError, target_changes
    async with pool().acquire() as conn:
        row = await target_metadata_row(conn, target_id)
        try:
            return await target_changes(conn, row['id'], device=True, since=since, limit=limit)
        except ChangeQueryError as exc:
            raise HTTPException(422, {'error': 'invalid_since', 'message': str(exc)}) from None


@router.get('/targets/{target_id}/knowledge/continue')
async def get_target_knowledge_continue(target_id: str, request: Request,
                                        since: str = Query('release', max_length=100),
                                        limit: int = Query(25, ge=1, le=100),
                                        after: str | None = Query(None, max_length=2048)):
    """Continue investigating this target after its latest release: what changed, what still applies,
    what needs re-testing, and the next experiments ranked by fixed rules. Reads only; a passive refresh
    is offered, never started (``shakerscan knowledge continue --refresh`` starts it after a keypress)."""
    _operator(request)
    try:
        from hunt.knowledge_changes import ChangeQueryError
        from hunt.knowledge_continue import CursorError, continue_report
    except ModuleNotFoundError:  # package import
        from ..hunt.knowledge_changes import ChangeQueryError
        from ..hunt.knowledge_continue import CursorError, continue_report
    async with pool().acquire() as conn:
        row = await target_metadata_row(conn, target_id)
        try:
            return await continue_report(conn, row['id'], device=True, audience='operator', since=since, limit=limit,
                                         after=after)
        except CursorError as exc:
            raise HTTPException(422, {'error': 'invalid_cursor', 'message': str(exc)}) from None
        except ChangeQueryError as exc:
            raise HTTPException(422, {'error': 'invalid_since', 'message': str(exc)}) from None


@router.get('/targets/{target_id}/knowledge/releases')
async def get_target_releases(target_id: str, request: Request, limit: int = Query(50, ge=1, le=50)):
    _operator(request)
    async with pool().acquire() as conn:
        row = await target_metadata_row(conn, target_id)
        return await list_releases(conn, row['id'], device=True, limit=limit)


@router.post('/targets/{target_id}/knowledge/releases', status_code=201)
async def post_target_release(target_id: str, body: ReleaseMarkerInput, request: Request):
    """Declare that this target was released (an operator's statement): the point
    ``since=release`` starts from. Changes no applicability and grants nothing."""
    actor = _operator(request)
    async with pool().acquire() as conn:
        row = await target_metadata_row(conn, target_id)
        from .decision_receipts import receipt_request, _canonical
        import hashlib
        # Preserve the approval's literal timestamp spelling, rather than reserializing a datetime.
        raw = await request.json()
        bound = {'label': raw.get('label'), 'released_at': raw.get('released_at')}
        recorded = await receipt_request(conn, request, row['id'], 'release_marker',
            perform=lambda identity: declare_release(conn, row['id'], body, actor=identity),
            release_label=bound['label'], released_at=bound['released_at'],
            text_sha256=hashlib.sha256(_canonical(bound).encode('ascii')).hexdigest())
        if recorded is not None:
            return recorded
        return await declare_release(conn, row['id'], body, actor=actor)


@router.post('/targets/{target_id}/findings/{finding_id}/dismiss')
async def post_dismiss_finding(target_id: str, finding_id: str, body: DismissalInput, request: Request):
    """Dismiss a finding (false positive, accepted risk or duplicate) with a reason: an operator's decision."""
    actor = _operator(request)
    async with pool().acquire() as conn:
        from .decision_receipts import receipt_request
        if request.headers.get('x-shakerscan-decision-id') and body.evidence_refs:
            raise HTTPException(422, 'This approval did not name evidence references')
        recorded = await receipt_request(conn, request, target_id, 'dismiss', subject_id=finding_id,
                                         reason=body.reason, note=body.note,
            perform=lambda identity: dismiss_finding(conn, target_id, finding_id, body, actor=identity))
        if recorded is not None:
            return recorded
        return await dismiss_finding(conn, target_id, finding_id, body, actor=actor)


@router.post('/targets/{target_id}/findings/{finding_id}/reopen')
async def post_reopen_finding(target_id: str, finding_id: str, body: StatusNote, request: Request):
    actor = _operator(request)
    async with pool().acquire() as conn:
        from .decision_receipts import receipt_request
        recorded = await receipt_request(conn, request, target_id, 'reopen', subject_id=finding_id, note=body.note,
            perform=lambda identity: reopen_finding(conn, target_id, finding_id, actor=identity, note=body.note))
        if recorded is not None:
            return recorded
        return await reopen_finding(conn, target_id, finding_id, actor=actor, note=body.note)


__all__ = ['router']
