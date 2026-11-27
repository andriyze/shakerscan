"""Operator HTTP entry points for receipts and guarded reversal."""
from uuid import UUID
from typing import get_args

from fastapi import APIRouter, HTTPException, Query, Request

from .asset_router import pool
from .operator_identity import operator_identity as _operator
from .decision_actions import apply_operator_decision
from .decision_receipts import DecisionInput, RevertInput, _open, apply_decision, public_receipt, revert_decision

router = APIRouter(tags=['targets'])


@router.post('/targets/{target_id}/knowledge/decisions')
async def post_decision(target_id: UUID, body: DecisionInput, request: Request):
    actor = _operator(request)
    async with pool().acquire() as conn:
        return await apply_decision(conn, target_id, body, actor,
            perform=lambda identity: apply_operator_decision(conn, target_id, body, identity))


@router.get('/knowledge/decisions')
async def get_decisions(request: Request, limit: int = Query(50, ge=1, le=100)):
    _operator(request)
    async with pool().acquire() as conn:
        rows = await conn.fetch('SELECT * FROM target_operator_decisions ORDER BY created_at DESC,id DESC LIMIT $1', limit)
    return {'decisions': [public_receipt(row) for row in rows],
            'supported_decisions': list(get_args(DecisionInput.model_fields['decision'].annotation))}


@router.get('/targets/{target_id}/knowledge/decisions/{receipt_id}')
async def get_decision(target_id: UUID, receipt_id: UUID, request: Request):
    _operator(request)
    async with pool().acquire() as conn:
        row = await conn.fetchrow('SELECT * FROM target_operator_decisions WHERE id=$1 AND target_id=$2', receipt_id, target_id)
    if row is None:
        raise HTTPException(404, 'Decision receipt not found')
    return {'decision_receipt': public_receipt(row), 'result': _open(row['snapshot'])['result']}


@router.post('/targets/{target_id}/knowledge/decisions/{receipt_id}/revert')
async def post_revert(target_id: UUID, receipt_id: UUID, body: RevertInput, request: Request):
    actor = _operator(request)
    async with pool().acquire() as conn:
        return await revert_decision(conn, target_id, receipt_id, body.receipt_sha256, actor)
