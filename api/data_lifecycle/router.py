"""UI/API entry points for previewed, explicitly approved record deletion."""
from __future__ import annotations

from typing import Literal
from uuid import UUID
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator
from . import service

router = APIRouter(tags=['Data lifecycle'])
_pool_provider = None


def configure_data_lifecycle_router(pool_provider):
    global _pool_provider
    _pool_provider = pool_provider


def pool():
    result = _pool_provider() if _pool_provider else None
    if result is None:
        raise HTTPException(503, 'Database pool is not ready')
    return result


class DeletionSelection(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['target', 'findings']
    target_id: UUID | None = None
    finding_ids: list[UUID] = Field(default_factory=list, max_length=500)
    scan_id: UUID | None = None
    older_than_days: int | None = Field(default=None, ge=1, le=3650)
    status: Literal['active', 'resolved', 'false_positive', 'accepted_risk'] | None = None
    root_domain: str | None = Field(default=None, min_length=1, max_length=253)

    @model_validator(mode='after')
    def selection_is_explicit(self):
        if self.kind == 'target':
            if not self.target_id or self.finding_ids or self.scan_id or self.older_than_days or self.status or self.root_domain:
                raise ValueError('Target deletion requires exactly one target_id, without finding filters')
        elif self.target_id or bool(self.finding_ids) == bool(self.older_than_days):
            raise ValueError('Finding deletion requires explicit finding_ids or older_than_days, not both')
        elif self.finding_ids and (self.status or self.root_domain):
            raise ValueError('Explicit finding selection cannot be combined with cleanup filters')
        elif self.older_than_days and self.scan_id:
            raise ValueError('Age cleanup does not accept scan_id; use explicit finding_ids')
        return self

    def selection(self):
        value = self.model_dump(mode='json', exclude_none=True)
        if value.get('finding_ids'):
            value['finding_ids'] = sorted(set(value['finding_ids']))
        else:
            value.pop('finding_ids', None)
        return value


class DeletionExecution(BaseModel):
    model_config = ConfigDict(extra='forbid')
    preview_id: UUID
    preview_hash: str = Field(pattern=r'^[a-f0-9]{64}$')
    approval_receipt_id: UUID


@router.post('/data-deletion/preview')
async def preview_record_deletion(request: DeletionSelection):
    """Freeze a bounded exact selection; return cascade counts, blockers and retained data."""
    return await service.preview(pool(), request.selection())


@router.post('/data-deletion/execute')
async def execute_record_deletion(request: DeletionExecution):
    """Consume one dangerous Arsenal approval; retries return the same durable receipt."""
    return await service.execute(pool(), request.preview_id, request.approval_receipt_id, preview_hash=request.preview_hash)
