"""One versioned target methodology, stored alongside existing target metadata.

This is planner context in the shared Hunt skill system, never executable authority.
The retained revision after deletion prevents stale editors from overwriting a recreation.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Literal
import uuid

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError, field_validator

from .skill_trust import instruction_trust, planner_snapshot

try:
    from runtime.asset_capability_specs import MAX_TARGET_SKILL_CHARACTERS
except ModuleNotFoundError:
    from ..runtime.asset_capability_specs import MAX_TARGET_SKILL_CHARACTERS
router = APIRouter(tags=['targets'])


def pool():
    # Keep instruction validation/projection importable without API composition.
    from .asset_router import pool as configured_pool
    return configured_pool()


class TargetSkillDocument(BaseModel):
    schema_version: Literal['hunt-skill/v2']
    skill_id: str
    target_id: str
    source: Literal['target']
    kind: Literal['target_instructions']
    title: str
    methodology: str
    version: str
    body_sha256: str
    updated_at: str
    written_by: str | None = None


class TargetSkillResponse(BaseModel):
    target_id: str
    revision: int
    skill: TargetSkillDocument | None
    max_characters: int
    operator_skill: TargetSkillDocument | None = None
    trust: Literal['none', 'operator', 'hunt_advisory', 'unknown_advisory'] = 'none'


class TargetSkillWrite(BaseModel):
    model_config = ConfigDict(extra='forbid')
    title: str = Field(default='Target instructions', min_length=1, max_length=120)
    methodology: str = Field(min_length=1, max_length=MAX_TARGET_SKILL_CHARACTERS)
    expected_revision: StrictInt = Field(ge=0)

    @field_validator('title', 'methodology')
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip() or '\x00' in value:
            raise ValueError('Enter nonblank text without null characters')
        return value.strip()


async def _target(conn: Any, target_id: Any, *, lock: bool = False):
    try:
        identifier = uuid.UUID(str(target_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(400, 'Invalid target id') from exc
    row = await conn.fetchrow('SELECT id,metadata_json FROM targets WHERE id=$1' +
                             (' FOR UPDATE' if lock else ''), identifier)
    if row is None:
        raise HTTPException(404, 'Target not found')
    return row


def _saved(row: Any) -> dict[str, Any]:
    metadata = row['metadata_json'] or {}
    if isinstance(metadata, str):
        metadata = json.loads(metadata)
    saved = metadata.get('target_skill')
    if not isinstance(saved, dict):
        return {}
    revision = saved.get('revision', 0)
    if type(revision) is not int or revision < 0:
        return {}
    if saved.get('methodology'):
        try:
            TargetSkillWrite(title=saved.get('title'), methodology=saved['methodology'],
                            expected_revision=revision)
        except ValidationError:
            return {'revision': revision}
        digest = hashlib.sha256(saved['methodology'].encode('utf-8')).hexdigest()
        if saved.get('body_sha256') != digest or not isinstance(saved.get('updated_at'), str):
            return {'revision': revision}
    return dict(saved)


def _operator_skill(row: Any, saved: dict, current: dict | None) -> dict | None:
    # Once the snapshot key exists, explicit null is a tombstone. Never resurrect
    # a deleted operator instruction by mining the revision history.
    if 'operator_snapshot' not in saved:
        return current if instruction_trust(current) == 'operator' else None
    value = saved.get('operator_snapshot')
    if not isinstance(value, dict) or instruction_trust(value) != 'operator':
        return None
    try:
        parsed = TargetSkillDocument.model_validate(value)
        revision = int(parsed.version)
        text = TargetSkillWrite(title=parsed.title, methodology=parsed.methodology,
                               expected_revision=revision)
    except (ValidationError, TypeError, ValueError):
        return None
    if (parsed.target_id != str(row['id']) or parsed.skill_id != f"skill.target.{row['id']}"
            or revision > int(saved.get('revision') or 0)
            or parsed.body_sha256 != hashlib.sha256(text.methodology.encode('utf-8')).hexdigest()):
        return None
    return parsed.model_dump()


def _public(row: Any) -> dict[str, Any]:
    saved = _saved(row)
    revision = int(saved.get('revision') or 0)
    skill = None
    if saved.get('methodology'):
        skill = {
            'schema_version': 'hunt-skill/v2', 'skill_id': f"skill.target.{row['id']}",
            'target_id': str(row['id']), 'source': 'target', 'kind': 'target_instructions',
            'title': saved['title'], 'methodology': saved['methodology'],
            'version': str(revision), 'body_sha256': saved['body_sha256'],
            'updated_at': saved['updated_at'],
            'written_by': saved.get('written_by'),
        }
    return {'target_id': str(row['id']), 'revision': revision, 'skill': skill,
            'max_characters': MAX_TARGET_SKILL_CHARACTERS,
            'operator_skill': _operator_skill(row, saved, skill), 'trust': instruction_trust(skill)}


async def read_target_skill(conn: Any, target_id: Any) -> dict[str, Any]:
    return _public(await _target(conn, target_id))


async def write_target_skill(conn: Any, target_id: Any, operation: str,
                             *, expected_revision: int, request: TargetSkillWrite | None = None,
                             source: str = 'operator:target-skill-api'):
    async with conn.transaction():
        row = await _target(conn, target_id, lock=True)
        current = _public(row)
        if current['revision'] != expected_revision:
            raise HTTPException(409, 'Target instructions changed. Reload before saving your edits.')
        if operation == 'create' and current['skill'] is not None:
            raise HTTPException(409, 'This target already has instructions. Read and update them instead.')
        operator = instruction_trust({'written_by': source}) == 'operator'
        if (operation in {'update', 'delete'} and current['skill'] is None
                and not (operator and operation == 'delete' and current['operator_skill'])):
            raise HTTPException(404, 'Target instructions not found')
        if operation not in {'create', 'update', 'delete'}:
            raise HTTPException(422, 'Unsupported target skill operation')
        saved = {'revision': current['revision'] + 1,
                 'updated_at': datetime.now(timezone.utc).isoformat(), 'written_by': source}
        history = object_history(row)
        if current['skill'] is not None:
            history.append(current['skill'])
        saved['history'] = history[-20:]
        if operation != 'delete':
            if request is None:
                raise HTTPException(422, 'Target instructions are required')
            saved.update(title=request.title, methodology=request.methodology,
                         body_sha256=hashlib.sha256(request.methodology.encode('utf-8')).hexdigest())
        # A Hunt can edit/delete the current draft, but cannot erase or promote
        # the operator's instruction snapshot. Only the operator API can do so.
        next_row = {'id': row['id'], 'metadata_json': {'target_skill': saved}}
        if operator:
            saved['operator_snapshot'] = _public(next_row)['skill'] if operation != 'delete' else None
        else:
            saved['operator_snapshot'] = current['operator_skill']
        row = await conn.fetchrow("""UPDATE targets SET
            metadata_json=jsonb_set(COALESCE(metadata_json,'{}'::jsonb),'{target_skill}',$2::jsonb),
            updated_at=NOW() WHERE id=$1 RETURNING id,metadata_json""", row['id'], json.dumps(saved))
        return _public(row)


async def attach_target_skill_snapshot(conn: Any, target_id: Any, context: dict,
                                      methodology_context: Any) -> dict:
    """Compose the library methodologies and saved target instructions at admission."""
    context['skills'] = dict(methodology_context)
    from .hunt_authority import read_hunt_authority
    context['hunt_authority'] = await read_hunt_authority(conn, target_id)
    saved = await read_target_skill(conn, target_id)
    context['target_skill'] = planner_snapshot(saved)
    return context


def object_history(row):
    saved = _saved(row)
    history = saved.get('history')
    return list(history) if isinstance(history, list) else []


@router.get('/targets/{target_id}/skill', response_model=TargetSkillResponse)
async def get_target_skill(target_id: str):
    async with pool().acquire() as conn:
        return await read_target_skill(conn, target_id)


@router.post('/targets/{target_id}/skill', status_code=201, response_model=TargetSkillResponse)
async def create_target_skill(target_id: str, request: TargetSkillWrite):
    async with pool().acquire() as conn:
        return await write_target_skill(conn, target_id, 'create',
                                        expected_revision=request.expected_revision, request=request)


@router.put('/targets/{target_id}/skill', response_model=TargetSkillResponse)
async def update_target_skill(target_id: str, request: TargetSkillWrite):
    async with pool().acquire() as conn:
        return await write_target_skill(conn, target_id, 'update',
                                        expected_revision=request.expected_revision, request=request)


@router.delete('/targets/{target_id}/skill', response_model=TargetSkillResponse)
async def delete_target_skill(target_id: str, expected_revision: int = Query(..., ge=0)):
    async with pool().acquire() as conn:
        return await write_target_skill(conn, target_id, 'delete', expected_revision=expected_revision)
