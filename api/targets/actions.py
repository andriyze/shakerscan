"""Named target recipes use canonical Hunt capabilities, never another executor."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from .metadata_row import target_metadata_row as _target

router = APIRouter(tags=['targets'])
MAX_ACTIONS = 32
MAX_STEPS = 16
MAX_RECIPE_BYTES = 32768


class ActionParameter(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['string', 'integer', 'boolean']
    description: str = Field(default='', max_length=240)
    default: Any = None

    @model_validator(mode='after')
    def default_type(self):
        if self.default is not None and type(self.default) is not {'string':str,'integer':int,'boolean':bool}[self.type]:
            raise ValueError('Parameter default has the wrong type')
        return self


class ActionStep(BaseModel):
    model_config = ConfigDict(extra='forbid')
    capability: str = Field(min_length=1, max_length=120)
    input: dict[str, Any] = Field(default_factory=dict)
    description: str = Field(default='', max_length=240)

    @field_validator('capability')
    @classmethod
    def canonical(cls, value):
        from runtime.capability_registry import CAPABILITY_REGISTRY
        try:
            spec = CAPABILITY_REGISTRY.require(value)
        except KeyError as exc:
            raise ValueError('Use an existing canonical capability') from exc
        if not spec.planner_visible or not spec.hunt_executor or value.startswith('targets.actions.'):
            raise ValueError('Capability cannot be used in a saved action')
        return value


class TargetActionWrite(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=120)
    instructions: str = Field(default='', max_length=4000)
    steps: list[ActionStep] = Field(min_length=1, max_length=MAX_STEPS)
    parameters: dict[str, ActionParameter] = Field(default_factory=dict, max_length=16)
    expected_revision: StrictInt = Field(ge=0)

    @field_validator('name')
    @classmethod
    def nonblank(cls, value):
        if not value.strip() or '\x00' in value:
            raise ValueError('Enter an action name')
        return value.strip()

    @field_validator('parameters')
    @classmethod
    def safe_parameter_names(cls, values):
        for name in values:
            if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_]{0,63}', name):
                raise ValueError('Parameter names must be simple identifiers')
            if name.lower() in {'password','secret','private_key','token','authorization','cookie'}:
                raise ValueError('Use credential references instead of secret parameters')
        return values


def _record(row):
    metadata = row['metadata_json'] or {}
    if isinstance(metadata, str):
        metadata = json.loads(metadata)
    saved = metadata.get('hunt_actions') or {}
    return deepcopy(saved) if isinstance(saved, dict) else {}


def public_actions(row):
    saved = _record(row)
    return {'target_id':str(row['id']), 'revision':int(saved.get('revision') or 0),
            'actions':saved.get('actions') or [], 'max_actions':MAX_ACTIONS,
            'authority_granted':False}


async def read_target_actions(conn, target_id):
    return public_actions(await _target(conn, target_id))


def _check_parameters(value, parameters):
    if isinstance(value, dict):
        if '$parameter' in value:
            if set(value) != {'$parameter'} or value['$parameter'] not in parameters:
                raise ValueError('Parameter references must name a declared parameter')
        else:
            for key, nested in value.items():
                if key.lower() in {'password','secret','private_key','token','authorization','cookie'}:
                    raise ValueError('Use saved credential references instead of inline secrets')
                _check_parameters(nested, parameters)
    elif isinstance(value, list):
        for nested in value:
            _check_parameters(nested, parameters)


def resolve_steps(action, values=None):
    """Typed whole-value substitution; no shell interpolation or eval."""
    from runtime.capability_registry import CAPABILITY_REGISTRY
    values = dict(values or {})
    parameters = action.get('parameters') or {}
    if set(values) - set(parameters):
        raise HTTPException(422, 'Unknown action parameter')
    for name, definition in parameters.items():
        if name not in values:
            if definition.get('default') is None:
                raise HTTPException(422, f'Missing action parameter: {name}')
            values[name] = definition['default']
        expected = {'string':str, 'integer':int, 'boolean':bool}[definition['type']]
        if type(values[name]) is not expected:
            raise HTTPException(422, f'Invalid type for action parameter: {name}')
    def replace(value):
        if isinstance(value, dict):
            if set(value) == {'$parameter'}:
                return deepcopy(values[value['$parameter']])
            return {key:replace(nested) for key,nested in value.items()}
        if isinstance(value, list):
            return [replace(nested) for nested in value]
        return value
    steps = []
    for step in action['steps']:
        try:
            inputs = CAPABILITY_REGISTRY.validate_hunt_input(step['capability'], replace(step['input']))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        steps.append({**step, 'input':inputs})
    return steps


async def write_target_action(conn, target_id, operation, *, expected_revision,
                              action_id=None, request=None, source='operator:target-action-api'):
    async with conn.transaction():
        row = await _target(conn, target_id, lock=True)
        current = public_actions(row)
        if current['revision'] != expected_revision:
            raise HTTPException(409, 'Saved actions changed. Reload before saving.')
        identifier = str(UUID(str(action_id))) if action_id else str(uuid4())
        actions = current['actions']
        existing = next((item for item in actions if item['id'] == identifier), None)
        if operation in {'update','delete'} and not existing:
            raise HTTPException(404, 'Saved action not found on this target')
        if operation == 'create' and len(actions) >= MAX_ACTIONS:
            raise HTTPException(422, 'A target can save at most 32 actions')
        if operation not in {'create','update','delete'}:
            raise HTTPException(422, 'Unsupported saved action operation')
        actions = [item for item in actions if item['id'] != identifier]
        if operation != 'delete':
            if request is None:
                raise HTTPException(422, 'An action is required')
            recipe = request.model_dump(exclude={'expected_revision'})
            try:
                _check_parameters(recipe['steps'], recipe['parameters'])
                if not recipe['parameters']:
                    resolve_steps(recipe)
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from exc
            raw = json.dumps(recipe, sort_keys=True, ensure_ascii=False).encode()
            if len(raw) > MAX_RECIPE_BYTES:
                raise HTTPException(422, 'Saved action exceeds 32 KiB')
            actions.append({**recipe, 'id':identifier, 'target_id':str(row['id']),
                            'revision':current['revision']+1,
                            'body_sha256':hashlib.sha256(raw).hexdigest(),
                            'updated_at':datetime.now(timezone.utc).isoformat(),
                            'written_by':source})
        saved = {'revision':current['revision']+1, 'actions':actions}
        if len(json.dumps(saved).encode()) > 131072:
            raise HTTPException(422, 'Saved actions for this target exceed 128 KiB')
        updated = await conn.fetchrow("""UPDATE targets SET metadata_json=jsonb_set(
            COALESCE(metadata_json,'{}'::jsonb),'{hunt_actions}',$2::jsonb),updated_at=NOW()
            WHERE id=$1 RETURNING id,metadata_json""", row['id'], json.dumps(saved))
        return public_actions(updated)


def _pool():
    from .asset_router import pool
    return pool()


@router.get('/targets/{target_id}/actions')
async def list_target_actions(target_id: str):
    async with _pool().acquire() as conn:
        return await read_target_actions(conn, target_id)


@router.post('/targets/{target_id}/actions', status_code=201)
async def create_target_action(target_id: str, request: TargetActionWrite):
    async with _pool().acquire() as conn:
        return await write_target_action(conn, target_id, 'create',
            expected_revision=request.expected_revision, request=request)


@router.put('/targets/{target_id}/actions/{action_id}')
async def update_target_action(target_id: str, action_id: UUID, request: TargetActionWrite):
    async with _pool().acquire() as conn:
        return await write_target_action(conn, target_id, 'update', action_id=action_id,
            expected_revision=request.expected_revision, request=request)


@router.delete('/targets/{target_id}/actions/{action_id}')
async def delete_target_action(target_id: str, action_id: UUID, expected_revision: int = Query(...,ge=0)):
    async with _pool().acquire() as conn:
        return await write_target_action(conn, target_id, 'delete', action_id=action_id,
            expected_revision=expected_revision)
