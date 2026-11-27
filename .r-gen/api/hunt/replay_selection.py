"""One metadata-only selection for Hunt admission and replay queue dispatch."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import json
from typing import Any, Callable, Mapping

from fastapi import HTTPException
from capabilities.replay import require_hunt_replay_authority
from request_collection_api import select_request_collection_index_rows
from runtime.request_collection_store import RequestCollectionSelection


@dataclass(frozen=True)
class HuntReplaySelection:
    collection: Mapping[str, Any] = field(repr=False)
    reference: Mapping[str, Any] = field(repr=False)
    request_ids: tuple[str, ...]
    writes: int


async def select_hunt_replay(
    conn: Any, *, run: Mapping[str, Any], context: Mapping[str, Any], values: Mapping[str, Any],
    capability_name: str, load_collection: Callable[..., Any],
) -> HuntReplaySelection:
    policy = run['policy_json']
    if isinstance(policy, str):
        policy = json.loads(policy)
    row, ref = await load_collection(conn, run, context, values.get('collection_id'))
    if not ref.get('selection_id'):
        raise HTTPException(403, 'Replay requires a saved request collection selection')
    if values.get('selection_id') and str(values['selection_id']) != str(ref['selection_id']):
        raise HTTPException(409, 'Selection is not the one bound to this Hunt')
    try:
        active = require_hunt_replay_authority(capability_name, policy,
            replay_policy=str(ref.get('replay_policy') or ''))
        saved = RequestCollectionSelection.from_mapping(ref.get('selector') or {})
        saved = replace(saved, safe_methods_only=saved.safe_methods_only or not active)
        requested = RequestCollectionSelection(request_ids=tuple(values.get('request_ids') or ()),
            methods=tuple(values.get('methods') or ()), path_regex=values.get('path_regex'),
            safe_methods_only=not active, max_requests=min(25, int(values.get('limit') or 25)))
    except ValueError as exc:
        raise HTTPException(403, str(exc)) from exc
    rows = await conn.fetch('''SELECT request_id, ordinal, folder, name, method, redacted_url,
        normalized_path, body_mode, auth_type, tags_json, safe_method, supported
        FROM request_collection_requests WHERE collection_id=$1 ORDER BY ordinal LIMIT 20000''', row['id'])
    selected = select_request_collection_index_rows(rows, saved)
    selected = select_request_collection_index_rows(selected, requested)
    if not selected:
        raise HTTPException(422, 'Replay selection is empty')
    return HuntReplaySelection(row, ref, tuple(str(item['request_id']) for item in selected),
        sum(str(item['method']).upper() in {'POST', 'PUT', 'PATCH', 'DELETE'} for item in selected))
