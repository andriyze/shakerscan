"""Mark stored instructions and saved actions that no operator wrote as agent-written, unconfirmed.

Before instruction edits had their own opt-in, a Hunt with metadata delegation could write a
target's instructions and saved actions, and they were then treated as operator guidance. This
migration stamps every such record ``origin: agent_unconfirmed`` so it is presented to Hunts as
advisory notes until an operator saves it (an operator write replaces the record, clearing the mark).

The rule is conservative: an instruction record or saved action whose last writer cannot be shown
to be an operator (``written_by`` of ``operator:...``), and was not written under the explicit
instruction_changes opt-in, is marked. The mark only ever demotes trust.

It runs on every startup from the always-run path (api/targets/asset_migration.py
``run_unified_startup``), including on databases converted long ago, and is idempotent: a
marked record is never rewritten, and a database with nothing to mark pays one read.
"""
from __future__ import annotations

import json
from typing import Any

from .skill_trust import AGENT_UNCONFIRMED, EFFECTIVE_TRUST, action_trust, instruction_trust

# Only rows that may need a mark, and only the two sub-documents. The Python rule below is the
# authority; this predicate is a superset of it so a database with nothing to mark reads no JSON.
_DOCUMENT_NEEDS = """(d ? 'methodology' AND COALESCE(d->>'purpose','instructions') <> 'knowledge'
      AND d->>'origin' IS NULL
      AND (COALESCE(d->>'written_by','') NOT LIKE 'operator:%'
           OR COALESCE(d->>'instruction_authority','') = 'target_metadata_delegation')
      AND NOT (COALESCE(d->>'written_by','') LIKE 'hunt:%'
               AND COALESCE(d->>'instruction_authority','') = 'target_instruction_delegation'))"""
CANDIDATES_SQL = f"""SELECT id, metadata_json->'target_skill' AS target_skill,
           metadata_json->'hunt_actions' AS hunt_actions
    FROM targets
    WHERE jsonb_typeof(metadata_json) = 'object' AND (
        (jsonb_typeof(metadata_json->'target_skill') = 'object' AND (
            (SELECT {_DOCUMENT_NEEDS} FROM (SELECT metadata_json->'target_skill' AS d) s)
            OR (jsonb_typeof(metadata_json->'target_skill'->'operator_snapshot') = 'object'
                AND (SELECT {_DOCUMENT_NEEDS}
                     FROM (SELECT metadata_json->'target_skill'->'operator_snapshot' AS d) s))))
        OR (jsonb_typeof(metadata_json->'hunt_actions'->'actions') = 'array' AND EXISTS (
            SELECT 1 FROM jsonb_array_elements(metadata_json->'hunt_actions'->'actions') a(item)
            WHERE jsonb_typeof(item) = 'object' AND item->>'origin' IS NULL
              AND COALESCE(item->>'written_by','') NOT LIKE 'operator:%'
              AND NOT (COALESCE(item->>'written_by','') LIKE 'hunt:%'
                       AND COALESCE(item->>'instruction_authority','') = 'target_instruction_delegation'))))"""


def _object(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except ValueError:  # a JSON string scalar that is not itself JSON: nothing to mark
        return value


def _needs_mark(document: Any) -> bool:
    if not isinstance(document, dict) or not document.get('methodology'):
        return False
    # A record that already carries an origin (this engine's or a later one's) is never re-marked.
    if document.get('purpose', 'instructions') == 'knowledge' or document.get('origin') is not None:
        return False
    return instruction_trust(document) not in EFFECTIVE_TRUST


def marked(metadata: Any) -> dict[str, Any] | None:
    """The changed ``target_skill``/``hunt_actions`` values, or None when nothing needs marking."""
    metadata = _object(metadata)
    if not isinstance(metadata, dict):
        return None
    changes: dict[str, Any] = {}
    record = metadata.get('target_skill')
    if isinstance(record, dict):
        record = json.loads(json.dumps(record))
        changed = False
        if _needs_mark(record):
            record['origin'] = AGENT_UNCONFIRMED
            changed = True
        if _needs_mark(record.get('operator_snapshot')):
            record['operator_snapshot']['origin'] = AGENT_UNCONFIRMED
            changed = True
        if changed:
            changes['target_skill'] = record
    saved = metadata.get('hunt_actions')
    if isinstance(saved, dict) and isinstance(saved.get('actions'), list):
        saved = json.loads(json.dumps(saved))
        changed = False
        for item in saved['actions']:
            if (isinstance(item, dict) and item.get('origin') is None
                    and action_trust(item) == AGENT_UNCONFIRMED):
                item['origin'] = AGENT_UNCONFIRMED
                changed = True
        if changed:
            changes['hunt_actions'] = saved
    return changes or None


async def mark_unconfirmed_agent_writes(conn: Any) -> int:
    """Stamp unconfirmed agent-written records; returns how many targets changed."""
    changed = 0
    for candidate in await conn.fetch(CANDIDATES_SQL):
        subset = {key: _object(candidate[key]) for key in ('target_skill', 'hunt_actions')
                  if candidate[key] is not None}
        if marked(subset) is None:
            continue
        # Re-read under a row lock so a concurrent write is never overwritten with older data.
        row = await conn.fetchrow('SELECT id, metadata_json FROM targets WHERE id=$1 FOR UPDATE', candidate['id'])
        changes = marked(row['metadata_json']) if row is not None else None
        if not changes:
            continue
        for key, value in changes.items():
            await conn.execute("""UPDATE targets SET metadata_json=jsonb_set(metadata_json, $2::text[], $3::jsonb)
                WHERE id=$1""", row['id'], [key], json.dumps(value))
        changed += 1
    return changed


__all__ = ['CANDIDATES_SQL', 'mark_unconfirmed_agent_writes', 'marked']
