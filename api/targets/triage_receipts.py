"""Reversible receipts for the older triage writes (``legacy_triage``).

The finding routes ``PATCH /findings/{id}`` and ``POST /findings/bulk`` and the finding-exception
routes (create, update, delete) predate decision receipts. When a gateway attaches
``X-ShakerScan-Decision-Id`` after its human approval check, the engine records the same encrypted
before/after receipt the knowledge decisions use (``decision_receipts.apply_decision``), so the
decision can be reverted within 24 hours while its records still match the applied state.

What a receipt covers:

* findings: status, analyst verdict and its notes, notes and resolution time of every finding the
  request names (all on the receipt's target asset), and every dismissal entry of those findings
  (a status change ends an operator's dismissal; reverting restores it);
* a finding exception: the whole row (a reverted creation deletes it, a reverted update restores
  the previous values, a reverted deletion restores the row).

A receipt belongs to one target: a bulk change across targets, or an exception that names neither a
target nor a finding on one, is refused when a receipt is requested (the gateway splits it).
Nothing about scope, credentials or proof is touched.
"""
from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid5

from fastapi import HTTPException

FINDING_FIELDS = ('id', 'status', 'analyst_verdict', 'analyst_verdict_at', 'analyst_verdict_notes', 'notes',
                  'resolved_at', 'updated_at')
ENTRY_FIELDS = ('id', 'status', 'status_changed_by', 'status_changed_at', 'status_note', 'target_id')
TRIAGE_ROUTES = ('finding_patch', 'findings_bulk', 'exception_create', 'exception_update', 'exception_delete')
MAX_FINDINGS = 500
NOTE = 'Operator reverted the decision within 24 hours.'


def created_exception_id(receipt_id: Any) -> UUID:
    """The id a receipted exception creation uses, fixed by the receipt id (a retry names the same row)."""
    return uuid5(UUID(str(receipt_id)), 'finding-exception')


async def finding_owner(conn: Any, finding_ids: list[UUID]) -> UUID:
    """The one target asset every named finding belongs to (its web target, else its device)."""
    rows = await conn.fetch('SELECT DISTINCT COALESCE(target_id, device_target_id) AS owner FROM findings '
                            'WHERE id = ANY($1::uuid[])', finding_ids)
    owners = {row['owner'] for row in rows if row['owner'] is not None}
    if not rows:
        raise HTTPException(404, 'Finding not found')
    if len(owners) != 1:
        raise HTTPException(409, 'A reversible triage decision covers the findings of one target; split the request '
                                 'per target')
    return next(iter(owners))


async def exception_owner(conn: Any, *, target_id: Any = None, finding_id: Any = None) -> UUID:
    """The target a finding exception's receipt belongs to: its target, else its finding's."""
    if target_id:
        try:
            return UUID(str(target_id))
        except ValueError as exc:
            raise HTTPException(422, 'target_id must be a UUID') from exc
    if finding_id:
        try:
            identifier = UUID(str(finding_id))
        except ValueError:
            identifier = None
        if identifier is not None:
            owner = await conn.fetchval('SELECT COALESCE(target_id, device_target_id) FROM findings WHERE id=$1',
                                        identifier)
            if owner is not None:
                return owner
    raise HTTPException(422, 'A reversible exception decision needs a target: name target_id, or a finding_id of a '
                             'finding on a target')


async def snapshot(conn: Any, target: UUID, item: Any) -> dict:
    """The records a triage decision changes, locked, as they are now."""
    state: dict[str, Any] = {'entry_scope': 'decision/v2', 'triage_route': item.triage_route}
    if item.triage_route in {'finding_patch', 'findings_bulk'}:
        ids = sorted({UUID(str(value)) for value in item.finding_ids or ()})
        rows = await conn.fetch(f"""SELECT {', '.join(FINDING_FIELDS)}, COALESCE(target_id, device_target_id) AS owner
            FROM findings WHERE id = ANY($1::uuid[]) ORDER BY id FOR UPDATE""", ids)
        if any(row['owner'] != target for row in rows):
            raise HTTPException(409, 'A named finding is not on this target')
        state['findings'] = [{key: row[key] for key in FINDING_FIELDS} for row in rows]
        entries = await conn.fetch(f"""SELECT {', '.join(ENTRY_FIELDS)} FROM target_interpretations
            WHERE finding_id = ANY($1::uuid[]) ORDER BY id LIMIT 4001 FOR UPDATE""", ids)
        if len(entries) > 4000:
            raise HTTPException(422, 'Too many entries for one reversible decision.')
        state['entries'] = [{key: entry[key] for key in ENTRY_FIELDS} for entry in entries]
    else:
        row = await conn.fetchrow('SELECT * FROM finding_exceptions WHERE id=$1 FOR UPDATE', item.exception_id)
        state['exception'] = dict(row) if row is not None else None
    return json.loads(json.dumps(state, sort_keys=True, default=str))


async def restore(conn: Any, target: UUID, before: dict, after: dict, actor: str) -> None:
    """Put the records back as they were before the decision (the caller checked they still match
    the applied state)."""
    from datetime import datetime
    for finding in before.get('findings') or ():
        await conn.execute('''UPDATE findings SET status=$2,analyst_verdict=$3,analyst_verdict_at=$4,
            analyst_verdict_notes=$5,notes=$6,resolved_at=$7,updated_at=NOW() WHERE id=$1''',
            UUID(finding['id']), finding['status'], finding['analyst_verdict'],
            datetime.fromisoformat(finding['analyst_verdict_at']) if finding['analyst_verdict_at'] else None,
            finding['analyst_verdict_notes'], finding['notes'],
            datetime.fromisoformat(finding['resolved_at']) if finding['resolved_at'] else None)
    if before.get('findings'):
        try:
            from finding_routes.router import _refresh_finding_owner_counts
        except ModuleNotFoundError:
            from ..finding_routes.router import _refresh_finding_owner_counts
        owners = await conn.fetch('SELECT target_id, device_target_id FROM findings WHERE id = ANY($1::uuid[])',
                                  [UUID(item['id']) for item in before['findings']])
        await _refresh_finding_owner_counts(conn, owners)
    # Restoring a finding's dismissed status does not revive its dismissal on its own (the trigger
    # only ends dismissals): each entry the decision changed gets its earlier status back.
    previous = {entry['id']: entry for entry in before.get('entries') or ()}
    for entry in after.get('entries') or ():
        old = previous.get(entry['id'])
        if old is None or old == entry:
            continue
        await conn.execute('''UPDATE target_interpretations SET status=$2,status_changed_by=$3,
            status_changed_at=NOW(),status_note=$4 WHERE id=$1''', UUID(entry['id']), old['status'], actor, NOTE)
    if 'exception' in before:
        old, new = before['exception'], after.get('exception')
        identifier = UUID(str((old or new or {}).get('id')))
        await conn.execute('DELETE FROM finding_exceptions WHERE id=$1', identifier)
        if old is not None:
            await conn.execute("""INSERT INTO finding_exceptions
                SELECT * FROM jsonb_populate_record(NULL::finding_exceptions, $1::jsonb)""", json.dumps(old))


__all__ = ['TRIAGE_ROUTES', 'created_exception_id', 'exception_owner', 'finding_owner', 'restore', 'snapshot']
