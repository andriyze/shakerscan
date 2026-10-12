"""Human decision receipts and guarded reversal of existing target records.

This is an operator audit, not planner memory. Snapshots remain encrypted at the engine;
the console receives a redacted difference and an opaque receipt. Reversal changes the
same instruction, permission, interpretation and finding records as their normal routes.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import difflib
import hashlib
import json
from typing import Any, Awaitable, Callable, Literal
from uuid import UUID

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from .metadata_row import target_metadata_row
from .operator_identity import operator_identity
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 4000
LIFETIME = timedelta(hours=24)


class DecisionInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    receipt_id: UUID
    decision: Literal['accept', 'confirm', 'allow_changes', 'dismiss', 'reopen', 'retract',
                      'retract_hunt', 'release_marker']
    target_id: UUID
    subject_id: UUID | None = None
    text_sha256: str | None = Field(default=None, pattern=r'^[0-9a-f]{64}$')
    expected_revision: StrictInt | None = Field(default=None, ge=0)
    reason: Literal['false_positive', 'accepted_risk', 'duplicate'] | None = None
    note: str | None = Field(default=None, max_length=2000)
    release_label: str | None = Field(default=None, max_length=120)
    released_at: str | None = Field(default=None, max_length=100)

    @model_validator(mode='after')
    def shape(self):
        kind = self.decision
        if (self.subject_id is not None) != (kind in {'accept','dismiss','reopen','retract','retract_hunt'}):
            raise ValueError('Decision must name exactly its subject')
        if (self.text_sha256 is not None) != (kind in {'accept','confirm','release_marker'}):
            raise ValueError('Decision must name exactly its reviewed text')
        if (self.expected_revision is not None) != (kind in {'confirm','allow_changes'}):
            raise ValueError('Decision must name exactly its revision')
        if (self.reason is not None) != (kind == 'dismiss'):
            raise ValueError('Only dismissal names a reason')
        if kind != 'release_marker' and (self.release_label is not None or self.released_at is not None):
            raise ValueError('Only a release marker names release fields')
        if kind in {'dismiss','reopen','retract','retract_hunt'} and not (self.note or '').strip():
            raise ValueError('This decision needs a note')
        if self.note is not None and kind not in {'accept','dismiss','reopen','retract','retract_hunt'}:
            raise ValueError('This decision takes no note')
        return self


class RevertInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    receipt_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), default=str, ensure_ascii=True)


def _crypto():
    try:
        from secret_store import decrypt_secret, encrypt_secret
    except ModuleNotFoundError:
        from ..secret_store import decrypt_secret, encrypt_secret
    return encrypt_secret, decrypt_secret


def _sealed(value: Any) -> str:
    text = _canonical(value)
    if len(text.encode()) > MAX_SNAPSHOT_BYTES:
        raise HTTPException(422, 'Decision receipt is too large; review a smaller set of entries.')
    encrypt, _ = _crypto()
    try:
        return encrypt(text)
    except Exception as exc:
        # Never apply a decision without a durably encrypted inverse.
        raise HTTPException(503, 'Decision receipt encryption is unavailable') from exc


def _open(value: str) -> dict:
    _, decrypt = _crypto()
    return json.loads(decrypt(value))


def _redacted(value: Any) -> str:
    try:
        from redaction import redact_text
    except ModuleNotFoundError:
        from scanner.redaction import redact_text
    return redact_text(json.dumps(value, indent=2, sort_keys=True, default=str))


def public_receipt(row: Any) -> dict:
    shown = _json(row['display'])
    return {**shown, 'id': str(row['id']), 'receipt_sha256': row['receipt_sha256'],
            'created_at': row['created_at'].isoformat(),
            'revert_until': (row['created_at'] + LIFETIME).isoformat(),
            'reverted_at': row['reverted_at'].isoformat() if row['reverted_at'] else None,
            'reverted_by': row['reverted_by'], 'state': 'reverted' if row['reverted_at'] else 'applied'}


async def _snapshot(conn: Any, target: UUID, item: DecisionInput) -> dict:
    row = await target_metadata_row(conn, target, lock=True)
    if item.decision == 'allow_changes':
        from .hunt_authority import authority_row
        # Permissions live on the shared host asset, as on the canonical write route.
        # Bind that owner as well so a changed service/asset relationship blocks reversal.
        row = await authority_row(conn, target, lock=True)
    metadata = _json(row['metadata_json']) or {}
    kind = item.decision
    # Only the existing record being changed. Nothing about credential selections, grants,
    # scope, policy, network execution or proof is part of a reversible decision.
    keys = (['target_skill', 'hunt_actions'] if kind == 'accept' else
            ['target_skill'] if kind in {'confirm', 'retract', 'retract_hunt'} else
            ['hunt_authority'] if kind == 'allow_changes' else [])
    state: dict = {'metadata': {key: deepcopy(metadata.get(key)) for key in keys}}
    if kind == 'allow_changes':
        state['authority_owner'] = str(row['id'])
    if kind in {'dismiss', 'reopen'}:
        try:
            from hunt.interpretations import _finding_on_asset
        except ModuleNotFoundError:
            from ..hunt.interpretations import _finding_on_asset
        await _finding_on_asset(conn, target, item.subject_id, lock=True)
        finding = await conn.fetchrow('SELECT * FROM findings WHERE id=$1 FOR UPDATE', item.subject_id)
        state['finding'] = {key: finding[key] for key in
            ('id', 'status', 'analyst_verdict', 'analyst_verdict_at', 'analyst_verdict_notes',
             'notes', 'resolved_at', 'updated_at')}
    if kind in {'dismiss', 'reopen', 'retract', 'retract_hunt'}:
        rows = await conn.fetch('''SELECT id,status,status_changed_by,status_changed_at,status_note
            FROM target_interpretations WHERE target_id=$1 ORDER BY id LIMIT $2 FOR UPDATE''',
            target, MAX_ENTRIES + 1)
        if len(rows) > MAX_ENTRIES:
            raise HTTPException(422, 'Too many entries for one reversible decision.')
        state['entries'] = [dict(entry) for entry in rows]
    if kind == 'retract_hunt':
        hunt = await conn.fetchrow('SELECT notes FROM hunt_runs WHERE id=$1 AND COALESCE(target_id,device_target_id)=$2 FOR UPDATE',
                                  item.subject_id, target)
        if hunt is None:
            raise HTTPException(404, 'Hunt not found on this target')
        state['hunt_notes'] = _json(hunt['notes']) or []
    if kind == 'release_marker':
        rows = await conn.fetch('''SELECT id,retracted_at,retracted_by FROM target_release_markers
            WHERE target_id=$1 ORDER BY id FOR UPDATE''', target)
        state['markers'] = [dict(entry) for entry in rows]
    return json.loads(_canonical(state))


async def apply_decision(conn: Any, target: UUID, item: DecisionInput, actor: str,
                         *, perform: Callable[[str], Awaitable[dict]]) -> dict:
    if item.target_id != target:
        raise HTTPException(422, 'Decision target does not match the route')
    request_digest = hashlib.sha256(_canonical(item.model_dump(mode='json')).encode()).hexdigest()
    async with conn.transaction():
        await target_metadata_row(conn, target, lock=True)
        existing = await conn.fetchrow('SELECT * FROM target_operator_decisions WHERE id=$1 FOR UPDATE',
                                       item.receipt_id)
        if existing:
            if existing['target_id'] != target or existing['request_sha256'] != request_digest:
                raise HTTPException(409, 'Receipt id already names another decision')
            return {'decision_receipt': public_receipt(existing), 'result': _open(existing['snapshot'])['result']}
        before = await _snapshot(conn, target, item)
        # Check encryption and limits before applying; any later failure rolls back the same transaction.
        _sealed(before)
        result = await perform(actor)
        after = await _snapshot(conn, target, item)
        difference = '\n'.join(difflib.unified_diff(_redacted(before).splitlines(),
            _redacted(after).splitlines(), fromfile='before', tofile='after', lineterm=''))
        display = {'target_id': str(target), 'decision': item.decision,
            'subject_id': str(item.subject_id) if item.subject_id else None,
            'decided_by': actor, 'channel': 'terminal_stepup' if 'terminal step-up' in actor else
                'browser_stepup' if 'browser step-up' in actor else 'operator',
            'text_sha256': item.text_sha256, 'diff': difference[:16000], 'diff_truncated': len(difference) > 16000}
        sha = hashlib.sha256(_canonical(display).encode()).hexdigest()
        snapshot = _sealed({'before': before, 'after': after, 'request': item.model_dump(mode='json'),
                            'result': result})
        row = await conn.fetchrow('''INSERT INTO target_operator_decisions
            (id,target_id,request_sha256,receipt_sha256,display,snapshot)
            VALUES($1,$2,$3,$4,$5::jsonb,$6) RETURNING *''',
            item.receipt_id, target, request_digest, sha, _canonical(display), snapshot)
        return {'decision_receipt': public_receipt(row), 'result': result}


async def receipt_request(conn: Any, request: Request, target_id: Any, kind: str,
                          *, perform: Callable[[str], Awaitable[dict]], **values: Any) -> dict | None:
    """Optional receipt on the existing operator route. The gateway sets this opaque id only
    after the fresh step-up; it is never proof of authority and never accepted from a planner."""
    identifier = request.headers.get('x-shakerscan-decision-id')
    if identifier is None:
        return None
    from pydantic import ValidationError
    try:
        item = DecisionInput(receipt_id=identifier, target_id=target_id, decision=kind, **values)
    except ValidationError as exc:
        raise HTTPException(422, 'Invalid decision receipt request') from exc
    recorded = await apply_decision(conn, UUID(str(target_id)), item, operator_identity(request), perform=perform)
    return {**recorded['result'], 'decision_receipt': recorded['decision_receipt']}


async def _restore(conn: Any, target: UUID, item: DecisionInput, before: dict, after: dict, actor: str):
    row = await target_metadata_row(conn, target, lock=True)
    if item.decision == 'allow_changes':
        from .hunt_authority import authority_row
        row = await authority_row(conn, target, lock=True)
    metadata = _json(row['metadata_json']) or {}
    for key, value in before['metadata'].items():
        if value == after['metadata'].get(key):
            continue
        current = metadata.get(key) or {}
        restored = deepcopy(value) if value is not None else {}
        restored['revision'] = int(current.get('revision') or 0) + 1
        if key == 'target_skill':
            # Preserve the version being reversed as history; never mine it for effective
            # guidance. The original writer and trust of the restored version stay intact.
            historical = deepcopy(current)
            historical.pop('history', None)
            restored['history'] = [*(current.get('history') or []), historical][-20:]
        if key == 'hunt_authority':
            # Only instruction-edit delegation changes; every other permission stays as it is.
            restored = {**current, 'instruction_changes': bool((value or {}).get('instruction_changes')),
                        'revision': restored['revision'], 'recorded_by': actor}
        metadata[key] = restored
    await conn.execute('UPDATE targets SET metadata_json=$2::jsonb,updated_at=NOW() WHERE id=$1',
                       row['id'], _canonical(metadata))
    if 'finding' in before:
        finding = before['finding']
        await conn.execute('''UPDATE findings SET status=$2,analyst_verdict=$3,analyst_verdict_at=$4,
            analyst_verdict_notes=$5,notes=$6,resolved_at=$7,updated_at=NOW() WHERE id=$1''',
            UUID(finding['id']), finding['status'], finding['analyst_verdict'],
            datetime.fromisoformat(finding['analyst_verdict_at']) if finding['analyst_verdict_at'] else None,
            finding['analyst_verdict_notes'], finding['notes'],
            datetime.fromisoformat(finding['resolved_at']) if finding['resolved_at'] else None)
        try:
            from finding_routes.router import _refresh_finding_owner_counts
        except ModuleNotFoundError:
            from ..finding_routes.router import _refresh_finding_owner_counts
        owners = await conn.fetch('SELECT target_id,device_target_id FROM findings WHERE id=$1', UUID(finding['id']))
        await _refresh_finding_owner_counts(conn, owners)
    previous = {entry['id']: entry for entry in before.get('entries', [])}
    for entry in after.get('entries', []):
        old = previous.get(entry['id'])
        if old == entry:
            continue
        # New dismissal rows remain in history as reopened. No finding proof or interpretation
        # text is written here, and an old row's original writer/trust is retained.
        status = old['status'] if old else 'reopened'
        await conn.execute('''UPDATE target_interpretations SET status=$2,status_changed_by=$3,
            status_changed_at=NOW(),status_note=$4 WHERE id=$1 AND target_id=$5''',
            UUID(entry['id']), status, actor, 'Operator reverted the decision within 24 hours.', target)
    if 'hunt_notes' in before:
        await conn.execute('UPDATE hunt_runs SET notes=$2::jsonb,updated_at=NOW() WHERE id=$1 AND COALESCE(target_id,device_target_id)=$3',
                           item.subject_id, _canonical(before['hunt_notes']), target)
    existing = {entry['id'] for entry in before.get('markers', [])}
    for entry in after.get('markers', []):
        if entry['id'] not in existing:
            await conn.execute('''UPDATE target_release_markers SET retracted_at=NOW(),retracted_by=$2
                WHERE id=$1 AND target_id=$3''', UUID(entry['id']), actor, target)


async def revert_decision(conn: Any, target: UUID, receipt: UUID, sha: str, actor: str) -> dict:
    async with conn.transaction():
        await target_metadata_row(conn, target, lock=True)
        row = await conn.fetchrow('SELECT * FROM target_operator_decisions WHERE id=$1 AND target_id=$2 FOR UPDATE',
                                 receipt, target)
        if row is None:
            raise HTTPException(404, 'Decision receipt not found')
        if row['receipt_sha256'] != sha:
            raise HTTPException(409, 'Receipt does not match the decision reviewed')
        if row['reverted_at']:
            return public_receipt(row)
        if datetime.now(timezone.utc) > row['created_at'] + LIFETIME:
            raise HTTPException(409, 'The 24-hour reversal window has closed')
        snapshot = _open(row['snapshot'])
        item = DecisionInput.model_validate(snapshot['request'])
        current = await _snapshot(conn, target, item)
        if current != snapshot['after']:
            raise HTTPException(409, 'State changed after this decision; review the current records instead')
        await _restore(conn, target, item, snapshot['before'], snapshot['after'], actor)
        row = await conn.fetchrow('''UPDATE target_operator_decisions SET reverted_at=NOW(),reverted_by=$2
            WHERE id=$1 RETURNING *''', receipt, actor)
        return public_receipt(row)
