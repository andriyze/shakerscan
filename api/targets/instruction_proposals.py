"""Reviewable proposals to change a target's operator instructions or saved actions.

A proposal is advisory data: the full replacement text a Hunt (or an operator) suggests, the exact
revision it was written against, a reason and references to existing records. Nothing here changes
instructions except ``accept``, an operator route that applies the text through the ordinary
revision-checked operator write. Proposal text is never loaded into a Hunt's instructions, briefing
or planner context while it is pending.

A proposal is *stale* when the target's instructions changed after its base revision (advisory
knowledge writes share the revision counter but do not make a proposal stale). A stale proposal
cannot be accepted; ``rebase`` re-files the same text against the current instructions as a new
pending proposal so the operator reviews the new difference before accepting.

Saved actions shape future Hunts like instructions do. A Hunt without the instruction_changes
setting that creates, updates or deletes a saved action files a ``saved_action`` proposal here
instead; it is listed, diffed, accepted, rejected and rebased the same way. A saved-action
proposal is stale whenever the target's saved actions changed after its base revision.
"""
from __future__ import annotations

import difflib
import re
import hashlib
import json
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError, field_validator

from .metadata_row import target_metadata_row as _target
from .skill import TargetSkillWrite, read_target_skill, write_target_skill
from .actions import (TargetActionWrite, _invisible, find_action, read_target_actions, review_text,
                      validated_recipe, write_target_action)

try:
    from runtime.asset_capability_specs import (
        MAX_PROPOSALS_PER_HUNT,
        MAX_TARGET_SKILL_CHARACTERS,
    )
except ModuleNotFoundError:
    from ..runtime.asset_capability_specs import (
        MAX_PROPOSALS_PER_HUNT,
        MAX_TARGET_SKILL_CHARACTERS,
    )

from .instruction_proposal_schema import (  # noqa: F401 - re-exported
    INSTRUCTION_PROPOSAL_SCHEMA_SQL, MAX_REASON_CHARACTERS, MAX_SAVED_ACTION_REVIEW_CHARACTERS,
    MAX_TITLE_CHARACTERS, PROPOSAL_KINDS,
)

router = APIRouter(tags=['targets'])

PROPOSAL_STATUSES = ('pending', 'accepted', 'rejected', 'superseded')
MAX_PENDING_PER_TARGET = 20
MAX_EVIDENCE_REFS = 20
MAX_DIFF_CHARACTERS = 40_000
LIST_LIMIT = 100
DEFAULT_INSTRUCTION_TITLE = 'Target instructions'
ACCEPT_SOURCE = 'operator:instruction-proposal'
ACTION_ACCEPT_SOURCE = 'operator:saved-action-proposal'


CONTROL_CHARACTERS = re.compile(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]')
BIDI_CONTROLS = re.compile('[\u202a-\u202e\u2066-\u2069]')


def _record_ids(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        try:
            identifier = str(UUID(str(value)))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError('evidence_refs are ids of existing records (UUIDs)') from exc
        if identifier not in result:
            result.append(identifier)
    return result


class ProposalText(BaseModel):
    model_config = ConfigDict(extra='forbid')
    title: str = Field(min_length=1, max_length=MAX_TITLE_CHARACTERS)
    methodology: str = Field(min_length=1, max_length=MAX_TARGET_SKILL_CHARACTERS)
    reason: str = Field(min_length=1, max_length=MAX_REASON_CHARACTERS)
    base_revision: StrictInt = Field(ge=0)
    evidence_refs: list[str] = Field(default_factory=list, max_length=MAX_EVIDENCE_REFS)

    @field_validator('title', 'methodology', 'reason')
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip() or '\x00' in value:
            raise ValueError('Enter nonblank text without null characters')
        # Reviewers read proposals in a terminal: control sequences, invisible format characters
        # (zero-width, direction marks, tag characters) and line separators could hide or rewrite
        # the diff, so the text a reviewer accepts would not be the text Hunts read.
        if CONTROL_CHARACTERS.search(value) or any(_invisible(ch) for ch in value):
            raise ValueError('Proposal text may not contain control, invisible formatting or line-separator '
                             'characters other than newline and tab')
        return value.strip()

    @field_validator('evidence_refs')
    @classmethod
    def record_ids(cls, values: list[str]) -> list[str]:
        return _record_ids(values)


class ActionProposalNote(BaseModel):
    """What a Hunt may add to a saved-action write that becomes a proposal."""
    model_config = ConfigDict(extra='forbid')
    reason: str = Field(default='', max_length=MAX_REASON_CHARACTERS)
    evidence_refs: list[str] = Field(default_factory=list, max_length=MAX_EVIDENCE_REFS)

    @field_validator('reason')
    @classmethod
    def plain(cls, value: str) -> str:
        if CONTROL_CHARACTERS.search(value) or '\x00' in value or any(_invisible(ch) for ch in value):
            raise ValueError('Proposal text may not contain control, invisible formatting or line-separator '
                             'characters other than newline and tab')
        return value.strip()

    @field_validator('evidence_refs')
    @classmethod
    def record_ids(cls, values: list[str]) -> list[str]:
        return _record_ids(values)


class ProposalDecision(BaseModel):
    model_config = ConfigDict(extra='forbid')
    note: str | None = Field(default=None, max_length=MAX_REASON_CHARACTERS)
    # The digest of the text the reviewer saw; when sent, accept applies only that exact text.
    methodology_sha256: str | None = Field(default=None, pattern=r'^[0-9a-f]{64}$')


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def instruction_base(current: dict[str, Any]) -> tuple[int | None, str | None, str]:
    """(revision at which the instructions were last written, their digest, their text)."""
    document = current.get('operator_skill')
    if not document:
        return None, None, ''
    try:
        version = int(document.get('version'))
    except (TypeError, ValueError):
        version = None
    return version, document.get('body_sha256'), str(document.get('methodology') or '')


def _kind(row: Any) -> str:
    try:
        return row['kind'] or 'instructions'
    except (KeyError, IndexError):
        return 'instructions'


def _action_body(row: Any) -> dict[str, Any] | None:
    body = row['action_body']
    return json.loads(body) if isinstance(body, str) else (dict(body) if body is not None else None)


def action_review_pair(row: Any, actions: dict[str, Any]) -> tuple[str, str]:
    """(current text, proposed text) of a saved-action proposal, as the reviewer reads them."""
    existing = find_action(actions, row['action_id']) if row['action_id'] else None
    before = review_text(existing) if existing else ''
    after = '' if row['action_operation'] == 'delete' else row['methodology']
    return before, after


def is_stale(row: Any, current: dict[str, Any]) -> bool:
    if _kind(row) == 'saved_action':
        return int(current['revision']) != int(row['base_revision'])
    version, digest, _ = instruction_base(current)
    if digest != row['base_sha256']:
        return True
    return version is not None and version > int(row['base_revision'])


def unified_diff(before: str, after: str,
                 labels: tuple[str, str] = ('current instructions', 'proposed instructions')) -> dict[str, Any]:
    # Split on newline only: str.splitlines also breaks at U+2028 and friends, which would show
    # line breaks the stored text does not have.
    lines = list(difflib.unified_diff(before.split('\n') if before else [], after.split('\n') if after else [],
                                      labels[0], labels[1], lineterm=''))
    text = '\n'.join(lines)
    truncated = len(text) > MAX_DIFF_CHARACTERS
    return {'format': 'unified', 'text': text[:MAX_DIFF_CHARACTERS], 'truncated': truncated,
            'added_lines': sum(1 for line in lines if line.startswith('+') and not line.startswith('+++')),
            'removed_lines': sum(1 for line in lines if line.startswith('-') and not line.startswith('---'))}


def public_proposal(row: Any, current: dict[str, Any] | None = None, *, include_text: bool = True) -> dict[str, Any]:
    refs = row['evidence_refs']
    if isinstance(refs, str):
        refs = json.loads(refs)
    result = {
        'id': str(row['id']), 'target_id': str(row['target_id']), 'status': row['status'],
        'title': row['title'], 'reason': row['reason'], 'evidence_refs': list(refs or []),
        'proposed_by': row['proposed_by'],
        'hunt_id': str(row['hunt_run_id']) if row['hunt_run_id'] else None,
        'base_revision': int(row['base_revision']), 'base_sha256': row['base_sha256'],
        'methodology_sha256': row['methodology_sha256'], 'characters': len(row['methodology']),
        'rebased_from': str(row['rebased_from']) if row['rebased_from'] else None,
        'decided_by': row['decided_by'], 'decision_note': row['decision_note'],
        'decided_at': row['decided_at'].isoformat() if row['decided_at'] else None,
        'applied_revision': row['applied_revision'],
        'created_at': row['created_at'].isoformat() if row['created_at'] else None,
        'advisory': True, 'authority_granted': False, 'kind': _kind(row),
    }
    if result['kind'] == 'saved_action':
        result['action_operation'] = row['action_operation']
        result['action_id'] = str(row['action_id']) if row['action_id'] else None
    if include_text:
        result['methodology'] = row['methodology']
    if current is not None and row['status'] == 'pending':
        if result['kind'] == 'saved_action':
            before, after = action_review_pair(row, current)
            labels = ('current saved action', 'proposed saved action')
        else:
            _, _, before = instruction_base(current)
            after, labels = row['methodology'], ('current instructions', 'proposed instructions')
        result['stale'] = is_stale(row, current)
        result['current_revision'] = current['revision']
        result['diff'] = unified_diff(before, after, labels)
    return result


async def _unknown_evidence(conn: Any, target_id: Any, refs: list[str]) -> list[str]:
    """Refs that are not records of this target's asset (actions, receipts, findings, candidates, scans)."""
    if not refs:
        return []
    found = await conn.fetch("""
        SELECT r.id FROM unnest($1::uuid[]) AS r(id)
        WHERE EXISTS (SELECT 1 FROM hunt_actions a JOIN hunt_runs h ON h.id=a.hunt_run_id
                      WHERE (a.id=r.id OR a.receipt_id=r.id)
                        AND target_asset_access_owner(h.target_id)=target_asset_access_owner($2))
           OR EXISTS (SELECT 1 FROM findings f WHERE f.id=r.id
                        AND target_asset_access_owner(f.target_id)=target_asset_access_owner($2))
           OR EXISTS (SELECT 1 FROM investigation_candidates c WHERE c.id=r.id
                        AND target_asset_access_owner(c.target_id)=target_asset_access_owner($2))
           OR EXISTS (SELECT 1 FROM scans s WHERE s.id=r.id
                        AND target_asset_access_owner(s.target_id)=target_asset_access_owner($2))
    """, [UUID(ref) for ref in refs], target_id)
    known = {str(item['id']) for item in found}
    return [ref for ref in refs if ref not in known]


async def create_proposal(conn: Any, target_id: Any, proposal: ProposalText, *,
                          proposed_by: str, hunt_run_id: Any = None) -> dict[str, Any]:
    """File one pending proposal. Never changes instructions or any authority."""
    async with conn.transaction():
        row = await _target(conn, target_id, lock=True)
        current = await read_target_skill(conn, row['id'])
        if proposal.base_revision != current['revision']:
            raise HTTPException(409, {
                'error': 'proposal_base_changed', 'current_revision': current['revision'],
                'message': 'The target instructions changed. Read them again with targets.skill.read '
                           'and base the proposal on the current revision.'})
        _, digest, text = instruction_base(current)
        if text == proposal.methodology:
            raise HTTPException(422, 'The proposed text is identical to the current instructions')
        if hunt_run_id is not None:
            filed = await conn.fetchval("""SELECT count(*) FROM target_instruction_proposals
                WHERE proposed_by=$1 AND rebased_from IS NULL AND kind='instructions'""", proposed_by)
            if filed >= MAX_PROPOSALS_PER_HUNT:
                raise HTTPException(429, {
                    'error': 'proposal_limit', 'limit': MAX_PROPOSALS_PER_HUNT,
                    'message': f'A Hunt may file at most {MAX_PROPOSALS_PER_HUNT} instruction proposals.'})
        unknown = await _unknown_evidence(conn, row['id'], proposal.evidence_refs)
        if unknown:
            raise HTTPException(422, {
                'error': 'unknown_evidence_refs', 'evidence_refs': unknown,
                'message': 'evidence_refs must name existing Hunt actions or receipts, findings, candidates '
                           'or scans on this target\u2019s asset.'})
        if proposed_by.startswith('hunt:'):
            # A Hunt's newer proposal replaces its own earlier pending one. Operator proposals
            # share one provenance on an engine without accounts, so they never supersede.
            await conn.execute("""UPDATE target_instruction_proposals
                SET status='superseded', decided_at=NOW(), decided_by=$3
                WHERE target_id=$1 AND proposed_by=$2 AND status='pending' AND kind='instructions'""",
                               row['id'], proposed_by, proposed_by)
        await _check_pending_quota(conn, row['id'], proposed_by, 'instructions')
        saved = await conn.fetchrow("""INSERT INTO target_instruction_proposals(
                target_id, base_revision, base_sha256, title, methodology, methodology_sha256,
                reason, evidence_refs, proposed_by, hunt_run_id)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10) RETURNING *""",
            row['id'], proposal.base_revision, digest, proposal.title, proposal.methodology,
            _sha(proposal.methodology), proposal.reason, json.dumps(proposal.evidence_refs),
            proposed_by, hunt_run_id)
        return public_proposal(saved, current)


async def _check_pending_quota(conn: Any, target_id: Any, proposed_by: str, kind: str) -> None:
    # Hunts and operators have separate pending quotas per kind, so Hunts cannot crowd out
    # operators, and saved-action proposals cannot crowd out instruction proposals.
    pending = await conn.fetchval("""SELECT count(*) FROM target_instruction_proposals
        WHERE target_id=$1 AND status='pending' AND kind=$3 AND (proposed_by LIKE 'hunt:%') = $2""",
                                  target_id, proposed_by.startswith('hunt:'), kind)
    if pending >= MAX_PENDING_PER_TARGET:
        raise HTTPException(429, {
            'error': 'pending_proposal_limit', 'limit': MAX_PENDING_PER_TARGET,
            'message': 'This target already has the maximum number of proposals waiting for review.'})


def _action_title(operation: str, name: str) -> str:
    shown = BIDI_CONTROLS.sub('?', CONTROL_CHARACTERS.sub('?', name)).replace('\n', ' ').replace('\t', ' ')
    return f'{operation.capitalize()} saved action: {shown}'[:MAX_TITLE_CHARACTERS]


async def create_action_proposal(conn: Any, target_id: Any, operation: str, *, expected_revision: int,
                                 action_id: Any = None, request: TargetActionWrite | None = None,
                                 note: ActionProposalNote | None = None, proposed_by: str,
                                 hunt_run_id: Any = None) -> dict[str, Any]:
    """File a saved-action change for operator review. Never changes saved actions or authority."""
    if operation not in {'create', 'update', 'delete'}:
        raise HTTPException(422, 'Unsupported saved action operation')
    note = note or ActionProposalNote()
    async with conn.transaction():
        row = await _target(conn, target_id, lock=True)
        actions = await read_target_actions(conn, row['id'])
        if expected_revision != actions['revision']:
            raise HTTPException(409, 'Saved actions changed. Reload before saving.')
        existing = None
        if operation == 'create':
            action_id = None
        else:
            if action_id is None:
                raise HTTPException(422, 'action_id is required')
            existing = find_action(actions, action_id)
            if existing is None:
                raise HTTPException(404, 'Saved action not found on this target')
        body = None
        if operation == 'delete':
            text = review_text(existing)
            name = existing.get('name') or ''
        else:
            if request is None:
                raise HTTPException(422, 'An action is required')
            body, _ = validated_recipe(request)
            text = review_text(body)
            name = body['name']
            if existing is not None and review_text(existing) == text:
                raise HTTPException(422, 'The proposed action is identical to the saved action')
        if len(text) > MAX_SAVED_ACTION_REVIEW_CHARACTERS:
            raise HTTPException(422, 'The saved action is too large to review as a proposal')
        if hunt_run_id is not None:
            filed = await conn.fetchval("""SELECT count(*) FROM target_instruction_proposals
                WHERE proposed_by=$1 AND rebased_from IS NULL AND kind='saved_action'""", proposed_by)
            if filed >= MAX_PROPOSALS_PER_HUNT:
                raise HTTPException(429, {
                    'error': 'proposal_limit', 'limit': MAX_PROPOSALS_PER_HUNT,
                    'message': f'A Hunt may file at most {MAX_PROPOSALS_PER_HUNT} saved-action proposals.'})
        unknown = await _unknown_evidence(conn, row['id'], note.evidence_refs)
        if unknown:
            raise HTTPException(422, {
                'error': 'unknown_evidence_refs', 'evidence_refs': unknown,
                'message': 'evidence_refs must name existing Hunt actions or receipts, findings, candidates '
                           'or scans on this target\u2019s asset.'})
        if proposed_by.startswith('hunt:') and action_id is not None:
            # A Hunt's newer proposal for the same saved action replaces its own earlier pending one.
            await conn.execute("""UPDATE target_instruction_proposals
                SET status='superseded', decided_at=NOW(), decided_by=$2
                WHERE target_id=$1 AND proposed_by=$2 AND status='pending' AND kind='saved_action'
                  AND action_id=$3""", row['id'], proposed_by, UUID(str(action_id)))
        await _check_pending_quota(conn, row['id'], proposed_by, 'saved_action')
        reason = note.reason or ('Proposed by a Hunt without the instruction_changes setting; '
                                 'no reason was given.' if proposed_by.startswith('hunt:') else 'No reason given.')
        saved = await conn.fetchrow("""INSERT INTO target_instruction_proposals(
                target_id, base_revision, base_sha256, title, methodology, methodology_sha256,
                reason, evidence_refs, proposed_by, hunt_run_id, kind, action_operation, action_id, action_body)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,'saved_action',$11,$12,$13::jsonb) RETURNING *""",
            row['id'], actions['revision'], (existing or {}).get('body_sha256'), _action_title(operation, name),
            text, _sha(text), reason[:MAX_REASON_CHARACTERS], json.dumps(note.evidence_refs), proposed_by,
            hunt_run_id, operation, UUID(str(action_id)) if action_id else None,
            json.dumps(body) if body is not None else None)
        return public_proposal(saved, actions)


async def _current(conn: Any, target_id: Any, kind: str) -> dict[str, Any]:
    if kind == 'saved_action':
        return await read_target_actions(conn, target_id)
    return await read_target_skill(conn, target_id)


async def pending_count(conn: Any, target_id: Any) -> int:
    return int(await conn.fetchval("""SELECT count(*) FROM target_instruction_proposals
        WHERE target_id=$1 AND status='pending'""", target_id) or 0)


async def _locked_proposal(conn: Any, target_id: Any, proposal_id: str) -> tuple[Any, Any]:
    row = await _target(conn, target_id, lock=True)
    try:
        identifier = UUID(str(proposal_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(400, 'Invalid proposal id') from exc
    proposal = await conn.fetchrow("""SELECT * FROM target_instruction_proposals
        WHERE id=$1 AND target_id=$2 FOR UPDATE""", identifier, row['id'])
    if proposal is None:
        raise HTTPException(404, 'Instruction proposal not found')
    if proposal['status'] != 'pending':
        raise HTTPException(409, {'error': 'proposal_not_pending', 'status': proposal['status'],
                                  'message': f"This proposal is already {proposal['status']}."})
    return row, proposal


async def accept_proposal(conn: Any, target_id: Any, proposal_id: str, *, actor: str,
                          note: str | None = None, reviewed_sha256: str | None = None) -> dict[str, Any]:
    async with conn.transaction():
        row, proposal = await _locked_proposal(conn, target_id, proposal_id)
        if reviewed_sha256 is not None and reviewed_sha256 != proposal['methodology_sha256']:
            raise HTTPException(409, {'error': 'proposal_text_mismatch',
                                      'message': 'This proposal is not the text that was reviewed.'})
        if _kind(proposal) == 'saved_action':
            return await _accept_action(conn, row, proposal, actor=actor, note=note)
        current = await read_target_skill(conn, row['id'])
        if is_stale(proposal, current):
            raise HTTPException(409, {
                'error': 'proposal_stale', 'base_revision': int(proposal['base_revision']),
                'current_revision': current['revision'],
                'message': 'The instructions changed after this proposal was made. Rebase it onto the '
                           'current instructions and review the new difference before accepting.'})
        existing = current.get('operator_skill')
        request = TargetSkillWrite(
            title=(existing or {}).get('title') or DEFAULT_INSTRUCTION_TITLE,
            methodology=proposal['methodology'], expected_revision=current['revision'],
            purpose='instructions')
        written = await write_target_skill(
            conn, row['id'], 'update' if existing else 'create',
            expected_revision=current['revision'], request=request, source=ACCEPT_SOURCE)
        decided = await conn.fetchrow("""UPDATE target_instruction_proposals
            SET status='accepted', decided_by=$2, decided_at=NOW(), decision_note=$3, applied_revision=$4
            WHERE id=$1 RETURNING *""", proposal['id'], actor, note, written['revision'])
        return {'proposal': public_proposal(decided), 'instructions': written}


def _stale_refusal(proposal: Any, current: dict[str, Any], what: str) -> HTTPException:
    return HTTPException(409, {
        'error': 'proposal_stale', 'base_revision': int(proposal['base_revision']),
        'current_revision': current['revision'],
        'message': f'The {what} changed after this proposal was made. Rebase it onto the '
                   'current version and review the new difference before accepting.'})


async def _accept_action(conn: Any, row: Any, proposal: Any, *, actor: str, note: str | None) -> dict[str, Any]:
    current = await read_target_actions(conn, row['id'])
    if is_stale(proposal, current):
        raise _stale_refusal(proposal, current, 'saved actions')
    operation = proposal['action_operation']
    request = None
    if operation != 'delete':
        try:
            request = TargetActionWrite(**_action_body(proposal), expected_revision=current['revision'])
        except (ValidationError, TypeError) as exc:
            raise HTTPException(422, {'error': 'proposal_invalid',
                                      'message': 'The proposed saved action is no longer valid; reject it.'}) from exc
    # The operator's decision is the write: it is recorded as an operator write.
    written = await write_target_action(conn, row['id'], operation, expected_revision=current['revision'],
                                        action_id=proposal['action_id'], request=request,
                                        source=ACTION_ACCEPT_SOURCE)
    decided = await conn.fetchrow("""UPDATE target_instruction_proposals
        SET status='accepted', decided_by=$2, decided_at=NOW(), decision_note=$3, applied_revision=$4
        WHERE id=$1 RETURNING *""", proposal['id'], actor, note, written['revision'])
    return {'proposal': public_proposal(decided), 'saved_actions': written}


async def _rebase_action(conn: Any, row: Any, proposal: Any, *, actor: str) -> dict[str, Any]:
    current = await read_target_actions(conn, row['id'])
    if not is_stale(proposal, current):
        raise HTTPException(409, {'error': 'proposal_current',
                                  'message': 'This proposal is already based on the current saved actions.'})
    await conn.execute("""UPDATE target_instruction_proposals
        SET status='superseded', decided_by=$2, decided_at=NOW(), decision_note='rebased'
        WHERE id=$1""", proposal['id'], actor)
    operation = proposal['action_operation']
    existing = find_action(current, proposal['action_id']) if proposal['action_id'] else None
    if operation != 'create' and existing is None:
        return {'proposal': None, 'superseded': str(proposal['id']),
                'message': 'The saved action no longer exists.'}
    text = review_text(existing) if operation == 'delete' else proposal['methodology']
    if operation == 'update' and review_text(existing) == text:
        return {'proposal': None, 'superseded': str(proposal['id']),
                'message': 'The saved action already matches the proposal.'}
    refs = proposal['evidence_refs']
    rebased = await conn.fetchrow("""INSERT INTO target_instruction_proposals(
            target_id, base_revision, base_sha256, title, methodology, methodology_sha256,
            reason, evidence_refs, proposed_by, hunt_run_id, rebased_from,
            kind, action_operation, action_id, action_body)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,'saved_action',$12,$13,$14::jsonb) RETURNING *""",
        row['id'], current['revision'], (existing or {}).get('body_sha256'), proposal['title'], text, _sha(text),
        proposal['reason'], json.dumps(json.loads(refs) if isinstance(refs, str) else list(refs or [])),
        proposal['proposed_by'], proposal['hunt_run_id'], proposal['id'], operation, proposal['action_id'],
        json.dumps(_action_body(proposal)) if proposal['action_body'] is not None else None)
    return {'proposal': public_proposal(rebased, current), 'superseded': str(proposal['id'])}


async def reject_proposal(conn: Any, target_id: Any, proposal_id: str, *, actor: str,
                          note: str | None = None) -> dict[str, Any]:
    async with conn.transaction():
        _, proposal = await _locked_proposal(conn, target_id, proposal_id)
        decided = await conn.fetchrow("""UPDATE target_instruction_proposals
            SET status='rejected', decided_by=$2, decided_at=NOW(), decision_note=$3
            WHERE id=$1 RETURNING *""", proposal['id'], actor, note)
        return {'proposal': public_proposal(decided)}


async def rebase_proposal(conn: Any, target_id: Any, proposal_id: str, *, actor: str) -> dict[str, Any]:
    """Re-file a stale proposal's text against the current instructions, for a fresh review."""
    async with conn.transaction():
        row, proposal = await _locked_proposal(conn, target_id, proposal_id)
        if _kind(proposal) == 'saved_action':
            return await _rebase_action(conn, row, proposal, actor=actor)
        current = await read_target_skill(conn, row['id'])
        if not is_stale(proposal, current):
            raise HTTPException(409, {'error': 'proposal_current',
                                      'message': 'This proposal is already based on the current instructions.'})
        _, digest, text = instruction_base(current)
        await conn.execute("""UPDATE target_instruction_proposals
            SET status='superseded', decided_by=$2, decided_at=NOW(), decision_note='rebased'
            WHERE id=$1""", proposal['id'], actor)
        if text == proposal['methodology']:
            return {'proposal': None, 'superseded': str(proposal['id']),
                    'message': 'The current instructions already contain the proposed text.'}
        rebased = await conn.fetchrow("""INSERT INTO target_instruction_proposals(
                target_id, base_revision, base_sha256, title, methodology, methodology_sha256,
                reason, evidence_refs, proposed_by, hunt_run_id, rebased_from)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11) RETURNING *""",
            row['id'], current['revision'], digest, proposal['title'], proposal['methodology'],
            proposal['methodology_sha256'], proposal['reason'], json.dumps(
                json.loads(proposal['evidence_refs']) if isinstance(proposal['evidence_refs'], str)
                else list(proposal['evidence_refs'] or [])),
            proposal['proposed_by'], proposal['hunt_run_id'], proposal['id'])
        return {'proposal': public_proposal(rebased, current), 'superseded': str(proposal['id'])}


async def list_proposals(conn: Any, target_id: Any | None, *, status: str | None,
                         limit: int = LIST_LIMIT, kind: str | None = None) -> dict[str, Any]:
    params: list[Any] = []
    where: list[str] = []
    if target_id is not None:
        row = await _target(conn, target_id)
        params.append(row['id'])
        where.append(f'p.target_id=${len(params)}')
    if status is not None:
        params.append(status)
        where.append(f'p.status=${len(params)}')
    if kind is not None:
        params.append(kind)
        where.append(f'p.kind=${len(params)}')
    params.append(limit + 1)
    rows = await conn.fetch(f"""SELECT p.*, t.name AS target_name, t.url AS target_url
        FROM target_instruction_proposals p JOIN targets t ON t.id=p.target_id
        {('WHERE ' + ' AND '.join(where)) if where else ''}
        ORDER BY p.created_at ASC, p.id ASC LIMIT ${len(params)}""", *params)
    current: dict[tuple[str, str], dict[str, Any]] = {}
    proposals = []
    for item in rows[:limit]:
        key = (str(item['target_id']), _kind(item))
        if key not in current and item['status'] == 'pending':
            current[key] = await _current(conn, item['target_id'], key[1])
        proposals.append({**public_proposal(item, current.get(key)),
                          'target_name': item['target_name'], 'target_url': item['target_url']})
    unconfirmed = []
    if status in (None, 'pending') and kind in (None, 'instructions'):
        from .skill import unconfirmed_targets
        unconfirmed = await unconfirmed_targets(conn, params[0] if target_id is not None else None, limit=limit)
    return {'proposals': proposals, 'count': len(proposals), 'has_more': len(rows) > limit,
            # Instructions a Hunt wrote that no operator confirmed: advisory until an operator saves them.
            'unconfirmed_instructions': unconfirmed,
            'advisory': True,
            'review': ('Accepting applies the proposed text as the target instructions, or the proposed '
                       'saved-action change, for future Hunts.')}


def _actor(request: Request) -> str:
    # A managed gateway may supply a server-authenticated identity; OSS routes name their provenance.
    return str(request.scope.get('shakerscan.operator_identity') or 'operator:instruction-proposals-api')[:200]


def pool():
    from .asset_router import pool as configured_pool
    return configured_pool()


StatusFilter = Literal['pending', 'accepted', 'rejected', 'superseded']
KindFilter = Literal['instructions', 'saved_action']


@router.get('/instruction-proposals')
async def get_all_instruction_proposals(status: StatusFilter | None = 'pending',
                                        limit: int = Query(LIST_LIMIT, ge=1, le=LIST_LIMIT),
                                        kind: KindFilter | None = None):
    async with pool().acquire() as conn:
        return await list_proposals(conn, None, status=status, limit=limit, kind=kind)


@router.get('/targets/{target_id}/instruction-proposals')
async def get_target_instruction_proposals(target_id: str, status: StatusFilter | None = 'pending',
                                           limit: int = Query(LIST_LIMIT, ge=1, le=LIST_LIMIT),
                                           kind: KindFilter | None = None):
    async with pool().acquire() as conn:
        return await list_proposals(conn, target_id, status=status, limit=limit, kind=kind)


@router.post('/targets/{target_id}/instruction-proposals', status_code=201)
async def post_instruction_proposal(target_id: str, proposal: ProposalText, request: Request):
    """An operator's own proposal, for another operator to review; it changes nothing by itself."""
    actor = _actor(request)
    async with pool().acquire() as conn:
        return await create_proposal(conn, target_id, proposal,
                                     proposed_by=actor if actor.startswith('operator:') else f'operator:{actor}'[:200])


@router.post('/targets/{target_id}/instruction-proposals/{proposal_id}/accept')
async def post_accept_instruction_proposal(target_id: str, proposal_id: str, request: Request,
                                           decision: ProposalDecision | None = None):
    async with pool().acquire() as conn:
        return await accept_proposal(conn, target_id, proposal_id, actor=_actor(request),
                                     note=decision.note if decision else None,
                                     reviewed_sha256=decision.methodology_sha256 if decision else None)


@router.post('/targets/{target_id}/instruction-proposals/{proposal_id}/reject')
async def post_reject_instruction_proposal(target_id: str, proposal_id: str, request: Request,
                                           decision: ProposalDecision | None = None):
    async with pool().acquire() as conn:
        return await reject_proposal(conn, target_id, proposal_id, actor=_actor(request),
                                     note=decision.note if decision else None)


@router.post('/targets/{target_id}/instruction-proposals/{proposal_id}/rebase')
async def post_rebase_instruction_proposal(target_id: str, proposal_id: str, request: Request):
    async with pool().acquire() as conn:
        return await rebase_proposal(conn, target_id, proposal_id, actor=_actor(request))


__all__ = [
    'INSTRUCTION_PROPOSAL_SCHEMA_SQL', 'MAX_PENDING_PER_TARGET', 'MAX_PROPOSALS_PER_HUNT', 'ProposalText',
    'ActionProposalNote', 'accept_proposal', 'create_action_proposal', 'create_proposal', 'is_stale', 'list_proposals', 'pending_count', 'public_proposal',
    'rebase_proposal', 'reject_proposal', 'router', 'unified_diff',
]
