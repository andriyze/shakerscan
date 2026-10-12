"""Operator-only adapter to canonical decision services; no receipt core depends on it."""
from typing import Any
from uuid import UUID
import hashlib

from fastapi import HTTPException

from .decision_receipts import DecisionInput, _canonical


async def apply_operator_decision(conn: Any, target: UUID, item: DecisionInput, actor: str) -> dict:
    from .instruction_proposals import accept_proposal
    from .skill import UnconfirmedConfirmation, confirm_unconfirmed_instructions
    from .hunt_authority import authority_row, read_hunt_authority, save_authority
    try:
        from hunt.interpretations import (DismissalInput, StatusNote, dismiss_finding, reopen_finding,
                                         retract_interpretation, retract_run)
        from hunt.release_markers import ReleaseMarkerInput, declare_release
    except ModuleNotFoundError:
        from ..hunt.interpretations import (DismissalInput, StatusNote, dismiss_finding, reopen_finding,
                                          retract_interpretation, retract_run)
        from ..hunt.release_markers import ReleaseMarkerInput, declare_release
    kind = item.decision
    if kind == 'accept':
        if item.text_sha256 is None:
            raise HTTPException(422, 'Accept must name the reviewed text')
        return await accept_proposal(conn, target, str(item.subject_id), actor=actor, note=item.note,
                                     reviewed_sha256=item.text_sha256)
    if kind == 'confirm':
        return await confirm_unconfirmed_instructions(conn, target,
            UnconfirmedConfirmation(expected_revision=item.expected_revision, body_sha256=item.text_sha256), source=actor)
    if kind == 'allow_changes':
        row = await authority_row(conn, target, lock=True)
        if not row['is_active']:
            raise HTTPException(409, 'Reactivate this target before delegating Hunt actions')
        current = await read_hunt_authority(conn, target)
        if current['revision'] != item.expected_revision or current['instruction_changes'] is True:
            raise HTTPException(409, 'Hunt permissions changed; review again')
        return await save_authority(conn, row,
            {**current, 'instruction_changes': True, 'revision': current['revision'] + 1}, recorded_by=actor)
    if kind == 'dismiss':
        return await dismiss_finding(conn, target, item.subject_id,
            DismissalInput(reason=item.reason, note=item.note), actor=actor)
    if kind == 'release_marker':
        bound = {'label': item.release_label, 'released_at': item.released_at}
        if hashlib.sha256(_canonical(bound).encode('ascii')).hexdigest() != item.text_sha256:
            raise HTTPException(422, 'Release marker does not match the approved label and time')
        return await declare_release(conn, target, ReleaseMarkerInput(**bound), actor=actor)
    note = StatusNote(note=item.note).note
    if kind == 'reopen':
        return await reopen_finding(conn, target, item.subject_id, actor=actor, note=note)
    if kind == 'retract':
        return await retract_interpretation(conn, target, item.subject_id, actor=actor, note=note)
    return await retract_run(conn, target, item.subject_id, actor=actor, note=note)


