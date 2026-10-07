"""Attempts a later batch action carries from an earlier one instead of re-running them.

* A verification extension (see ``verification_extension``) re-plans a wall-killed verifier
  slice and the proof escalation behind it; it carries every candidate the extended action
  already took to a verdict.
* A passive Scan's continuation slices run the reviewed passive pack over the discovered
  surface, which includes the frozen origin and admitted seeds the required admission
  ``passive.templates`` action already examined with the same pack; they carry those routes.

A carried attempt counts as attempted with its original verdict, spends no budget and sends
no traffic. Only its ``candidate_attempt`` bookkeeping record is copied, marked with the
action it came from; the original action keeps its own evidence and findings.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .verification_extension import SIGNAL_SOURCES_ARG

ADMISSION_PASSIVE_TEMPLATES = "passive.templates"
_SUCCESS_STATUSES = frozenset({"success", "succeeded", "completed"})


def finished_attempts(attempts: Iterable[Any], *, key: str = "attempt_id") -> dict[str, dict]:
    """Checkpointed attempts that reached a verdict, keyed by ``key``.

    A timed-out, failed or cancelled attempt never reached a verdict, so the later action
    re-runs it rather than inheriting its gap.
    """
    finished: dict[str, dict] = {}
    for item in attempts or ():
        if not isinstance(item, Mapping):
            continue
        identity = str(item.get(key) or "")
        if (
            identity
            and str(item.get("status") or "") in _SUCCESS_STATUSES
            and not item.get("timed_out")
        ):
            finished.setdefault(identity, dict(item))
    return finished


def carried_records(attempt: Mapping[str, Any], *, source: str) -> list[dict]:
    """The bookkeeping records a carried attempt contributes, marked with its source."""
    return [
        {**dict(item), "carried_from": source}
        for item in attempt.get("observations") or ()
        if isinstance(item, Mapping) and item.get("kind") == "candidate_attempt"
    ]


def proof_signal_sources(action: Any, plan: Any) -> tuple[str, ...]:
    """Every action whose observations a proof escalation reads candidate signals from.

    Its dependencies, plus -- for a proof re-planned behind a verification extension --
    the verifier slices the original escalation depended on. Those are terminal actions of
    an earlier round, so they cannot be dependencies of this round's plan; without them the
    re-planned proof saw only the extensions and dropped its siblings' signals. A named
    source is honoured only when it precedes this action in the Scan plan.
    """
    ordered = [item.action_id for item in getattr(plan, "actions", ()) or ()]
    earlier = set(ordered[:ordered.index(action.action_id)]) if action.action_id in ordered else set()
    named = action.capability_args.get(SIGNAL_SOURCES_ARG) or ()
    extra = tuple(
        str(item) for item in (named if isinstance(named, (list, tuple)) else ())
        if str(item) in earlier
    )
    return tuple(dict.fromkeys((*action.dependencies, *extra)))


def admission_template_source(action: Any, plan: Any) -> str | None:
    """The required admission passive-pack action a continuation passive slice carries from.

    Only a continuation slice of the same reviewed pack qualifies: the admission action must
    be in the Scan plan and bind the identical template manifest. The two worklists are
    different manifests, so the carry is keyed by route identity, not by attempt id.
    """
    if (
        getattr(action, "capability_name", None) != "templates.passive_batch"
        or not action.capability_args.get("continuation_work_key")
        or action.action_id == ADMISSION_PASSIVE_TEMPLATES
    ):
        return None
    source = next((
        item for item in getattr(plan, "actions", ()) or ()
        if item.action_id == ADMISSION_PASSIVE_TEMPLATES
        and item.capability_name == "templates.passive_batch"
    ), None)
    if source is None or source.capability_args.get("template_manifest_ref") != (
        action.capability_args.get("template_manifest_ref")
    ):
        return None
    return ADMISSION_PASSIVE_TEMPLATES
