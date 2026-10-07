"""Attempts a verification extension carries from the action it extends.

A verification extension (see ``verification_extension``) re-plans a wall-killed verifier
slice and the proof escalation behind it. Every candidate the extended action already took
to a verdict is carried: it counts as attempted with its original verdict, spends no budget
and sends no traffic. Only its ``candidate_attempt`` bookkeeping record is copied, marked
with the action it came from; the original action keeps its own evidence and findings.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .verification_extension import SIGNAL_SOURCES_ARG

_SUCCESS_STATUSES = frozenset({"success", "succeeded", "completed"})


def finished_attempts(attempts: Iterable[Any]) -> dict[str, dict]:
    """Checkpointed attempts that reached a verdict, keyed by attempt id.

    A timed-out, failed or cancelled attempt never reached a verdict, so the extension
    re-runs it rather than inheriting its gap.
    """
    finished: dict[str, dict] = {}
    for item in attempts or ():
        if not isinstance(item, Mapping):
            continue
        identity = str(item.get("attempt_id") or "")
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
