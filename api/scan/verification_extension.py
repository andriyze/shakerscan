"""Carry wall-killed verification into the next continuation round, sized by measured latency.

A verifier slice is sized before any traffic from measured costs on responsive targets: an
SQLi body attempt holds 480 requests and 420 seconds. Against an AI endpoint that answers in
about 3.7 seconds, sqlmap sent 112 of its 800 requests before the wall killed it; both SQLi
slices of soak scan 2c637857 ended `timed_out` with most of their request budget unspent and
nothing proven, while the Scan still had half of its tool wall unallocated.

The attempt itself is the latency measurement. When a verifier slice times out with at least
half of its request hold unspent, the next continuation round plans ONE optional extension of
that slice: same manifest slice and authority, its request, mutation and wall holds scaled by
the measured seconds-per-request so the same paced rate can reach the requests it was denied.
The scale is bounded by the lane's share of the profile wall and by what the reconciled
residual can still fund, so every hard ceiling stays where it was; the allocator admits the
extension like any other optional work or skips it. Candidates the original attempted to a
verdict are carried into the extension rather than re-run, and the finalizer reads the
extension's outcome in place of the slice it extends.

SQLi verification is resumable (see ``sqli_stages``): each candidate's verification is a
sequence of technique stages, every finished stage is checkpointed, and an extension continues
at the first unfinished stage instead of re-sending what the slice already settled. Because a
later extension makes progress rather than repeating its predecessor, a wall-killed SQLi
extension is itself extended in the next round -- at the same lane share, bounded by the
reconciled residual and the round bound -- until its candidates finish or the budget is gone.
An XSS extension still re-runs Dalfox from scratch, so it is never extended again.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any

from .action_plan import CAPABILITY_REGISTRY, _LANE_WALL_SHARE

EXTENDS_ARG = "extends"
# A proof re-planned behind an extension also reads candidate signals from the verifier slices
# its original escalation depended on (terminal actions of an earlier round).
SIGNAL_SOURCES_ARG = "signal_sources"
EXTENDABLE_CAPABILITIES = frozenset({"xss.verify_batch", "sqli.verify_batch"})
# Verifiers whose extension continues durable per-candidate progress, so extending an
# extension again is not a repeat of the same work.
RESUMABLE_CAPABILITIES = frozenset({"sqli.verify_batch"})
# Proof escalation reads its candidates from the verifiers it depends on, so a slice whose
# verifier is extended gets its escalation re-planned behind the extension.
PROOF_CAPABILITIES = frozenset({"sqli.prove_batch", "xss.browser_prove_batch"})
# The share of the profile's tool wall one lane's extensions may hold together in a round: the
# bound a single verifier lane holds in one compile, so extensions cannot starve the proof
# stage they feed.
EXTENSION_WALL_SHARE = _LANE_WALL_SHARE
# An extension is worth planning only when it buys meaningfully more time than the slice had.
_MINIMUM_SCALE = 1.25
# A slice that spent more than this fraction of its request hold was not starved by latency.
_MAXIMUM_SPENT_FRACTION = 0.5
_SCALED_DIMENSIONS = ("http_requests", "state_changing_requests", "tool_wall_seconds")
_ROUND_SUFFIX = re.compile(r"\.r\d{2}$")
_CARRIED_ARGS_EXCLUDED = frozenset({"continuation_work_key", EXTENDS_ARG, SIGNAL_SOURCES_ARG})


def _status(result: Any) -> str:
    status = getattr(result, "status", None)
    return str(getattr(status, "value", status) or "")


def extension_action_id(action_id: str) -> str:
    """The extension's id before the round compiler namespaces it with its own ``.rNN``."""
    return f"{action_id}.ext"


def extension_scale(
    *,
    reserved: Mapping[str, int],
    consumed: Mapping[str, int],
    wall_ceiling: int,
    residual: Mapping[str, int],
    minimum: float = _MINIMUM_SCALE,
) -> float | None:
    """How much larger the extension's holds are than the slice's, or None for no extension."""
    held_requests = int(reserved.get("http_requests") or 0)
    sent = int(consumed.get("http_requests") or 0)
    held_wall = int(reserved.get("tool_wall_seconds") or 0)
    spent_wall = int(consumed.get("tool_wall_seconds") or 0)
    if held_requests <= 0 or held_wall <= 0 or sent <= 0 or spent_wall <= 0:
        # No measured traffic means no latency measurement: nothing to scale by.
        return None
    if sent > held_requests * _MAXIMUM_SPENT_FRACTION:
        return None
    seconds_per_request = spent_wall / sent
    # The wall the slice's request hold needs at the measured rate.
    scale = (held_requests * seconds_per_request) / held_wall
    scale = min(scale, max(0, int(wall_ceiling)) / held_wall)
    for dimension in _SCALED_DIMENSIONS:
        amount = int(reserved.get(dimension) or 0)
        if amount > 0:
            scale = min(scale, max(0, int(residual.get(dimension, 0))) / amount)
    return scale if scale >= minimum else None


def plan_verification_extensions(
    *,
    parent_plan: Any,
    parent_results: Mapping[str, Any],
    profile_limits: Mapping[str, int],
    residual: Mapping[str, int],
) -> tuple[dict[str, Any], ...]:
    """One optional extension per timed-out, latency-starved verifier slice not yet extended."""
    actions = tuple(getattr(parent_plan, "actions", ()) or ())
    already = {
        str(action.capability_args.get(EXTENDS_ARG))
        for action in actions if action.capability_args.get(EXTENDS_ARG)
    }
    wall_ceiling = int(int(profile_limits.get("tool_wall_seconds") or 0) * EXTENSION_WALL_SHARE)
    # The terminal finalizer is always funded from the same residual.
    finalizer = dict(CAPABILITY_REGISTRY.require("scan.finalize").budget_cost)
    remaining = {
        name: int(amount) - int(finalizer.get(name, 0))
        for name, amount in dict(residual).items()
    }
    planned: list[dict[str, Any]] = []
    # One lane (a verifier family) holds at most its share of the wall across all of its
    # extensions in this round, exactly as its slices do in one compile. Sizing every
    # extension against the whole share let two SQLi slices hold half the profile wall.
    # A slice the share cannot fund now is extended in a later round, from a fresh share.
    lane_wall: dict[str, int] = {}
    for action in actions:
        chained = bool(action.capability_args.get(EXTENDS_ARG))
        if (
            action.capability_name not in EXTENDABLE_CAPABILITIES
            or (chained and action.capability_name not in RESUMABLE_CAPABILITIES)
            or action.action_id in already
        ):
            continue
        result = parent_results.get(action.action_id)
        if result is None or _status(result) != "timed_out":
            continue
        reserved = dict(getattr(result, "budget_reserved", {}) or {})
        scale = extension_scale(
            reserved=reserved,
            consumed=dict(getattr(result, "budget_consumed", {}) or {}),
            wall_ceiling=max(0, wall_ceiling - lane_wall.get(action.capability_name, 0)),
            residual=remaining,
            # An extension already holds the lane share; continuing it at that same share is
            # worth a round because it resumes where its predecessor stopped.
            minimum=1.0 if chained else _MINIMUM_SCALE,
        )
        if scale is None:
            continue
        budget = {
            name: (
                int(math.floor(int(amount) * scale))
                if name in _SCALED_DIMENSIONS else int(amount)
            )
            for name, amount in reserved.items()
            if int(amount) > 0
        }
        for name, amount in budget.items():
            remaining[name] = remaining.get(name, 0) - amount
        lane_wall[action.capability_name] = (
            lane_wall.get(action.capability_name, 0) + int(budget.get("tool_wall_seconds", 0))
        )
        planned.append({
            "action_id": extension_action_id(action.action_id),
            "stage": action.stage,
            "capability_name": action.capability_name,
            "capability_args": {
                **{
                    key: value for key, value in action.capability_args.items()
                    if key not in _CARRIED_ARGS_EXCLUDED
                },
                EXTENDS_ARG: action.action_id,
            },
            "budget": budget,
            "dependencies": (),
        })
    extended = {
        str(item["capability_args"][EXTENDS_ARG]): str(item["action_id"]) for item in planned
    }
    for action in actions:
        # A proof escalation that already succeeded is re-planned too: its success covers
        # only the candidates its verifiers had signalled before the wall, and the extension
        # can signal new ones. The re-planned proof carries every candidate the original
        # took to a verdict, so nothing already proven is proven again.
        if (
            action.capability_name not in PROOF_CAPABILITIES
            or action.action_id in already
        ):
            continue
        dependencies = tuple(
            extended[item] for item in action.dependencies if item in extended
        )
        if not dependencies:
            continue
        budget = {
            name: int(amount)
            for name, amount in dict(
                getattr(parent_results.get(action.action_id), "budget_reserved", None)
                or action.requested_budget
            ).items()
            if int(amount) > 0
        }
        if not budget or any(remaining.get(name, 0) < amount for name, amount in budget.items()):
            continue
        for name, amount in budget.items():
            remaining[name] = remaining.get(name, 0) - amount
        planned.append({
            "action_id": extension_action_id(action.action_id),
            "stage": action.stage,
            "capability_name": action.capability_name,
            "capability_args": {
                **{
                    key: value for key, value in action.capability_args.items()
                    if key not in _CARRIED_ARGS_EXCLUDED
                },
                EXTENDS_ARG: action.action_id,
                # Signals from every verifier slice the original escalation read, not just
                # the extended ones: a non-extended sibling's candidates must not be dropped.
                # A proof re-planned again keeps the sources its predecessor already read.
                SIGNAL_SOURCES_ARG: list(dict.fromkeys((
                    *(
                        str(item)
                        for item in action.capability_args.get(SIGNAL_SOURCES_ARG) or ()
                    ),
                    *action.dependencies,
                ))),
            },
            "budget": budget,
            "dependencies": dependencies,
        })
    return tuple(planned)


def superseding_results(
    actions: Any, action_results: Mapping[str, Any],
) -> dict[str, Any]:
    """Map each extended slice to the settled result of the last extension in its chain.

    A SQLi extension can itself be extended; the slice and every intermediate extension are
    then covered by the outcome of the newest settled one.
    """
    extended_by: dict[str, str] = {}
    for action in actions or ():
        original = str(action.capability_args.get(EXTENDS_ARG) or "")
        if original and action.action_id in action_results:
            extended_by[original] = action.action_id
    superseded: dict[str, Any] = {}
    for original in extended_by:
        latest, seen = extended_by[original], {original}
        while latest in extended_by and latest not in seen:
            seen.add(latest)
            latest = extended_by[latest]
        superseded[original] = action_results[latest]
    return superseded


def extension_lineage(action: Any, plan: Any) -> tuple[str, ...]:
    """The actions this one extends, nearest first: its slice's whole extension chain."""
    by_id = {
        item.action_id: item for item in getattr(plan, "actions", ()) or ()
    }
    lineage: list[str] = []
    current = str(action.capability_args.get(EXTENDS_ARG) or "")
    while current and current not in lineage and current != action.action_id:
        lineage.append(current)
        ancestor = by_id.get(current)
        current = (
            str(ancestor.capability_args.get(EXTENDS_ARG) or "") if ancestor is not None else ""
        )
    return tuple(lineage)


def base_lane_id(action_id: str) -> str:
    return _ROUND_SUFFIX.sub("", str(action_id))
