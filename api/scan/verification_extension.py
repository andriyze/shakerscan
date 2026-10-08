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

Every wall-killed slice of a lane is eligible in the same round, and the lane's wall share is
divided fairly among them (see ``plan_verification_extensions``): candidates with the fewest
extensions go first, and the share is spread max-min above each slice's progress floor.
Soak scan 44e393ba gave its first SQLi candidate the whole share while three others never got
an extension, and no candidate reached a verdict.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any

from .action_plan import CAPABILITY_REGISTRY, _LANE_WALL_SHARE
from .capability_result import BUDGET_EXHAUSTION_REASONS
from .sqli_stages import MINIMUM_STAGE_WALL_SECONDS

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
# A resumable slice that stopped because its own holds could not fund the candidates it was
# given. Soak scan 0eb39a8a (Thorough, honey) planned four SQLi candidates, three of them
# request bodies, into one slice holding 720 s and one body attempt's 480 mutations: the first
# body candidate ran, the other two could never be funded, the slice settled `partial` for
# `state_changing_budget_exhausted` with 120 s and 1,441 requests unspent, and -- not being
# wall-killed -- was never extended, while 7,121 of the Scan's 10,800 tool-wall seconds were
# never allocated. Its measured latency sizes an extension exactly as a wall-killed slice's does.
_UNFUNDED_STOP_REASONS = frozenset(reason.value for reason in BUDGET_EXHAUSTION_REASONS.values())


def _status(result: Any) -> str:
    status = getattr(result, "status", None)
    return str(getattr(status, "value", status) or "")


def _reason(result: Any) -> str:
    reason = getattr(result, "reason_code", None)
    return str(getattr(reason, "value", reason) or "")


def _extendable_stop(capability_name: str, result: Any) -> bool:
    """A wall-killed slice, or a resumable one its own holds left with unfunded candidates."""
    status = _status(result)
    if status == "timed_out":
        return True
    return (
        capability_name in RESUMABLE_CAPABILITIES
        and status == "partial"
        and _reason(result) in _UNFUNDED_STOP_REASONS
    )


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


def _floor_scale(
    capability_name: str, held_wall: int, resume_wall: int | None = None,
) -> float:
    """The smallest scale at which an extension still makes progress on its slice.

    A Dalfox extension restarts from scratch, so it must buy meaningfully more time than the
    slice had. A SQLi extension resumes at the first unfinished technique stage, and the stage
    guard re-runs an interrupted stage only on a hold strictly larger than the one it ran out
    of. Its floor is therefore read from the slice's own checkpoints when they are known
    (``resume_wall``: the least wall any of its unfinished candidates needs, see
    ``stage_resume_walls``). Without them it is the slice's whole wall plus one stage's minimum,
    because no stage can have run longer than the hold it ran in.

    A chained link used to get just its predecessor's wall, on the assumption that the
    interrupted stage started part-way through that hold. When the earlier stages were carried,
    the stage had the whole hold, so an equal wall was refused (``would_repeat_timeout``), the
    link settled partial instead of timed out, and the chain ended on a no-op (audit S002).
    """
    if capability_name not in RESUMABLE_CAPABILITIES:
        return _MINIMUM_SCALE
    if resume_wall is not None and resume_wall > 0:
        # Never below the slice's own holds: the request and mutation holds scale with the
        # wall, and a candidate needs at least its attempt floor in every dimension, so a
        # smaller extension would be unfundable in those and send nothing.
        return max(1.0, resume_wall / held_wall)
    return (held_wall + MINIMUM_STAGE_WALL_SECONDS) / held_wall


# The records an unfinished SQLi candidate names its next attempt's least useful wall on.
_RESUME_RECORD_KINDS = frozenset({"candidate_attempt", "candidate_deferred"})


def stage_resume_walls(observations: Mapping[str, Any]) -> dict[str, int]:
    """The least wall that makes progress on each resumable slice, from its own receipt.

    Every unfinished SQLi candidate's record names ``resume_wall_seconds``: its first
    unfinished technique stage's checkpoint plus one stage's minimum, never below the attempt
    floor. The slice makes progress on any hold that funds one of them, so its floor is the
    smallest. A slice whose receipt names none falls back to the conservative floor.
    """
    walls: dict[str, int] = {}
    for action_id, rows in (observations or {}).items():
        needs = [
            int(row["resume_wall_seconds"])
            for row in rows or ()
            if isinstance(row, Mapping)
            and row.get("kind") in _RESUME_RECORD_KINDS
            and not row.get("carried_from")
            and isinstance(row.get("resume_wall_seconds"), int)
            and not isinstance(row.get("resume_wall_seconds"), bool)
            and int(row["resume_wall_seconds"]) > 0
        ]
        if needs:
            walls[str(action_id)] = min(needs)
    return walls


def resume_observation_action_ids(
    parent_plan: Any, parent_results: Mapping[str, Any],
) -> tuple[str, ...]:
    """The resumable slices whose receipts the next round reads its extension floors from."""
    actions = tuple(getattr(parent_plan, "actions", ()) or ())
    extended = {
        str(action.capability_args.get(EXTENDS_ARG))
        for action in actions if action.capability_args.get(EXTENDS_ARG)
    }
    return tuple(
        action.action_id
        for action in actions
        if action.capability_name in RESUMABLE_CAPABILITIES
        and action.action_id not in extended
        and action.action_id in parent_results
        and _extendable_stop(action.capability_name, parent_results[action.action_id])
    )


def _fair_walls(
    eligible: list[dict[str, Any]], allowance: int,
) -> dict[int, int]:
    """Max-min fair wall per eligible extension inside one lane's round allowance.

    ``eligible`` is in priority order. Extensions are admitted in that order while their floors
    fit the allowance (one whose floor does not fit is skipped, so a smaller later one can
    still be admitted); the allowance is then shared as evenly as the admitted extensions'
    floors and needs allow, so no candidate takes the whole lane while another waits.
    """
    admitted: list[dict[str, Any]] = []
    committed = 0
    for item in eligible:
        if committed + item["floor_wall"] <= allowance:
            admitted.append(item)
            committed += item["floor_wall"]
    if not admitted:
        return {}
    # Water-filling: raise one common level until the allowance is spent; an extension never
    # goes below its floor nor above its latency-sized need.
    low = 0.0
    high = float(max(item["need_wall"] for item in admitted))

    def total(level: float) -> int:
        return sum(
            max(item["floor_wall"], min(item["need_wall"], int(level)))
            for item in admitted
        )

    if total(high) <= allowance:
        return {item["index"]: item["need_wall"] for item in admitted}
    for _ in range(64):
        middle = (low + high) / 2
        if total(middle) <= allowance:
            low = middle
        else:
            high = middle
    return {
        item["index"]: max(item["floor_wall"], min(item["need_wall"], int(low)))
        for item in admitted
    }


def _lineage_measurement(
    action: Any, by_id: Mapping[str, Any], parent_results: Mapping[str, Any],
) -> dict[str, int] | None:
    """The consumption of the nearest link in ``action``'s chain that sent traffic."""
    seen: set[str] = set()
    current = str(action.capability_args.get(EXTENDS_ARG) or "")
    while current and current not in seen:
        seen.add(current)
        consumed = dict(getattr(parent_results.get(current), "budget_consumed", {}) or {})
        if int(consumed.get("http_requests") or 0) > 0 and int(
            consumed.get("tool_wall_seconds") or 0
        ) > 0:
            return consumed
        ancestor = by_id.get(current)
        current = (
            str(ancestor.capability_args.get(EXTENDS_ARG) or "") if ancestor is not None else ""
        )
    return None


def plan_verification_extensions(
    *,
    parent_plan: Any,
    parent_results: Mapping[str, Any],
    profile_limits: Mapping[str, int],
    residual: Mapping[str, int],
    stage_resume_walls: Mapping[str, int] | None = None,
) -> tuple[dict[str, Any], ...]:
    """One optional extension per timed-out, latency-starved verifier slice not yet extended.

    ``stage_resume_walls`` maps a resumable slice to the least wall its unfinished candidates'
    checkpoints say makes progress (``stage_resume_walls()`` over its receipt); an extension is
    never admitted below it, so two extensions that would each be refused are not admitted in
    place of one that can finish. A slice whose floor cannot fit waits for a later round.

    Every such slice is eligible, not only the first one a lane meets. One lane holds at
    most its share of the profile wall across all of its extensions in a round (exactly as
    its slices do in one compile), and that share is divided fairly: slices with the fewest
    extensions so far come first -- a candidate that has never been extended before one that
    already was, then plan order -- and the share is spread max-min across every slice whose
    progress floor fits. A slice the round cannot fund keeps its place for the next round.
    Soak scan 44e393ba gave its first SQLi candidate the whole 900-second share while three
    POST candidates, each wall-killed in technique B, were never extended at all.
    """
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
    by_id = {action.action_id: action for action in actions}
    lanes: dict[str, list[dict[str, Any]]] = {}
    for index, action in enumerate(actions):
        chained = bool(action.capability_args.get(EXTENDS_ARG))
        if (
            action.capability_name not in EXTENDABLE_CAPABILITIES
            or (chained and action.capability_name not in RESUMABLE_CAPABILITIES)
            or action.action_id in already
        ):
            continue
        result = parent_results.get(action.action_id)
        if result is None or not _extendable_stop(action.capability_name, result):
            continue
        reserved = dict(getattr(result, "budget_reserved", {}) or {})
        held_wall = int(reserved.get("tool_wall_seconds") or 0)
        floor = (
            _floor_scale(
                action.capability_name, held_wall,
                (stage_resume_walls or {}).get(action.action_id),
            )
            if held_wall > 0 else 0
        )
        consumed = dict(getattr(result, "budget_consumed", {}) or {})
        if (
            chained and action.action_id in (stage_resume_walls or {})
            and int(consumed.get("http_requests") or 0) <= 0
        ):
            # A link that deferred every candidate before any traffic measured nothing; its
            # chain's nearest measured link holds the target's latency.
            consumed = _lineage_measurement(action, by_id, parent_results) or consumed
        # The largest extension this slice can use: its latency-sized need inside the lane
        # share and the whole remaining residual.
        scale = extension_scale(
            reserved=reserved,
            consumed=consumed,
            wall_ceiling=wall_ceiling,
            residual=remaining,
            minimum=floor,
        )
        if scale is None:
            continue
        depth = 0
        current = action
        while current is not None and current.capability_args.get(EXTENDS_ARG):
            depth += 1
            current = by_id.get(str(current.capability_args.get(EXTENDS_ARG)))
        lanes.setdefault(action.capability_name, []).append({
            "index": index, "action": action, "reserved": reserved, "depth": depth,
            "need_wall": int(math.floor(held_wall * scale)),
            "floor_wall": int(math.ceil(held_wall * floor)),
            "held_wall": held_wall,
        })
    planned_by_index: dict[int, dict[str, Any]] = {}
    for capability_name in sorted(lanes):
        eligible = sorted(lanes[capability_name], key=lambda item: (item["depth"], item["index"]))
        allowance = max(0, min(wall_ceiling, remaining.get("tool_wall_seconds", 0)))
        walls = _fair_walls(eligible, allowance)
        for item in eligible:
            wall = walls.get(item["index"])
            if wall is None:
                continue
            scale = wall / item["held_wall"]
            # The other scaled holds must still fit what earlier extensions left.
            for name in _SCALED_DIMENSIONS:
                amount = int(item["reserved"].get(name) or 0)
                if amount > 0:
                    scale = min(scale, max(0, remaining.get(name, 0)) / amount)
            if scale * item["held_wall"] < item["floor_wall"]:
                continue
            action = item["action"]
            budget = {
                name: (
                    int(math.floor(int(amount) * scale))
                    if name in _SCALED_DIMENSIONS else int(amount)
                )
                for name, amount in item["reserved"].items()
                if int(amount) > 0
            }
            for name, amount in budget.items():
                remaining[name] = remaining.get(name, 0) - amount
            planned_by_index[item["index"]] = {
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
            }
    planned: list[dict[str, Any]] = [planned_by_index[index] for index in sorted(planned_by_index)]
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
