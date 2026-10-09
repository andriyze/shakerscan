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

An extension needs evidence that it can make progress, not just a slower target. Soak scan
9de6a910 (2.8.0, Balanced, honey) extended two chat candidates whose slices had settled no
stage at 13 and 5 s per request: each extension was granted 450 s against a 440 s floor, and
union-based alone needed 424 and 212 requests there, so both were killed in the same stage
again -- 900 s, a quarter of the Scan, that also crowded out the extension of the login form's
XSS slice. A body with several fields is now verified one field per run, and each unfinished
SQLi candidate names the wall its next unit is predicted to need at its own robust rate
(``sqli_stages.resume_plan``); that prediction is the extension's floor, and the predicted wall
of every fundable unit it has left is its cap. Each SQLi extension also carries its part of the
Scan's residual (``SCAN_WALL_SHARE_ARG``, divided shortest remaining need first), and a
technique that needs more is inconclusive for budget. A slice whose candidates have nothing
fundable left is not extended. A slice stopped by its request or mutation hold is extended with
the holds its remaining units need, and those holds never bound its wall.

Every wall-killed slice of a lane is eligible in the same round, and the lane's wall share is
divided fairly among them (see ``plan_verification_extensions``): candidates with the fewest
extensions go first, and the share is spread max-min above each slice's progress floor.
Soak scan 44e393ba gave its first SQLi candidate the whole share while three others never got
an extension, and no candidate reached a verdict.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .action_plan import CAPABILITY_REGISTRY, _LANE_WALL_SHARE
from .capability_result import BUDGET_EXHAUSTION_REASONS
from .external_process import BATCH_ATTEMPT_REQUEST_HEADROOM, batch_attempt_floor
from .sqli_stages import MINIMUM_STAGE_WALL_SECONDS

EXTENDS_ARG = "extends"
# A resumable extension's fair part of the Scan's tool-wall residual when it was planned.
SCAN_WALL_SHARE_ARG = "scan_wall_share"
# A resumable extension that is the Scan's final attempt at a unit: the residual cannot fund the
# unit's negative verdict, but can a run that proves an injection.
LAST_CHANCE_ARG = "last_chance"
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
_CARRIED_ARGS_EXCLUDED = frozenset({
    "continuation_work_key", EXTENDS_ARG, SIGNAL_SOURCES_ARG, SCAN_WALL_SHARE_ARG,
    LAST_CHANCE_ARG,
})
# A resumable slice that stopped because its own holds could not fund the candidates it was
# given. Soak scan 0eb39a8a (Thorough, honey) planned four SQLi candidates, three of them
# request bodies, into one slice holding 720 s and one body attempt's 480 mutations: the first
# body candidate ran, the other two could never be funded, the slice settled `partial` for
# `state_changing_budget_exhausted` with 120 s and 1,441 requests unspent, and -- not being
# wall-killed -- was never extended, while 7,121 of the Scan's 10,800 tool-wall seconds were
# never allocated. Its measured latency sizes an extension exactly as a wall-killed slice's does.
_UNFUNDED_STOP_REASONS = frozenset(reason.value for reason in BUDGET_EXHAUSTION_REASONS.values())


def lane_round_wall_ceiling(execution_plan: Any) -> int | None:
    """The most tool wall one lane's extensions may hold in a round, from the Scan's plan.

    ``execution_plan`` is the canonical execution-plan mapping a worker runs under (its
    ``budget.max_tool_wall_seconds`` is the profile wall ``plan_verification_extensions``
    divides). None when the plan does not name it.
    """
    budget = execution_plan.get("budget") if isinstance(execution_plan, Mapping) else None
    wall = budget.get("max_tool_wall_seconds") if isinstance(budget, Mapping) else None
    if isinstance(wall, bool) or not isinstance(wall, int) or wall <= 0:
        return None
    return int(wall * EXTENSION_WALL_SHARE)


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
    request_bound: bool = False,
    request_need: Mapping[str, tuple[int, int]] | None = None,
) -> float | None:
    """How much larger the extension's holds are than the slice's, or None for no extension.

    ``request_need`` names request dimensions a resumable slice needs only so much of (its
    remaining units' requests): those are held at that need instead of scaling with the wall,
    so a slow endpoint's extension is not refused for mutations it would never send.

    ``request_bound`` is a resumable slice its request or mutation hold stopped, not its wall.
    When it spent most of its requests it was not starved by latency, so it gets the holds its
    remaining units need (``minimum``) rather than a latency-sized one; otherwise it is sized
    from its latency like a wall-killed slice.
    """
    held_requests = int(reserved.get("http_requests") or 0)
    sent = int(consumed.get("http_requests") or 0)
    held_wall = int(reserved.get("tool_wall_seconds") or 0)
    spent_wall = int(consumed.get("tool_wall_seconds") or 0)
    if held_requests <= 0 or held_wall <= 0 or sent <= 0 or spent_wall <= 0:
        # No measured traffic means no latency measurement: nothing to scale by.
        return None
    latency_scale = (
        (held_requests * (spent_wall / sent)) / held_wall
        if sent <= held_requests * _MAXIMUM_SPENT_FRACTION else None
    )
    if latency_scale is None and request_need:
        # A resumable slice whose request holds were sized for its units spends most of them
        # by design; that it did is no sign it was not starved of wall. Its wall is bounded
        # by the round share here and by its remaining units' predicted wall by the caller.
        latency_scale = max(float(minimum), max(0, int(wall_ceiling)) / held_wall)
    if request_bound:
        # Whatever its latency says, it needs at least the holds its remaining units need.
        scale = max(latency_scale or 0.0, 1.0, float(minimum))
        scale = min(scale, max(float(minimum), max(0, int(wall_ceiling)) / held_wall))
        scale = _bound_by_residual(scale, reserved, residual, request_need)
        if scale is None:
            return None
        return scale if scale >= min(1.0, float(minimum)) else None
    if latency_scale is None:
        return None
    # The wall the slice's request hold needs at the measured rate.
    scale = latency_scale
    scale = min(scale, max(0, int(wall_ceiling)) / held_wall)
    scale = _bound_by_residual(scale, reserved, residual, request_need)
    if scale is None:
        return None
    return scale if scale >= minimum else None


def _bound_by_residual(
    scale: float, reserved: Mapping[str, int], residual: Mapping[str, int],
    request_need: Mapping[str, tuple[int, int]] | None,
) -> float | None:
    """``scale`` bounded by what the residual can fund in every held dimension."""
    for dimension in _SCALED_DIMENSIONS:
        amount = int(reserved.get(dimension) or 0)
        if amount <= 0:
            continue
        room = max(0, int(residual.get(dimension, 0)))
        need = (request_need or {}).get(dimension)
        if need is not None:
            # Scaled with the wall, but never past what the remaining units need, and never
            # below one attempt's floor.
            # Held at what fits the residual instead of bounding the wall.
            if room < need[0]:
                return None
            continue
        scale = min(scale, room / amount)
    return scale


def _floor_scale(
    capability_name: str, held_wall: int, resume_wall: int | None = None,
    reserved: Mapping[str, int] | None = None,
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
        # Never below one candidate attempt's floor in any held dimension: the request and
        # mutation holds scale with the wall, and a smaller extension would be unfundable in
        # those and send nothing. It used to be never below the slice's own holds, so every
        # link of a chain was at least as large as the one before -- a candidate settled one
        # unit per round with the whole share (soak N55 review).
        attempt = batch_attempt_floor(capability_name, body_candidate=True)
        held = dict(reserved or {})
        # The wall floor is the checkpoint's own: a measured candidate runs one unit at a
        # time, and ``resume_wall`` is what its next unit needs.
        dimension_floor = max((
            int(attempt[name]) / int(held[name])
            for name in ("http_requests", "state_changing_requests")
            if int(attempt.get(name) or 0) > 0 and int(held.get(name) or 0) > 0
        ), default=0.0)
        return max(resume_wall / held_wall, dimension_floor)
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


def stage_last_chance_walls(observations: Mapping[str, Any]) -> dict[str, int]:
    """The least wall a final run at each resumable slice's next unit needs to prove anything."""
    walls: dict[str, int] = {}
    for action_id, rows in (observations or {}).items():
        needs = [
            int(row["last_chance_wall_seconds"]) for row in rows or ()
            if isinstance(row, Mapping)
            and row.get("kind") in _RESUME_RECORD_KINDS
            and not row.get("carried_from")
            and row.get("resume_wall_seconds")
            and isinstance(row.get("last_chance_wall_seconds"), int)
        ]
        if needs:
            walls[str(action_id)] = min(needs)
    return walls


def stage_remaining_walls(
    observations: Mapping[str, Any], *, key: str = "remaining_wall_seconds",
) -> dict[str, int]:
    """The most wall each resumable slice's unfinished candidates are predicted to use.

    Each unfinished SQLi candidate names the predicted wall of every fundable unit it has left
    (``remaining_wall_seconds``); an extension is never sized above their sum, so a slice with
    two units left is not handed a whole round's share. With ``key="remaining_requests"`` it
    is the requests those units need instead.
    """
    walls: dict[str, int] = {}
    for action_id, rows in (observations or {}).items():
        unfinished = [
            row for row in rows or ()
            if isinstance(row, Mapping)
            and row.get("kind") in _RESUME_RECORD_KINDS
            and not row.get("carried_from")
            and row.get("resume_wall_seconds")
        ]
        if unfinished and all(isinstance(row.get(key), int) for row in unfinished):
            walls[str(action_id)] = sum(int(row[key]) for row in unfinished)
    return walls


# Techniques judged unfundable at which a candidate's continuation yields to new work.
_MOSTLY_UNFUNDABLE = 3


def budget_concluded_slices(observations: Mapping[str, Any]) -> dict[str, str]:
    """Resumable slices whose every unfinished candidate is inconclusive for budget.

    ``"closed"``: nothing any of them still has to run is fundable (``sqli_stages``), so the
    slice is never extended. A slice whose every unfinished candidate is on a probe round is
    ``"probe"``: it is funded at its floor and no more.
    """
    concluded: dict[str, str] = {}
    for action_id, rows in (observations or {}).items():
        unfinished = [
            row for row in rows or ()
            if isinstance(row, Mapping)
            and row.get("kind") in _RESUME_RECORD_KINDS
            and not row.get("carried_from")
            and (row.get("resume_wall_seconds") or row.get("verdict"))
        ]
        if unfinished and all(row.get("verdict") == "inconclusive" for row in unfinished):
            concluded[str(action_id)] = "closed"
        elif unfinished and all(
            row.get("resume_probe") or row.get("resume_unconfirmed")
            or row.get("verdict") == "inconclusive"
            for row in unfinished
        ):
            # A probe re-measures a rate; it is funded at its floor, never water-filled.
            concluded[str(action_id)] = "probe"
        elif unfinished and all(
            len(row.get("inconclusive_techniques") or ()) >= _MOSTLY_UNFUNDABLE
            or row.get("verdict") == "inconclusive"
            for row in unfinished
        ):
            # Every candidate has at most one technique left that any budget can fund:
            # continued only after candidates that have not had a first slice yet
            # (``reserved_for_new_work``).
            concluded[str(action_id)] = "degraded"
    return concluded


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


# A rate measured on earlier units is a prediction, not a promise: an extension capped at
# exactly the predicted wall of the units left is cut short by a slightly slower target and
# spends one of the Scan's continuation rounds on the remainder.
_REMAINING_WALL_SLACK = 1.2
_REMAINING_WALL_SLACK_SECONDS = 60


def _with_slack(remaining_wall: int) -> int:
    """The remaining-wall cap with room for the rate to have been mispredicted."""
    return max(
        math.ceil(remaining_wall * _REMAINING_WALL_SLACK),
        int(remaining_wall) + _REMAINING_WALL_SLACK_SECONDS,
    )


def _request_need(
    capability_name: str, reserved: Mapping[str, int], remaining_requests: int | None,
) -> dict[str, tuple[int, int]] | None:
    """(floor, cap) of the request and mutation holds a resumable slice's extension needs.

    The floor is one attempt's; the cap is what its remaining units can send, so a slow
    endpoint's extension is not sized -- or refused -- for mutations it would never send.
    """
    if capability_name not in RESUMABLE_CAPABILITIES or not remaining_requests:
        return None
    attempt = batch_attempt_floor(capability_name, body_candidate=True)
    cap = math.ceil(int(remaining_requests) / BATCH_ATTEMPT_REQUEST_HEADROOM) + 1
    needs = {}
    for name in ("http_requests", "state_changing_requests"):
        if int(reserved.get(name) or 0) > 0:
            floor_amount = int(attempt.get(name) or 0)
            needs[name] = (floor_amount, max(floor_amount, cap))
    return needs or None


def _request_scale(reserved: Mapping[str, int], needed: int | None) -> float:
    """How much larger a request-bound slice's holds must be to fund the units it has left."""
    held = min(
        int(reserved.get(name) or 0) for name in ("http_requests", "state_changing_requests")
        if int(reserved.get(name) or 0) > 0
    ) if any(int(reserved.get(name) or 0) > 0 for name in (
        "http_requests", "state_changing_requests",
    )) else 0
    if not needed or held <= 0:
        return 1.0
    return max(1.0, int(needed) / held)


def _admissible_reserve(new_work: int | Sequence[Any], residual_wall: int, lane_share: int) -> int:
    """The wall of the pending first slices the Scan's compiles can really admit.

    ``new_work`` lists ``(lane, wall floor)`` per pending first slice (a bare floor, or one
    total, counts as a single slice). Smallest first, a slice is reserved while it fits what is
    left; one whose floor no longer fits, or exceeds its lane's round share, will never be
    admitted and reserves nothing -- holding wall for it only left that wall idle (soak N55
    follow-up review). The lane share bounds one round's compile, not the Scan: slices beyond
    it are admitted in later rounds, and are still reserved so probes do not take their wall.
    """
    if isinstance(new_work, int):
        items: list[tuple[str, int]] = [("", int(new_work))] if new_work > 0 else []
    else:
        items = [
            (str(item[0]), int(item[1])) if isinstance(item, (tuple, list)) else ("", int(item))
            for item in new_work or ()
        ]
    reserve = 0
    for _lane, floor in sorted(items, key=lambda item: item[1]):
        if floor <= 0:
            continue
        if reserve + floor > residual_wall or floor > max(0, lane_share):
            continue
        reserve += floor
    return reserve


def _shortest_first_shares(demands: Mapping[int, int], total: int) -> dict[int, int]:
    """Divide ``total`` smallest demand first: each gets its demand while it lasts."""
    shares: dict[int, int] = {}
    left = max(0, int(total))
    for index, demand in sorted(demands.items(), key=lambda item: (item[1], item[0])):
        shares[index] = min(int(demand), left)
        left -= shares[index]
    return shares


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
    budget_concluded: Mapping[str, str] | None = None,
    stage_remaining_walls: Mapping[str, int] | None = None,
    stage_remaining_requests: Mapping[str, int] | None = None,
    stage_last_chance_walls: Mapping[str, int] | None = None,
    reserved_for_new_work: int | Sequence[Any] = 0,
    final_round: bool = False,
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
    wall_ceiling = lane_round_wall_ceiling(
        {"budget": {"max_tool_wall_seconds": int(profile_limits.get("tool_wall_seconds") or 0)}}
    ) or 0
    # The terminal finalizer is always funded from the same residual.
    finalizer = dict(CAPABILITY_REGISTRY.require("scan.finalize").budget_cost)
    remaining = {
        name: int(amount) - int(finalizer.get(name, 0))
        for name, amount in dict(residual).items()
    }
    by_id = {action.action_id: action for action in actions}
    lanes: dict[str, list[dict[str, Any]]] = {}
    # Resumable slices whose next unit could still prove an injection on less than its
    # negative verdict needs: the round's last chance if nothing else can be funded.
    last_chance_pool: list[dict[str, Any]] = []
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
        concluded = (budget_concluded or {}).get(action.action_id)
        if concluded == "closed":
            # Every unfinished candidate of the slice is inconclusive for budget, with nothing
            # cheap left that could prove an injection (soak N55).
            continue
        reserved = dict(getattr(result, "budget_reserved", {}) or {})
        held_wall = int(reserved.get("tool_wall_seconds") or 0)
        floor = (
            _floor_scale(
                action.capability_name, held_wall,
                (stage_resume_walls or {}).get(action.action_id), reserved,
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
        request_bound = (
            action.capability_name in RESUMABLE_CAPABILITIES
            and _status(result) == "partial"
            and _reason(result) in _UNFUNDED_STOP_REASONS
        )
        request_need = _request_need(
            action.capability_name, reserved,
            (stage_remaining_requests or {}).get(action.action_id),
        )
        resume_wall = (stage_resume_walls or {}).get(action.action_id)
        if request_need and resume_wall and held_wall > 0:
            # Its request holds are set from what its units need, not scaled with the wall,
            # so only its next unit's wall bounds the extension from below.
            floor = resume_wall / held_wall
        scale = extension_scale(
            reserved=reserved,
            consumed=consumed,
            wall_ceiling=wall_ceiling,
            residual=remaining,
            minimum=max(floor, min(
                _request_scale(reserved, (stage_remaining_requests or {}).get(action.action_id)),
                max(0, wall_ceiling) / max(1, held_wall),
            )) if request_bound else floor,
            request_bound=request_bound,
            request_need=request_need,
        )
        last_chance_wall = (stage_last_chance_walls or {}).get(action.action_id)
        if last_chance_wall and concluded != "closed":
            last_chance_pool.append({
                "index": index, "action": action, "reserved": reserved,
                "request_need": request_need, "last_chance_wall": int(last_chance_wall),
                "resume_wall": int((stage_resume_walls or {}).get(action.action_id) or 0),
            })
        if scale is None:
            continue
        depth = 0
        current = action
        while current is not None and current.capability_args.get(EXTENDS_ARG):
            depth += 1
            current = by_id.get(str(current.capability_args.get(EXTENDS_ARG)))
        lanes.setdefault(action.capability_name, []).append({
            "index": index, "action": action, "reserved": reserved, "depth": depth,
            "need_wall": (
                # A request-bound slice needs holds, not time: its requests scale with its wall.
                math.floor(held_wall * scale) if request_bound
                else math.ceil(held_wall * floor) if concluded == "probe"
                else min(
                    math.floor(held_wall * scale),
                    max(
                        math.ceil(held_wall * floor),
                        _with_slack(int((stage_remaining_walls or {}).get(
                            action.action_id, held_wall * scale,
                        ))),
                    ),
                )
            ),
            "floor_wall": int(math.ceil(held_wall * floor)),
            "held_wall": held_wall,
            "probe": concluded == "probe",
            # Funded only from what the round's new work leaves (``reserved_for_new_work``).
            "low": concluded in {"probe", "degraded"},
            "request_need": request_need,
        })
    planned_by_index: dict[int, dict[str, Any]] = {}
    # The residual is shared fairly between the lanes with work waiting, not handed to the
    # lanes in name order: soak scan 9de6a910's SQLi extensions drained it before the login
    # form's XSS extension was considered. In a first pass each lane holds an equal part of
    # what is left in every scaled dimension (its wall part never above its round share); in a
    # second pass every lane may use what the first left, smallest floor first.
    start = {name: max(0, int(remaining.get(name, 0))) for name in _SCALED_DIMENSIONS}
    # Candidates the Scan has not sliced yet: a first slice is worth more than a probe or the
    # continuation of a candidate that already cannot reach a full negative, so those are
    # funded only from what this reserve leaves (soak N55 review, follow-up 4).
    # In the Scan's last continuation round no later compile will admit a first slice, so
    # nothing is held back for one.
    reserve = 0 if final_round else _admissible_reserve(
        reserved_for_new_work, start["tool_wall_seconds"], wall_ceiling,
    )
    # Each SQLi extension carries its part of the Scan's residual: a technique whose remaining
    # units need more is inconclusive for budget (``sqli_stages.resume_plan``). The residual is
    # divided shortest-remaining-need first, so work that can conclude is funded to its end and
    # a candidate that needs many times what is left (13 s per request over eight fields)
    # keeps only its own hold, and is judged against that.
    # A slice's demand is the predicted wall of what its candidates have left when it is known
    # (a request-bound slice's extension is sized in requests, not in what it will take).
    demands = {
        item["index"]: (
            _with_slack(int(stage_remaining_walls[item["action"].action_id]))
            if item["action"].action_id in (stage_remaining_walls or {})
            else int(item["need_wall"])
        )
        for items in lanes.values() for item in items
    }
    scan_shares = _shortest_first_shares(demands, start["tool_wall_seconds"])
    lane_count = max(1, len(lanes))
    first_part = {name: amount // lane_count for name, amount in start.items()}
    first_part["tool_wall_seconds"] = min(wall_ceiling, first_part["tool_wall_seconds"])
    order = sorted(lanes, key=lambda name: (min(item["floor_wall"] for item in lanes[name]), name))
    lane_used: dict[str, dict[str, int]] = {name: {} for name in lanes}
    passes = [(name, True) for name in order] + [(name, False) for name in order]
    for capability_name, first in passes:
        used = lane_used[capability_name]
        if not first:
            # The second pass may top up what the first gave this lane: its extensions are
            # re-planned from what is left, without the equal-part bound.
            for index in [
                item["index"] for item in lanes[capability_name] if item["index"] in planned_by_index
            ]:
                for name, amount in planned_by_index.pop(index)["budget"].items():
                    remaining[name] = remaining.get(name, 0) + amount
                    used[name] = used.get(name, 0) - amount
        caps = {
            name: (
                first_part[name] - used.get(name, 0) if first
                else (wall_ceiling - used.get(name, 0) if name == "tool_wall_seconds" else None)
            )
            for name in _SCALED_DIMENSIONS
        }
        eligible = sorted(
            (item for item in lanes[capability_name] if item["index"] not in planned_by_index),
            # Work that can still conclude a candidate first, then probes.
            key=lambda item: (item["low"], item["probe"], item["depth"], item["index"]),
        )
        allowance = max(0, min(
            caps["tool_wall_seconds"], remaining.get("tool_wall_seconds", 0),
        ))
        walls = _fair_walls(eligible, allowance)
        for item in eligible:
            wall = walls.get(item["index"])
            if wall is None:
                continue
            scale = wall / item["held_wall"]
            if item["low"]:
                scale = min(
                    scale,
                    max(0, remaining.get("tool_wall_seconds", 0) - reserve) / item["held_wall"],
                )
            # The other scaled holds must still fit what earlier extensions left, and in the
            # first pass this lane's equal part of them.
            needs = item["request_need"] or {}
            for name in _SCALED_DIMENSIONS:
                amount = int(item["reserved"].get(name) or 0)
                if amount > 0:
                    room = max(0, remaining.get(name, 0))
                    if caps[name] is not None:
                        room = min(room, max(0, caps[name]))
                    if name in needs:
                        if room < needs[name][0]:
                            scale = 0.0
                        continue
                    scale = min(scale, room / amount)
            if scale * item["held_wall"] < item["floor_wall"]:
                continue
            action = item["action"]
            budget = {
                name: (
                    min(
                        max(0, remaining.get(name, 0)) if caps[name] is None
                        else max(0, min(remaining.get(name, 0), caps[name])),
                        max(needs[name][0], min(
                            needs[name][1], math.floor(int(amount) * scale),
                        )),
                    )
                    if name in needs
                    else int(math.floor(int(amount) * scale))
                    if name in _SCALED_DIMENSIONS else int(amount)
                )
                for name, amount in item["reserved"].items()
                if int(amount) > 0
            }
            for name, amount in budget.items():
                remaining[name] = remaining.get(name, 0) - amount
                if name in caps and caps[name] is not None:
                    caps[name] -= amount
                used[name] = used.get(name, 0) + amount
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
                    # Only when other work is waiting: a slice alone may use the whole residual,
                    # unit by unit, for as long as it lasts.
                    **(
                        {SCAN_WALL_SHARE_ARG: max(
                            int(scan_shares[item["index"]]),
                            int(budget.get("tool_wall_seconds", 0)),
                        )}
                        if action.capability_name in RESUMABLE_CAPABILITIES
                        and item["index"] in scan_shares
                        and scan_shares[item["index"]] < start["tool_wall_seconds"]
                        and len(scan_shares) > 1 else {}
                    ),
                },
                "budget": budget,
                "dependencies": (),
            }
    # The last chance: what is left cannot fund any planned slice's next negative verdict, but
    # it can fund a final run that may still prove an injection (a late field's positive needs
    # a fraction of a negative's requests). It holds whatever the round has left.
    # Only when nothing else could be planned: the round is then the Scan's last.
    left_wall = (
        0 if planned_by_index
        else min(wall_ceiling, max(0, remaining.get("tool_wall_seconds", 0) - reserve))
    )
    for item in sorted(last_chance_pool, key=lambda row: (row["last_chance_wall"], row["index"])):
        if (
            item["index"] in planned_by_index or left_wall < item["last_chance_wall"]
            # Only a unit the Scan's residual itself cannot fund to its negative verdict; one
            # this round merely did not reach waits for the next round instead.
            or max(0, remaining.get("tool_wall_seconds", 0)) >= item["resume_wall"]
        ):
            continue
        needs = item["request_need"] or {}
        budget: dict[str, int] = {}
        for name, amount in item["reserved"].items():
            amount = int(amount)
            if amount <= 0:
                continue
            room = max(0, int(remaining.get(name, 0)))
            if name == "tool_wall_seconds":
                budget[name] = left_wall
            elif name in needs:
                budget[name] = min(room, needs[name][1])
            elif name in _SCALED_DIMENSIONS:
                budget[name] = min(room, amount)
            else:
                budget[name] = amount
        floors = batch_attempt_floor(item["action"].capability_name, body_candidate=True)
        if any(
            budget.get(name, 0) < min(int(floors.get(name) or 0), int(item["reserved"].get(name) or 0))
            for name in ("http_requests", "state_changing_requests")
        ):
            continue
        for name, amount in budget.items():
            remaining[name] = remaining.get(name, 0) - amount
        left_wall = 0
        action = item["action"]
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
                LAST_CHANCE_ARG: True,
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
