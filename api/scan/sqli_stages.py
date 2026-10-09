"""Resumable SQLi verification: one candidate is verified as a sequence of technique stages.

Soak target honey answers its AI endpoints in about 3.7 seconds, and no SQLi verification on
it ever finished. A body candidate's sqlmap run at level 2 / risk 2 needs about 430 requests
to reach a negative verdict (measured in the scanner image against a non-injectable JSON
field: boolean 87, error 144, union 53, time 189 when run one technique at a time; 432 for
all four together), so at ~4 seconds a request the 420-second slice sent 110 and the
latency-sized 900-second extension sent 230 -- and the extension restarted sqlmap from the
first payload, re-sending the slice's 110 before reaching anything new.

Resuming sqlmap's own session does not help: its session store keeps found injection points,
not which payloads came back negative, so a wall-killed run starts detection over. The unit
that can be resumed is a technique: ``--technique X`` is a complete, independent detection
pass, and its verdict ("not injectable by X") is final. Each stage runs as its own bounded
sqlmap invocation and is checkpointed when it finishes; a later attempt on the same
candidate -- after a crash, or in a verification extension -- continues at the first stage
without a verdict and only ever repeats the one stage the wall interrupted. A resume inside
the same action charges the stages that action already ran and holds only what is left for
the rest; a stage carried from an earlier action was charged on that action's receipt.

Stages run cheapest first, by the requests each needs for a negative verdict (measured in the
scanner image at level 2 / risk 2: UNION 53, boolean-based blind 87, error-based 144,
time-based blind 189). On a slow target every request costs the full response time, so a wall
that cannot reach the candidate's verdict still settles as many techniques as it can, and each
settled technique is a checkpoint a later extension never re-sends. A stage that proves an
injection ends the candidate, so time-based blind -- the most expensive and the slowest to
prove -- runs only when UNION, boolean and error-based were all inconclusive. Once an attempt
has settled a stage, it does not start a stage whose negative verdict cannot fit the wall left at
the response time just measured: that stage would be killed part-way and re-sent from its first
payload, so the candidate stops as wall-stopped and the unspent wall returns to its slice. Every stage is
paced and bounded exactly like the attempt it is part of; a stage holds whatever the
candidate's sub-budget has left, so no ceiling grows. A stage the wall interrupted is not a
verdict and the candidate stays unproven-incomplete; a stage that already ran out of wall
once is not re-run on a hold no larger than the one it ran out of.

A stage's cost is per tested field: sqlmap is handed every declared body field (``-p a,b``) and
runs the technique over each. Soak scan 9de6a910 (2.8.0, honey ``POST /hub/login`` with two
fields) measured U 103, B 171 and E 286 requests -- the single-field costs above times two --
so the guard that sized E at 144 requests started it with 159 s left and the wall killed it at
90. The same scan sent two JSON chat candidates (8 and 4 fields, 13 and 5 s per request) into
four slices and extensions, 1,740 s in all, without settling one stage: union-based alone
needed 424 and 212 requests there, more wall than any one round can grant a lane. So what an
unfinished candidate's next attempt needs is predicted from its own measurement -- the next
stage's per-field cost (or, for a stage that already outran it, half again what it sent before
the wall) at the seconds per request it measured -- and an extension is never sized below that
prediction (see ``verification_extension``). A candidate whose next stage cannot fit one
round's share is recorded as inconclusive for budget, with its numbers, instead of being
extended at a wall it is predicted to outrun.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .external_process import paced_request_delay

# Requests a negative verdict costs per technique (soak host, 2026-10-07): the stage order.
SQLI_TECHNIQUE_NEGATIVE_COST: dict[str, int] = {"U": 53, "B": 87, "E": 144, "T": 189}
SQLI_TECHNIQUE_STAGES: tuple[str, ...] = tuple(
    sorted(SQLI_TECHNIQUE_NEGATIVE_COST, key=SQLI_TECHNIQUE_NEGATIVE_COST.__getitem__)
)
STAGE_RECORD_KIND = "sqli_technique_stage"
_SUCCESS = frozenset({"success", "succeeded", "completed"})
# A stage holding less wall than this cannot get past sqlmap's connection and heuristic
# checks; the candidate stops there and a later attempt resumes the stage.
MINIMUM_STAGE_WALL_SECONDS = 20
# Matches the minimum delay of the paced batch attempt the worker builds.
_MINIMUM_DELAY_SECONDS = 0.05
# A stage the wall killed after it had already sent more than its predicted cost is assumed to
# need half again what it sent, so a chain that keeps underestimating it grows geometrically
# instead of being granted a few more seconds each round.
KILLED_STAGE_GROWTH = 1.5
INCONCLUSIVE_RECORD_KIND = "sqli_budget_inconclusive"


def stage_requests(technique: str, field_count: int | None = 1) -> int:
    """Requests a negative verdict of ``technique`` costs over ``field_count`` tested fields."""
    return SQLI_TECHNIQUE_NEGATIVE_COST[technique] * max(1, int(field_count or 1))


def predicted_stage_wall_seconds(
    technique: str,
    *,
    field_count: int | None,
    seconds_per_request: float | None,
    sent_before_kill: int = 0,
) -> int | None:
    """The wall one run of ``technique`` is predicted to need, or None without a measurement.

    ``seconds_per_request`` is the candidate's own measured rate (wall over requests sent,
    pacing delay included), never another endpoint's: one slow endpoint must not mark a fast
    one as unaffordable. A stage that the wall already stopped after ``sent_before_kill``
    requests needs more than that, whatever its nominal cost says.
    """
    if seconds_per_request is None or seconds_per_request <= 0:
        return None
    requests = max(
        stage_requests(technique, field_count),
        math.ceil(max(0, int(sent_before_kill)) * KILLED_STAGE_GROWTH),
    )
    return math.ceil(requests * seconds_per_request) + MINIMUM_STAGE_WALL_SECONDS


def stage_attempt_id(candidate_attempt_id: str, technique: str) -> str:
    """The durable checkpoint id of one technique stage of one candidate attempt."""
    return hashlib.sha256(
        f"{candidate_attempt_id}:technique:{technique}".encode()
    ).hexdigest()


def _status(value: Any) -> str:
    return str(getattr(value, "value", value) or "").strip().lower()


def _stage_record(checkpoint: Mapping[str, Any]) -> Mapping[str, Any]:
    return next((
        item for item in checkpoint.get("observations") or ()
        if isinstance(item, Mapping) and item.get("kind") == STAGE_RECORD_KIND
    ), {})


def _proved(observations: Iterable[Any]) -> bool:
    return any(
        isinstance(item, Mapping) and item.get("kind") == "sqli_finding"
        for item in observations or ()
    )


@dataclass
class PriorStages:
    """What earlier checkpoints already settled for one candidate's stages."""

    finished: dict[str, tuple[str, Mapping[str, Any]]] = field(default_factory=dict)
    wall_killed: dict[str, int] = field(default_factory=dict)
    latency_seconds: float | None = None
    # What every stage checkpoint of the candidate consumed, per action that recorded it.
    spent: dict[str, dict[str, int]] = field(default_factory=dict)
    # The most requests a wall-killed run of each stage had sent when it was stopped.
    killed_sent: dict[str, int] = field(default_factory=dict)
    # The candidate's own latest measured wall per request (pacing delay included); None when
    # none of its stages has run. Unlike ``latency_seconds`` it never falls back to another
    # candidate's measurement.
    seconds_per_request: float | None = None
    # The fields the candidate's stages tested, when a checkpoint recorded it.
    field_count: int | None = None


def prior_stages(
    sources: Sequence[tuple[str, Iterable[Mapping[str, Any]]]],
    candidate_attempt_id: str,
) -> PriorStages:
    """Collect the candidate's stage checkpoints from ``sources``, nearest first.

    ``sources`` is this action's own checkpoints followed by those of every action it
    extends, nearest first. The first finished checkpoint of a stage wins; the largest wall a
    stage was ever killed at is kept so it is not re-run on a hold no larger. The latest
    response time measured by the nearest action that measured one (seconds per request less
    the delay the stage was paced at) is the latency the next stage is paced with; a candidate
    with no measurement of its own takes the latest one any candidate measured on the target.
    """
    prior = PriorStages()
    wanted = {
        stage_attempt_id(candidate_attempt_id, technique): technique
        for technique in SQLI_TECHNIQUE_STAGES
    }
    target_latency: float | None = None
    for source, attempts in sources:
        source_latency: float | None = None
        source_rate: float | None = None
        source_target_latency: float | None = None
        for item in attempts or ():
            if not isinstance(item, Mapping):
                continue
            record = _stage_record(item)
            if not record:
                continue
            consumed = dict(item.get("budget_consumed") or {})
            sent = int(consumed.get("http_requests") or 0)
            wall = int(consumed.get("tool_wall_seconds") or 0)
            measured = (
                max(0.0, wall / sent - float(record.get("delay_ms") or 0) / 1_000)
                if sent > 0 and wall > 0 else None
            )
            if measured is not None:
                # Any candidate's stage measured the same target's response time.
                source_target_latency = measured
            technique = wanted.get(str(item.get("attempt_id") or ""))
            if technique is None:
                continue
            spent = prior.spent.setdefault(source, {})
            for name, amount in consumed.items():
                spent[str(name)] = spent.get(str(name), 0) + max(0, int(amount or 0))
            if measured is not None:
                source_latency = measured
                source_rate = wall / sent
            if prior.field_count is None and isinstance(record.get("field_count"), int):
                prior.field_count = max(1, int(record["field_count"]))
            if (
                _status(item.get("status")) in _SUCCESS
                and not item.get("timed_out")
            ):
                prior.finished.setdefault(technique, (source, item))
            elif item.get("timed_out") or _status(item.get("status")) == "timed_out":
                prior.wall_killed[technique] = max(
                    prior.wall_killed.get(technique, 0),
                    int(consumed.get("tool_wall_seconds") or 0),
                )
                prior.killed_sent[technique] = max(prior.killed_sent.get(technique, 0), sent)
        if prior.latency_seconds is None and source_latency is not None:
            prior.latency_seconds = source_latency
        if prior.seconds_per_request is None and source_rate is not None:
            prior.seconds_per_request = source_rate
        if target_latency is None and source_target_latency is not None:
            target_latency = source_target_latency
    if prior.latency_seconds is None:
        # A candidate not yet attempted is paced by what the target's responses measured on
        # another candidate, rather than starting with the blind full delay.
        prior.latency_seconds = target_latency
    return prior


def next_stage(finished: Iterable[str], *, proven: bool = False) -> str | None:
    """The first technique stage without a verdict, or None when the candidate is finished."""
    if proven:
        return None
    settled = set(finished)
    return next((item for item in SQLI_TECHNIQUE_STAGES if item not in settled), None)


def resume_wall_seconds(
    finished: Iterable[str], wall_killed: Mapping[str, int], *, proven: bool = False,
    field_count: int | None = None, seconds_per_request: float | None = None,
    killed_sent: Mapping[str, int] | None = None,
) -> int | None:
    """The least wall a further attempt needs to make progress, or None if nothing is left.

    That is its first stage without a verdict, re-run on a hold strictly larger than any it
    already ran out of (the stage guard refuses one no larger): the largest wall that stage
    was killed at, plus one stage's minimum. A stage never killed needs that minimum.
    Extensions are sized from this checkpoint, not from the predecessor's hold (audit S002).

    When the candidate measured its own rate, the wall is never below what the stage is
    predicted to need at that rate (``predicted_stage_wall_seconds``): a hold a few seconds
    above the one the stage ran out of is not progress when the stage needs ten times that.
    """
    technique = next_stage(finished, proven=proven)
    if technique is None:
        return None
    floor = int(wall_killed.get(technique, 0)) + MINIMUM_STAGE_WALL_SECONDS
    predicted = predicted_stage_wall_seconds(
        technique, field_count=field_count, seconds_per_request=seconds_per_request,
        sent_before_kill=int((killed_sent or {}).get(technique, 0)),
    )
    return max(floor, predicted or 0)


def _prior_proven(prior: PriorStages) -> bool:
    return any(_proved(item.get("observations")) for _source, item in prior.finished.values())


def prior_resume_wall_seconds(
    prior: PriorStages, *, field_count: int | None = None,
) -> int | None:
    """``resume_wall_seconds`` for a candidate that has not run in this attempt yet."""
    return resume_wall_seconds(
        prior.finished, prior.wall_killed, proven=_prior_proven(prior),
        field_count=field_count or prior.field_count,
        seconds_per_request=prior.seconds_per_request, killed_sent=prior.killed_sent,
    )


def budget_inconclusive_record(
    *,
    candidate_id: str,
    finished: Iterable[str],
    technique: str,
    field_count: int | None,
    seconds_per_request: float | None,
    predicted_wall_seconds: int,
    round_wall_ceiling_seconds: int,
) -> dict[str, Any]:
    """The explicit verdict for a candidate whose next stage no round can fund.

    The candidate is neither proven nor refuted: the techniques it settled were negative, and
    the next one is predicted to need more wall than one continuation round may grant the
    lane, so no extension is planned for it.
    """
    settled = set(finished)
    return {
        "kind": INCONCLUSIVE_RECORD_KIND,
        "family": "sqli",
        "candidate_id": candidate_id,
        "verdict": "inconclusive",
        "reason": "verdict_exceeds_round_budget",
        "refuted_techniques": [item for item in SQLI_TECHNIQUE_STAGES if item in settled],
        "unsettled_techniques": [item for item in SQLI_TECHNIQUE_STAGES if item not in settled],
        "technique": technique,
        "field_count": max(1, int(field_count or 1)),
        "seconds_per_request_ms": round(float(seconds_per_request or 0) * 1_000),
        "predicted_wall_seconds": int(predicted_wall_seconds),
        "round_wall_ceiling_seconds": int(round_wall_ceiling_seconds),
    }


@dataclass(frozen=True)
class StagedAttempt:
    """One candidate's staged verification, in the shape the batch loop reads a result in."""

    status: str
    observations: tuple[Mapping[str, Any], ...]
    errors: tuple[str, ...]
    actual_budget: Mapping[str, int]
    timed_out: bool
    stages: tuple[Mapping[str, Any], ...]
    # The least wall the candidate's next attempt needs to make progress; None when finished.
    resume_wall_seconds: int | None = None
    # The stage that next attempt starts at, and the measurement its wall was predicted from.
    resume_technique: str | None = None
    seconds_per_request: float | None = None
    field_count: int = 1


RunStage = Callable[[str, Mapping[str, int], float], Awaitable[Any]]
Checkpoint = Callable[[Mapping[str, Any]], Awaitable[None]]


async def run_staged_sqli_attempt(
    *,
    candidate_attempt_id: str,
    candidate_id: str,
    budget: Mapping[str, int],
    prior: PriorStages,
    own_action_id: str,
    run_stage: RunStage,
    checkpoint: Checkpoint,
    cancelled: Callable[[], bool],
    measured: Callable[[float], None] | None = None,
    field_count: int | None = None,
) -> StagedAttempt:
    """Verify one candidate stage by stage from what earlier checkpoints left unsettled.

    ``measured`` receives each response time a finished stage measured, so a batch running
    candidates concurrently can size its slots from the target's latency (``sqli_concurrency``).
    ``field_count`` is how many fields each stage tests (sqlmap's ``-p``); a stage costs its
    single-field requests once per field.
    """
    fields = max(1, int(field_count or prior.field_count or 1))
    remaining = {name: max(0, int(amount)) for name, amount in budget.items()}
    consumed: dict[str, int] = {name: 0 for name in budget}
    # Resumed inside the same action (audit L001): the stages it already ran were sent under
    # this action's reservation, but never settled on a receipt. They are charged now, and the
    # stages still to run hold only what the candidate's budget has left. Stages carried from
    # an earlier action were settled on that action's receipt and are not charged again.
    for name, amount in prior.spent.get(own_action_id, {}).items():
        consumed[name] = consumed.get(name, 0) + amount
        if name in remaining:
            remaining[name] = max(0, remaining[name] - amount)
    observations: list[Mapping[str, Any]] = []
    errors: list[str] = []
    stages: list[Mapping[str, Any]] = []
    latency = prior.latency_seconds or 0.0
    complete = True
    proven = False
    timed_out = False
    was_cancelled = False
    ran_here = False
    settled = set(prior.finished)
    wall_killed = dict(prior.wall_killed)
    killed_sent = dict(prior.killed_sent)
    rate = prior.seconds_per_request
    for technique in SQLI_TECHNIQUE_STAGES:
        finished = prior.finished.get(technique)
        if finished is not None:
            source, item = finished
            if source == own_action_id:
                # Resumed inside the same action: its records were never settled on a
                # receipt, so they are this action's evidence (and its cost, charged above).
                observations.extend(
                    dict(record) for record in item.get("observations") or ()
                    if isinstance(record, Mapping)
                )
            else:
                observations.append({
                    **dict(_stage_record(item)), "kind": STAGE_RECORD_KIND,
                    "technique": technique, "carried_from": source,
                })
            stages.append({"technique": technique, "outcome": "carried", "source": source})
            if _proved(item.get("observations")):
                proven = True
                break
            continue
        if cancelled():
            complete, was_cancelled = False, True
            break
        wall = int(remaining.get("tool_wall_seconds", 0))
        http = int(remaining.get("http_requests", 0))
        if http < 1:
            # The candidate's request hold is spent: the request ceiling stopped it.
            complete = False
            stages.append({"technique": technique, "outcome": "requests_exhausted"})
            errors.append("connection_limit_exceeded")
            break
        if wall < MINIMUM_STAGE_WALL_SECONDS:
            # The candidate's wall ran out between stages. That is the wall stopping a
            # candidate mid-verification, exactly as a stage killed by it, so a later
            # extension may continue here.
            complete = False
            timed_out = True
            stages.append({"technique": technique, "outcome": "wall_exhausted"})
            errors.append("timeout")
            break
        if prior.wall_killed.get(technique, 0) >= wall:
            # The same stage already ran out of a hold at least this large: re-running it
            # would send the same requests and stop the same way. The candidate stays
            # incomplete for want of wall, and nothing new was interrupted, so this does
            # not ask for another extension.
            complete = False
            stages.append({"technique": technique, "outcome": "would_repeat_timeout"})
            errors.append("timeout")
            break
        stage_budget = {name: amount for name, amount in remaining.items() if amount > 0}
        delay, _ceiling = paced_request_delay(
            int(stage_budget.get("http_requests", 1)), wall,
            minimum_seconds=_MINIMUM_DELAY_SECONDS, latency_seconds=latency,
        )
        if ran_here and latency > 0 and (
            stage_requests(technique, fields) * (latency + delay) > wall
        ):
            # This attempt already settled a stage, and the next one cannot reach its verdict
            # in the wall left at the response time just measured: starting it would only be
            # killed part-way and re-sent from its first payload by the next attempt. The
            # candidate stops here as wall-stopped, so an extension continues at this stage
            # with a hold that fits it, and the wall it did not spend returns to the slice.
            complete = False
            timed_out = True
            stages.append({"technique": technique, "outcome": "wall_exhausted"})
            errors.append("timeout")
            break
        ran_here = True
        result = await run_stage(technique, stage_budget, latency)
        status = _status(getattr(result, "status", ""))
        spent = {
            str(name): max(0, int(amount))
            for name, amount in dict(getattr(result, "actual_budget", {}) or {}).items()
        }
        for name, amount in spent.items():
            consumed[name] = consumed.get(name, 0) + amount
            remaining[name] = max(0, remaining.get(name, 0) - amount)
        stage_killed = bool(getattr(result, "timed_out", False)) or status == "timed_out"
        sent = int(spent.get("http_requests", 0))
        took = int(spent.get("tool_wall_seconds", 0))
        if sent > 0 and took > 0:
            latency = max(0.0, took / sent - delay)
            rate = took / sent
            if measured is not None:
                measured(latency)
        record = {
            "kind": STAGE_RECORD_KIND, "technique": technique, "status": status,
            "timed_out": stage_killed, "budget_consumed": dict(spent),
            "delay_ms": int(round(delay * 1_000)),
            "measured_latency_ms": int(round(latency * 1_000)),
            "field_count": fields,
        }
        stage_observations = (record, *(
            dict(item) for item in getattr(result, "observations", ()) or ()
            if isinstance(item, Mapping)
        ))
        stage_errors = tuple(str(item) for item in getattr(result, "errors", ()) or ())
        if status != "cancelled":
            await checkpoint({
                "attempt_id": stage_attempt_id(candidate_attempt_id, technique),
                "candidate_id": candidate_id,
                "status": status or "failed",
                "timed_out": stage_killed,
                "budget_consumed": dict(spent),
                "observations": stage_observations,
                "errors": stage_errors,
                "proof_state": "verified" if _proved(stage_observations) else "unproven",
            })
        observations.extend(stage_observations)
        errors.extend(stage_errors)
        stages.append({"technique": technique, "outcome": status, "timed_out": stage_killed})
        if status in _SUCCESS and not stage_killed:
            settled.add(technique)
        elif stage_killed:
            wall_killed[technique] = max(wall_killed.get(technique, 0), took)
            killed_sent[technique] = max(killed_sent.get(technique, 0), sent)
        timed_out = timed_out or stage_killed
        if status == "cancelled":
            complete, was_cancelled = False, True
            break
        if _proved(stage_observations):
            proven = True
            break
        if status not in _SUCCESS:
            complete = False
            break
    if was_cancelled:
        outcome = "cancelled"
    elif proven or complete:
        outcome = "success"
    else:
        outcome = "partial"
    return StagedAttempt(
        status=outcome,
        observations=tuple(observations),
        errors=tuple(errors[:20]),
        actual_budget=consumed,
        timed_out=timed_out and outcome != "success",
        stages=tuple(stages),
        resume_wall_seconds=(
            None if outcome == "success" else resume_wall_seconds(
                settled, wall_killed, field_count=fields, seconds_per_request=rate,
                killed_sent=killed_sent,
            )
        ),
        resume_technique=None if outcome == "success" else next_stage(settled),
        seconds_per_request=rate,
        field_count=fields,
    )
