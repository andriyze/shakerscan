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

A stage's cost is per tested field: sqlmap runs the technique over every field it is handed
with ``-p``. Soak scan 9de6a910 (2.8.0, honey ``POST /hub/login``, two fields) measured U 103,
B 171 and E 286 requests -- the single-field costs above times two -- so a guard that sized E
at 144 requests started it with 159 s left and the wall killed it at 90. The same scan sent two
JSON chat candidates (8 and 4 fields, 13 and 5 s per request) into four slices and extensions,
1,740 s in all, without settling one stage, and every extension was granted a few seconds more
than the wall the stage had just run out of.

So a body candidate with several fields is verified one field at a time: each unit is one
technique over one field (``-p`` names that field; the request still carries the whole body),
checkpointed like a stage. A wall that cannot finish a technique over every field still
settles the fields it reached, and the next attempt continues at the first unsettled field.
sqlmap stops at the first vulnerable field either way, and a unit that proves an injection
still ends the candidate. A candidate with one tested field keeps its one unit per technique.

What an unfinished candidate's next attempt needs is predicted from its own measurement: the
next unit's cost (or, for a unit that already outran it, half again what it sent before the
wall) at the candidate's measured seconds per request. Only runs that sent at least
``MINIMUM_RATE_SAMPLE_REQUESTS`` and settled or were wall-killed are rate samples; a unit is
predicted from its own runs, else its technique's, else all of the candidate's, and the
prediction rests on two or more samples judged by their minimum. An extension is never sized
below the prediction (see ``verification_extension``).

Verdicts are per technique. A technique is inconclusive for budget -- its units are not run --
when a unit of it needs more than one round may grant the lane, or all its remaining units more
than the candidate's part of the Scan's residual. The candidate's other techniques are still
funded unit by unit and conclude normally, so a late-field injection by a technique that fits is
still found; the candidate is closed only when nothing fundable is left. A next unit predicted
above the share on a single sample is not a verdict: it gets one probe with the least hold that
measures its rate again. A candidate still waiting for a continuation when the Scan ends is
reported as inconclusive for ``scan_budget_exhausted`` (``sqli_budget_outcomes``).
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .external_process import BATCH_ATTEMPT_REQUEST_HEADROOM, paced_request_delay

# Requests a negative verdict costs per technique and tested field (soak host, 2026-10-07):
# the stage order.
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
# A unit the wall killed after it had already sent more than its predicted cost is assumed to
# need half again what it sent, so a chain that keeps underestimating it grows geometrically
# instead of being granted a few more seconds each round.
KILLED_STAGE_GROWTH = 1.5
# A run that sent fewer requests than this measured start-up and one or two slow answers,
# not the target's rate (a stage killed after 2 requests in 20 s is not 10 s per request).
MINIMUM_RATE_SAMPLE_REQUESTS = 10
INCONCLUSIVE_RECORD_KIND = "sqli_budget_inconclusive"

Unit = tuple[str, "str | None"]


def stage_requests(technique: str, field_count: int | None = 1) -> int:
    """Requests a negative verdict of ``technique`` costs over ``field_count`` tested fields."""
    return SQLI_TECHNIQUE_NEGATIVE_COST[technique] * max(1, int(field_count or 1))


def stage_units(fields: Sequence[str] | None) -> tuple[tuple[str, str | None], ...]:
    """The candidate's verification units in order: each technique, field by field.

    A candidate with at most one tested field has one unit per technique, with no field.
    """
    chunks: tuple[str | None, ...] = (
        tuple(dict.fromkeys(str(item) for item in fields))
        if fields and len(set(fields)) > 1 else (None,)
    )
    return tuple((technique, item) for technique in SQLI_TECHNIQUE_STAGES for item in chunks)


def unit_key(technique: str, field_name: str | None = None) -> str:
    """The checkpoint key of one unit; a whole-technique unit keeps the technique's key."""
    return technique if field_name is None else f"{technique}:{field_name}"


def _unit_requests(technique: str, field_name: str | None, field_count: int) -> int:
    return stage_requests(technique, 1 if field_name is not None else field_count)


def predicted_stage_wall_seconds(
    technique: str,
    *,
    field_count: int | None,
    seconds_per_request: float | None,
    sent_before_kill: int = 0,
) -> int | None:
    """The wall one run of ``technique`` over ``field_count`` fields is predicted to need.

    None without a measurement. ``seconds_per_request`` is the candidate's own robust rate
    (``robust_rate``), never another endpoint's: one slow endpoint must not mark a fast one as
    unaffordable. A run that the wall already stopped after ``sent_before_kill`` requests
    needs more than that, whatever its nominal cost says.
    """
    if seconds_per_request is None or seconds_per_request <= 0:
        return None
    requests = max(
        stage_requests(technique, field_count),
        math.ceil(max(0, int(sent_before_kill)) * KILLED_STAGE_GROWTH),
    )
    return math.ceil(requests * seconds_per_request) + MINIMUM_STAGE_WALL_SECONDS


def stage_attempt_id(candidate_attempt_id: str, technique: str) -> str:
    """The durable checkpoint id of one unit (``unit_key``) of one candidate attempt."""
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


def rate_sample(*, status: Any, timed_out: bool, sent: int, wall: int) -> float | None:
    """One run's seconds per request for prediction, or None when it measured nothing useful.

    A run counts when it settled or the wall killed it, and sent enough requests to measure
    the target rather than start-up; an errored run does not count. Its rate is its wall over
    the requests it sent, pacing included: an extension's holds scale together, so its
    attempts are paced as the run that measured them was.
    """
    settled = _status(status) in _SUCCESS and not timed_out
    killed = bool(timed_out) or _status(status) == "timed_out"
    if not (settled or killed) or sent < MINIMUM_RATE_SAMPLE_REQUESTS or wall <= 0:
        return None
    return wall / sent


RateSample = tuple[str, float]


def _relevant(samples: Iterable[Any], key: str | None = None) -> list[float]:
    """The rates a unit is predicted from: its own runs, else its technique's, else all.

    Techniques differ in their rate (time-based blind waits on its payloads), so time-based is
    never predicted from union-based while a time-based run has measured anything. ``samples``
    holds ``(unit_key, rate)`` pairs or bare rates.
    """
    pairs = [
        (str(item[0]), float(item[1])) if isinstance(item, tuple) else ("", float(item))
        for item in samples or ()
    ]
    if key is None:
        return [rate for _name, rate in pairs]
    technique = key.split(":", 1)[0]
    own = [rate for name, rate in pairs if name == key]
    same = [
        rate for name, rate in pairs
        if name == technique or name.startswith(f"{technique}:")
    ]
    return own or same or [rate for _name, rate in pairs]


def robust_rate(samples: Iterable[Any], key: str | None = None) -> float | None:
    """The candidate's rate for predictions: its fastest qualifying measurement."""
    relevant = _relevant(samples, key)
    return min(relevant) if relevant else None


@dataclass
class PriorStages:
    """What earlier checkpoints already settled for one candidate's units."""

    # Keyed by ``unit_key``; a whole-technique checkpoint settles every field of it.
    finished: dict[str, tuple[str, Mapping[str, Any]]] = field(default_factory=dict)
    wall_killed: dict[str, int] = field(default_factory=dict)
    latency_seconds: float | None = None
    # What every stage checkpoint of the candidate consumed, per action that recorded it.
    spent: dict[str, dict[str, int]] = field(default_factory=dict)
    # The most requests a wall-killed run of each unit had sent when it was stopped.
    killed_sent: dict[str, int] = field(default_factory=dict)
    # The candidate's own qualifying rate measurements (``rate_sample``), every action.
    rate_samples: list[RateSample] = field(default_factory=list)

    @property
    def seconds_per_request(self) -> float | None:
        return robust_rate(self.rate_samples)


def _settled(finished: Iterable[str], technique: str, field_name: str | None) -> bool:
    keys = set(finished)
    return technique in keys or unit_key(technique, field_name) in keys


def prior_stages(
    sources: Sequence[tuple[str, Iterable[Mapping[str, Any]]]],
    candidate_attempt_id: str,
    *,
    fields: Sequence[str] | None = None,
) -> PriorStages:
    """Collect the candidate's unit checkpoints from ``sources``, nearest first.

    ``sources`` is this action's own checkpoints followed by those of every action it
    extends, nearest first. The first finished checkpoint of a unit wins; the largest wall a
    unit was ever killed at is kept so it is not re-run on a hold no larger. The latest
    response time measured by the nearest action that measured one (seconds per request less
    the delay the stage was paced at) is the latency the next stage is paced with; a candidate
    with no measurement of its own takes the latest one any candidate measured on the target.
    """
    prior = PriorStages()
    keys = {unit_key(technique, None) for technique in SQLI_TECHNIQUE_STAGES}
    keys.update(unit_key(technique, item) for technique, item in stage_units(fields))
    wanted = {stage_attempt_id(candidate_attempt_id, key): key for key in keys}
    target_latency: float | None = None
    for source, attempts in sources:
        source_latency: float | None = None
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
            delay = float(record.get("delay_ms") or 0) / 1_000
            measured = max(0.0, wall / sent - delay) if sent > 0 and wall > 0 else None
            if measured is not None:
                # Any candidate's stage measured the same target's response time.
                source_target_latency = measured
            key = wanted.get(str(item.get("attempt_id") or ""))
            if key is None:
                continue
            spent = prior.spent.setdefault(source, {})
            for name, amount in consumed.items():
                spent[str(name)] = spent.get(str(name), 0) + max(0, int(amount or 0))
            if measured is not None:
                source_latency = measured
            killed = bool(item.get("timed_out")) or _status(item.get("status")) == "timed_out"
            sample = rate_sample(status=item.get("status"), timed_out=killed, sent=sent, wall=wall)
            if sample is not None:
                prior.rate_samples.append((key, sample))
            if _status(item.get("status")) in _SUCCESS and not item.get("timed_out"):
                prior.finished.setdefault(key, (source, item))
            elif killed:
                prior.wall_killed[key] = max(prior.wall_killed.get(key, 0), wall)
                prior.killed_sent[key] = max(prior.killed_sent.get(key, 0), sent)
        if prior.latency_seconds is None and source_latency is not None:
            prior.latency_seconds = source_latency
        if target_latency is None and source_target_latency is not None:
            target_latency = source_target_latency
    if prior.latency_seconds is None:
        # A candidate not yet attempted is paced by what the target's responses measured on
        # another candidate, rather than starting with the blind full delay.
        prior.latency_seconds = target_latency
    return prior


def next_unit(
    finished: Iterable[str], fields: Sequence[str] | None = None, *, proven: bool = False,
) -> tuple[str, str | None] | None:
    """The first unit without a verdict, or None when the candidate is finished."""
    if proven:
        return None
    keys = set(finished)
    return next((
        (technique, item) for technique, item in stage_units(fields)
        if not _settled(keys, technique, item)
    ), None)


def next_stage(
    finished: Iterable[str], *, proven: bool = False, fields: Sequence[str] | None = None,
) -> str | None:
    """The technique of the first unit without a verdict, or None when finished."""
    unit = next_unit(finished, fields, proven=proven)
    return unit[0] if unit is not None else None


@dataclass(frozen=True)
class Resume:
    """What a further attempt on an unfinished candidate needs, and what no round can fund."""

    wall_seconds: int | None
    technique: str | None = None
    field_name: str | None = None
    # No technique the candidate still has to run can be funded: it is closed, inconclusive.
    budget_inconclusive: bool = False
    # The next unit is predicted above the share on a single sample: a probe re-measures it.
    probe: bool = False
    # The rate the wall was predicted at.
    seconds_per_request: float | None = None
    # Techniques no round (or the Scan's fair share) can fund: inconclusive for budget. The
    # candidate's other techniques are still funded and conclude normally.
    unfundable: tuple[str, ...] = ()
    # The predicted wall of every fundable unit left: the most a continuation can use.
    remaining_wall: int | None = None
    # The requests every fundable unit left needs for its negative verdict.
    remaining_requests: int | None = None
    # The least wall a last attempt at the next unit needs to be able to prove an injection.
    last_chance_wall: int | None = None
    # A technique is predicted above the share on a single sample: likely to be judged
    # unfundable once measured again, so it does not divide the Scan's residual.
    unconfirmed: bool = False


def resume_plan(
    finished: Iterable[str],
    wall_killed: Mapping[str, int],
    *,
    proven: bool = False,
    fields: Sequence[str] | None = None,
    field_count: int | None = None,
    rate_samples: Iterable[Any] = (),
    killed_sent: Mapping[str, int] | None = None,
    round_wall_ceiling: int | None = None,
    scan_wall_share: int | None = None,
) -> Resume:
    """The least wall a further attempt needs to make progress (audit S002, soak N55).

    That is its first fundable unit without a verdict, re-run on a hold strictly larger than any
    it already ran out of (the stage guard refuses one no larger): the largest wall that unit
    was killed at, plus one stage's minimum. With a rate it is never below the unit's predicted
    wall: a hold a few seconds above the one the unit ran out of is not progress when it needs
    ten times that.

    Rates are judged per unit: its own runs, else its technique's, else all of the candidate's
    (``_relevant``), and a prediction rests on their minimum. Verdicts are per technique. A
    technique is unfundable -- inconclusive for budget -- when, on two or more rate samples
    judged by their minimum, its next unit is predicted above ``round_wall_ceiling`` (or that
    unit was already killed at the ceiling), or its remaining units together are predicted
    above ``scan_wall_share``, the candidate's fair part of what the Scan has left. Its units
    are not run; the candidate's other techniques are funded unit by unit and conclude
    normally, so a late-field injection by a technique that does fit is still found. The
    candidate is closed (``budget_inconclusive``) only when nothing it still has to run is
    fundable. A next unit predicted above the ceiling on a single sample is not a verdict: it
    gets one probe with the least hold that measures its rate again.
    """
    if next_unit(finished, fields, proven=proven) is None:
        return Resume(None)
    samples = list(rate_samples or ())
    killed = dict(killed_sent or {})
    keys = set(finished)
    ceiling = int(round_wall_ceiling or 0)

    def assess(technique: str, field_name: str | None) -> tuple[int, int | None, float | None, int]:
        key = unit_key(technique, field_name)
        count = max(1, int(field_count or 1)) if field_name is None else 1
        floor = int(wall_killed.get(key, 0)) + MINIMUM_STAGE_WALL_SECONDS
        relevant = _relevant(samples, key)
        rate = min(relevant) if relevant else None
        predicted = predicted_stage_wall_seconds(
            technique, field_count=count, seconds_per_request=rate,
            sent_before_kill=int(killed.get(key, 0)),
        )
        return max(floor, predicted or 0), predicted, rate, len(relevant)

    pending: dict[str, list[tuple[str | None, tuple[int, int | None, float | None, int]]]] = {}
    for technique, field_name in stage_units(fields):
        if not _settled(keys, technique, field_name):
            pending.setdefault(technique, []).append(
                (field_name, assess(technique, field_name)),
            )
    unfundable: list[str] = []
    for technique, units in pending.items():
        need, predicted, _rate, count = units[0][1]
        floor = int(wall_killed.get(unit_key(technique, units[0][0]), 0))
        confirmed = count >= 2
        over_round = bool(ceiling) and predicted is not None and need > ceiling and (
            confirmed or floor + MINIMUM_STAGE_WALL_SECONDS > ceiling
        )
        total = sum(item[1][0] for item in units)
        over_scan = bool(scan_wall_share) and predicted is not None and confirmed and (
            total > int(scan_wall_share or 0)
        )
        if over_round or over_scan:
            unfundable.append(technique)
    fundable = next((
        (technique, units[0]) for technique, units in pending.items()
        if technique not in unfundable
    ), None)
    remaining_wall = sum(
        item[1][0] for technique, units in pending.items() if technique not in unfundable
        for item in units
    )
    remaining_requests = sum(
        _unit_requests(technique, item[0], max(1, int(field_count or 1)))
        for technique, units in pending.items() if technique not in unfundable
        for item in units
    )
    unconfirmed = bool(ceiling) and any(
        units[0][1][1] is not None and units[0][1][0] > ceiling and units[0][1][3] < 2
        for technique, units in pending.items() if technique not in unfundable
    )
    if fundable is None:
        return Resume(None, budget_inconclusive=True, unfundable=tuple(unfundable))
    technique, (field_name, (need, predicted, rate, count)) = fundable
    if ceiling and predicted is not None and need > ceiling and count < 2:
        # Only the unit about to run is probed: a later technique over the share on one
        # sample is judged when it is next.
        key = unit_key(technique, field_name)
        probe_wall = max(
            int(wall_killed.get(key, 0)) + MINIMUM_STAGE_WALL_SECONDS,
            MINIMUM_STAGE_WALL_SECONDS + math.ceil(
                MINIMUM_RATE_SAMPLE_REQUESTS * KILLED_STAGE_GROWTH * float(rate or 0)
            ),
        )
        return Resume(
            min(need, probe_wall, ceiling), technique, field_name, probe=True,
            seconds_per_request=rate, unfundable=tuple(unfundable),
            remaining_wall=min(need, probe_wall, ceiling), unconfirmed=True,
        )
    return Resume(
        need, technique, field_name, seconds_per_request=rate, unfundable=tuple(unfundable),
        remaining_wall=remaining_wall if rate is not None else None, unconfirmed=unconfirmed,
        remaining_requests=remaining_requests,
        last_chance_wall=last_chance_wall_seconds(rate),
    )


def last_chance_wall_seconds(seconds_per_request: float | None) -> int | None:
    """The least wall in which a run can still prove an injection at the measured rate.

    A positive needs far fewer requests than a negative verdict (sqlmap stops at the first
    confirmed payload); this is the probe's minimum -- enough requests for a rate sample, half
    again -- which is the least a final attempt is worth starting with.
    """
    if not seconds_per_request:
        return None
    return MINIMUM_STAGE_WALL_SECONDS + math.ceil(
        MINIMUM_RATE_SAMPLE_REQUESTS * KILLED_STAGE_GROWTH * float(seconds_per_request)
    )


def unfundable_techniques(
    finished: Iterable[str], wall_killed: Mapping[str, int], **kwargs: Any,
) -> tuple[str, ...]:
    """The techniques ``resume_plan`` judges unfundable for this state."""
    return resume_plan(finished, wall_killed, **kwargs).unfundable


def resume_wall_seconds(
    finished: Iterable[str], wall_killed: Mapping[str, int], *, proven: bool = False,
    field_count: int | None = None, seconds_per_request: float | None = None,
    killed_sent: Mapping[str, int] | None = None,
) -> int | None:
    """``resume_plan``'s wall for a candidate with one unit per technique and no ceiling."""
    return resume_plan(
        finished, wall_killed, proven=proven, field_count=field_count,
        rate_samples=() if seconds_per_request is None else (seconds_per_request,),
        killed_sent=killed_sent,
    ).wall_seconds


def _prior_proven(prior: PriorStages) -> bool:
    return any(_proved(item.get("observations")) for _source, item in prior.finished.values())


def prior_resume(
    prior: PriorStages, *, fields: Sequence[str] | None = None,
    field_count: int | None = None, round_wall_ceiling: int | None = None,
    scan_wall_share: int | None = None,
) -> Resume:
    """``resume_plan`` for a candidate that has not run in this attempt yet."""
    return resume_plan(
        prior.finished, prior.wall_killed, proven=_prior_proven(prior), fields=fields,
        field_count=field_count, rate_samples=prior.rate_samples,
        killed_sent=prior.killed_sent, round_wall_ceiling=round_wall_ceiling,
        scan_wall_share=scan_wall_share,
    )


def prior_resume_wall_seconds(
    prior: PriorStages, *, fields: Sequence[str] | None = None,
    field_count: int | None = None, round_wall_ceiling: int | None = None,
) -> int | None:
    """``prior_resume``'s wall."""
    return prior_resume(
        prior, fields=fields, field_count=field_count, round_wall_ceiling=round_wall_ceiling,
    ).wall_seconds


def budget_inconclusive_record(
    *,
    candidate_id: str,
    finished: Iterable[str],
    unfundable_techniques: Sequence[str],
    fields: Sequence[str] | None = None,
    field_count: int | None,
    seconds_per_request: float | None,
    round_wall_ceiling_seconds: int,
    scan_wall_share_seconds: int | None = None,
    closed: bool,
    next_technique: str | None = None,
    next_field: str | None = None,
) -> dict[str, Any]:
    """The explicit, per-technique budget verdict for one candidate.

    ``unfundable_techniques`` are inconclusive for budget: on two or more rate samples judged
    by their minimum, a unit of theirs needs more than one round may grant the lane, or all of
    their remaining units more than the candidate's fair part of what the Scan has left. Those
    techniques neither proved nor refuted anything and are not run. The candidate's other
    techniques are refuted (settled negative) or still funded; ``closed`` says nothing
    fundable is left.
    """
    keys = set(finished)
    units = stage_units(fields)
    refuted = [
        technique for technique in SQLI_TECHNIQUE_STAGES
        if all(_settled(keys, technique, item) for name, item in units if name == technique)
    ]
    return {
        "kind": INCONCLUSIVE_RECORD_KIND,
        "family": "sqli",
        "candidate_id": candidate_id,
        "verdict": "inconclusive",
        "reason": "verdict_exceeds_budget",
        "unfundable_techniques": list(unfundable_techniques),
        "refuted_techniques": refuted,
        "unsettled_techniques": [
            technique for technique in SQLI_TECHNIQUE_STAGES if technique not in refuted
        ],
        "settled_units": sorted(keys),
        "closed": bool(closed),
        **({"next_technique": next_technique} if next_technique and not closed else {}),
        **({"next_field": next_field} if next_field and not closed else {}),
        "field_count": max(1, int(field_count or 1)),
        "seconds_per_request_ms": round(float(seconds_per_request or 0) * 1_000),
        "round_wall_ceiling_seconds": int(round_wall_ceiling_seconds),
        **(
            {"scan_wall_share_seconds": int(scan_wall_share_seconds)}
            if scan_wall_share_seconds else {}
        ),
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
    # The unit that next attempt starts at, and the measurement its wall was predicted from.
    resume_technique: str | None = None
    resume_field: str | None = None
    seconds_per_request: float | None = None
    field_count: int = 1
    # Nothing the candidate still has to run is fundable; see ``resume_plan``.
    budget_inconclusive: bool = False
    # The next round is a probe that measures the rate again.
    resume_probe: bool = False
    settled_units: tuple[str, ...] = ()
    # Techniques inconclusive for budget (never run); the others conclude normally.
    unfundable_techniques: tuple[str, ...] = ()
    # The predicted wall of every fundable unit the candidate has left.
    remaining_wall_seconds: int | None = None
    # A technique it still has is above the share on a single sample (``Resume.unconfirmed``).
    resume_unconfirmed: bool = False
    remaining_requests: int | None = None
    last_chance_wall_seconds: int | None = None


RunStage = Callable[..., Awaitable[Any]]
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
    fields: Sequence[str] | None = None,
    round_wall_ceiling: int | None = None,
    scan_wall_share: int | None = None,
    last_chance: bool = False,
) -> StagedAttempt:
    """Verify one candidate unit by unit from what earlier checkpoints left unsettled.

    ``measured`` receives each response time a finished stage measured, so a batch running
    candidates concurrently can size its slots from the target's latency (``sqli_concurrency``).
    ``fields`` are the fields sqlmap is handed with ``-p``; with more than one, each technique
    runs field by field and ``run_stage`` receives the field as a fourth argument.
    ``field_count`` is how many fields a whole-technique unit tests (default: one).
    ``round_wall_ceiling`` and ``scan_wall_share`` bound what is funded (``resume_plan``): a
    unit of a technique that cannot be funded is not run, and the attempt moves on to the
    next technique that can. ``last_chance`` is the Scan's final attempt at the next unit: its
    hold cannot fund the unit's negative verdict but can a positive, so the unit is started
    even on a hold no larger than one it already ran out of.
    """
    fields = tuple(dict.fromkeys(str(item) for item in fields or ())) or None
    count = max(1, int(field_count or (len(fields) if fields else 1)))
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
    samples = list(prior.rate_samples)
    carried_techniques: set[str] = set()
    for technique, field_name in stage_units(fields):
        key = unit_key(technique, field_name)
        label = {"technique": technique, **({"field": field_name} if field_name else {})}
        finished = prior.finished.get(key) or prior.finished.get(technique)
        if finished is not None:
            source, item = finished
            whole = key not in prior.finished
            if whole and technique in carried_techniques:
                # A whole-technique checkpoint settles every field; it is carried once.
                continue
            carried_techniques.add(technique)
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
                    **({"technique": technique} if whole else label), "carried_from": source,
                })
            stages.append({
                **({"technique": technique} if whole else label),
                "outcome": "carried", "source": source,
            })
            if _proved(item.get("observations")):
                proven = True
                break
            continue
        plan = resume_plan(
            settled, wall_killed, fields=fields, field_count=count, rate_samples=samples,
            killed_sent=killed_sent, round_wall_ceiling=round_wall_ceiling,
            scan_wall_share=scan_wall_share,
        )
        if technique in plan.unfundable:
            # Inconclusive for budget: no round can fund this technique, so its units are not
            # run; the candidate's fundable techniques still are.
            complete = False
            stages.append({**label, "outcome": "budget_inconclusive"})
            continue
        if cancelled():
            complete, was_cancelled = False, True
            break
        wall = int(remaining.get("tool_wall_seconds", 0))
        http = int(remaining.get("http_requests", 0))
        unit_requests = _unit_requests(technique, field_name, count)
        if http < 1 or unit_requests > http or (
            ran_here and unit_requests > http * BATCH_ATTEMPT_REQUEST_HEADROOM
        ):
            # The candidate's request hold cannot fund this unit's verdict (for a body, the
            # request hold is its mutation hold; pacing spreads only its headroom share over
            # the wall): the request ceiling stops it, named as such so the planner can extend
            # the slice for its unfunded candidates rather than read it as a timeout.
            complete = False
            stages.append({**label, "outcome": "requests_exhausted"})
            errors.append("connection_limit_exceeded")
            break
        if wall < MINIMUM_STAGE_WALL_SECONDS:
            # The candidate's wall ran out between stages. That is the wall stopping a
            # candidate mid-verification, exactly as a stage killed by it, so a later
            # extension may continue here.
            complete = False
            timed_out = True
            stages.append({**label, "outcome": "wall_exhausted"})
            errors.append("timeout")
            break
        if prior.wall_killed.get(key, 0) >= wall and not (last_chance and not ran_here):
            # The same unit already ran out of a hold at least this large: re-running it
            # would send the same requests and stop the same way. The candidate stays
            # incomplete for want of wall, and nothing new was interrupted, so this does
            # not ask for another extension.
            complete = False
            stages.append({**label, "outcome": "would_repeat_timeout"})
            errors.append("timeout")
            break
        stage_budget = {name: amount for name, amount in remaining.items() if amount > 0}
        delay, _ceiling = paced_request_delay(
            int(stage_budget.get("http_requests", 1)), wall,
            minimum_seconds=_MINIMUM_DELAY_SECONDS, latency_seconds=latency,
        )
        probing = plan.probe and (plan.technique, plan.field_name) == (
            technique, field_name,
        ) and wall >= MINIMUM_STAGE_WALL_SECONDS + math.ceil(
            MINIMUM_RATE_SAMPLE_REQUESTS * (latency + delay)
        )
        # Never predicted faster than the candidate has been observed to answer.
        observed = robust_rate(samples, key)
        per_request = max(latency + delay, observed or 0.0)
        if ran_here and (latency > 0 or observed) and not probing and (
            _unit_requests(technique, field_name, count) * per_request > wall
        ):
            # This attempt already settled a unit, and the next one cannot reach its verdict
            # in the wall left at the response time just measured: starting it would only be
            # killed part-way and re-sent from its first payload by the next attempt. The
            # candidate stops here as wall-stopped, so an extension continues at this unit
            # with a hold that fits it, and the wall it did not spend returns to the slice.
            complete = False
            timed_out = True
            stages.append({**label, "outcome": "wall_exhausted"})
            errors.append("timeout")
            break
        # Otherwise, when the candidate's verdict rests on a single rate sample, the wall the
        # unit cannot finish in is spent re-measuring it instead of being returned: a run of
        # at least ``MINIMUM_RATE_SAMPLE_REQUESTS`` is the second sample a budget verdict needs.
        ran_here = True
        if field_name is None:
            result = await run_stage(technique, stage_budget, latency)
        else:
            result = await run_stage(technique, stage_budget, latency, field_name)
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
            if measured is not None:
                measured(latency)
        sample = rate_sample(status=status, timed_out=stage_killed, sent=sent, wall=took)
        if sample is not None:
            samples.append((key, sample))
        record = {
            "kind": STAGE_RECORD_KIND, **label, "status": status,
            "timed_out": stage_killed, "budget_consumed": dict(spent),
            "delay_ms": int(round(delay * 1_000)),
            "measured_latency_ms": int(round(latency * 1_000)),
            "field_count": 1 if field_name is not None else count,
        }
        stage_observations = (record, *(
            dict(item) for item in getattr(result, "observations", ()) or ()
            if isinstance(item, Mapping)
        ))
        stage_errors = tuple(str(item) for item in getattr(result, "errors", ()) or ())
        if status != "cancelled":
            await checkpoint({
                "attempt_id": stage_attempt_id(candidate_attempt_id, key),
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
        stages.append({**label, "outcome": status, "timed_out": stage_killed})
        if status in _SUCCESS and not stage_killed:
            settled.add(key)
        elif stage_killed:
            wall_killed[key] = max(wall_killed.get(key, 0), took)
            killed_sent[key] = max(killed_sent.get(key, 0), sent)
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
    resume = (
        Resume(None) if outcome in {"success", "cancelled"} else resume_plan(
            settled, wall_killed, fields=fields, field_count=count, rate_samples=samples,
            killed_sent=killed_sent, round_wall_ceiling=round_wall_ceiling,
            scan_wall_share=scan_wall_share,
        )
    )
    if resume.budget_inconclusive:
        # Closed for budget: the slice states that, not a timeout or an adapter failure.
        errors.append("insufficient_plan_budget")
    if outcome == "cancelled":
        # A cancelled attempt is resumed like any interrupted one, but never given a verdict.
        resume = Resume(resume_plan(
            settled, wall_killed, fields=fields, field_count=count, rate_samples=samples,
            killed_sent=killed_sent,
        ).wall_seconds)
    return StagedAttempt(
        status=outcome,
        observations=tuple(observations),
        errors=tuple(errors[:20]),
        actual_budget=consumed,
        timed_out=timed_out and outcome != "success",
        stages=tuple(stages),
        resume_wall_seconds=resume.wall_seconds,
        resume_technique=resume.technique,
        resume_field=resume.field_name,
        seconds_per_request=(
            resume.seconds_per_request if resume.wall_seconds else robust_rate(samples)
        ),
        field_count=count,
        budget_inconclusive=resume.budget_inconclusive,
        resume_probe=resume.probe,
        settled_units=tuple(sorted(settled)),
        unfundable_techniques=resume.unfundable,
        remaining_wall_seconds=resume.remaining_wall,
        resume_unconfirmed=resume.unconfirmed,
        remaining_requests=resume.remaining_requests,
        last_chance_wall_seconds=resume.last_chance_wall,
    )


def sqli_budget_outcomes(
    rows_in_plan_order: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Every SQLi candidate the Scan left inconclusive for budget, for the report.

    ``rows_in_plan_order`` are the observations of every SQLi verifier action in plan order;
    the latest record of a candidate stands. Each outcome separates what was settled from what
    was not, so no reader takes an untested technique for a refuted one:

    * ``refuted_techniques`` -- every unit settled negative;
    * ``inconclusive_techniques`` -- judged unfundable (``verdict_exceeds_budget``);
    * ``unfinished_techniques`` -- fundable, but not reached before the Scan's budget ran out.

    A closed candidate (nothing fundable left) reports ``verdict_exceeds_budget``. One still
    waiting for a continuation when the Scan ended reports ``scan_budget_exhausted`` with the
    unit it would have run next, whether or not some of its techniques were judged unfundable.
    """
    latest: dict[str, Mapping[str, Any]] = {}
    verdicts: dict[str, Mapping[str, Any]] = {}
    urls: dict[str, str] = {}
    settled: dict[str, set[tuple[str, str | None]]] = {}
    for row in rows_in_plan_order:
        if not isinstance(row, Mapping):
            continue
        candidate = str(row.get("candidate_id") or "")
        if not candidate:
            continue
        kind = row.get("kind")
        if row.get("url"):
            urls.setdefault(candidate, str(row["url"]))
        if kind == STAGE_RECORD_KIND:
            if _status(row.get("status")) in _SUCCESS and not row.get("timed_out"):
                field_name = row.get("field")
                settled.setdefault(candidate, set()).add(
                    (str(row.get("technique") or ""), str(field_name) if field_name else None),
                )
            continue
        if row.get("carried_from"):
            continue
        if kind in {"candidate_attempt", "candidate_deferred"} and row.get("family", "sqli") == "sqli":
            latest[candidate] = row
            if not row.get("verdict") and not row.get("inconclusive_techniques"):
                verdicts.pop(candidate, None)
        elif kind == INCONCLUSIVE_RECORD_KIND:
            verdicts[candidate] = row
    outcomes: list[dict[str, Any]] = []
    for candidate, row in latest.items():
        verdict = verdicts.get(candidate)
        unfinished = bool(row.get("resume_wall_seconds")) and str(row.get("status") or "") != "success"
        if verdict is None and not unfinished:
            continue
        field_count = max(1, int(row.get("field_count") or (verdict or {}).get("field_count") or 1))
        units = settled.get(candidate, set())
        refuted = [
            technique for technique in SQLI_TECHNIQUE_STAGES
            if (technique, None) in units
            or len({item for name, item in units if name == technique and item}) >= field_count
        ]
        if verdict is not None:
            refuted = list(dict.fromkeys([*verdict.get("refuted_techniques", ()), *refuted]))
        unfundable = [str(item) for item in (verdict or {}).get("unfundable_techniques") or ()]
        closed = bool((verdict or {}).get("closed")) or row.get("verdict") == "inconclusive"
        outcome = {
            "candidate_id": candidate, "url": urls.get(candidate, ""),
            "reason": (
                "verdict_exceeds_budget" if closed or not unfinished else "scan_budget_exhausted"
            ),
            "refuted_techniques": [item for item in SQLI_TECHNIQUE_STAGES if item in refuted],
            "inconclusive_techniques": [
                item for item in SQLI_TECHNIQUE_STAGES if item in unfundable
            ],
            "unfinished_techniques": [
                item for item in SQLI_TECHNIQUE_STAGES
                if item not in refuted and item not in unfundable
            ] if not closed else [],
            "closed": closed,
        }
        if unfinished and not closed:
            if row.get("resume_technique"):
                outcome["next_technique"] = row["resume_technique"]
            if row.get("resume_field"):
                outcome["next_field"] = row["resume_field"]
        outcomes.append(outcome)
    return outcomes
