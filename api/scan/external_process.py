"""Fail-closed wire-budget contracts for registry-owned external processes.

An external command is executable only when its immutable process plan carries a
command-derived upper bound that fits the already-reserved durable budget.  The
post-execution receipt is intentionally content-free: it proves the authority
used to launch the process without persisting argv, headers, or environment
values that can contain worker-only credentials.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from typing import Any, Mapping, Sequence


PROCESS_PLAN_SCHEMA = "enforced-process-plan/v1"
PROCESS_BUDGET_PROOF_SCHEMA = "external-process-budget-proof/v1"
PROCESS_ENFORCEMENT_SCHEMA = "external-process-enforcement/v1"
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_BUDGET_DIMENSIONS = frozenset({
    "http_requests",
    "state_changing_requests",
    "browser_actions",
    "tcp_ports_attempted",
    "hosts_attempted",
    "tool_wall_seconds",
})
# The smallest slice on which one batched attempt can still reach a verdict.
# The planner uses it so a batch never declares more candidates than its own
# reservation can pay for, and the adapter uses it so it never starts an attempt
# too small to prove anything. Both must read the same numbers: when they drifted
# a batch planned fifty candidates on a budget that funded eight, every run
# reported the family partial and made the whole grade unreliable.
# Measured against a live target, not estimated. dalfox has no request ceiling:
# it issues roughly 1300 requests per parameter, finishing in about 10 seconds
# unpaced and 200 seconds when paced down to the 120 requests declared below --
# at which point the wall kills it mid-scan (exit -9) and the attempt proves
# nothing. The declared figure is therefore still short of what the tool really
# costs, and raising it is a product decision: at 1400 requests per candidate the
# fast profile's 5,000-request ledger affords 3 full-cost candidates,
# balanced affords 14, thorough 42, and opt-in deep 107.
#
# Bounding the tool instead was tried and rejected on evidence. Against a
# deliberately vulnerable reflector, unbounded dalfox reports a verified finding
# with a working proof, while `--only-custom-payload` over the bundled 52
# polyglots reports none, and `--skip-discovery -p <param>` also reports none:
# its discovery phase is what makes detection work. Cheapening the run that way
# trades the finding for the budget, so it is not an option.
BATCH_ATTEMPT_FLOORS: dict[str, dict[str, int]] = {
    "xss.verify_batch": {"http_requests": 120, "tool_wall_seconds": 30},
    # Measured: sqlmap reaches a verdict on an obvious error-based injection in
    # about a hundred requests, so a slice below that cannot prove anything.
    "sqli.verify_batch": {"http_requests": 160, "tool_wall_seconds": 30},
}

# A request-body attempt is a different cost class, and these numbers are measured rather than
# chosen. Against the worker's own sqlmap on a live JSON login endpoint, reaching and confirming
# the injection took 410 HTTP requests and about 420 seconds end to end (the boolean-based blind
# technique reports at roughly 150s; sqlmap continues to a verdict from there). The query floor
# grants 30 seconds, which is why every body attempt in a real scan returned unproven while the
# execution chain itself worked.
#
# These floors are deliberately set to what the work costs. The action planner scales query
# reservations with the profile ceiling and, when state-changing HTTP is authorized, expands and
# resizes a slice so it can fund at least one body attempt without diluting the measured cost.
# Every request a body attempt sends is a mutation, so its state-changing cost equals its
# request cost. These floors omitted the dimension entirely, which meant a body attempt
# consumed nothing from `max_state_changing_requests` -- the ceiling that exists to bound
# exactly this traffic never decremented, so it bounded nothing. The permission itself was
# always enforced: `work_manifests` only creates a body candidate when
# `allow_state_changing_http` is set. What was missing was the accounting.
# The active profile ceilings deliberately fund this cost class. That keeps the
# mutation ledger authoritative without making a required second batch
# unadmittable; query-only attempts settle zero mutation units.
BATCH_ATTEMPT_BODY_FLOORS: dict[str, dict[str, int]] = {
    "xss.verify_batch": {
        "http_requests": 240,
        "state_changing_requests": 240,
        "tool_wall_seconds": 120,
    },
    "sqli.verify_batch": {
        "http_requests": 480,
        "state_changing_requests": 480,
        "tool_wall_seconds": 420,
    },
}


def batch_attempt_floor(capability_name: str, *, body_candidate: bool = False) -> dict[str, int]:
    """Return the per-attempt floor for one capability, by candidate cost class."""
    name = str(capability_name or "")
    if body_candidate:
        floor = BATCH_ATTEMPT_BODY_FLOORS.get(name)
        if floor:
            return dict(floor)
    return dict(BATCH_ATTEMPT_FLOORS.get(name) or {})


def batch_row_cost_class(row: Mapping[str, Any] | Any) -> int:
    """Rank a ranked-manifest candidate by verdict cost: 0 cheap (query/path), 1 expensive (body).

    A body candidate reaches a verdict at the measured body floor (sqlmap on a JSON login: ~420s /
    480 requests) versus ~30s / 160 requests for a query or path candidate. When one batch mixes
    the two, funding the expensive one first can consume the wall that several cheap verdicts
    needed: adding one login-body candidate to Juice Shop's SQLi family took it from verifying the
    products search injection to zero verified (recall 0.44 -> 0.33), because the body candidate
    outranked the query candidate by score and displaced it. Cost is orthogonal to score, so the
    batch orders by cost class first and preserves score order within a class; an expensive
    candidate then runs only on the budget cheaper verdicts did not need, and can never remove one.
    """
    mapping = row if isinstance(row, Mapping) else {}
    method = str(mapping.get("method") or "GET").upper()
    location = str(mapping.get("parameter_location") or mapping.get("location") or "")
    has_body = bool(mapping.get("body_field_names")) or location == "body"
    return 1 if (method != "GET" and has_body) else 0


def order_batch_rows_by_cost_class(rows: Sequence[Any]) -> list[Any]:
    """Reorder ``(index, candidate)`` batch rows cheapest cost class first, score order preserved.

    A stable sort on the cost class alone keeps the manifest's score ranking inside each class, so
    the change is exactly: never let an expensive body candidate be attempted before a cheaper
    candidate it would otherwise starve. Resume is unaffected because attempt ids are content
    addressed by candidate, not by position.
    """
    return sorted(rows, key=lambda entry: batch_row_cost_class(
        entry[1] if isinstance(entry, tuple) and len(entry) == 2 else entry
    ))


# The fraction of its reserved request ceiling a batched attempt is paced to send across the
# WHOLE wall; below 1.0 it keeps a margin so scheduling jitter cannot reach the ceiling.
BATCH_ATTEMPT_REQUEST_HEADROOM = 0.9
# The share of a measured per-request latency a paced attempt's delay is shortened by. The
# remainder stays as margin in case the target answers faster than it did when measured.
MEASURED_LATENCY_CREDIT = 0.75
MAXIMUM_MEASURED_LATENCY_SECONDS = 60.0


def paced_request_delay(
    http: int, wall: int, *, minimum_seconds: float, latency_seconds: float = 0.0,
) -> tuple[float, int]:
    """(delay between requests, request ceiling) for one paced, single-threaded attempt.

    The delay paces the reserved count across the whole wall, so the count stays inside the
    reservation however long the tool runs (see agent_tools._batch_attempt_pacing). A tool
    that waits for each response -- sqlmap detection is sequential -- already spends the
    target's latency between requests, and on soak target honey (~3 s per response) the
    0.97 s delay on top of it cost a quarter of every SQLi attempt's throughput. When the
    latency was measured on an earlier attempt against the same candidate, the delay is
    shortened by part of it (never below ``minimum_seconds``). The request ceiling is not
    raised: the pinned transport refuses connections past the reservation and sqlmap opens one
    per request, so a target that turns faster stops the attempt at its hold, never past it.
    """
    requests = max(1, int(http))
    seconds = max(1, int(wall))
    paced_requests = max(1.0, requests * BATCH_ATTEMPT_REQUEST_HEADROOM)
    delay = seconds / paced_requests
    if delay < minimum_seconds:
        # Too little wall to pace this many requests even at the floor delay: keep the
        # floor and admit only the smaller number the wall can actually cover.
        return minimum_seconds, min(int(http), max(1, int(seconds / minimum_seconds)))
    credit = min(
        MAXIMUM_MEASURED_LATENCY_SECONDS, max(0.0, float(latency_seconds or 0.0)),
    ) * MEASURED_LATENCY_CREDIT
    return max(minimum_seconds, delay - credit), int(http)


# One reviewed passive-pack attempt sends its seven GETs one at a time (concurrency 1, nuclei
# `-timeout 5`), so the attempt can need up to seven request timeouts plus process start-up.
# Measured in the scanner image against a 3-second origin: 7 requests, 23 seconds.
PASSIVE_PACK_ATTEMPT_WALL_SECONDS = 7 * 5 + 5
# An active template attempt may take this many times its planned share when earlier
# attempts left the wall unspent.
_TEMPLATE_ATTEMPT_SHARE_MULTIPLE = 3
#: The windows the permitted active-template allowlist splits into on the pinned bundle with
#: state-changing HTTP: ceil(1,146 / 30), at ``nuclei_execution.ACTIVE_TEMPLATE_WINDOW_SIZE``
#: templates an attempt. A thorough or deep direct Scan plans one attempt per window even when
#: the host has fewer endpoints than windows (a host with two endpoints otherwise ran 2 of 39
#: windows, about 60 of 1,146 templates). An image test pins it to the bundle; a GET-only
#: allowlist has fewer windows, and an attempt past them runs nothing
#: (``nuclei_execution.active_template_window_applies``).
ACTIVE_TEMPLATE_PLANNED_WINDOWS = 39
#: The same without state-changing HTTP: the GET-only allowlist's ceil(636 / 30) windows on the
#: pinned bundle. A Scan without that authority plans only these, so it neither holds budget
#: for positions that would run nothing nor reads partial when a deadline cuts them. (26 until
#: 2.11.1, when 52 login attempts by GET, four GETs reviewed as changing state and 68
#: exploit-class GETs joined the state-changing allowlist.)
ACTIVE_TEMPLATE_PLANNED_GET_ONLY_WINDOWS = 22
#: The record an active-template slice ends with: the windows its attempts finished and how
#: many the allowlist has. The report unions them into ``nuclei_active.template_windows``.
ACTIVE_TEMPLATE_WINDOWS_RECORD_KIND = "active_template_windows"
#: Why a planned position past the allowlist's own windows ran nothing.
TEMPLATE_WINDOW_BEYOND_ALLOWLIST = "template_window_beyond_allowlist"
#: Why a sweep position past every base's windows ran nothing: each (base, window) pair it could
#: name already runs at an earlier position (a host with more endpoints than its bases have
#: windows).
TEMPLATE_WINDOW_PAST_BASES = "template_window_past_bases"
#: Why a thorough or deep Scan's active templates read partial when a sweep base -- the target's
#: or another origin's -- ran fewer than every window.
TEMPLATE_WINDOWS_INCOMPLETE_ON_ORIGIN = "template_windows_incomplete_on_origin"


# What a later passive-pack attempt is reserved once finished attempts on this target have
# measured the pack: the typical (median) finished attempt's wall with this margin, never
# below process start-up and never above the planned share.
_PASSIVE_MEASURED_MARGIN = 1.5
_PASSIVE_MEASURED_FLOOR_SECONDS = 5


def template_attempt_wall(
    *,
    remaining_wall: int,
    remaining_attempts: int,
    planned_share: int,
    passive_pack: bool,
    measured_wall: float | None = None,
) -> int:
    """The wall one template sweep attempt may hold, front-loading what earlier ones left.

    An even split of what is left gave every endpoint of soak scan 146b6c03's required
    passive batch 12 seconds. The fast endpoints finished in about three, and the slow AI
    endpoint -- seven sequential GETs at ~3.7 s each -- was wall-killed at 13 seconds with
    128 of the batch's 216 seconds never used. An attempt may now take what earlier attempts
    left unspent, up to what the work can need, while every attempt after it keeps at least
    its planned share: a later attempt is never funded below what the plan promised it.

    Once passive-pack attempts on this target have finished, ``measured_wall`` (the typical
    finished attempt's wall) replaces the planned share as what each later attempt is
    reserved. Soak e5264021 gave an AI endpoint answering in ~3-5 s 12 seconds while its
    fast siblings had each finished in about three, because every later attempt was still
    reserved 12. A later endpoint that turns out slower than measured is cut off and retried
    at the pack's bound (``template_retry_wall``), so nothing is left unexamined silently.
    """
    remaining = max(0, int(remaining_wall))
    attempts = max(1, int(remaining_attempts))
    share = max(1, int(planned_share))
    even = remaining // attempts
    ceiling = (
        max(share, PASSIVE_PACK_ATTEMPT_WALL_SECONDS) if passive_pack
        else share * _TEMPLATE_ATTEMPT_SHARE_MULTIPLE
    )
    reserve = share
    if passive_pack and measured_wall is not None and measured_wall > 0:
        reserve = min(share, max(
            _PASSIVE_MEASURED_FLOOR_SECONDS,
            math.ceil(float(measured_wall) * _PASSIVE_MEASURED_MARGIN),
        ))
    spare = remaining - (attempts - 1) * reserve
    return max(even, min(ceiling, spare))


def template_retry_wall(
    *,
    remaining_wall: int,
    planned_share: int,
    passive_pack: bool,
) -> int:
    """The wall a template endpoint's retry holds, sized by what its first attempt measured.

    Only an endpoint whose first attempt the wall cut off is retried, so the attempt measured
    it as slower than the share allowed. The passive pack sends its seven GETs one at a time
    and nuclei abandons any request after its 5-second ``-timeout``, so however slow the
    endpoint answers, the pack needs at most ``PASSIVE_PACK_ATTEMPT_WALL_SECONDS``; an active
    attempt keeps its share multiple. Retries run after every endpoint's first attempt, so a
    retry takes that need from what the batch has left, in order: completing one slow endpoint
    is worth more than starving each of them below what it needs again.
    """
    share = max(1, int(planned_share))
    need = (
        max(share, PASSIVE_PACK_ATTEMPT_WALL_SECONDS) if passive_pack
        else share * _TEMPLATE_ATTEMPT_SHARE_MULTIPLE
    )
    return max(0, min(need, int(remaining_wall)))


#: The wall a slice of further template windows (positions past a host's endpoints) holds beside
#: its per-position share: one retry of a window the wall cut off, at the share multiple
#: (``template_retry_wall``). Zoo run d0a8d43c8: windows send 32-102 requests (2 per second
#: at the 120-request / 45-second position hold), so a heavy window that opened a slice -- with
#: no earlier attempt to have left it wall -- needed about 48 s of its 45 and was cut off; with
#: a match already reported it was not retried, and 16 of 57 hosts lost one or two windows. The
#: slice holds the requests (and mutations) this wall paces at the positions' rate beside it
#: (``action_plan.window_retry_hold``): without them a final slice's retry was shortened to the
#: few requests left and never ran.
ACTIVE_TEMPLATE_WINDOW_RETRY_SECONDS = 45 * _TEMPLATE_ATTEMPT_SHARE_MULTIPLE


def window_template_attempt_hold(
    sub_budget: Mapping[str, int],
    *,
    remaining_budget: Mapping[str, int],
    remaining_attempts: int,
    requested_budget: Mapping[str, int],
    first_pass: int,
    planned_wall_share: int,
) -> dict[str, int]:
    """One template-window attempt's hold, paced at the rate its position was planned at.

    nuclei's rate is the attempt's requests over its wall (``agent_tools``: requests // wall).
    ``template_attempt_wall`` front-loads the wall earlier attempts left unspent, but the
    request hold was still an even split of what was left, so a carried wall LOWERED the rate:
    zoo d0a8d43c8 ran a 102-request window at 1 request/s on 74 s of wall (122 requests) and
    cut it off. Requests are carried the same way as wall, up to what the wall paces at the
    planned rate, and every later attempt keeps its planned request share. When the requests
    left cannot keep that pace over the wall, the wall is shortened to what they can pace
    (never below the planned share), so the rate never falls below the planned one. The hold
    never exceeds what the slice has left and the rate never exceeds what the even split
    already allowed, so the slice's request and state-changing ceilings and its pacing stand.
    """
    budget = dict(sub_budget)
    wall = int(budget.get("tool_wall_seconds") or 0)
    passes = max(1, int(first_pass))
    later = max(0, int(remaining_attempts) - 1)
    planned_requests = int(requested_budget.get("http_requests") or 0) // passes
    rate = max(1, planned_requests // max(1, int(planned_wall_share)))
    if wall <= 0 or planned_requests <= 0:
        return budget
    for name in ("http_requests", "state_changing_requests"):
        if name not in budget:
            continue
        share = int(requested_budget.get(name) or 0) // passes
        spare = int(remaining_budget.get(name, 0)) - later * share
        budget[name] = max(int(budget[name]), min(spare, wall * rate))
    paced = min(
        int(budget[name]) for name in ("http_requests", "state_changing_requests")
        if name in budget
    )
    if paced // wall < rate:
        budget["tool_wall_seconds"] = min(wall, max(int(planned_wall_share), paced // rate))
    return budget


def batch_attempt_capacity(
    capability_name: str, budget: dict[str, int] | None,
) -> int | None:
    """How many attempts this reservation can fund, or None when unbounded."""
    floor = BATCH_ATTEMPT_FLOORS.get(str(capability_name or ""))
    if not floor or not budget:
        return None
    affordable = [
        int(budget.get(name, 0)) // amount
        for name, amount in floor.items() if amount > 0
    ]
    return max(1, min(affordable)) if affordable else None


_PROOF_METHODS = frozenset({
    "exact_request_count",
    "rate_time_upper_bound",
    # A headless crawl bounds total egress over its time box rather than the
    # crawler's own request rate: the browser fetches every subresource of every
    # page it opens, and katana's rate limiter does not govern those.
    "browser_rate_time_upper_bound",
    "exact_wordlist",
    "reviewed_template_allowlist",
    "fixed_conservative_profile",
    "exact_port_set",
    "version_probe_upper_bound",
    "port_retry_upper_bound",
    "runtime_transport_wall_limiter",
})


class ExternalProcessContractError(ValueError):
    """A process cannot prove that its wire behavior fits its reservation."""


def _positive_budget(value: Mapping[str, Any], *, label: str) -> dict[str, int]:
    normalized: dict[str, int] = {}
    for raw_name, raw_amount in dict(value).items():
        name = str(raw_name or "").strip()
        if name not in _BUDGET_DIMENSIONS:
            raise ExternalProcessContractError(
                f"{label} uses unknown budget dimension: {name}"
            )
        if isinstance(raw_amount, bool):
            raise ExternalProcessContractError(
                f"{label} budget must contain integers"
            )
        try:
            amount = int(raw_amount)
        except (TypeError, ValueError) as exc:
            raise ExternalProcessContractError(
                f"{label} budget must contain integers"
            ) from exc
        if amount <= 0:
            raise ExternalProcessContractError(
                f"{label} budget must contain positive amounts"
            )
        normalized[name] = amount
    if not normalized:
        raise ExternalProcessContractError(f"{label} budget is empty")
    return normalized


def _wire_reservation(value: Mapping[str, Any]) -> dict[str, int]:
    """Select process-owned dimensions from a broader Scan/Hunt ledger hold."""
    selected = {
        str(name): amount for name, amount in dict(value).items()
        if str(name) in _BUDGET_DIMENSIONS
    }
    return _positive_budget(selected, label="process reservation")


def _canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class EnforcedProcessPlan:
    """One immutable, validated command and its pre-launch hard ceiling."""

    tool_name: str
    binary: str
    argv: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    timeout_ms: int
    hard_budget: tuple[tuple[str, int], ...]
    budget_proof: Mapping[str, Any]
    parser_version: str

    def __post_init__(self) -> None:
        tool = str(self.tool_name or "").strip().lower()
        binary = str(self.binary or "").strip()
        parser = str(self.parser_version or "").strip()
        if not tool or not binary or not parser:
            raise ExternalProcessContractError(
                "process plan requires tool, binary, and parser identities"
            )
        if not self.argv or any("\x00" in str(item) for item in self.argv):
            raise ExternalProcessContractError("process argv is empty or invalid")
        if int(self.timeout_ms) < 1_000:
            raise ExternalProcessContractError("process timeout must be at least 1000ms")
        names = [str(name) for name, _value in self.env]
        if len(names) != len(set(names)) or any(
            not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name) for name in names
        ):
            raise ExternalProcessContractError("process environment overrides are invalid")
        hard = _positive_budget(dict(self.hard_budget), label="process hard")
        if int(self.timeout_ms) > hard.get("tool_wall_seconds", 0) * 1_000:
            raise ExternalProcessContractError(
                "process timeout exceeds its hard wall budget"
            )
        proof = dict(self.budget_proof)
        if proof.get("schema_version") != PROCESS_BUDGET_PROOF_SCHEMA:
            raise ExternalProcessContractError("process budget proof schema is invalid")
        if str(proof.get("tool_name") or "").strip().lower() != tool:
            raise ExternalProcessContractError("process budget proof tool mismatch")
        mode = str(proof.get("accounting_mode") or "")
        if mode not in {"exact", "conservative"}:
            raise ExternalProcessContractError("process accounting mode is invalid")
        method = str(proof.get("method") or "")
        if method not in _PROOF_METHODS:
            raise ExternalProcessContractError("process proof method is invalid")
        if _positive_budget(
            proof.get("upper_bound") if isinstance(proof.get("upper_bound"), Mapping) else {},
            label="process proof upper bound",
        ) != hard:
            raise ExternalProcessContractError(
                "process proof upper bound does not match its hard budget"
            )
        object.__setattr__(self, "tool_name", tool)
        object.__setattr__(self, "binary", binary)
        object.__setattr__(self, "parser_version", parser)
        object.__setattr__(self, "hard_budget", tuple(sorted(hard.items())))
        object.__setattr__(self, "budget_proof", proof)

    @property
    def hard_budget_dict(self) -> dict[str, int]:
        return dict(self.hard_budget)

    @property
    def digest(self) -> str:
        # Values can contain credentials. Only the one-way digest leaves the
        # worker; neither argv nor env is placed in a durable receipt.
        return _canonical_digest({
            "schema_version": PROCESS_PLAN_SCHEMA,
            "tool_name": self.tool_name,
            "binary": self.binary,
            "argv": list(self.argv),
            "env": list(self.env),
            "timeout_ms": int(self.timeout_ms),
            "hard_budget": self.hard_budget_dict,
            "budget_proof": dict(self.budget_proof),
            "parser_version": self.parser_version,
        })

    def validate_reservation(self, reserved: Mapping[str, Any]) -> None:
        reservation = _wire_reservation(reserved)
        shortages = sorted(
            name for name, amount in self.hard_budget
            if reservation.get(name, 0) < amount
        )
        if shortages:
            raise ExternalProcessContractError(
                "process hard ceiling exceeds reservation: " + ",".join(shortages)
            )

    def enforcement_receipt(self) -> dict[str, Any]:
        proof = dict(self.budget_proof)
        receipt = {
            "schema_version": PROCESS_ENFORCEMENT_SCHEMA,
            "tool_name": self.tool_name,
            "process_plan_digest": self.digest,
            "hard_budget": self.hard_budget_dict,
            "accounting_mode": proof["accounting_mode"],
            "proof_method": proof["method"],
            "parser_version": self.parser_version,
        }
        rate_bound = process_rate_bound(proof)
        if rate_bound is not None:
            receipt["rate_bound"] = rate_bound
        return receipt


def _non_negative_integer(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def process_rate_bound(proof: Mapping[str, Any]) -> dict[str, int] | None:
    """The enforced request rate a process proof rests on, when it rests on one.

    A crawler, a content sweep or a paced template attempt is launched with a request rate its
    hard ceiling is derived from (rate x time box + an initial burst). The same rate bounds what
    the tool could have sent in the time it actually ran, which is what its settlement charges
    when no wire log counts the requests (see capabilities/scanner.py).
    """
    inputs = proof.get("inputs") if isinstance(proof.get("inputs"), Mapping) else {}
    rate = _non_negative_integer(inputs.get("rate_per_second"))
    if not rate:
        return paced_worker_rate_bound(proof)
    burst = next((
        value for value in (
            _non_negative_integer(inputs.get(name))
            for name in ("startup_burst", "burst", "threads", "concurrency")
        ) if value is not None
    ), rate)
    return {"rate_per_second": rate, "startup_burst": max(1, burst)}


# Paced verifiers whose workers each wait the delay between requests: Dalfox (3 workers at
# --delay 1000 ms, measured about 3.3 requests a second) and sqlmap (one thread at --delay 1,
# measured about 1). One request a second of headroom is added.
_PACED_WORKER_TOOLS = frozenset({"dalfox", "sqlmap"})


def paced_worker_rate_bound(proof: Mapping[str, Any]) -> dict[str, int] | None:
    """The rate a full, paced Dalfox or sqlmap verification is held to: its workers at its delay.

    Derived from the proof's own inputs (``workers`` or ``threads``, ``delay_ms``), so the plan and
    its digest are unchanged. Headless Dalfox and batch attempts keep their hard bound.
    """
    inputs = proof.get("inputs") if isinstance(proof.get("inputs"), Mapping) else {}
    workers = _non_negative_integer(inputs.get("workers", inputs.get("threads")))
    delay_ms = _non_negative_integer(inputs.get("delay_ms"))
    if (str(proof.get("tool_name") or "") not in _PACED_WORKER_TOOLS or inputs.get("profile") != "full"
            or inputs.get("headless") is True or not workers or not delay_ms):
        return None
    return {"rate_per_second": -(-workers * 1_000 // delay_ms) + 1, "startup_burst": workers}


def validate_enforcement_receipt(
    receipt: Mapping[str, Any], *, reserved: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the content-free proof returned by the worker process runner."""
    value = dict(receipt)
    if value.get("schema_version") != PROCESS_ENFORCEMENT_SCHEMA:
        raise ExternalProcessContractError("process enforcement receipt schema is invalid")
    if not _DIGEST_RE.fullmatch(str(value.get("process_plan_digest") or "")):
        raise ExternalProcessContractError("process plan digest is invalid")
    if str(value.get("accounting_mode") or "") not in {"exact", "conservative"}:
        raise ExternalProcessContractError("process enforcement accounting mode is invalid")
    if str(value.get("proof_method") or "") not in _PROOF_METHODS:
        raise ExternalProcessContractError("process enforcement proof method is invalid")
    hard = _positive_budget(
        value.get("hard_budget") if isinstance(value.get("hard_budget"), Mapping) else {},
        label="process enforcement hard",
    )
    reservation = _wire_reservation(reserved)
    shortages = sorted(
        name for name, amount in hard.items()
        if reservation.get(name, 0) < amount
    )
    if shortages:
        raise ExternalProcessContractError(
            "process enforcement exceeds reservation: " + ",".join(shortages)
        )
    value["hard_budget"] = hard
    if "rate_bound" in value:
        raw = value.get("rate_bound")
        rate = _non_negative_integer(raw.get("rate_per_second")) if isinstance(raw, Mapping) else None
        burst = _non_negative_integer(raw.get("startup_burst")) if isinstance(raw, Mapping) else None
        if not rate or not burst:
            raise ExternalProcessContractError("process enforcement rate bound is invalid")
        value["rate_bound"] = {"rate_per_second": rate, "startup_burst": burst}
    return value


# Reviewed reservation tiers for external verifiers whose registry budget is the
# maximum useful profile. Each tier is selected before traffic, becomes part of
# the immutable action digest, and has a matching command-derived proof builder.
RESERVATION_SCALED_PROFILES: Mapping[
    str, tuple[Mapping[str, int], ...]
] = {
    # The passive pack is a fixed seven-request GET-only allowlist. Shorter
    # wall-time tiers do not widen traffic authority: the request ceiling,
    # templates, methods, redirect policy, and concurrency stay identical.
    # Parallel endpoint partitions need these reviewed tiers so a child can
    # preserve the required passive baseline inside its exact sub-budget.
    "templates.passive_scan": (
        {"http_requests": 7, "tool_wall_seconds": 30},
        {"http_requests": 7, "tool_wall_seconds": 20},
        {"http_requests": 7, "tool_wall_seconds": 10},
    ),
    "templates.scan": (
        {"http_requests": 4_000, "tool_wall_seconds": 300},
    ),
    "xss.verify": (
        {"http_requests": 400, "tool_wall_seconds": 120},
    ),
    "sqli.verify": (
        {"http_requests": 900, "tool_wall_seconds": 300},
    ),
    # Family-partitioned shards can retain deterministic query verification even when their
    # immutable sub-budget cannot fund the much larger request-body floor. Body candidates remain
    # visible as unattempted; they are never silently executed against this smaller hold.
    "xss.verify_batch": (
        {"http_requests": 120, "tool_wall_seconds": 30},
    ),
    "sqli.verify_batch": (
        {"http_requests": 160, "tool_wall_seconds": 30},
    ),
    "sqli.prove_batch": (
        {"http_requests": 8, "tool_wall_seconds": 30},
    ),
}


def fit_reservation_scaled_profile(
    capability_name: str,
    *,
    requested: Mapping[str, int],
    available: Mapping[str, int],
) -> dict[str, int] | None:
    """Return the largest reviewed tier bounded by request and residual hold."""
    for profile in RESERVATION_SCALED_PROFILES.get(str(capability_name), ()):
        if all(
            int(amount) <= int(requested.get(name, 0))
            and int(amount) <= int(available.get(name, 0))
            for name, amount in profile.items()
        ):
            return dict(profile)
    return None


def minimum_reservation_scaled_profile(
    capability_name: str,
) -> dict[str, int] | None:
    profiles = RESERVATION_SCALED_PROFILES.get(str(capability_name), ())
    return dict(profiles[-1]) if profiles else None
