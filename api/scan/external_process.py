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
import re
from typing import Any, Mapping


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
# fast profile's 1000-request ledger affords no XSS verification at all,
# balanced affords 3 candidates and thorough 15.
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
# These floors are deliberately set to what the work costs, not to what current profiles can
# afford: `thorough` grants its sqli batch 1,600 requests and 300 seconds per ten-candidate slice,
# so one body attempt exceeds an entire slice's wall budget. The consequence is that a body
# candidate is reported as unattempted rather than run in a way that cannot reach a verdict --
# which is the same principle the batch adapter already applies to query candidates. Making these
# land needs a profile-ceiling decision, not a smaller floor.
BATCH_ATTEMPT_BODY_FLOORS: dict[str, dict[str, int]] = {
    "xss.verify_batch": {"http_requests": 240, "tool_wall_seconds": 120},
    "sqli.verify_batch": {"http_requests": 480, "tool_wall_seconds": 420},
}


def batch_attempt_floor(capability_name: str, *, body_candidate: bool = False) -> dict[str, int]:
    """Return the per-attempt floor for one capability, by candidate cost class."""
    name = str(capability_name or "")
    if body_candidate:
        floor = BATCH_ATTEMPT_BODY_FLOORS.get(name)
        if floor:
            return dict(floor)
    return dict(BATCH_ATTEMPT_FLOORS.get(name) or {})


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
        return {
            "schema_version": PROCESS_ENFORCEMENT_SCHEMA,
            "tool_name": self.tool_name,
            "process_plan_digest": self.digest,
            "hard_budget": self.hard_budget_dict,
            "accounting_mode": proof["accounting_mode"],
            "proof_method": proof["method"],
            "parser_version": self.parser_version,
        }


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
