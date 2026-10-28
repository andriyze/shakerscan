"""How fast Hunt work can spend each budget, so a profile's limits outlast its duration.

The duration is the Hunt's clock: the ``tool_wall_seconds`` ledger, bounded by
``max_duration_seconds``, is charged the wall each call took. Every call that runs is charged at
least ``SETTLED_WALL_FLOOR_SECONDS``: inline adapters settle ``max(1, ceil(elapsed))``, browser,
login and replay calls round a positive elapsed time up, and worker processes report their elapsed
time rounded up. A paced limit therefore cannot run out before the clock when it is at least
``max_duration_seconds`` times the most one call can be charged in it per second of settled wall
(``spend_pace``):

- calls, approval-gated calls and verifications: one per call, so one per second;
- browser actions: the most one call is charged at its densest valid input, over one second: a
  login check's conservative 32 (an eight-step ``browser.interact`` with a one-second timeout
  is 9);
- HTTP requests: for a call whose executor sets no request rate, the most it can send in one
  second (a login check's 128 admitted attempts; a browser call's 50; a 25-request replay; a
  candidate verification's 24; an ``http.request`` that follows three redirects, 4); for a scanner
  or network process, which runs at its own rate or delay (Nuclei at 10 per second, katana 5, the
  headless crawler's 10 per second of egress, Dalfox about 3, sqlmap about 1), its hold per second
  of the wall it holds; and at least the fastest of those wire rates.

Two charges are not a pace an investigation keeps up, and are not covered: a call admitted but
refused before it starts is charged one call and no wall, and a process whose traffic the proxy
cannot count and whose launch sets no request rate (headless Dalfox) is charged its hard bound.
Paced Dalfox and sqlmap without their request log are charged their rate over the seconds they ran
(``scan.external_process.paced_worker_rate_bound``), which the pace covers.
Recording a finding or candidate reserves no wall and no traffic. The safety ceilings
(state-changing requests, TCP ports, hosts, UDP ports, out-of-band interactions, device
fragility) and every approval are deliberately not derived from pace. ``HUNT_BUDGET_PROFILES`` in
``start_contract`` is sized from ``paced_minimum``; tests/test_hunt_budget_pace.py settles real
calls against the real ledger to check every profile.
"""
from __future__ import annotations

from fractions import Fraction
from typing import Mapping

# Ledger dimensions a profile sizes from pace; the rest are safety ceilings.
PACED_DIMENSIONS = ("http_requests", "browser_actions", "agent_actions", "active_actions", "verifications")
# The capabilities admission charges one ``verifications`` unit (interaction_router).
VERIFICATION_CAPABILITIES = frozenset({"candidate.verify", "authz.verify"})
# The least wall a call that runs settles.
SETTLED_WALL_FLOOR_SECONDS = 1
# Executors that run a tool process at its own request rate or delay, so their traffic is spread
# over the wall they hold rather than sent at once.
RATE_PACED_EXECUTORS = frozenset({"worker_scanner", "worker_network"})
# Request-collection replays: admission holds the selected requests (at most 25) for 60 s.
REPLAY_MAX_REQUESTS = 25
REPLAY_WALL_SECONDS = 60
# Target kinds whose candidate verification admission adds the HTTP envelope to (a network
# target's candidate is verified on the HTTP service it names).
_CANDIDATE_HTTP_KINDS = frozenset({"web", "api", "network"})


def _registry():
    try:
        from runtime.capability_registry import CAPABILITY_REGISTRY
    except ModuleNotFoundError:  # package import in host-side tests
        from ..runtime.capability_registry import CAPABILITY_REGISTRY
    return CAPABILITY_REGISTRY


def wire_requests_per_second() -> int:
    """The fastest request rate any Hunt executor is held to on its target."""
    try:
        import agent_tools
    except ModuleNotFoundError:  # package import in host-side tests
        from .. import agent_tools
    dalfox = 3  # --worker 3 at --delay 1000
    sqlmap = 1  # --threads 1 at --delay 1
    device = 1  # one device HTTP request per second
    return max(agent_tools._NUCLEI_RATE_CEILING, agent_tools._BROWSER_MAX_REQUESTS_PER_SECOND,
               agent_tools._KATANA_MAX_RATE_PER_SECOND, dalfox, sqlmap, device)


def executor_hold(name: str, *, profile: str, target_kind: str, smallest: bool = False) -> dict[str, int]:
    """What admission reserves for one call: the scanner's profile hold, a replay's selection, or
    the registry hold. ``smallest`` is the least a call can reserve (a one-request replay)."""
    spec = _registry().require(name)
    if spec.hunt_executor == "worker_scanner":
        try:
            from agent_tools import canonical_hunt_scanner_budget
        except ModuleNotFoundError:
            from ..agent_tools import canonical_hunt_scanner_budget
        return dict(canonical_hunt_scanner_budget(name, budget_profile=profile,
                                                  device_target=target_kind == "device"))
    if spec.hunt_executor == "worker_replay":
        requests = 1 if smallest else REPLAY_MAX_REQUESTS
        hold = {"http_requests": requests, "tool_wall_seconds": REPLAY_WALL_SECONDS}
        if name == "collections.replay_active" and not smallest:
            hold["state_changing_requests"] = requests
        return hold
    return {str(key): int(value) for key, value in spec.budget_cost.items()}


def call_ceiling(name: str, *, profile: str, target_kind: str) -> dict[str, int]:
    """The most one call of ``name`` can be charged in each dimension, at its densest valid input:
    its hold, plus what admission adds to it (an ``http.request`` that follows redirects, a web
    candidate verification's HTTP envelope)."""
    ceiling = executor_hold(name, profile=profile, target_kind=target_kind)
    if name == "http.request":
        try:
            from http_experiment import MAX_REDIRECT_HOPS
        except ModuleNotFoundError:
            from ..http_experiment import MAX_REDIRECT_HOPS
        ceiling["http_requests"] = max(int(ceiling.get("http_requests") or 0), 1 + MAX_REDIRECT_HOPS)
    if name == "candidate.verify" and target_kind in _CANDIDATE_HTTP_KINDS:
        from .verification_budget import web_candidate_budget
        for dimension, amount in web_candidate_budget("bola").items():
            ceiling[dimension] = max(int(ceiling.get(dimension) or 0), int(amount))
    return ceiling


def spend_pace(profile: str, target_kind: str = "web") -> dict[str, Fraction]:
    """Per paced dimension, the most one call can be charged per second of the wall it settles."""
    from .recording import evidence_recording

    floor = Fraction(1, SETTLED_WALL_FLOOR_SECONDS)
    pace = {dimension: Fraction(0) for dimension in PACED_DIMENSIONS}
    for spec in _registry().list(target_kind=target_kind):
        if not spec.planner_visible or not spec.hunt_executor or evidence_recording(spec.name):
            continue  # recording: no wall, no traffic
        ceiling = call_ceiling(spec.name, profile=profile, target_kind=target_kind)
        held = int(ceiling.get("tool_wall_seconds") or 0)
        seconds = held if spec.hunt_executor in RATE_PACED_EXECUTORS and held > 0 else SETTLED_WALL_FLOOR_SECONDS
        for dimension in ("http_requests", "browser_actions"):
            pace[dimension] = max(pace[dimension], Fraction(int(ceiling.get(dimension) or 0), seconds))
        # Any call can need its approval checked (a session, a principal, a write), so
        # approval-gated calls may be every call; each one still checks its approval receipt.
        pace["agent_actions"] = pace["active_actions"] = floor
        if spec.name in VERIFICATION_CAPABILITIES:
            pace["verifications"] = floor
    pace["http_requests"] = max(pace["http_requests"], Fraction(wire_requests_per_second()))
    return pace


def paced_minimum(budget: Mapping[str, int], profile: str, target_kind: str = "web") -> dict[str, int]:
    """The least each paced limit may be for ``budget``'s duration (rounded up)."""
    duration = int(budget.get("max_duration_seconds") or 0)
    return {dimension: -(-duration * rate.numerator // rate.denominator)
            for dimension, rate in spend_pace(profile, target_kind).items()}


__all__ = ["PACED_DIMENSIONS", "RATE_PACED_EXECUTORS", "SETTLED_WALL_FLOOR_SECONDS", "VERIFICATION_CAPABILITIES",
           "call_ceiling", "executor_hold", "paced_minimum", "spend_pace", "wire_requests_per_second"]
