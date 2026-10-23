"""How fast Hunt work can spend each budget, so the profiles can outlast their clock.

A Hunt call is paced by its executor, never by its budget:

- ``templates.scan``: Nuclei at ``-rate-limit 10``; its hold is 4,000 requests for 300 s (10/s plus
  the reviewed start-up allowance), the highest requests-per-second any hold reserves;
- the headless crawler and browser actions: the browser egress ceiling, 10 requests/s;
- ``web.crawl``: katana, at most 5 requests/s;
- ``xss.verify``: Dalfox at ``--delay 1000`` with 3 workers, about 3 requests/s (1,800 per 480 s);
- ``sqli.verify``: sqlmap at ``--delay 1`` with one thread, about 1 request/s (900 per 540 s);
- ``web.content_discover``: ffuf, its fixed wordlist spread over the wall (220 per 75 s);
- request-collection replays: at most 25 requests per 60 s call;
- ``http.request`` one request per call, and a device's HTTP plane one request per second.

Each call charges its tool wall to ``max_duration_seconds`` (settled to what elapsed) and its
holds to the other ledgers. A ledger therefore cannot run out before the duration does when its
limit covers ``max_duration_seconds`` times the most any call reserves per second of wall
(``spend_pace``), and for HTTP also times the fastest enforced wire rate. The profiles in
``start_contract`` are sized that way; tests/test_hunt_start_guidance.py checks every profile.
Recording a finding or candidate reserves no wall and no traffic; ``max_candidates`` only bounds
runaway writes. The safety ceilings (state-changing requests, ports, hosts, UDP, out-of-band,
device fragility) and every approval are deliberately not derived from pace.
"""
from __future__ import annotations

from fractions import Fraction
from typing import Mapping

# Ledger dimensions a profile sizes from pace; the rest are safety ceilings.
PACED_DIMENSIONS = ("http_requests", "browser_actions", "agent_actions", "active_actions", "verifications")
# The capabilities admission charges one ``verifications`` unit (interaction_router).
VERIFICATION_CAPABILITIES = frozenset({"candidate.verify", "authz.verify"})
# Request-collection replays: admission holds the selected requests (at most 25) for 60 s.
REPLAY_MAX_REQUESTS = 25
REPLAY_WALL_SECONDS = 60


def wire_requests_per_second() -> int:
    """The fastest request rate any Hunt executor is held to on its target."""
    try:
        import agent_tools
    except ModuleNotFoundError:  # package import in host-side tests
        from .. import agent_tools
    dalfox = 3  # --worker 3 at --delay 1000 ms
    sqlmap = 1  # --threads 1 at --delay 1
    device = 1  # one device HTTP request per second
    return max(agent_tools._NUCLEI_RATE_CEILING, agent_tools._BROWSER_MAX_REQUESTS_PER_SECOND,
               agent_tools._KATANA_MAX_RATE_PER_SECOND, dalfox, sqlmap, device)


def executor_hold(name: str, *, profile: str, target_kind: str, smallest: bool = False) -> dict[str, int]:
    """What admission reserves for one call: the scanner's profile hold, a replay's selection, or
    the registry hold. ``smallest`` is the least a call can reserve (a one-request replay)."""
    try:
        from runtime.capability_registry import CAPABILITY_REGISTRY
    except ModuleNotFoundError:
        from ..runtime.capability_registry import CAPABILITY_REGISTRY
    spec = CAPABILITY_REGISTRY.require(name)
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


def spend_pace(profile: str, target_kind: str = "web") -> dict[str, Fraction]:
    """Per paced dimension, the most any one call reserves per second of the wall it holds."""
    try:
        from runtime.capability_registry import CAPABILITY_REGISTRY
    except ModuleNotFoundError:
        from ..runtime.capability_registry import CAPABILITY_REGISTRY
    from .recording import evidence_recording

    pace = {dimension: Fraction(0) for dimension in PACED_DIMENSIONS}
    for spec in CAPABILITY_REGISTRY.list(target_kind=target_kind):
        if not spec.planner_visible or not spec.hunt_executor:
            continue
        hold = executor_hold(spec.name, profile=profile, target_kind=target_kind)
        wall = int(hold.get("tool_wall_seconds") or 0)
        if wall <= 0:
            continue  # recording: no wall, no traffic
        for dimension in ("http_requests", "browser_actions"):
            pace[dimension] = max(pace[dimension], Fraction(int(hold.get(dimension) or 0), wall))
        if not evidence_recording(spec.name):
            pace["agent_actions"] = max(pace["agent_actions"], Fraction(1, wall))
        if spec.name in VERIFICATION_CAPABILITIES:
            pace["verifications"] = max(pace["verifications"], Fraction(1, wall))
    pace["http_requests"] = max(pace["http_requests"], Fraction(wire_requests_per_second()))
    # Any call can need its approval checked (a session, a principal, a write), so approval-gated
    # calls may use the whole call allowance; each one still checks its approval receipt.
    pace["active_actions"] = pace["agent_actions"]
    return pace


def paced_minimum(budget: Mapping[str, int], profile: str, target_kind: str = "web") -> dict[str, int]:
    """The least each paced limit may be for ``budget``'s duration (rounded up)."""
    duration = int(budget.get("max_duration_seconds") or 0)
    return {dimension: -(-duration * rate.numerator // rate.denominator)
            for dimension, rate in spend_pace(profile, target_kind).items()}


__all__ = ["PACED_DIMENSIONS", "VERIFICATION_CAPABILITIES", "executor_hold", "paced_minimum",
           "spend_pace", "wire_requests_per_second"]
