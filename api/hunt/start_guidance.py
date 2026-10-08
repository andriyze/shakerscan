"""What a Hunt start tells its planner up front: budget warnings and the verifiable families.

Budget warnings. Agents set their own start limits, and in live OpenCode runs one set
``max_http_requests`` to 300, then 180: below what one content discovery reserves, so it
skipped content discovery and missed every exposed file while reporting that no budget had
stopped useful work. A limit the person or agent chooses is never refused or raised here; the
start response names, in ``budget_warnings``, every capability in the manifest that the chosen
limits leave unable to run even once, and the cost of mapping a web target once (one crawl and one
content discovery), so the planner can restart with a workable budget or ask the person.

Only limits a start can change are named (D49): a limit left at its profile default is the most a
start allows, so a reservation above it is not warned about at start (every start used to repeat
``collections.replay_active`` 2000 > ``max_state_changing_requests`` 20); calling that capability
raises a ``budget.raise`` request the person can allow. A lowered limit is named; when even the
profile's start maximum is below the reservation, the warning says so instead of "start again".

Verification. ``verification`` names the candidate families ``candidate.verify`` can prove on
this target kind (D27), so no attempt is spent on a family no verifier accepts.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields
from typing import Any

from .candidate_verification_preflight import public_verification_families
from .start_contract import HUNT_BUDGET_PROFILES, HuntBudget

# One crawl and one content discovery: the least a web Hunt spends to map its target before it
# can find exposed files, configuration and routes.
MAPPING_CAPABILITIES = ("web.crawl", "web.content_discover")
MAX_WARNINGS = 12


def _ledger_limits(budget: Mapping[str, Any]) -> dict[str, tuple[str, int]]:
    """Ledger dimension -> (the budget limit that bounds it, its value)."""
    names = [field.name for field in fields(HuntBudget)]
    # HuntBudget owns the mapping; filled with field positions it says which field each uses.
    positions = HuntBudget(*range(len(names))).ledger_limits()
    return {ledger: (names[index], int(budget.get(names[index]) or 0)) for ledger, index in positions.items()}


def _costs(capabilities: Any) -> dict[str, dict[str, int]]:
    costs: dict[str, dict[str, int]] = {}
    for item in capabilities or ():
        if not isinstance(item, Mapping) or not isinstance(item.get("budget_cost"), Mapping):
            continue
        costs[str(item.get("name"))] = {
            str(key): int(value) for key, value in item["budget_cost"].items()
            if isinstance(value, int) and not isinstance(value, bool) and value > 0
        }
    return costs


def start_budget_warnings(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Warnings for limits too small for the capabilities this Hunt was started with."""
    budget = result.get("budget") if isinstance(result.get("budget"), Mapping) else {}
    if not budget:
        return []
    profile_name = str(result.get("budget_profile") or "balanced")
    profile = HUNT_BUDGET_PROFILES.get(profile_name)
    limits = _ledger_limits(budget)
    costs = _costs(result.get("capabilities"))
    warnings: list[dict[str, Any]] = []
    for capability, cost in sorted(costs.items()):
        for ledger, amount in sorted(cost.items()):
            limit_name, limit = limits.get(ledger, ("", 0))
            # A zero limit is a dimension the policy turned off, not a lowered budget.
            if not limit_name or limit <= 0 or amount <= limit:
                continue
            default = int(getattr(profile, limit_name, 0) or 0) if profile else 0
            if limit >= default:
                # D49: not lowered. The profile's start maximum is below this reservation, so no
                # allowed start setting meets it; a call asks the person for a budget raise.
                continue
            fits = amount <= default
            warnings.append({
                "code": "budget_below_capability_reservation",
                "limit": limit_name, "value": limit, "capability": capability, "reserves": amount,
                "profile_default": default or None, "start_maximum": default or None,
                "restart_fixes_it": fits,
                "message": (
                    f"{limit_name} is {limit}, below the {amount} {ledger} that {capability} "
                    f"reserves for one call, so {capability} can never run in this Hunt"
                    + (
                        f" (the {profile_name} profile default is {default}). Start again without "
                        "lowering it, or ask the person for a budget raise."
                        if fits else
                        f". Even the {profile_name} start maximum, {default}, is below that, so "
                        "starting again cannot fix it; only a budget raise the person approves "
                        "during the Hunt can, and calling it asks for one."
                    )
                ),
            })
    mapping = [costs[name].get("http_requests", 0) for name in MAPPING_CAPABILITIES if name in costs]
    needed = sum(mapping)
    limit_name, limit = limits.get("http_requests", ("max_http_requests", 0))
    lowered = profile is not None and limit < int(getattr(profile, limit_name, 0) or 0)
    if len(mapping) == len(MAPPING_CAPABILITIES) and 0 < limit < needed and lowered:
        default = int(getattr(profile, limit_name, 0) or 0) if profile else 0
        warnings.append({
            "code": "budget_below_mapping_minimum",
            "limit": limit_name, "value": limit, "needed": needed,
            "capabilities": list(MAPPING_CAPABILITIES), "profile_default": default or None,
            "message": (
                f"{limit_name} is {limit}; mapping the target once (one web.crawl and one "
                f"web.content_discover) reserves {needed} http_requests, so crawling or content "
                "discovery will be skipped and exposed files (/.env, /.git, backups) are likely to "
                "be missed"
                + (f". The {profile_name} profile default is {default}" if default else "")
                + ". Prefer the profile default; never lower a limit below what discovery needs."
            ),
        })
    return warnings[:MAX_WARNINGS]


def with_start_guidance(result: Any) -> Any:
    """The start response with ``budget_warnings`` and, for HTTP Hunts, ``verification``."""
    if not isinstance(result, Mapping) or not result.get("hunt_id"):
        return result
    guided = dict(result)
    guided["budget_warnings"] = start_budget_warnings(result)
    if str(result.get("target_kind") or "") != "device":
        guided["verification"] = public_verification_families()
    return guided


__all__ = ["MAPPING_CAPABILITIES", "start_budget_warnings", "with_start_guidance"]
