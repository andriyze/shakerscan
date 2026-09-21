"""Shared standing target authority; exact target, revocation and scope remain enforced."""
from __future__ import annotations
from typing import Any, Mapping

STANDING_ACTION_NAME = "target.authorization"
STANDING_RISK_TIERS = ("active", "intrusive")
RISK_TIER_ORDER = {"read_only": 0, "passive": 1, "active": 2,
                   "intrusive": 3, "credential": 4, "dangerous": 5}


def is_standing_target_authorization(receipt: Mapping[str, Any]) -> bool:
    """A receipt type, not a validity check: callers still revalidate every field."""
    return (receipt.get("action_name") == STANDING_ACTION_NAME
            and receipt.get("risk_tier") in STANDING_RISK_TIERS)


def approval_covers_risk(receipt: Mapping[str, Any], required: str) -> bool:
    """Standing target testing includes explicitly selected target credentials, never deletion."""
    if required not in RISK_TIER_ORDER:
        return False
    if required == "credential" and is_standing_target_authorization(receipt):
        return True
    return RISK_TIER_ORDER.get(str(receipt.get("risk_tier") or ""), -1) >= RISK_TIER_ORDER[required]
