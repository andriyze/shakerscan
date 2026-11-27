"""Shared standing target authority; exact target, revocation and scope remain enforced."""
from __future__ import annotations
import json
from typing import Any, Mapping

STANDING_ACTION_NAME = "target.authorization"
STANDING_RISK_TIERS = ("active", "intrusive")
RISK_TIER_ORDER = {"read_only": 0, "passive": 1, "active": 2,
                   "intrusive": 3, "credential": 4, "dangerous": 5}


def is_standing_target_authorization(receipt: Mapping[str, Any]) -> bool:
    """A receipt type, not a validity check: callers still revalidate every field."""
    return (receipt.get("action_name") == STANDING_ACTION_NAME
            and receipt.get("risk_tier") in STANDING_RISK_TIERS)


# A credential-tier receipt derived for one credentialed Scan from the target's standing
# authorization (target_authorization.derive_credential_scan_receipt).
DERIVED_CREDENTIAL_SCAN = "credential_scan"


def _derived_credential_scan_source_tier(receipt: Mapping[str, Any]) -> str | None:
    """The source's tier of a derived credential-scan receipt ("" when unrecorded), else None."""
    context = receipt.get("action_context")
    if isinstance(context, (bytes, bytearray)):
        context = context.decode("utf-8", "replace")
    if isinstance(context, str):
        try:
            context = json.loads(context)
        except json.JSONDecodeError:
            return None
    if not isinstance(context, Mapping) or context.get("derived_for") != DERIVED_CREDENTIAL_SCAN:
        return None
    return str(context.get("source_risk_tier") or "")


def approval_covers_risk(receipt: Mapping[str, Any], required: str) -> bool:
    """Standing target testing includes explicitly selected target credentials, never deletion."""
    if required not in RISK_TIER_ORDER:
        return False
    source_tier = _derived_credential_scan_source_tier(receipt)
    if source_tier is not None:
        # Stored as tier credential, which ranks above intrusive; it covers the Scan's selected
        # credentials and what its standing source covered, never more than that source.
        return required == "credential" or (
            RISK_TIER_ORDER.get(source_tier, -1) >= RISK_TIER_ORDER[required]
        )
    if required == "credential" and is_standing_target_authorization(receipt):
        return True
    return RISK_TIER_ORDER.get(str(receipt.get("risk_tier") or ""), -1) >= RISK_TIER_ORDER[required]
