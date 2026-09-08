"""Secret-free recurring Scan intent; execution authority is resolved at admission."""

import os
from uuid import UUID

from request_models import ScanRequest
from scan.contracts import resolve_scan_contract

from .managed_dispatch import ManagedScheduleDispatcher


def enabled():
    origin = os.environ.get("SHAKERSCAN_SCHEDULE_DISPATCH_ORIGIN", "")
    token = os.environ.get("SHAKERSCAN_SCHEDULE_DISPATCH_TOKEN", "")
    if not origin and not token:
        return False
    # Validate the complete opt-in transport, never partially opt in.
    ManagedScheduleDispatcher(origin, token)
    return True


def validate(options, *, target="https://schedule-validation.invalid"):
    options = dict(options)
    if options.pop("scan_generation", "v2") != "v2":
        raise ValueError("Managed schedules require canonical V2 Scan intent")
    if options.pop("kind", "normal_scan") not in {"scan", "normal", "normal_scan"}:
        raise ValueError("Conflicting managed schedule kind")
    allowed = {"budget_profile", "policy", "advanced", "credential_profile_ids", "request_collections"}
    if set(options) - allowed:
        raise ValueError("Managed schedules accept only policy, budgets and opaque input references")
    request = ScanRequest(target=target, **options)
    # Do not turn nested public-model defaults into caller-supplied authority.
    # Gateways may intentionally accept a narrower advanced override contract.
    body = request.model_dump(mode="json", exclude_none=True, exclude_unset=True)
    body.pop("options", None)
    # This is validation, not a fabricated approval. Per-occurrence active and
    # credential approvals come from the admission gateway; no receipt is stored.
    contract = resolve_scan_contract(
        budget_profile=request.budget_profile, policy=request.policy,
        advanced=body.get("advanced"),
    )
    body["budget_profile"] = contract.budget_profile
    body["policy"] = request.policy or {"active_testing": False}
    body["advanced"] = body.get("advanced") or {}
    for identifier in request.credential_profile_ids:
        UUID(identifier)
    for ref in request.request_collections:
        if set(ref) - {"id", "replay_policy"} or "id" not in ref:
            raise ValueError("Collections require opaque selection references only")
        UUID(ref["id"])
        if ref.get("replay_policy", "safe_reads") not in {
            "discovery_only", "safe_reads", "safe_authentication", "confirmed_active",
        }:
            raise ValueError("Invalid collection replay policy")
    return body
