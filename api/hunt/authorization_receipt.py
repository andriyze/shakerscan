"""Read authorization observations from their existing, canonical receipt.

HTTP workers persist a small action summary and put observations in the budget
reservation's receipt_json. Never mistake that summary for the complete result,
or use a caller/queue-returned observation as a substitute for durable evidence.
"""
from __future__ import annotations

from typing import Any, Mapping

try:
    from runtime.receipts import CapabilityReceipt
except ModuleNotFoundError:
    from ..runtime.receipts import CapabilityReceipt

from .authorization_evidence import AuthorizationWorkflowError, mapping


def receipt_backed_action(
    action: Mapping[str, Any], reservation: Mapping[str, Any] | None, *, target_id: Any,
) -> dict[str, Any]:
    """Return a detached read projection, without rewriting the action or proof.

    The reservation is fetched by action, Hunt and capability. Its canonical
    content address and all ownership links must agree before its observations
    can reach the existing exact-object attribution code.
    """
    summary = mapping(action.get("result_summary"))
    record = dict(reservation or {})
    try:
        raw = mapping(record.get("receipt_json"))
        if not raw.get("receipt_hash"):
            raise ValueError("missing content address")
        receipt = CapabilityReceipt.from_dict(raw)
        if (
            record.get("owner_kind") != "hunt"
            or str(record.get("owner_id")) != str(action["hunt_run_id"])
            or str(record.get("action_id")) != str(action["id"])
            or record.get("capability_name") != "authz.verify"
            or action.get("capability_name") != "authz.verify"
            or action.get("status") not in {"completed", "partial"}
            or record.get("status") != "committed"
            or str(record.get("id")) != str(summary.get("budget_reservation_id"))
            or summary.get("budget_reservation_state") != "committed"
            or receipt.budget_reservation_id != str(record["id"])
            or receipt.budget_reservation_state != record["status"]
            or receipt.input_digest != record.get("action_digest")
            or receipt.receipt_hash != record.get("execution_receipt_hash")
            or receipt.receipt_id != str(action.get("receipt_id"))
            or receipt.receipt_id != str(summary.get("receipt_id"))
            or receipt.hunt_id != str(action["hunt_run_id"])
            or receipt.scan_id is not None
            or receipt.target_id != str(target_id)
            or receipt.capability_name != action["capability_name"]
            or receipt.adapter_name != "authz.differential"
            or receipt.status != ("partial" if action["status"] == "partial" else "succeeded")
        ):
            raise ValueError("receipt binding mismatch")
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        # Errors/receipt contents can contain target data; never echo them.
        raise AuthorizationWorkflowError(
            "Canonical authorization receipt is missing, invalid or bound to another action; "
            "the stored action cannot supply an authorization conclusion"
        ) from exc
    # There is one source of observations. A stale or fabricated summary cannot
    # be combined with the receipt to pick whichever result is more favorable.
    summary = {key: value for key, value in summary.items()
               if key not in {"observation", "observations", "typed_output", "result"}}
    summary["observations"] = [dict(item) for item in receipt.observations]
    summary["observation_source"] = "canonical_capability_receipt"
    return {**dict(action), "result_summary": summary}
