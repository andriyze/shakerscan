"""Project settled authorization proof into Hunt's existing finding persistence.

Scan and Hunt use the same pure finding projection. This module adds ownership,
receipt provenance and endpoint identity, not a verifier or an entitlement rule.
"""
from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

try:
    from runtime.receipts import CapabilityReceipt
    from scan.finalizer import canonical_authz_findings
except ModuleNotFoundError:
    from ..runtime.receipts import CapabilityReceipt
    from ..scan.finalizer import canonical_authz_findings

try:
    from findings import templated_finding_identity
except ModuleNotFoundError:
    from scanner.findings import templated_finding_identity


def _origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None or parsed.fragment):
            return None
        return parsed.scheme, parsed.hostname.lower().rstrip("."), parsed.port or (443 if parsed.scheme == "https" else 80)
    except (ValueError, TypeError):
        return None


def authz_finding_records(
    capability_receipt: Any, *, hunt_id: UUID, action_id: UUID,
    target_id: UUID, receipt_id: UUID, allowed_origins: tuple[str, ...],
    target_kind: str = "web",
) -> list[dict[str, Any]]:
    """Accept only this Hunt's canonical receipt, never the caller's loose flags.

    The worker calls this inside its locked atomic settlement. Reading history
    or replaying a settled action does not call it or create verification rows.
    Selected-object observations remain inconclusive under the shared predicate.
    """
    if capability_receipt is None:
        return []
    try:
        receipt = CapabilityReceipt.from_dict(
            capability_receipt.public_dict() if hasattr(capability_receipt, "public_dict")
            else capability_receipt,
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        return []
    if (receipt.capability_name != "authz.verify" or receipt.hunt_id != str(hunt_id)
            or receipt.target_id != str(target_id) or receipt.receipt_id != str(receipt_id)
            or receipt.redacted_execution.get("target_kind") != target_kind
            or receipt.scan_id is not None or receipt.validation_id is not None
            or receipt.status not in {"succeeded", "partial"}
            or receipt.budget_reservation_state not in {"committed", "failed"}
            or not receipt.worker_id or not receipt.budget_reservation_id):
        return []
    origins = {_origin(value) for value in allowed_origins} - {None}
    reference = {"schema_version": "capability-receipt-reference/v1",
                 "receipt_id": receipt.receipt_id, "receipt_hash": receipt.receipt_hash}
    records = []
    for finding in canonical_authz_findings(receipt.observations, receipt=reference):
        evidence = dict(finding["evidence"])
        if (not origins or _origin(finding["url"]) not in origins
                or _origin(evidence["producer_url"]) not in origins):
            continue
        identity = templated_finding_identity(finding)
        if not identity:
            continue
        proof = finding["proof_contract_v2"]
        evidence.update({
            "schema_version": "hunt-deterministic-finding/v1",
            "authoritative": True, "proof_state": "verified", "finding_verdict": "verified",
            "hunt_id": str(hunt_id), "source_action_id": str(action_id),
            "tool_receipt_id": str(receipt_id), "method": "GET",
            "proof_contract_v2": proof,
        })
        records.append({
            "fingerprint": "t:" + hashlib.sha256(identity.encode()).hexdigest()[:16],
            "url": finding["url"], "title": finding["title"],
            "description": finding["description"], "evidence": evidence,
            "tool": finding["tool"], "cwe": finding["cwe"], "finding_type": "bola",
            "verdict_reason": finding["verification_reason"], "contract_id": proof["contract_id"],
        })
    return records
