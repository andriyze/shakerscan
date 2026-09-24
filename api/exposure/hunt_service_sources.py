"""Shared service evidence from Hunt's already-durable, content-hashed receipts.

Read the canonical settlement, not Redis replies, planner notes or action summaries.
The existing reservation store owns persistence, idempotency and retention; no second
observation ledger or write-on-GET backfill is needed to reuse these observations.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Mapping
from urllib.parse import urlsplit

from .service_inventory import address, normalized_observation, object_value, origin, timestamp

try:
    from runtime.receipts import CapabilityReceipt
    from runtime.reservation_store import ReservationStoreError, StoredBudgetReservation
except ModuleNotFoundError:
    from ..runtime.receipts import CapabilityReceipt
    from ..runtime.reservation_store import ReservationStoreError, StoredBudgetReservation


SERVICE_OBSERVATION_KINDS = {
    "ports.discover": frozenset({"open_port"}),
    "service.fingerprint": frozenset({"open_port", "service"}),
    "web.probe": frozenset({"http_fingerprint"}),
    "http.request": frozenset({"http_observation"}),
    "collections.replay_safe": frozenset({"http_observation"}),
}
MAX_HUNT_SOURCES = 12
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_OBSERVATIONS = 2_000

HUNT_SOURCES_SQL = """
SELECT b.id,b.action_id,b.action_digest,b.state_json,b.state_digest,
       CASE WHEN octet_length(b.receipt_json::text) <= $3 THEN b.receipt_json END AS receipt_json,
       b.status AS reservation_status,b.capability_name,b.finished_at,
       a.id AS hunt_action_id,a.status AS action_status,a.receipt_id AS action_receipt_id,
       h.id AS hunt_id,h.target_id,h.device_target_id,h.target_kind,h.created_at AS hunt_created_at,
       h.context_pack->'target' AS target_context,
       h.context_pack->'authorized_target_addresses' AS authorized_addresses
FROM hunt_runs h JOIN hunt_actions a ON a.hunt_run_id=h.id
JOIN budget_reservations b ON b.owner_kind='hunt' AND b.owner_id=h.id::text
 AND b.action_id=a.id::text AND b.capability_name=a.capability_name
WHERE (($1::text='web' AND h.target_id=$2 AND h.device_target_id IS NULL)
    OR ($1::text='device' AND h.device_target_id=$2 AND h.target_id IS NULL))
 AND b.capability_name=ANY($4::text[])
 AND b.status IN ('committed','failed')
 AND a.status IN ('completed','partial','failed','cancelled','blocked')
 AND b.receipt_json IS NOT NULL
ORDER BY b.finished_at DESC,b.id
LIMIT $5
"""


def _addresses(value: Any) -> frozenset[str]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, list):
        return frozenset()
    return frozenset(item for raw in value if (item := address(raw)))


def validated_hunt_source(row: Mapping[str, Any], target: Mapping[str, Any]) -> dict[str, Any]:
    """Validate owner/action/receipt/settlement before publishing a narrow projection."""
    try:
        payload = row.get("receipt_json")
        if not payload or len(json.dumps(payload, ensure_ascii=True).encode()) > MAX_RECEIPT_BYTES:
            raise ValueError("Hunt receipt exceeds read budget")
        stored = StoredBudgetReservation.from_row(row)
        record = stored.record
        receipt = CapabilityReceipt.from_dict(stored.receipt or {})
        owner = "device_target_id" if target["kind"] == "device" else "target_id"
        opposite = "target_id" if owner == "device_target_id" else "device_target_id"
        expected_status = {
            "completed": "succeeded", "partial": "partial", "blocked": "blocked",
            "cancelled": "cancelled", "failed": "failed",
        }.get(row.get("action_status"))
        if (
            not record.terminal or record.owner_kind != "hunt"
            or stored.action_id != str(row["hunt_action_id"])
            or row.get("target_kind") not in ({"device"} if target["kind"] == "device" else {"web", "api", "network"})
            or receipt.redacted_execution.get("target_kind") != row.get("target_kind")
            or str(row.get(owner)) != str(target["id"]) or row.get(opposite) is not None
            or record.owner_id != str(row["hunt_id"]) or receipt.hunt_id != record.owner_id
            or receipt.scan_id is not None or receipt.validation_id is not None
            or receipt.target_id != str(target["id"])
            or record.capability_name != row["capability_name"]
            or receipt.capability_name != record.capability_name
            or receipt.capability_name not in SERVICE_OBSERVATION_KINDS
            or receipt.input_digest != stored.action_digest
            or receipt.receipt_hash != record.execution_receipt_hash
            or receipt.receipt_id != str(row.get("action_receipt_id"))
            or receipt.status != expected_status
            or record.status != row["reservation_status"]
            or receipt.budget_reservation_id != record.reservation_id
            or receipt.budget_reservation_state != record.status
            or dict(receipt.budget_reserved) != dict(record.requested)
            or dict(receipt.budget_consumed) != dict(record.actual)
            or receipt.worker_id != record.worker_id
            or timestamp(receipt.finished_at) != record.finished_at
            or timestamp(row.get("finished_at")) != record.finished_at
            or len(receipt.observations) > MAX_RECEIPT_OBSERVATIONS
        ):
            raise ValueError("Hunt evidence identity mismatch")
        context = object_value(row.get("target_context"))
        locator = str(context.get("url") or context.get("locator") or "")
        context_origin = origin(locator)
        host = urlsplit(context_origin).hostname if context_origin else locator.lower().rstrip(".")
        hosts = {host}
        for value in context.get("origins") or ():
            if (candidate := origin(value)):
                hosts.add(urlsplit(candidate).hostname)
        addresses = _addresses(row.get("authorized_addresses"))
        allowed_kinds = SERVICE_OBSERVATION_KINDS[receipt.capability_name]
        observations = []
        rejected = 0
        for raw in receipt.observations:
            if raw.get("kind") not in allowed_kinds:
                continue
            item = normalized_observation(raw)
            if item is None:
                rejected += 1
                continue
            app_host = urlsplit(item["application_origin"]).hostname if item["application_origin"] else None
            if ((item["address"] is not None and item["address"] not in addresses) or (app_host and app_host not in hosts)):
                rejected += 1
                continue
            # Persisted receipts are already redacted. This additionally drops banners,
            # headers, bodies, query strings and arbitrary output before the shared view.
            observations.append({
                "kind": "open_port" if item["identity_basis"] == "port_hint" else "service",
                "address": item["address"], "transport": item["transport"], "port": item["port"],
                "state": item["state"], "service": item["service"], "product": item["product"],
                "version": item["version"], "cpe": item["cpes"], "web_origin": item["application_origin"],
                "method": item["detection_method"], "confidence": item["detection_confidence"],
                "encrypted": item["encrypted"], "tunnel": item["tunnel"],
            })
        generation = None
        historical = False
        if target["kind"] == "device":
            changed = timestamp(target.get("locator_changed_at"))
            started = timestamp(row.get("hunt_created_at"))
            if locator == str(target.get("locator")) and changed and started and started >= changed:
                generation = target.get("locator_generation")
            historical = generation is None
        else:
            historical = not context_origin or context_origin != origin(target.get("locator"))
        return {
            "ref": f"hunt:{receipt.hunt_id}:{stored.action_id}", "hunt_id": receipt.hunt_id,
            "action_id": stored.action_id, "sha256": receipt.receipt_hash,
            "observed_at": receipt.finished_at, "status": receipt.status, "vantage": receipt.worker_id,
            "locator_generation": generation, "historical_locator": historical,
            "observations": observations, "rejected_observations": rejected,
        }
    except (ValueError, TypeError, KeyError, AttributeError, ReservationStoreError) as exc:
        raise ValueError("hunt_service_source_invalid_or_over_budget") from exc


async def hunt_service_sources(conn: Any, target: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[str], bool]:
    """Bounded read of existing settlement rows; no network, writes or authority changes."""
    rows = await conn.fetch(
        HUNT_SOURCES_SQL, target["kind"], uuid.UUID(str(target["id"])), MAX_RECEIPT_BYTES,
        list(SERVICE_OBSERVATION_KINDS), MAX_HUNT_SOURCES + 1,
    )
    sources, warnings = [], []
    for row in rows[:MAX_HUNT_SOURCES]:
        try:
            source = validated_hunt_source(dict(row), target)
        except ValueError:
            warnings.append("A retained Hunt service receipt could not be validated or exceeds the read budget.")
            continue
        sources.append(source)
        if source["rejected_observations"]:
            warnings.append("Malformed or unbound observations were omitted from a retained Hunt service receipt.")
    return sources, warnings, len(rows) > MAX_HUNT_SOURCES
