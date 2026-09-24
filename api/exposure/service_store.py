"""Bounded read model over existing target, device and Scan evidence stores."""
from __future__ import annotations

from typing import Any
import uuid

from .hunt_service_sources import hunt_service_sources
from .service_actions import hunt_handoff, service_activities
from .service_intel import enrich_service, snapshot_summary
from .service_inventory import SCHEMA_VERSION, attach_findings, build_inventory, object_value, origin, text

MAX_SOURCES = 12
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SERVICES = 500
MAX_FINDINGS = 300

TARGETS_SQL = """
WITH inventory_targets AS (
 SELECT id, 'web'::text AS kind, COALESCE(name,url) AS label, url AS locator,
        root_domain, NULL::integer AS locator_generation, NULL::timestamptz AS locator_changed_at
 FROM targets WHERE is_active=true AND COALESCE(discovery_source,'') <> 'model-intake'
 UNION ALL
 SELECT d.id, 'device', d.name, d.primary_locator, NULL::text, d.locator_generation,
        COALESCE((SELECT max(changed_at) FROM device_locator_history h WHERE h.device_target_id=d.id), d.created_at)
 FROM device_targets d WHERE d.is_active=true
)
SELECT * FROM inventory_targets
WHERE ($1::text='all' OR kind=$1) AND ($2::uuid IS NULL OR id=$2)
 AND ($3::text IS NULL OR lower(root_domain)=$3 OR
      (kind='device' AND (lower(locator)=$3 OR right(lower(locator),length($3)+1)='.'||$3)))
 AND ($4::text='' OR strpos(lower(label),$4)>0 OR strpos(lower(locator),$4)>0)
"""

SCAN_SOURCES_SQL = """
SELECT a.action_id,a.capability_name,a.action_digest,a.result_digest,a.result_json,
       a.status,a.worker_id,a.finished_at,s.id AS scan_id
FROM scan_capability_actions a JOIN scans s ON s.id=a.scan_id
WHERE s.target_id=$1 AND s.device_target_id IS NULL
  AND (a.capability_name IN ('ports.discover','service.fingerprint','web.probe')
       OR (a.capability_name='http.request' AND a.action_id='baseline.http'))
  AND a.status IN ('success','partial','timed_out','failed','cancelled')
ORDER BY a.finished_at DESC NULLS LAST,a.scan_id,a.action_id
LIMIT $2
"""
DEVICE_SOURCES_SQL = """
SELECT ds.id,ds.scan_id,ds.transport,ds.port,ds.state,ds.service_name,ds.product,
       ds.version,ds.cpe,ds.encrypted,ds.web_origin,ds.first_seen_at,ds.last_seen_at,
       ds.metadata_json->>'address' AS observed_address,
       ds.metadata_json->>'detection_method' AS detection_method,
       s.target_url AS scanned_locator,s.created_at AS scan_created_at,s.status AS scan_status,
       CASE WHEN s.target_url=d.primary_locator AND s.created_at >= $2
            THEN d.locator_generation ELSE NULL END AS observation_generation
FROM device_services ds JOIN device_targets d ON d.id=ds.device_target_id
LEFT JOIN scans s ON s.id=ds.scan_id AND s.device_target_id=ds.device_target_id
WHERE ds.device_target_id=$1
ORDER BY ds.transport,ds.port,ds.id LIMIT $3
"""


async def validated_scan_source(conn: Any, row: dict[str, Any]) -> dict[str, Any] | None:
    """Use the canonical result and manifest validators, not unchecked JSON."""
    try:
        from runtime.observation_store import PostgresObservationManifestStore, ObservationStoreError
        from scan.capability_result import CapabilityResultReference
    except ModuleNotFoundError:
        from ..runtime.observation_store import PostgresObservationManifestStore, ObservationStoreError
        from ..scan.capability_result import CapabilityResultReference
    payload = object_value(row.get("result_json"))
    if not payload:
        return None
    try:
        result = CapabilityResultReference.from_dict(payload)
        if (result.action_id != row["action_id"] or result.capability_name != row["capability_name"]
                or result.action_digest != row["action_digest"] or result.result_digest != row["result_digest"]
                or result.status.value != row["status"]):
            raise ValueError("action result identity mismatch")
        reference = result.observation_manifest_ref
        if reference is None:
            return None
        if reference.size_bytes > MAX_SOURCE_BYTES or reference.count > MAX_SERVICES * 4:
            raise ValueError("source exceeds service-view read budget")
        observations = await PostgresObservationManifestStore().load(
            conn, reference=reference, scan_id=str(row["scan_id"]), action_id=row["action_id"],
        )
        if observations is None:
            raise ValueError("source manifest unavailable")
        allowed = {
            "ports.discover": {"open_port"}, "service.fingerprint": {"open_port", "service"},
            "web.probe": {"http_fingerprint"}, "http.request": {"http_observation"},
        }[row["capability_name"]]
        return {
            "ref": f"scan:{row['scan_id']}:{row['action_id']}",
            "scan_id": str(row["scan_id"]), "action_id": row["action_id"],
            "sha256": reference.sha256, "observed_at": row.get("finished_at"),
            "status": row["status"], "vantage": row.get("worker_id"),
            "observations": [item for item in observations if item.get("kind") in allowed],
        }
    except (ValueError, TypeError, KeyError, ObservationStoreError) as exc:
        # Preserve a stable reason without publishing private payloads or SQL.
        raise ValueError("service_source_invalid_or_over_budget") from exc


async def target_inventory(conn: Any, target: dict[str, Any], snapshot: dict[str, Any], matcher: Any, registry: Any) -> dict[str, Any]:
    target_id = uuid.UUID(str(target["id"]))
    sources = []
    warnings = []
    source_truncated = False
    if target["kind"] == "web":
        rows = await conn.fetch(SCAN_SOURCES_SQL, target_id, MAX_SOURCES + 1)
        source_truncated = len(rows) > MAX_SOURCES
        for raw in rows[:MAX_SOURCES]:
            row = dict(raw)
            try:
                source = await validated_scan_source(conn, row)
                if source:
                    sources.append(source)
            except ValueError:
                warnings.append(f"Evidence for scan {row['scan_id']} / {row['action_id']} could not be validated or exceeds the read budget.")
    else:
        rows = await conn.fetch(DEVICE_SOURCES_SQL, target_id, target["locator_changed_at"], MAX_SERVICES + 1)
        source_truncated = len(rows) > MAX_SERVICES
        for raw in rows[:MAX_SERVICES]:
            row = dict(raw)
            sources.append({
                "ref": f"device-service:{row['id']}", "scan_id": str(row["scan_id"]) if row.get("scan_id") else None,
                "observed_at": row["last_seen_at"], "status": row.get("scan_status") or "unknown",
                "locator_generation": row.get("observation_generation"),
                "observations": [{
                    **{key: row.get(key) for key in ("transport", "port", "state", "service_name", "product", "version", "cpe", "encrypted", "web_origin", "detection_method")},
                    "kind": "device_service", "address": row.get("observed_address") or row.get("scanned_locator"),
                }],
            })
    hunt_sources, hunt_warnings, hunt_truncated = await hunt_service_sources(conn, target)
    sources.extend(hunt_sources)
    warnings.extend(hunt_warnings)
    source_truncated = source_truncated or hunt_truncated
    services, rejected = build_inventory(target, sources)
    if len(services) > MAX_SERVICES:
        source_truncated = True
        services = services[:MAX_SERVICES]
    if rejected:
        warnings.append(f"{rejected} malformed or non-positive service observations were omitted.")
    if source_truncated:
        warnings.append("The retained-evidence window is truncated; narrow to a target or inspect its source Scans and Hunts.")
    # The column name is server-selected, never user-supplied SQL.
    owner = "device_target_id" if target["kind"] == "device" else "target_id"
    finding_rows = await conn.fetch(
        f"""SELECT id,{owner},url,title,severity,status,last_verification_verdict,
                   to_jsonb(findings)->>'proof_state' AS proof_state,
                   jsonb_build_object('service_id',evidence->>'service_id',
                     'pinned_address',evidence->>'pinned_address','connect_address',evidence->>'connect_address') AS evidence
            FROM findings WHERE {owner}=$1 AND status='active'
            ORDER BY last_seen_at DESC,id LIMIT $2""", target_id, MAX_FINDINGS + 1,
    )
    unlinked = attach_findings(target, services, [dict(row) for row in finding_rows[:MAX_FINDINGS]])
    for service in services:
        enrich_service(service, snapshot, matcher)
        service["activities"] = service_activities(target, service, registry)
        service["hunt_href"] = hunt_handoff(target, service)
    return {
        "id": str(target_id), "kind": target["kind"], "label": text(target["label"], 300),
        "locator": origin(target["locator"]) if target["kind"] == "web" else text(target["locator"], 253),
        "root_domain": text(target.get("root_domain"), 253) or None,
        "services": services, "source_count": len(sources), "sources_truncated": source_truncated,
        "warnings": warnings, "unlinked_findings_count": unlinked,
        "findings_truncated": len(finding_rows) > MAX_FINDINGS,
    }


async def service_page(conn: Any, *, target_kind: str, target_id: uuid.UUID | None, root_domain: str | None,
                       search: str, limit: int, offset: int, snapshot: dict[str, Any], matcher: Any, registry: Any) -> dict[str, Any]:
    params = (target_kind, target_id, root_domain.lower().rstrip(".") if root_domain else None, search.lower().strip())
    total = int(await conn.fetchval(f"SELECT count(*) FROM ({TARGETS_SQL}) filtered", *params) or 0)
    rows = await conn.fetch(TARGETS_SQL + " ORDER BY kind,id LIMIT $5 OFFSET $6", *params, limit, offset)
    targets = [await target_inventory(conn, dict(row), snapshot, matcher, registry) for row in rows]
    return {
        "schema_version": SCHEMA_VERSION, "targets": targets, "total_targets": total,
        "limit": limit, "offset": offset, "has_more": offset + len(targets) < total,
        "intelligence": snapshot_summary(snapshot),
        "limitations": [
            "This view reads existing evidence only; it performs no scans, logins or exploit execution.",
            "Web history is bounded to 12 canonical Scan actions and 12 settled Hunt receipts per target. Hunt output without a validated durable receipt is not imported.",
            "A missing service, CVE match or linked finding does not establish a clean assessment.",
        ],
    }
