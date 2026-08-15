"""Normalized connected-device observations and cross-layer graph contracts."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _stable_id(kind: str, key: Any) -> str:
    encoded = json.dumps(key, sort_keys=True, separators=(",", ":"), default=str)
    return f"{kind}:{hashlib.sha256(encoded.encode()).hexdigest()[:24]}"


def _confidence(value: Any, default: str = "observed") -> str:
    normalized = str(value or default).strip().lower()
    return normalized if normalized in {"inconclusive", "observed", "validated", "correlated"} else default


def build_device_evidence_graph(
    *,
    locator: str,
    identity: dict[str, Any],
    services: list[dict[str, Any]],
    inconclusive_observations: list[dict[str, Any]],
    web_origins: list[dict[str, Any]],
    protocol_observations: list[dict[str, Any]] | None = None,
    tool_receipts: list[dict[str, Any]],
    safety_receipt: dict[str, Any],
) -> dict[str, Any]:
    """Return normalized observations plus a deterministic entity graph.

    Raw scanner output remains available in the parent report.  This contract
    gives correlation and future protocol adapters stable subjects to refer to
    without parsing tool-specific strings.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()
    seen_edges: set[str] = set()

    def add_node(kind: str, key: Any, attributes: dict[str, Any], *, confidence: str = "observed") -> str:
        node_id = _stable_id(kind, key)
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({
                "id": node_id,
                "kind": kind,
                "confidence": _confidence(confidence),
                "attributes": attributes,
            })
        return node_id

    def add_edge(kind: str, source: str, target: str, *, evidence: str | None = None) -> None:
        edge_id = _stable_id("edge", [kind, source, target])
        if edge_id in seen_edges:
            return
        seen_edges.add(edge_id)
        row: dict[str, Any] = {"id": edge_id, "kind": kind, "source": source, "target": target}
        if evidence:
            row["evidence"] = evidence
        edges.append(row)

    def add_observation(kind: str, subject: str, attributes: dict[str, Any], *, source: str, confidence: str) -> str:
        observation_id = _stable_id("observation", [kind, subject, source, attributes])
        observations.append({
            "id": observation_id,
            "kind": kind,
            "subject": subject,
            "source": source,
            "confidence": _confidence(confidence),
            "attributes": attributes,
        })
        return observation_id

    device_id = add_node("device", locator, {"primary_locator": locator})
    for address in identity.get("addresses") or []:
        if not isinstance(address, dict) or not address.get("address"):
            continue
        interface_id = add_node(
            "network_interface",
            [locator, address.get("type"), address.get("address")],
            dict(address),
        )
        evidence_id = add_observation(
            "interface_identity",
            interface_id,
            dict(address),
            source="nmap",
            confidence="observed",
        )
        add_edge("identifies", interface_id, device_id, evidence=evidence_id)

    service_ids: dict[tuple[str, int], str] = {}
    for service in [*services, *inconclusive_observations]:
        if not isinstance(service, dict):
            continue
        transport = str(service.get("transport") or "tcp").lower()
        try:
            port = int(service.get("port"))
        except (TypeError, ValueError):
            continue
        confidence = "inconclusive" if service.get("policy_eligible") is False else "observed"
        service_id = add_node(
            "network_service",
            [locator, transport, port],
            dict(service),
            confidence=confidence,
        )
        service_ids[(transport, port)] = service_id
        evidence_id = add_observation(
            "service_state",
            service_id,
            {
                "state": service.get("state"),
                "state_reason": service.get("state_reason"),
                "service_name": service.get("service_name"),
                "product": service.get("product"),
                "version": service.get("version"),
                "cpe": service.get("cpe"),
            },
            source="nmap",
            confidence=confidence,
        )
        add_edge("exposes", device_id, service_id, evidence=evidence_id)

    for origin in web_origins:
        if not isinstance(origin, dict) or not origin.get("origin"):
            continue
        origin_id = add_node("web_origin", origin["origin"], dict(origin))
        evidence_id = add_observation(
            "http_response",
            origin_id,
            {
                "status_line": origin.get("status_line"),
                "tls": origin.get("tls"),
                "peer_certificate_present": origin.get("peer_certificate_present"),
            },
            source="device_http_probe",
            confidence="validated",
        )
        service_id = service_ids.get(("tcp", int(origin.get("port") or 0)))
        if service_id:
            add_edge("served_by", origin_id, service_id, evidence=evidence_id)

    for protocol in protocol_observations or []:
        if not isinstance(protocol, dict):
            continue
        try:
            port = int(protocol.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        subject = service_ids.get((str(protocol.get("transport") or "udp"), port), device_id)
        add_observation(
            "protocol_discovery",
            subject,
            {key: value for key, value in protocol.items() if key != "receipt"},
            source=f"device_protocol_{str(protocol.get('protocol') or 'unknown')}",
            confidence="validated" if protocol.get("confirmed") else "observed",
        )

    for receipt in tool_receipts:
        if not isinstance(receipt, dict):
            continue
        add_observation(
            "tool_execution",
            device_id,
            dict(receipt),
            source=str(receipt.get("stage") or "device_tool"),
            confidence="observed",
        )
    for checkpoint in safety_receipt.get("health_checkpoints") or []:
        if not isinstance(checkpoint, dict):
            continue
        add_observation(
            "device_health",
            device_id,
            dict(checkpoint),
            source="device_safety_governor",
            confidence="observed",
        )

    nodes.sort(key=lambda item: item["id"])
    edges.sort(key=lambda item: item["id"])
    observations.sort(key=lambda item: item["id"])
    return {
        "schema_version": "device-evidence/v1",
        "root_device_id": device_id,
        "nodes": nodes,
        "edges": edges,
        "observations": observations,
    }
