"""Deterministic connected-device application and API discovery.

The catalog is server owned and versioned.  Automatic probes are limited to
transport handshakes, descriptors, and semantically read-only operations.
State-changing operations remain available through exact, user-confirmed
request collections under the authenticated-active safety profile; they are
reported here as testable surfaces rather than silently exercised.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import urllib.parse
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    from defusedxml import ElementTree as ET
except ImportError:  # pragma: no cover - minimal host test environment
    from xml.etree import ElementTree as ET

try:
    from .device_web import request_pinned_device_http
except ImportError:  # pragma: no cover - flat scanner runtime
    from device_web import request_pinned_device_http


CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "device_api_catalog.json"
PROFILE_RANK = {"inventory": 0, "posture": 1, "thorough": 2}
REQUEST_BUDGETS = {"inventory": 8, "posture": 20, "thorough": 40}
MAX_DESCRIPTOR_BYTES = 256 * 1024
MAX_DESCRIPTOR_URLS = 8
_SAFE_AUTOMATIC_ACTIONS = {
    "transport_handshake",
    "read_only",
    "read_only_rpc",
    "privacy_sensitive_read",
}


@lru_cache(maxsize=1)
def load_device_api_catalog() -> dict[str, Any]:
    raw = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    if raw.get("schema_version") != "device-api-catalog/v1":
        raise ValueError("unsupported connected-device API catalog schema")
    platforms = raw.get("platforms")
    if not isinstance(platforms, list) or not platforms:
        raise ValueError("connected-device API catalog has no platforms")
    for platform in platforms:
        if not isinstance(platform, dict) or not platform.get("id"):
            raise ValueError("connected-device API catalog contains an invalid platform")
        for probe in platform.get("probes") or []:
            if probe.get("action_class") not in _SAFE_AUTOMATIC_ACTIONS:
                raise ValueError(f"unsafe automatic device probe in catalog: {probe.get('id')}")
            if str(probe.get("method") or "GET").upper() not in {"GET", "HEAD", "POST"}:
                raise ValueError(f"unsupported device probe method: {probe.get('id')}")
    return raw


def public_device_api_catalog() -> dict[str, Any]:
    """Return secret-free catalog metadata suitable for API and agent context."""
    catalog = load_device_api_catalog()
    return {
        "schema_version": catalog["schema_version"],
        "catalog_version": catalog.get("catalog_version"),
        "platforms": [
            {
                "id": platform["id"],
                "title": platform.get("title"),
                "port_hints": list(platform.get("port_hints") or []),
                "automatic_probes": [
                    {
                        key: probe.get(key)
                        for key in (
                            "id", "title", "transport", "ports", "method", "path",
                            "minimum_profile", "action_class", "data_class",
                        )
                    }
                    for probe in platform.get("probes") or []
                ],
                "controlled_operations": [
                    {
                        **dict(operation),
                        "status": "available_with_confirmation",
                        "minimum_safety_profile": "authenticated_active",
                        "execution_mode": "exact_user_confirmed_request",
                        "supported_via": ["imported_request", "device_hunt_bound_request"],
                    }
                    for operation in platform.get("controlled_operations") or []
                ],
            }
            for platform in catalog.get("platforms") or []
        ],
    }


def _local_name(tag: Any) -> str:
    return str(tag or "").rsplit("}", 1)[-1]


def _bounded_text(value: Any, limit: int = 500) -> str | None:
    text = " ".join(str(value or "").replace("\x00", "").split())
    return text[:limit] if text else None


def _first_descendant_text(element: Any, name: str) -> str | None:
    for item in element.iter():
        if _local_name(item.tag) == name:
            return _bounded_text(item.text)
    return None


def parse_upnp_device_description(body: bytes) -> dict[str, Any] | None:
    """Parse a bounded UPnP/DIAL descriptor without resolving external entities."""
    if not body or len(body) > MAX_DESCRIPTOR_BYTES:
        return None
    try:
        root = ET.fromstring(body)
    except (ET.ParseError, ValueError, TypeError):
        return None
    device = next((item for item in root.iter() if _local_name(item.tag) == "device"), None)
    if device is None:
        return None
    fields = {
        "device_type": _first_descendant_text(device, "deviceType"),
        "friendly_name": _first_descendant_text(device, "friendlyName"),
        "manufacturer": _first_descendant_text(device, "manufacturer"),
        "model_description": _first_descendant_text(device, "modelDescription"),
        "model_name": _first_descendant_text(device, "modelName"),
        "model_number": _first_descendant_text(device, "modelNumber"),
        "udn": _first_descendant_text(device, "UDN"),
        "presentation_url": _first_descendant_text(device, "presentationURL"),
    }
    services: list[dict[str, Any]] = []
    for service in (item for item in device.iter() if _local_name(item.tag) == "service"):
        row = {
            "service_type": _first_descendant_text(service, "serviceType"),
            "service_id": _first_descendant_text(service, "serviceId"),
            "schema_url": _first_descendant_text(service, "SCPDURL"),
            "control_url": _first_descendant_text(service, "controlURL"),
            "event_url": _first_descendant_text(service, "eventSubURL"),
        }
        if any(row.values()):
            services.append(row)
        if len(services) >= 64:
            break
    return {
        **{key: value for key, value in fields.items() if value},
        "services": services,
        "service_count": len(services),
    }


def _same_authorized_address(host: str | None, connect_address: str) -> bool:
    if not host:
        return False
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]) == ipaddress.ip_address(
            connect_address.split("%", 1)[0]
        )
    except ValueError:
        return False


def _public_response_headers(headers: dict[str, Any]) -> dict[str, str]:
    allowed = {"server", "content-type", "www-authenticate", "upgrade", "connection"}
    result: dict[str, str] = {}
    for key, value in headers.items():
        normalized = str(key).lower()
        if normalized not in allowed:
            continue
        if normalized == "www-authenticate":
            result[normalized] = str(value).strip().split(None, 1)[0][:40]
        else:
            result[normalized] = str(value)[:1000]
    return result


def _application_finding(
    *, title: str, severity: str, description: str, remediation: str,
    observation: dict[str, Any], cwe: str,
) -> dict[str, Any]:
    evidence = {
        key: observation.get(key)
        for key in (
            "platform", "title", "origin", "port", "method", "path", "status",
            "outcome", "auth_required", "action_class", "data_class",
            "response_headers", "body_bytes", "body_sha256",
        )
        if observation.get(key) is not None
    }
    fingerprint = hashlib.sha256(json.dumps(
        [title, observation.get("platform"), observation.get("origin"), observation.get("path")],
        separators=(",", ":"),
    ).encode()).hexdigest()
    return {
        "fingerprint": fingerprint,
        "title": title,
        "description": description,
        "severity": severity,
        "tool": "device_application_dast",
        "source": "device",
        "cwe": cwe,
        "url": urllib.parse.urljoin(str(observation.get("origin") or ""), str(observation.get("path") or "/")),
        "evidence": evidence,
        "remediation": remediation,
        "verification": "deterministic_observation",
    }


def build_application_findings(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn confirmed application behavior into reviewable device findings."""
    findings: list[dict[str, Any]] = []
    cleartext_origins: set[str] = set()
    for observation in observations:
        if observation.get("source") != "device_api_catalog":
            continue
        if observation.get("outcome") not in {"confirmed", "responded"}:
            continue
        origin = str(observation.get("origin") or "")
        if origin.startswith("http://") and origin not in cleartext_origins:
            cleartext_origins.add(origin)
            findings.append(_application_finding(
                title="Connected-device API is exposed over cleartext HTTP",
                severity="medium",
                description="A confirmed device application endpoint is reachable without transport encryption. Network peers can observe or modify API traffic.",
                remediation="Use HTTPS with a pinned or locally trusted certificate, or isolate the management API on a restricted network segment.",
                observation=observation,
                cwe="CWE-319",
            ))
        if observation.get("action_class") == "privacy_sensitive_read" and not observation.get("auth_required"):
            findings.append(_application_finding(
                title="Privacy-sensitive device API responds without authentication",
                severity="medium",
                description="A read-only endpoint exposing installed applications or current media state returned a confirmed response without an authentication challenge.",
                remediation="Require a paired or authenticated management session for privacy-sensitive inventory and playback-state APIs.",
                observation=observation,
                cwe="CWE-306",
            ))
        elif observation.get("data_class") == "software_version" and not observation.get("auth_required"):
            findings.append(_application_finding(
                title="Device software version is exposed without authentication",
                severity="info",
                description="The device API disclosed a software or firmware version to an unauthenticated network peer. This can improve vulnerability matching accuracy for both defenders and attackers.",
                remediation="Restrict version-detail endpoints to paired clients where the platform supports it, and keep firmware current.",
                observation=observation,
                cwe="CWE-200",
            ))
    return findings


async def enrich_ssdp_descriptions(
    *,
    connect_address: str,
    protocols: list[dict[str, Any]],
) -> dict[str, Any]:
    """Fetch exact-device SSDP LOCATION descriptors with no redirect following."""
    observations: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    web_origins: list[dict[str, Any]] = []
    identity: dict[str, Any] = {}
    seen_urls: set[str] = set()
    attempted = 0
    skipped = 0
    for protocol in protocols:
        if str(protocol.get("protocol") or "").lower() != "ssdp":
            continue
        for response in protocol.get("responses") or []:
            if not isinstance(response, dict):
                continue
            location = str(response.get("location") or "").strip()
            if not location or location in seen_urls:
                continue
            seen_urls.add(location)
            if attempted >= MAX_DESCRIPTOR_URLS:
                skipped += 1
                continue
            try:
                parsed = urllib.parse.urlsplit(location)
                port = int(parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
            except (TypeError, ValueError):
                parsed = urllib.parse.SplitResult("", "", "", "", "")
                port = 0
            if (
                parsed.scheme.lower() not in {"http", "https"}
                or parsed.username is not None
                or parsed.password is not None
                or not 1 <= port <= 65535
                or not _same_authorized_address(parsed.hostname, connect_address)
            ):
                response["description_fetch"] = {
                    "status": "skipped",
                    "reason": "location_not_exact_authorized_device",
                }
                skipped += 1
                continue
            attempted += 1
            path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            try:
                result = await request_pinned_device_http(
                    connect_address=connect_address,
                    hostname=str(parsed.hostname),
                    port=port,
                    scheme=parsed.scheme.lower(),
                    method="GET",
                    path=path,
                    timeout=6.0,
                )
                body = bytes(result.get("body") or b"")
                descriptor = parse_upnp_device_description(body) if 200 <= int(result.get("status") or 0) < 300 else None
                observation = {
                    "id": "upnp-root-description",
                    "platform": "upnp",
                    "title": "UPnP root device description",
                    "transport": parsed.scheme.lower(),
                    "origin": urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")),
                    "method": "GET",
                    "path": path,
                    "action_class": "read_only",
                    "data_class": "device_and_service_schema",
                    "status": int(result.get("status") or 0),
                    "outcome": "confirmed" if descriptor else "responded",
                    "auth_required": int(result.get("status") or 0) in {401, 403},
                    "response_headers": _public_response_headers(dict(result.get("headers") or {})),
                    "body_bytes": len(body),
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "truncated": bool(result.get("truncated")),
                    "elapsed_ms": result.get("elapsed_ms"),
                    "descriptor": descriptor,
                    "source": "ssdp_location",
                }
                observations.append(observation)
                response["description_fetch"] = {
                    key: value
                    for key, value in observation.items()
                    if key not in {"descriptor"}
                }
                if descriptor:
                    response["device_description"] = descriptor
                    identity = {
                        key: descriptor.get(key)
                        for key in ("friendly_name", "manufacturer", "model_name", "model_number", "udn")
                        if descriptor.get(key)
                    }
                    origin = observation["origin"]
                    web_origins.append({
                        "origin": origin,
                        "scheme": parsed.scheme.lower(),
                        "connect_address": connect_address,
                        "host_header": str(parsed.hostname),
                        "sni": str(parsed.hostname) if parsed.scheme.lower() == "https" else None,
                        "port": port,
                        "status_line": f"HTTP {observation['status']}",
                        "tls": parsed.scheme.lower() == "https",
                        "peer_certificate_present": parsed.scheme.lower() == "https",
                        "detected_service": "upnp-description",
                        "discovery_source": "ssdp_location",
                    })
                    services.append({
                        "transport": "tcp",
                        "port": port,
                        "state": "open",
                        "state_reason": "validated-upnp-description-response",
                        "service_name": "https" if parsed.scheme.lower() == "https" else "http",
                        "product": descriptor.get("model_name") or descriptor.get("friendly_name") or "UPnP device",
                        "version": descriptor.get("model_number") or "",
                        "extra_info": "SSDP LOCATION",
                        "tunnel": "ssl" if parsed.scheme.lower() == "https" else None,
                        "cpe": None,
                        "confidence": "confirmed",
                        "policy_eligible": True,
                        "discovery_tool": "device_upnp_description",
                        "web_origin": origin,
                        "encrypted": parsed.scheme.lower() == "https",
                    })
            except Exception as exc:
                response["description_fetch"] = {
                    "status": "failed",
                    "reason": f"request_failed:{type(exc).__name__}",
                }
    return {
        "schema_version": "device-upnp-enrichment/v1",
        "observations": observations,
        "services": services,
        "web_origins": web_origins,
        "identity": identity,
        "receipt": {
            "stage": "device_upnp_description",
            "protocol": "upnp",
            "complete": True,
            "required": False,
            "attempted": attempted,
            "succeeded": sum(1 for item in observations if item.get("outcome") == "confirmed"),
            "skipped": skipped,
            "scope": "same_authorized_device_only",
        },
    }


def _evidence_text(
    *,
    device_name: str,
    manufacturer: str,
    model: str,
    identity: dict[str, Any],
    services: list[dict[str, Any]],
    protocols: list[dict[str, Any]],
) -> str:
    # The operator-editable display name is not product evidence.  Otherwise a
    # name such as "LG in conference room" could select vendor probes by itself.
    values: list[str] = [manufacturer, model]
    values.extend(str(item) for item in identity.get("hostnames") or [])
    for service in services:
        values.extend(str(service.get(key) or "") for key in ("service_name", "product", "version", "extra_info"))
    for protocol in protocols:
        for response in protocol.get("responses") or []:
            if isinstance(response, dict):
                values.extend(str(response.get(key) or "") for key in ("server", "search_target", "unique_service_name", "location"))
                descriptor = response.get("device_description") if isinstance(response.get("device_description"), dict) else {}
                values.extend(str(descriptor.get(key) or "") for key in ("friendly_name", "manufacturer", "model_name", "model_number", "device_type"))
    return " ".join(values).lower()[:200_000]


def _marker_present(evidence: str, marker: Any) -> bool:
    """Match vendor/platform evidence as a token or phrase, not a substring."""
    normalized = " ".join(str(marker or "").lower().split())
    if not normalized:
        return False
    return re.search(
        rf"(?<![a-z0-9]){re.escape(normalized)}(?![a-z0-9])",
        evidence,
    ) is not None


def _origin_for_probe(hostname: str, port: int, transport: str, web_origins: list[dict[str, Any]]) -> tuple[str, str]:
    matched = next((item for item in web_origins if int(item.get("port") or 0) == port), None)
    if transport == "auto_http":
        scheme = str((matched or {}).get("scheme") or ("https" if port == 443 else "http"))
    elif transport in {"wss", "https"}:
        scheme = "https"
    else:
        scheme = "http"
    formatted = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    return scheme, f"{scheme}://{formatted}:{port}"


def _probe_outcome(probe: dict[str, Any], response: dict[str, Any]) -> tuple[str, bool]:
    status = int(response.get("status") or 0)
    headers = {str(key).lower(): str(value) for key, value in dict(response.get("headers") or {}).items()}
    body = bytes(response.get("body") or b"").decode("utf-8", "replace").lower()
    if probe.get("transport") in {"ws", "wss"}:
        confirmed = status == 101 and "websocket" in headers.get("upgrade", "").lower()
        return ("confirmed" if confirmed else "handshake_rejected", False)
    if status in {401, 403}:
        return "authentication_required", True
    if status == 405:
        return "method_boundary_observed", False
    if status == 404:
        return "not_found", False
    if not status:
        return "failed", False
    terms = [str(item).lower() for item in probe.get("response_terms") or [] if str(item)]
    if 200 <= status < 300 and terms and any(term in body for term in terms):
        return "confirmed", False
    if 200 <= status < 400:
        return "responded", False
    return "rejected", False


async def discover_device_application_surface(
    *,
    connect_address: str,
    origin_locator: str,
    profile: str,
    safety_profile: str,
    device_name: str,
    manufacturer: str,
    model: str,
    identity: dict[str, Any],
    services: list[dict[str, Any]],
    web_origins: list[dict[str, Any]],
    protocols: list[dict[str, Any]],
    descriptor_enrichment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Select and execute bounded catalog probes against confirmed listeners."""
    catalog = load_device_api_catalog()
    rank = PROFILE_RANK.get(profile, 0)
    budget = REQUEST_BUDGETS.get(profile, REQUEST_BUDGETS["inventory"])
    open_ports = {
        int(item.get("port") or 0)
        for item in services
        if str(item.get("transport") or "tcp").lower() == "tcp" and str(item.get("state") or "open") == "open"
    }
    evidence = _evidence_text(
        device_name=device_name,
        manufacturer=manufacturer,
        model=model,
        identity=identity,
        services=services,
        protocols=protocols,
    )
    observations = list((descriptor_enrichment or {}).get("observations") or [])
    skipped: list[dict[str, Any]] = []
    platform_rows: list[dict[str, Any]] = []
    controlled_operations: list[dict[str, Any]] = []
    requests_executed = 0

    for platform in catalog.get("platforms") or []:
        platform_ports = sorted(open_ports.intersection(int(port) for port in platform.get("port_hints") or []))
        marker_signals = [
            str(marker)
            for marker in platform.get("markers") or []
            if _marker_present(evidence, marker)
        ]
        if not platform_ports and not marker_signals:
            continue
        platform_row = {
            "id": platform["id"],
            "title": platform.get("title"),
            "confidence": "probable" if marker_signals else "candidate",
            "signals": [*[f"marker:{item}" for item in marker_signals[:8]], *[f"open_tcp:{port}" for port in platform_ports]],
            "confirmed_endpoints": 0,
        }
        platform_rows.append(platform_row)
        for operation in platform.get("controlled_operations") or []:
            controlled_operations.append({
                "platform": platform["id"],
                "platform_title": platform.get("title"),
                **dict(operation),
                "status": "available_with_confirmation",
                "minimum_safety_profile": "authenticated_active",
                "execution_mode": "exact_user_confirmed_request",
                "supported_via": ["imported_request", "device_hunt_bound_request"],
            })
        for probe in platform.get("probes") or []:
            matching_ports = sorted(open_ports.intersection(int(port) for port in probe.get("ports") or []))
            if not matching_ports:
                continue
            if rank < PROFILE_RANK.get(str(probe.get("minimum_profile") or "inventory"), 0):
                skipped.append({"platform": platform["id"], "probe_id": probe.get("id"), "title": probe.get("title"), "reason": "available_in_deeper_profile"})
                continue
            if safety_profile == "observe_only":
                skipped.append({"platform": platform["id"], "probe_id": probe.get("id"), "title": probe.get("title"), "reason": "available_with_safe_remote"})
                continue
            if probe.get("requires_platform_evidence") and not marker_signals:
                skipped.append({"platform": platform["id"], "probe_id": probe.get("id"), "title": probe.get("title"), "reason": "awaiting_platform_evidence"})
                continue
            for port in matching_ports:
                if requests_executed >= budget:
                    skipped.append({"platform": platform["id"], "probe_id": probe.get("id"), "title": probe.get("title"), "port": port, "reason": "profile_request_budget"})
                    continue
                transport = str(probe.get("transport") or "http")
                scheme, origin = _origin_for_probe(origin_locator, port, transport, web_origins)
                headers: dict[str, str] = {}
                if probe.get("content_type"):
                    headers["Content-Type"] = str(probe["content_type"])
                if transport in {"ws", "wss"}:
                    headers.update({
                        "Connection": "Upgrade",
                        "Upgrade": "websocket",
                        "Sec-WebSocket-Version": "13",
                        "Sec-WebSocket-Key": base64.b64encode(secrets.token_bytes(16)).decode("ascii"),
                        "Origin": origin,
                    })
                body = str(probe.get("body") or "").encode("utf-8")
                requests_executed += 1
                try:
                    response = await request_pinned_device_http(
                        connect_address=connect_address,
                        hostname=origin_locator,
                        port=port,
                        scheme=scheme,
                        method=str(probe.get("method") or "GET"),
                        path=str(probe.get("path") or "/"),
                        headers=headers,
                        body=body,
                        timeout=7.0,
                    )
                    response_body = bytes(response.get("body") or b"")
                    outcome, auth_required = _probe_outcome(probe, response)
                    observation = {
                        "id": probe.get("id"),
                        "platform": platform["id"],
                        "platform_title": platform.get("title"),
                        "title": probe.get("title"),
                        "transport": transport,
                        "origin": origin,
                        "port": port,
                        "method": probe.get("method"),
                        "path": probe.get("path"),
                        "action_class": probe.get("action_class"),
                        "data_class": probe.get("data_class"),
                        "status": int(response.get("status") or 0),
                        "outcome": outcome,
                        "auth_required": auth_required,
                        "response_headers": _public_response_headers(dict(response.get("headers") or {})),
                        "body_bytes": len(response_body),
                        "body_sha256": hashlib.sha256(response_body).hexdigest(),
                        "truncated": bool(response.get("truncated")),
                        "elapsed_ms": response.get("elapsed_ms"),
                        "source": "device_api_catalog",
                    }
                    observations.append(observation)
                    if outcome == "confirmed":
                        platform_row["confirmed_endpoints"] += 1
                        platform_row["confidence"] = "confirmed"
                except Exception as exc:
                    observations.append({
                        "id": probe.get("id"),
                        "platform": platform["id"],
                        "platform_title": platform.get("title"),
                        "title": probe.get("title"),
                        "transport": transport,
                        "origin": origin,
                        "port": port,
                        "method": probe.get("method"),
                        "path": probe.get("path"),
                        "action_class": probe.get("action_class"),
                        "data_class": probe.get("data_class"),
                        "status": 0,
                        "outcome": "failed",
                        "auth_required": False,
                        "error_type": type(exc).__name__,
                        "source": "device_api_catalog",
                    })

    confirmed = sum(1 for item in observations if item.get("outcome") == "confirmed")
    auth_boundaries = sum(1 for item in observations if item.get("auth_required"))
    responded = sum(1 for item in observations if int(item.get("status") or 0) > 0)
    findings = build_application_findings(observations)
    return {
        "schema_version": "device-application-surface/v1",
        "catalog_version": catalog.get("catalog_version"),
        "platforms": platform_rows,
        "observations": observations,
        "controlled_operations": controlled_operations,
        "findings": findings,
        "skipped_probes": skipped,
        "summary": {
            "candidate_platforms": len(platform_rows),
            "confirmed_platforms": sum(1 for item in platform_rows if item.get("confidence") == "confirmed"),
            "requests_executed": requests_executed + int((descriptor_enrichment or {}).get("receipt", {}).get("attempted") or 0),
            "responding_endpoints": responded,
            "confirmed_endpoints": confirmed,
            "authentication_boundaries": auth_boundaries,
            "available_control_families": len(controlled_operations),
            "skipped_probes": len(skipped),
            "state_changing_automatically_executed": 0,
            "findings": len(findings),
        },
        "safety": {
            "automatic_action_classes": sorted(_SAFE_AUTOMATIC_ACTIONS),
            "controlled_operations_available": True,
            "controlled_operation_requirement": "authenticated_active plus exact user-confirmed request",
            "response_bodies_retained": False,
            "destination_pinned": True,
        },
    }
