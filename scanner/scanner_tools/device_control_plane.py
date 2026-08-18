"""Bounded read-only control-plane probes for connected devices.

Generic protocol logic that complements the per-platform catalog: UPnP IGD
WAN SOAP for routers, and RTSP/ONVIF for cameras.  Every request stays
pinned to the registered device's resolved address, performs only
semantically read-only operations, and spends the same per-profile request
budget as the catalog application probes.  Response bodies are never
retained; only bounded, redacted evidence fields survive.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import urllib.parse
from typing import Any
from xml.sax.saxutils import escape as _xml_escape

try:
    from .device_web import request_pinned_device_http
except ImportError:  # pragma: no cover - flat scanner runtime
    from device_web import request_pinned_device_http


PROFILE_RANK = {"inventory": 0, "posture": 1, "thorough": 2}
UPNP_WAN_SERVICE_TYPES = {
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1",
}
RTSP_PORTS = (554, 8554, 10554)
ONVIF_DEVICE_SERVICE_PATH = "/onvif/device_service"
ONVIF_DEVICE_WSDL = "http://www.onvif.org/ver10/device/wsdl"
MAX_SOAP_CALLS = 6
MAX_WAN_SERVICE_ENDPOINTS = 2
MAX_RTSP_PORTS = 2
MAX_ONVIF_CALLS = 2
SOAP_TIMEOUT_SECONDS = 5.0
MAX_SOAP_RESPONSE_BYTES = 64 * 1024
MAX_RTSP_RESPONSE_BYTES = 16 * 1024
_CREDENTIAL_PATTERN = re.compile(r"[A-Za-z0-9._%~+-]+:[A-Za-z0-9._%~+-]+@")


def soap_action_header(service_type: str, action: str) -> str:
    return f'"{service_type}#{action}"'


def build_soap_envelope(service_type: str, action: str, arguments: dict[str, str] | None = None) -> str:
    """Build a read-only UPnP SOAP 1.1 control request body."""
    inner = "".join(
        f"<{name}>{_xml_escape(str(value))}</{name}>"
        for name, value in (arguments or {}).items()
        if str(name).isalnum()
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
        ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f'<s:Body><u:{action} xmlns:u="{_xml_escape(service_type)}">'
        f"{inner}</u:{action}></s:Body></s:Envelope>"
    )


def build_onvif_envelope(action: str) -> str:
    return (
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        f'<s:Body><{action} xmlns="{ONVIF_DEVICE_WSDL}"/></s:Body></s:Envelope>'
    )


def select_wan_control_services(services: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Keep only IGD WAN control services with a usable control URL."""
    selected: list[dict[str, Any]] = []
    for service in services or []:
        service_type = str(service.get("service_type") or "")
        if service_type not in UPNP_WAN_SERVICE_TYPES:
            continue
        control_url = str(service.get("control_url") or "")
        if not control_url or "\r" in control_url or "\n" in control_url:
            continue
        selected.append({
            "service_type": service_type,
            "control_url": control_url,
            "schema_url": service.get("schema_url"),
        })
    return selected


def control_url_path(control_url: str) -> str | None:
    """Normalize a descriptor controlURL to one relative HTTP path."""
    value = str(control_url or "").strip()
    if not value:
        return None
    if "://" in value:
        try:
            parsed = urllib.parse.urlsplit(value)
        except ValueError:
            return None
        if parsed.scheme.lower() not in {"http", "https"} or parsed.username or parsed.password:
            return None
        value = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    elif not value.startswith("/"):
        value = "/" + value
    if "\r" in value or "\n" in value or len(value) > 512:
        return None
    return value or "/"


def _soap_argument(body: str, name: str) -> str | None:
    match = re.search(
        rf"<\s*(?:[\w.-]+:)?{re.escape(name)}\s*>(.*?)<\s*/\s*(?:[\w.-]+:)?{re.escape(name)}\s*>",
        body,
        re.DOTALL,
    )
    if not match:
        return None
    text = " ".join(match.group(1).replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").split())
    return text[:200] if text else None


def _soap_fault_present(body: str) -> bool:
    return "< Fault" in body.replace("soap:", " ").replace("s:", " ") or "UPnPError" in body


def parse_external_ipv4(body: str) -> str | None:
    raw = _soap_argument(body, "NewExternalIPAddress")
    if not raw:
        return None
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if address.version != 4 or raw == "0.0.0.0":
        return None
    return raw


def parse_port_mapping(body: str) -> dict[str, Any] | None:
    """Extract one generic port mapping entry without retaining free text."""
    mapping = {
        "remote_host": _soap_argument(body, "NewRemoteHost"),
        "external_port": _soap_argument(body, "NewExternalPort"),
        "internal_port": _soap_argument(body, "NewInternalPort"),
        "protocol": (_soap_argument(body, "NewProtocol") or "").upper() or None,
        "lease_duration": _soap_argument(body, "NewLeaseDuration"),
    }
    if not mapping["external_port"] or not mapping["internal_port"] or not mapping["protocol"]:
        return None
    description = _soap_argument(body, "NewPortMappingDescription")
    if description and len(description) <= 40:
        mapping["description"] = description
    return mapping


def port_mapping_is_wildcard(mapping: dict[str, Any]) -> bool:
    remote_host = str(mapping.get("remote_host") or "").strip().lower()
    return remote_host in {"", "*", "0.0.0.0", "anyhost"}


def classify_soap_response(action: str, status: int, body: str) -> dict[str, Any]:
    """Classify one read-only UPnP SOAP control response."""
    if not status:
        return {"outcome": "failed", "auth_required": False, "details": None}
    if status in {401, 403}:
        return {"outcome": "authentication_required", "auth_required": True, "details": None}
    if status in {404, 405}:
        return {"outcome": "not_supported", "auth_required": False, "details": None}
    if not 200 <= status < 300:
        return {"outcome": "rejected", "auth_required": False, "details": None}
    if _soap_fault_present(body):
        if action == "GetGenericPortMappingEntry":
            return {"outcome": "no_port_mapping", "auth_required": False, "details": None}
        return {"outcome": "soap_fault", "auth_required": False, "details": None}
    if action == "GetExternalIPAddress":
        address = parse_external_ipv4(body)
        if address:
            return {"outcome": "external_ip_returned", "auth_required": False, "details": {"external_ip": address}}
        return {"outcome": "external_ip_absent", "auth_required": False, "details": None}
    if action == "GetStatusInfo":
        status_text = _soap_argument(body, "NewConnectionStatus")
        if status_text:
            return {"outcome": "status_returned", "auth_required": False, "details": {"connection_status": status_text[:60]}}
        return {"outcome": "responded", "auth_required": False, "details": None}
    if action == "GetGenericPortMappingEntry":
        mapping = parse_port_mapping(body)
        if mapping:
            return {"outcome": "port_mapping_returned", "auth_required": False, "details": {"port_mapping": mapping}}
        return {"outcome": "no_port_mapping", "auth_required": False, "details": None}
    return {"outcome": "responded", "auth_required": False, "details": None}


def build_rtsp_options_request() -> bytes:
    return b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"


def build_rtsp_describe_request(host: str, port: int) -> bytes:
    target = f"rtsp://{host}:{port}/"
    return f"DESCRIBE {target} RTSP/1.0\r\nCSeq: 2\r\n\r\n".encode("ascii")


def parse_rtsp_response(data: bytes) -> dict[str, Any]:
    text = bytes(data or b"")[:MAX_RTSP_RESPONSE_BYTES]
    head, separator, body = text.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].split() if lines else []
    status = 0
    if parts and parts[0].upper().startswith(b"RTSP/") and len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, separator_colon, value = line.partition(b":")
        if separator_colon and len(headers) < 32:
            headers[key.strip().decode("latin-1").lower()[:64]] = value.strip().decode("latin-1")[:200]
    return {
        "status": status,
        "headers": headers,
        "body": body if separator else b"",
        "valid": bool(separator and status),
    }


def _redact_credentials(value: str) -> str:
    return _CREDENTIAL_PATTERN.sub("redacted@", value)


def classify_rtsp_describe(parsed: dict[str, Any]) -> dict[str, Any]:
    status = int(parsed.get("status") or 0)
    body = bytes(parsed.get("body") or b"")
    if status in {401, 403}:
        return {"outcome": "authentication_required", "auth_required": True, "details": None}
    if not 200 <= status < 300:
        return {"outcome": "not_available", "auth_required": False, "details": None}
    if b"v=0" not in body or not any(
        line.startswith(b"m=") for line in body.split(b"\r\n")
    ):
        return {"outcome": "responded", "auth_required": False, "details": None}
    session_name = None
    track_count = 0
    for raw in body.split(b"\r\n"):
        line = raw.decode("latin-1", "replace")
        if line.startswith("s="):
            candidate = _redact_credentials(line[2:].strip())[:80]
            session_name = candidate or session_name
        elif line.startswith("m="):
            track_count += 1
    return {
        "outcome": "media_described",
        "auth_required": False,
        "details": {"session_name": session_name, "track_count": track_count},
    }


def classify_onvif_response(action: str, status: int, body: str) -> dict[str, Any]:
    if not status:
        return {"outcome": "failed", "auth_required": False, "details": None}
    if status in {401, 403}:
        return {"outcome": "authentication_required", "auth_required": True, "details": None}
    if not 200 <= status < 300 or f"{action}Response" not in body:
        return {"outcome": "not_available", "auth_required": False, "details": None}
    if action != "GetDeviceInformation":
        return {"outcome": "onvif_service_accessible", "auth_required": False, "details": None}
    details = {
        "manufacturer": _soap_argument(body, "Manufacturer"),
        "model": _soap_argument(body, "Model"),
        "firmware": _soap_argument(body, "FirmwareVersion"),
    }
    if not details["manufacturer"] and not details["model"]:
        return {"outcome": "responded", "auth_required": False, "details": None}
    return {"outcome": "device_information_exposed", "auth_required": False, "details": details}


def plan_control_plane_requests(
    *,
    open_ports: set[int],
    wan_service_endpoints: list[dict[str, Any]],
    web_origins: list[dict[str, Any]],
    profile: str,
    remaining_budget: int,
) -> dict[str, Any]:
    """Order and truncate this stage's bounded requests without any I/O."""
    rank = PROFILE_RANK.get(profile, 0)
    units: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    budget = max(0, int(remaining_budget))
    soap_calls = 0

    def offer(unit: dict[str, Any], *, cost: int, reason_hint: str) -> None:
        nonlocal budget
        if budget < cost:
            skipped.append({"probe": unit.get("probe"), "port": unit.get("port"), "reason": "profile_request_budget"})
            return
        budget -= cost
        units.append(unit)

    for endpoint in (wan_service_endpoints or [])[:MAX_WAN_SERVICE_ENDPOINTS]:
        base = {
            "kind": "upnp_soap",
            "port": int(endpoint.get("port") or 0),
            "scheme": str(endpoint.get("scheme") or "http"),
            "origin": str(endpoint.get("origin") or ""),
            "service_type": str(endpoint.get("service_type") or ""),
            "path": str(endpoint.get("path") or ""),
        }
        for action, arguments, tier in (
            ("GetExternalIPAddress", None, 1),
            ("GetStatusInfo", None, 1),
            ("GetGenericPortMappingEntry", {"NewPortMappingIndex": "0"}, 1),
            ("GetGenericPortMappingEntry", {"NewPortMappingIndex": "1"}, 2),
        ):
            probe = f"upnp_igd:{action}:{arguments['NewPortMappingIndex'] if arguments else ''}"
            if tier == 2 and rank < PROFILE_RANK["thorough"]:
                skipped.append({"probe": probe, "port": base["port"], "reason": "available_in_deeper_profile"})
                continue
            if soap_calls >= MAX_SOAP_CALLS:
                skipped.append({"probe": probe, "port": base["port"], "reason": "soap_call_cap"})
                continue
            soap_calls += 1
            offer(
                {**base, "action": action, "arguments": arguments, "probe": probe, "cost": 1},
                cost=1,
                reason_hint=probe,
            )

    for port in sorted(open_ports.intersection(RTSP_PORTS))[:MAX_RTSP_PORTS]:
        offer(
            {"kind": "rtsp", "port": int(port), "probe": f"rtsp_describe:{port}", "cost": 2},
            cost=2,
            reason_hint="rtsp",
        )

    onvif_planned = 0
    for origin in sorted(
        (item for item in web_origins or [] if isinstance(item, dict) and item.get("port")),
        key=lambda item: int(item.get("port") or 0),
    ):
        if onvif_planned >= MAX_ONVIF_CALLS:
            break
        base = {
            "kind": "onvif_probe",
            "port": int(origin.get("port") or 0),
            "scheme": str(origin.get("scheme") or "http"),
            "origin": str(origin.get("origin") or ""),
            "path": ONVIF_DEVICE_SERVICE_PATH,
        }
        onvif_planned += 1
        offer(
            {**base, "action": "GetSystemDateAndTime", "probe": "onvif:GetSystemDateAndTime", "cost": 1},
            cost=1,
            reason_hint="onvif",
        )
        if onvif_planned >= MAX_ONVIF_CALLS:
            break
        if rank < PROFILE_RANK["thorough"]:
            skipped.append({"probe": "onvif:GetDeviceInformation", "port": base["port"], "reason": "available_in_deeper_profile"})
            break
        onvif_planned += 1
        offer(
            {
                **base,
                "action": "GetDeviceInformation",
                "probe": "onvif:GetDeviceInformation",
                "cost": 1,
                "conditional_on": "onvif_service_accessible",
            },
            cost=1,
            reason_hint="onvif",
        )
        break

    return {"units": units, "skipped": skipped}


_CONTROL_EVIDENCE_KEYS = (
    "platform", "title", "origin", "port", "method", "path", "status",
    "outcome", "auth_required", "action_class", "data_class", "protocol",
    "service_type", "soap_action", "external_ip", "connection_status",
    "port_mapping", "rtsp_session_name", "rtsp_track_count",
    "onvif_manufacturer", "onvif_model", "onvif_firmware",
    "response_headers", "body_bytes", "body_sha256",
)


def _control_plane_finding(
    *,
    title: str,
    severity: str,
    description: str,
    remediation: str,
    observation: dict[str, Any],
    cwe: str,
) -> dict[str, Any]:
    evidence = {
        key: observation.get(key)
        for key in _CONTROL_EVIDENCE_KEYS
        if observation.get(key) is not None
    }
    fingerprint = hashlib.sha256(json.dumps(
        [title, observation.get("platform"), observation.get("origin"), observation.get("port"), observation.get("path")],
        separators=(",", ":"),
    ).encode()).hexdigest()
    return {
        "fingerprint": fingerprint,
        "title": title,
        "description": description,
        "severity": severity,
        "tool": "device_control_plane_dast",
        "source": "device",
        "cwe": cwe,
        "url": urllib.parse.urljoin(str(observation.get("origin") or ""), str(observation.get("path") or "/")),
        "evidence": evidence,
        "remediation": remediation,
        "verification": "deterministic_observation",
    }


def build_control_plane_findings(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn confirmed control-plane observations into device findings."""
    findings: list[dict[str, Any]] = []
    for observation in observations:
        if observation.get("source") != "device_control_plane":
            continue
        outcome = observation.get("outcome")
        if outcome == "external_ip_returned":
            findings.append(_control_plane_finding(
                title="UPnP WAN address exposed without authentication",
                severity="medium",
                description="The UPnP IGD WAN control service answered an unauthenticated GetExternalIPAddress request with the device's current public IPv4 address.",
                remediation="Disable WAN-side UPnP on the router, or restrict the IGD control service to authenticated management sessions.",
                observation=observation,
                cwe="CWE-306",
            ))
        elif outcome == "port_mapping_returned":
            mapping = observation.get("port_mapping") or {}
            wildcard = port_mapping_is_wildcard(mapping)
            findings.append(_control_plane_finding(
                title="UPnP port mapping exposed",
                severity="high" if wildcard else "medium",
                description=(
                    "The UPnP IGD control service disclosed an active port mapping to an unauthenticated peer."
                    + (" The mapping accepts connections from any remote host." if wildcard else "")
                ),
                remediation="Disable UPnP port mapping or require operator approval per mapping, and review disclosed entries against expected forwarding rules.",
                observation=observation,
                cwe="CWE-749",
            ))
        elif outcome == "media_described":
            findings.append(_control_plane_finding(
                title="RTSP media stream accessible without authentication",
                severity="high",
                description="The RTSP service returned a full SDP media description to an unauthenticated DESCRIBE request, so the stream is directly watchable on the network.",
                remediation="Require RTSP authentication with unique per-user credentials, isolate the camera on a restricted VLAN, and disable anonymous stream access.",
                observation=observation,
                cwe="CWE-306",
            ))
        elif outcome == "device_information_exposed":
            findings.append(_control_plane_finding(
                title="ONVIF device information exposed without authentication",
                severity="medium",
                description="The ONVIF device service disclosed manufacturer, model, and firmware details to an unauthenticated GetDeviceInformation request.",
                remediation="Require ONVIF device-service authentication and keep camera firmware current.",
                observation=observation,
                cwe="CWE-200",
            ))
        elif outcome == "onvif_service_accessible":
            findings.append(_control_plane_finding(
                title="ONVIF device service accessible",
                severity="info",
                description="The ONVIF device service answered a read-only GetSystemDateAndTime request without authentication. This is a common default but widens unauthenticated device management surface.",
                remediation="Require authentication for ONVIF services where the camera supports it.",
                observation=observation,
                cwe="CWE-306",
            ))
    return findings


async def _rtsp_exchange(*, connect_address: str, port: int, requests: list[bytes]) -> list[bytes]:
    """Send bounded RTSP requests over one socket pinned to the device address."""
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_address, int(port)), timeout=SOAP_TIMEOUT_SECONDS,
        )
        responses: list[bytes] = []
        for payload in requests:
            writer.write(payload)
            await asyncio.wait_for(writer.drain(), timeout=SOAP_TIMEOUT_SECONDS)
            data = await asyncio.wait_for(
                reader.read(MAX_RTSP_RESPONSE_BYTES + 1), timeout=SOAP_TIMEOUT_SECONDS,
            )
            responses.append(bytes(data)[:MAX_RTSP_RESPONSE_BYTES])
        return responses
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def _base_observation(unit: dict[str, Any], platform: str, title: str) -> dict[str, Any]:
    return {
        "id": unit.get("probe"),
        "platform": platform,
        "title": title,
        "origin": unit.get("origin"),
        "port": unit.get("port"),
        "action_class": "read_only_rpc",
        "data_class": "device_control_plane",
        "source": "device_control_plane",
    }


async def discover_control_plane_surface(
    *,
    connect_address: str,
    origin_locator: str,
    profile: str,
    open_ports: set[int],
    web_origins: list[dict[str, Any]],
    descriptor_services: list[dict[str, Any]],
    remaining_budget: int,
) -> dict[str, Any]:
    """Run bounded read-only UPnP/RTSP/ONVIF probes against confirmed listeners."""
    wan_service_endpoints: list[dict[str, Any]] = []
    for row in descriptor_services or []:
        if not isinstance(row, dict):
            continue
        for service in select_wan_control_services(row.get("services")):
            path = control_url_path(str(service.get("control_url") or ""))
            if not path:
                continue
            wan_service_endpoints.append({
                "port": int(row.get("port") or 0),
                "scheme": str(row.get("scheme") or "http"),
                "origin": str(row.get("origin") or ""),
                "service_type": service["service_type"],
                "path": path,
            })
    plan = plan_control_plane_requests(
        open_ports={int(port) for port in open_ports or set()},
        wan_service_endpoints=wan_service_endpoints,
        web_origins=web_origins or [],
        profile=profile,
        remaining_budget=remaining_budget,
    )
    observations: list[dict[str, Any]] = []
    skipped = list(plan["skipped"])
    requests_executed = 0
    dead_control_urls: set[tuple[int, str]] = set()
    onvif_accessible = False

    for unit in plan["units"]:
        if unit["kind"] == "upnp_soap":
            dead_key = (int(unit["port"]), str(unit["path"]))
            if dead_key in dead_control_urls:
                continue
            service_type = str(unit["service_type"])
            action = str(unit["action"])
            body = build_soap_envelope(service_type, action, unit.get("arguments")).encode("utf-8")
            requests_executed += 1
            observation = _base_observation(
                unit, "upnp_igd", f"UPnP IGD {action} read-only control request",
            )
            observation.update({
                "method": "POST",
                "path": unit["path"],
                "protocol": "upnp_soap",
                "service_type": service_type,
                "soap_action": soap_action_header(service_type, action),
            })
            try:
                response = await request_pinned_device_http(
                    connect_address=connect_address,
                    hostname=origin_locator,
                    port=int(unit["port"]),
                    scheme=str(unit["scheme"]),
                    method="POST",
                    path=str(unit["path"]),
                    headers={
                        "Content-Type": 'text/xml; charset="utf-8"',
                        "SOAPAction": soap_action_header(service_type, action),
                    },
                    body=body,
                    timeout=SOAP_TIMEOUT_SECONDS,
                )
                status = int(response.get("status") or 0)
                response_body = bytes(response.get("body") or b"")[:MAX_SOAP_RESPONSE_BYTES]
                verdict = classify_soap_response(action, status, response_body.decode("utf-8", "replace"))
                observation.update({
                    "status": status,
                    "outcome": verdict["outcome"],
                    "auth_required": verdict["auth_required"],
                    "body_bytes": len(response_body),
                    "body_sha256": hashlib.sha256(response_body).hexdigest(),
                    "truncated": bool(response.get("truncated")),
                    "elapsed_ms": response.get("elapsed_ms"),
                })
                details = verdict.get("details") or {}
                if details.get("external_ip"):
                    observation["external_ip"] = details["external_ip"]
                if details.get("connection_status"):
                    observation["connection_status"] = details["connection_status"]
                if details.get("port_mapping"):
                    observation["port_mapping"] = details["port_mapping"]
                if verdict["outcome"] == "not_supported":
                    dead_control_urls.add(dead_key)
            except Exception as exc:
                observation.update({"status": 0, "outcome": "failed", "auth_required": False, "error_type": type(exc).__name__})
            observations.append(observation)
        elif unit["kind"] == "rtsp":
            port = int(unit["port"])
            requests_executed += 2
            observation = _base_observation(unit, "rtsp", "RTSP DESCRIBE media probe")
            observation.update({
                "method": "DESCRIBE",
                "path": "/",
                "protocol": "rtsp",
                "origin": f"rtsp://{origin_locator}:{port}",
            })
            try:
                responses = await _rtsp_exchange(
                    connect_address=connect_address,
                    port=port,
                    requests=[
                        build_rtsp_options_request(),
                        build_rtsp_describe_request(origin_locator, port),
                    ],
                )
                describe = parse_rtsp_response(responses[-1] if responses else b"")
                options = parse_rtsp_response(responses[0]) if len(responses) > 1 else {}
                verdict = classify_rtsp_describe(describe)
                observation.update({
                    "status": describe.get("status"),
                    "outcome": verdict["outcome"],
                    "auth_required": verdict["auth_required"],
                    "rtsp_options_status": options.get("status"),
                    "body_bytes": len(bytes(describe.get("body") or b"")),
                    "body_sha256": hashlib.sha256(bytes(describe.get("body") or b"")).hexdigest(),
                })
                details = verdict.get("details") or {}
                if details.get("session_name"):
                    observation["rtsp_session_name"] = details["session_name"]
                if details.get("track_count"):
                    observation["rtsp_track_count"] = details["track_count"]
            except Exception as exc:
                observation.update({"status": 0, "outcome": "failed", "auth_required": False, "error_type": type(exc).__name__})
            observations.append(observation)
        elif unit["kind"] == "onvif_probe":
            if unit.get("conditional_on") == "onvif_service_accessible" and not onvif_accessible:
                skipped.append({"probe": unit.get("probe"), "port": unit.get("port"), "reason": "prerequisite_not_met"})
                continue
            action = str(unit["action"])
            requests_executed += 1
            observation = _base_observation(unit, "onvif", f"ONVIF {action} read-only request")
            observation.update({
                "method": "POST",
                "path": ONVIF_DEVICE_SERVICE_PATH,
                "protocol": "onvif_soap",
                "soap_action": action,
            })
            try:
                response = await request_pinned_device_http(
                    connect_address=connect_address,
                    hostname=origin_locator,
                    port=int(unit["port"]),
                    scheme=str(unit["scheme"]),
                    method="POST",
                    path=ONVIF_DEVICE_SERVICE_PATH,
                    headers={"Content-Type": "application/soap+xml; charset=utf-8"},
                    body=build_onvif_envelope(action).encode("utf-8"),
                    timeout=SOAP_TIMEOUT_SECONDS,
                )
                status = int(response.get("status") or 0)
                response_body = bytes(response.get("body") or b"")[:MAX_SOAP_RESPONSE_BYTES]
                verdict = classify_onvif_response(action, status, response_body.decode("utf-8", "replace"))
                observation.update({
                    "status": status,
                    "outcome": verdict["outcome"],
                    "auth_required": verdict["auth_required"],
                    "body_bytes": len(response_body),
                    "body_sha256": hashlib.sha256(response_body).hexdigest(),
                    "truncated": bool(response.get("truncated")),
                    "elapsed_ms": response.get("elapsed_ms"),
                })
                details = verdict.get("details") or {}
                for key in ("manufacturer", "model", "firmware"):
                    if details.get(key):
                        observation[f"onvif_{key}"] = details[key]
                if verdict["outcome"] == "onvif_service_accessible":
                    onvif_accessible = True
            except Exception as exc:
                observation.update({"status": 0, "outcome": "failed", "auth_required": False, "error_type": type(exc).__name__})
            observations.append(observation)

    findings = build_control_plane_findings(observations)
    return {
        "schema_version": "device-control-plane-surface/v1",
        "observations": observations,
        "findings": findings,
        "skipped_probes": skipped,
        "summary": {
            "requests_executed": requests_executed,
            "responding_services": sum(1 for item in observations if int(item.get("status") or 0) > 0),
            "authentication_boundaries": sum(1 for item in observations if item.get("auth_required")),
            "findings": len(findings),
            "state_changing_automatically_executed": 0,
        },
        "safety": {
            "automatic_action_classes": ["read_only_rpc"],
            "destination_pinned": True,
            "response_bodies_retained": False,
        },
    }
