"""Read-only service projections. Observations never grant scope or prove a CVE.

Identity includes the owning target, observed address, transport, port and any
positively observed virtual-host origin. Do not collapse these to a root domain.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import json
import re
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit
import uuid

SCHEMA_VERSION = "service-intelligence/v1"
SERVICE_NAMESPACE = uuid.UUID("e4089322-9875-4dca-a92d-60be1c2694a1")
MAX_EVIDENCE = 12
MAX_HISTORY = 12
STALE_AFTER = timedelta(days=7)


def object_value(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return {}
    return dict(value) if isinstance(value, Mapping) else {}


def text(value: Any, limit: int = 200) -> str:
    """Bound untrusted labels, including terminal and bidi control characters."""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ""
    return re.sub(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]", "", str(value))[:limit]


def timestamp(value: Any) -> datetime | None:
    try:
        result = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def origin(value: Any) -> str | None:
    """Canonical exact HTTP origin; never return userinfo, paths or query secrets."""
    try:
        raw = str(value or "")
        if any(ord(c) < 32 for c in raw) or "\\" in raw:
            return None
        parts = urlsplit(raw)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        host = parts.hostname.lower().rstrip(".")
        host = host.encode("idna").decode("ascii")
        if any(c.isspace() for c in host) or "%" in host or len(host) > 253:
            return None
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            return None
        if ":" in host:
            host = f"[{ipaddress.ip_address(host)}]"
        elif not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in host.split(".")
        ):
            return None
        if port is not None and port != (443 if parts.scheme.lower() == "https" else 80):
            host += f":{port}"
        return urlunsplit((parts.scheme.lower(), host, "", "", ""))
    except (ValueError, TypeError, UnicodeError):
        return None


def address(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def port_number(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    if not re.fullmatch(r"[0-9]{1,5}", str(value)):
        return None
    port = int(value)
    return port if 1 <= port <= 65535 else None


def _cpe_list(value: Any) -> list[str]:
    values = value if isinstance(value, (list, tuple)) else [value]
    return sorted({text(item, 500) for item in values[:16] if isinstance(item, str) and item.startswith(("cpe:2.3:", "cpe:/"))})


def normalized_observation(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    """Allowlisted network and positive HTTP evidence, never port-number guesses."""
    row = dict(raw)
    kind = row.get("kind")
    app_origin = origin(row.get("web_origin"))
    network_address = address(row.get("address"))
    if kind in {"http_observation", "http_fingerprint"}:
        request, response = object_value(row.get("request")), object_value(row.get("response"))
        status = response.get("status") if kind == "http_observation" else row.get("status")
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            return None
        # A redirect response does not prove the destination's service was reached.
        app_origin = origin(request.get("origin") if kind == "http_observation" else row.get("url"))
        if app_origin is None:
            return None
        parts = urlsplit(app_origin)
        network_address = address(request.get("pinned_address") or row.get("pinned_address") or row.get("address"))
        row = {
            "state": "open", "transport": "tcp",
            "port": parts.port or (443 if parts.scheme == "https" else 80),
            "service": parts.scheme, "product": row.get("webserver"),
            "method": "http_response", "version": None,
            "encrypted": parts.scheme == "https",
        }
    elif kind not in {"service", "open_port", "device_service"}:
        return None
    port = port_number(row.get("port"))
    transport = str(row.get("transport") or "").lower()
    state = str(row.get("state") or ("open" if kind == "open_port" else "unknown")).lower()
    if port is None or transport not in {"tcp", "udp"}:
        return None
    if network_address is None and app_origin is None and kind != "device_service":
        return None
    method = text(row.get("method") or row.get("detection_method"), 40) or None
    service = text(row.get("service") or row.get("service_name"), 80).lower() or "unknown"
    # Nmap's table method is a port-name lookup, not a protocol fingerprint.
    identity_basis = "port_hint" if method == "table" or kind == "open_port" else "network_fingerprint"
    if method == "http_response":
        identity_basis = "http_response"
    if identity_basis == "port_hint":
        service = "unknown"
        row = {**row, "product": None, "version": None, "cpe": []}
    if app_origin:
        parts = urlsplit(app_origin)
        if transport != "tcp" or port != (parts.port or (443 if parts.scheme == "https" else 80)):
            app_origin = None
    confidence = row.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, int) or not 0 <= confidence <= 10:
        confidence = None
    return {
        "address": network_address, "transport": transport, "port": port,
        "application_origin": app_origin, "state": state,
        "service": service, "product": text(row.get("product")) or None,
        "version": text(row.get("version"), 120) or None,
        "cpes": _cpe_list(row.get("cpe")),
        "identity_basis": identity_basis, "detection_method": method,
        "detection_confidence": confidence,
        "encrypted": row.get("encrypted") if isinstance(row.get("encrypted"), bool) else True if row.get("tunnel") in {"ssl", "tls"} else None,
        "tunnel": text(row.get("tunnel"), 40) or None,
    }


def service_id(target: Mapping[str, Any], observation: Mapping[str, Any]) -> str:
    context = [
        str(target["kind"]), str(target["id"]), observation.get("address"),
        observation["transport"], observation["port"], observation.get("application_origin"),
    ]
    # Device identity survives DHCP, but observations with unknown addresses must
    # not be re-bound silently after an operator changes the device locator.
    if target["kind"] == "device":
        context.append(observation.get("locator_generation"))
    return str(uuid.uuid5(SERVICE_NAMESPACE, json.dumps(context, separators=(",", ":"))))


def build_inventory(target: Mapping[str, Any], sources: list[dict[str, Any]], *, now: datetime | None = None) -> tuple[list[dict[str, Any]], int]:
    now = now or datetime.now(timezone.utc)
    services: dict[str, dict[str, Any]] = {}
    rejected = 0
    # Chronology, not input order, decides current observations. Fingerprints win
    # ties with same-run open-port hints without overwriting later unknown identity.
    entries: list[tuple[datetime, int, dict[str, Any], dict[str, Any]]] = []
    for source in sources:
        when = timestamp(source.get("observed_at")) or datetime.min.replace(tzinfo=timezone.utc)
        for raw in source.get("observations", []):
            if not isinstance(raw, Mapping):
                rejected += 1
                continue
            item = normalized_observation(raw)
            if item is None:
                rejected += 1
                continue
            item["locator_generation"] = source.get("locator_generation")
            rank = 0 if raw.get("kind") == "open_port" else 1
            entries.append((when, rank, item, source))
    entries.sort(key=lambda entry: (entry[0], entry[1], str(entry[3].get("ref") or "")))
    for when, _, item, source in entries:
        sid = service_id(target, item)
        observed_at = when.isoformat() if when.year > 1 else None
        evidence = {
            "ref": text(source.get("ref"), 200),
            "scan_id": text(source.get("scan_id"), 80) or None,
            "action_id": text(source.get("action_id"), 200) or None,
            "sha256": text(source.get("sha256"), 64) or None,
            "observed_at": observed_at,
            "vantage": text(source.get("vantage"), 120) or None,
            "status": text(source.get("status"), 40) or "unknown",
        }
        record = services.get(sid)
        history = {key: item.get(key) for key in ("service", "product", "version", "state")}
        history.update({"observed_at": observed_at, "evidence_ref": evidence["ref"]})
        if record is None:
            record = {"id": sid, "target_id": str(target["id"]), "target_kind": target["kind"],
                      "evidence": [], "history": [], "evidence_truncated": False,
                      "first_seen_at": observed_at, "identity_observed_at": None}
            services[sid] = record
        # A port-only observation refreshes presence, not software identity.
        if item["identity_basis"] != "port_hint" or not record.get("service"):
            record.update(item)
            record["identity_observed_at"] = observed_at
        else:
            record["state"] = item["state"]
        record["last_seen_at"] = observed_at
        if evidence not in record["evidence"]:
            record["evidence"].append(evidence)
        if history not in record["history"]:
            record["history"].append(history)
        if len(record["evidence"]) > MAX_EVIDENCE or len(record["history"]) > MAX_HISTORY:
            record["evidence_truncated"] = True
        record["evidence"] = record["evidence"][-MAX_EVIDENCE:]
        record["history"] = record["history"][-MAX_HISTORY:]
        record["observation_status"] = evidence["status"]
    for record in services.values():
        last_seen, identified = timestamp(record["last_seen_at"]), timestamp(record["identity_observed_at"])
        record["freshness"] = "unknown" if last_seen is None else "stale" if now - last_seen > STALE_AFTER else "recent"
        record["identity_stale"] = identified is None or now - identified > STALE_AFTER
        record["presence"] = "observed_open" if record["state"] == "open" else "inconclusive" if record["state"] in {"open|filtered", "unknown"} else "not_observed"
        record["binding_status"] = "observation_only"
        if target["kind"] == "device" and record.get("locator_generation") != target.get("locator_generation"):
            record["binding_status"] = "historical_locator"
        record["findings"] = []
        record["cve_candidates"] = []
        record["activities"] = []
    return sorted(services.values(), key=lambda s: (s["transport"], s["port"], s.get("address") or "", s.get("application_origin") or "")), rejected


def attach_findings(target: Mapping[str, Any], services: list[dict[str, Any]], findings: list[dict[str, Any]]) -> int:
    """Attach by exact subject and origin/service evidence, never domain + path."""
    unlinked = 0
    target_field = "device_target_id" if target["kind"] == "device" else "target_id"
    for raw in findings:
        finding = object_value(raw)
        if str(finding.get(target_field) or "") != str(target["id"]):
            continue
        locus = origin(finding.get("url"))
        evidence = object_value(finding.get("evidence"))
        matches = []
        for service in services:
            if service["binding_status"] == "historical_locator":
                continue
            exact_service = str(evidence.get("service_id") or "") == service["id"]
            exact_origin = bool(locus and locus == service.get("application_origin"))
            if exact_service or exact_origin:
                matches.append(service)
        # Without a pinned address a finding cannot choose among multiple
        # observed backends serving the same origin. Leave it target-scoped.
        raw_pinned = evidence.get("pinned_address") or evidence.get("connect_address")
        pinned = address(raw_pinned) if raw_pinned else None
        if raw_pinned or len(matches) > 1:
            matches = [s for s in matches if pinned and s.get("address") == pinned]
        if len(matches) != 1:
            unlinked += 1
            continue
        matches[0]["findings"].append({
            "id": text(finding.get("id"), 80), "title": text(finding.get("title"), 300),
            "severity": text(finding.get("severity"), 30), "status": text(finding.get("status"), 40),
            # Render upstream proof verbatim; do not manufacture another predicate.
            "proof_state": text(finding.get("proof_state"), 60) or None,
            "last_verification_verdict": text(finding.get("last_verification_verdict"), 60) or None,
        })
    return unlinked
