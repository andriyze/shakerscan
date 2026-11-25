"""Keyless AI-directed connected-device investigation contracts.

The coding-agent session is the planner; ShakerScan executes a small bounded
tool set. The planner never receives local-host shell, arbitrary network destinations,
credentials, or a way to raise the session safety profile. Remote-device shell is
available only as an immutable proposal that a user separately confirms.
Deterministic
device scans remain the source of findings and evidence.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from typing import Any
try:
    from capabilities.secret_material import keyed_response_digest
except ModuleNotFoundError:  # package import layout
    from api.capabilities.secret_material import keyed_response_digest

try:
    from scanner_tools import device_advisories
    from scanner_tools.device_advisories import match_advisories
except ModuleNotFoundError:  # pragma: no cover - package import in host tests
    from scanner.scanner_tools import device_advisories
    from scanner.scanner_tools.device_advisories import match_advisories

try:
    from scanner_tools.device_posture import INVENTORY_UDP_PORTS, PROFILES as DEVICE_SCAN_PROFILES
    from scanner_tools.device_web import IMPORTED_REQUEST_LIMITS
    from scanner_tools.device_application import REQUEST_BUDGETS as DEVICE_PROBE_BUDGETS
except ModuleNotFoundError:  # pragma: no cover - package import in host tests
    from scanner.scanner_tools.device_posture import INVENTORY_UDP_PORTS, PROFILES as DEVICE_SCAN_PROFILES
    from scanner.scanner_tools.device_web import IMPORTED_REQUEST_LIMITS
    from scanner.scanner_tools.device_application import REQUEST_BUDGETS as DEVICE_PROBE_BUDGETS


# Contracts that answer from stored evidence and queue no device traffic at all.
NON_QUEUEING_VERIFIER_CONTRACTS: frozenset[str] = frozenset({
    "device.control_authorization",
    "device.firmware_advisory",
})

# The verification fan-out uses the `inventory` profile; see _device_verify_candidate_tool.
VERIFICATION_SCAN_PROFILE = "inventory"


def _inventory_tcp_port_count() -> int:
    """Return how many TCP ports the verification fan-out's profile sweeps."""
    profile = DEVICE_SCAN_PROFILES.get(VERIFICATION_SCAN_PROFILE)
    arguments = tuple(getattr(profile, "tcp_args", ()) or ())
    for index, argument in enumerate(arguments):
        if str(argument) == "-p-":
            return 65_535
        if str(argument) == "--top-ports":
            try:
                return int(arguments[index + 1])
            except (IndexError, TypeError, ValueError):
                break
    # An unrecognised port specification is charged as a full sweep: under-reserving is what let
    # the fan-out escape the Hunt's budget in the first place.
    return 65_535


def device_verification_fanout_budget(
    *, contract_id: str, web_scan_type: str = "standard", max_web_origins: int = 0,
) -> dict[str, int]:
    """Return the complete downstream budget one device candidate verification can queue.

    A device verification does not do its own traffic: it queues a device scan, and that scan
    sweeps the inventory profile's ports and may fan out to `max_web_origins` web children, each
    with its own imported-request ceiling. Charging the Hunt a flat parent cost let a small
    reservation authorize all of that, so budget-before-execution held for the parent action and
    nothing beneath it. Deriving the charge from the same constants the fan-out uses keeps the two
    from drifting apart: raise a child ceiling and the parent's reservation rises with it.
    """
    contract = str(contract_id or "")
    if contract in NON_QUEUEING_VERIFIER_CONTRACTS:
        return {}
    budget: dict[str, int] = {"device_fragility_points": 1}
    if contract == "device.service_exposure":
        # One fixed transport/port probe; the caller adds the transport dimension it verifies.
        budget["http_requests"] = 0
        budget["tcp_ports_attempted"] = 1
        return budget
    budget["tcp_ports_attempted"] = _inventory_tcp_port_count()
    budget["udp_ports_attempted"] = len(INVENTORY_UDP_PORTS)
    # Every queued web child may replay up to its scan type's imported-request ceiling, and the
    # scan itself probes the device application surface.
    per_child = int(IMPORTED_REQUEST_LIMITS.get(str(web_scan_type), IMPORTED_REQUEST_LIMITS["standard"]))
    origins = max(0, int(max_web_origins))
    budget["http_requests"] = (
        origins * per_child
        + int(DEVICE_PROBE_BUDGETS.get(VERIFICATION_SCAN_PROFILE, 8))
    )
    return {name: int(amount) for name, amount in budget.items() if int(amount) >= 0}


CALLABLE_TOOL_NAMES = {
    "inspect_device",
    "inspect_capabilities",
    "inspect_request_collections",
    "propose_ssh_shell",
    "queue_device_scan",
    "inspect_device_scan",
    "query_device_evidence",
    "diff_scans",
    "query_policy",
    "resolve_intel",
    "lookup_protocol_playbook",
    "verify_service_state",
    "verify_candidate",
    "device_http_request",
    "note",
}

CONTROL_CLEANUP_ADAPTERS = frozenset({
    "explicit_bound_request",
    "restore_query_parameter",
    "restore_json_field",
    "restore_form_field",
})
MAX_ACTIONS_PER_SESSION = 36
MAX_SCANS_PER_SESSION = 3
MAX_FRAGILITY_PER_SESSION = 40
# A single thorough Hunt is allowed up to 40,000 device-fragility points (a device target is
# charged one point per held request), so the per-device daily aggregate must sit above that
# (with headroom for repeat and verification runs) or an authorized thorough run could never
# start. Per-run fragility limits and pacing still bound each individual run's device wear.
MAX_FRAGILITY_PER_DEVICE_DAY = 160_000
CONFIRMED_SHELL_FRAGILITY_COST = 12
DEVICE_HTTP_REQUEST_SESSION_LIMIT = 40
DEVICE_HTTP_REQUEST_MIN_INTERVAL_SECONDS = 1.0
DEVICE_HTTP_REQUEST_TIMEOUT_SECONDS = 5.0
DEVICE_HTTP_REQUEST_BODY_PREVIEW_BYTES = 512
class DeviceHttpAttemptRejected(ValueError):
    def __init__(self, message: str, *, status_code: int):
        super().__init__(message)
        self.status_code = status_code


def reserve_device_http_attempt(state: dict[str, Any], *, now_monotonic: float) -> int:
    """Charge one device HTTP attempt before its socket is opened."""
    used = int(state.get("device_http_requests_used") or 0)
    limit = int(state.get("device_http_request_limit", DEVICE_HTTP_REQUEST_SESSION_LIMIT))
    if used >= limit:
        raise DeviceHttpAttemptRejected(
            "Session device HTTP request limit reached", status_code=409,
        )
    last_sent = float(state.get("last_device_http_request_monotonic") or 0.0)
    if last_sent and now_monotonic - last_sent < DEVICE_HTTP_REQUEST_MIN_INTERVAL_SECONDS:
        raise DeviceHttpAttemptRejected(
            "Device HTTP requests must be spaced at least one second apart", status_code=429,
        )
    state["device_http_requests_used"] = used + 1
    state["last_device_http_request_monotonic"] = now_monotonic
    return used + 1


PROTOCOL_PLAYBOOKS = {
    "upnp": {
        "summary": "UPnP/SSDP commonly advertises device identity and control services over UDP/1900.",
        "safe_next_steps": ["Compare SERVER and USN across scans", "Inspect captured LOCATION metadata without fetching an unapproved URL", "Confirm the service is limited to the intended network zone"],
        "policy_questions": ["Is UPnP expected for this device class?", "Is UDP/1900 reachable outside the local management segment?"],
    },
    "mdns": {
        "summary": "mDNS advertises local services and TXT metadata over UDP/5353.",
        "safe_next_steps": ["Diff service names and TXT metadata", "Check whether advertised services match confirmed TCP listeners"],
        "policy_questions": ["Are the advertised service types required?", "Does TXT metadata disclose unnecessary identity or management details?"],
    },
    "ssh": {
        "summary": "SSH posture depends on host-key strength, negotiated algorithms, and offered authentication methods.",
        "safe_next_steps": ["Review the deterministic SSH handshake receipt", "Use only a configured device credential profile for one bounded authentication attempt"],
        "policy_questions": ["Is public-key authentication offered?", "Are password authentication and legacy algorithms disabled?"],
    },
    "http": {
        "summary": "Embedded web administration often runs on nonstandard ports and may be cleartext or weakly authenticated.",
        "safe_next_steps": ["Use the discovered origin in a bounded device-owned web child", "Compare TLS and response status across scans"],
        "policy_questions": ["Is cleartext administration isolated?", "Is the interface authenticated with an operator-supplied profile?"],
    },
    "https": {
        "summary": "HTTPS protects transport but does not by itself prove safe authentication, authorization, or current firmware.",
        "safe_next_steps": ["Inspect certificate presence and passive web findings", "Run an authenticated passive child only with a device-bound credential profile"],
        "policy_questions": ["Is the certificate expected for this device?", "Does the interface expose sensitive unauthenticated content?"],
    },
    "rtsp": {
        "summary": "RTSP commonly exposes media streams on cameras and recorders.",
        "safe_next_steps": ["Confirm whether RTSP is expected and network-isolated", "Do not guess stream credentials or paths"],
        "policy_questions": ["Is the stream restricted to the video network?", "Is authentication required by documented configuration?"],
    },
    "ipp": {
        "summary": "IPP/IPPS provides printer capabilities and job interfaces, commonly on TCP/631.",
        "safe_next_steps": ["Compare IPP exposure with the printer policy", "Prefer IPPS and restrict job submission to print networks"],
        "policy_questions": ["Is unencrypted IPP permitted?", "Can untrusted network segments reach the print service?"],
    },
    "roku_ecp": {
        "summary": "Roku ECP exposes read queries and user-confirmed remote/application controls over TCP/8060.",
        "safe_next_steps": ["Run catalog discovery for device identity", "Use an exact confirmed request to test remote or application controls", "Compare paired, disabled, and permitted mobile-control states"],
        "policy_questions": ["Is ECP limited to the intended local segment?", "Do control settings reject unauthorized clients as configured?"],
    },
    "lg_webos": {
        "summary": "LG webOS uses SSAP over WS/3000 or WSS/3001; SSAP message URIs are not HTTP paths.",
        "safe_next_steps": ["Confirm the WebSocket transport handshake", "Bind a captured pairing/control flow for authenticated-active testing", "Test permission and token lifecycle with exact user-confirmed requests"],
        "policy_questions": ["Is secure WSS preferred?", "Are pairing grants scoped, revocable, and bound to the approved client?"],
    },
    "samsung_tizen": {
        "summary": "Samsung Tizen commonly exposes API metadata and paired WebSocket remote-control channels on TCP/8001 and 8002.",
        "safe_next_steps": ["Inspect /api/v2 identity evidence", "Bind the exact WebSocket/API flow before control testing", "Compare unpaired and paired authorization behavior"],
        "policy_questions": ["Does the TV require an on-device approval?", "Are tokens rejected after revocation?"],
    },
    "vizio_smartcast": {
        "summary": "Vizio SmartCast commonly exposes HTTPS APIs on TCP/7345 or legacy 9000 with pairing and control operations.",
        "safe_next_steps": ["Inspect safe status/version endpoints", "Import an exact paired flow for authenticated-active testing", "Use before/after evidence for settings or control actions"],
        "policy_questions": ["Are control requests authenticated?", "Are pairing tokens scoped and revocable?"],
    },
    "philips_jointspace": {
        "summary": "Philips JointSPACE exposes read and control APIs on TCP/1925 and secured variants on 1926.",
        "safe_next_steps": ["Identify the supported API version", "Inspect system identity and authentication boundary", "Exercise exact controls only after user confirmation"],
        "policy_questions": ["Is the secured interface required?", "Are legacy unauthenticated controls disabled or isolated?"],
    },
    "google_cast_dial": {
        "summary": "Google Cast and DIAL expose device descriptions and application-control surfaces, commonly around TCP/8008, 8009, and 8443.",
        "safe_next_steps": ["Parse same-device descriptors", "Inventory application surfaces", "Use exact confirmed launch/control requests for active testing"],
        "policy_questions": ["Are control services restricted to the intended network?", "Do application actions enforce the expected sender/session state?"],
    },
    "sony_bravia": {
        "summary": "Sony BRAVIA exposes JSON-RPC and IRCC operations over HTTP(S); read-only RPCs often use POST.",
        "safe_next_steps": ["Confirm Sony platform evidence before RPC", "Run the server-owned read-only identity RPC", "Bind PSK and exact control calls for authenticated-active tests"],
        "policy_questions": ["Is PSK or another authorization boundary enforced?", "Are control operations isolated from untrusted LAN clients?"],
    },
    "panasonic_viera": {
        "summary": "Panasonic VIERA may expose HTTP descriptors and SOAP remote/media control services on TCP/55000.",
        "safe_next_steps": ["Inspect descriptor schemas", "Bind exact SOAP actions and bodies", "Record before/after device state for control tests"],
        "policy_questions": ["Are SOAP control operations authenticated or network-isolated?", "Are unsafe actions rejected for unauthorized clients?"],
    },
}

PORT_PLAYBOOKS = {
    1925: "philips_jointspace", 1926: "philips_jointspace",
    3000: "lg_webos", 3001: "lg_webos",
    7345: "vizio_smartcast", 8060: "roku_ecp",
    8001: "samsung_tizen", 8002: "samsung_tizen",
    8008: "google_cast_dial",
}


def tool_fragility_cost(name: str, args: dict[str, Any]) -> int:
    if name == "verify_candidate":
        return 3
    if name == "device_http_request":
        return 1
    if name == "verify_service_state":
        return 6 if str(args.get("transport") or "tcp") == "udp" else 3
    if name != "queue_device_scan":
        return 0
    coverage = str(args.get("coverage_profile") or "inventory")
    cost = {"inventory": 5, "posture": 12, "thorough": 18}.get(coverage, 12)
    if args.get("include_web_dast"):
        cost += 4
    if args.get("include_imported_requests"):
        cost += 4
    if args.get("capability_ids"):
        cost += 6
    return cost


def lookup_protocol_playbook(service_name: str, port: int | None = None) -> dict[str, Any]:
    normalized = str(service_name or "unknown").strip().lower()
    aliases = {"ssdp": "upnp", "ssl/http": "https", "http-alt": "http", "ipps": "ipp"}
    key = aliases.get(normalized, normalized)
    if key not in PROTOCOL_PLAYBOOKS and port in PORT_PLAYBOOKS:
        key = PORT_PLAYBOOKS[int(port)]
    playbook = PROTOCOL_PLAYBOOKS.get(key)
    if not playbook:
        return {
            "status": "not_found",
            "service_name": normalized,
            "port": port,
            "guidance": "Use confirmed scanner evidence and policy context; do not infer a protocol from port number alone.",
        }
    return {"status": "available", "service_name": key, "port": port, **playbook}


def resolve_local_intel(*, cpe: str | None, product: str | None, version: str | None) -> dict[str, Any]:
    """Search the verified local advisory snapshot in force; never uses runtime egress.

    The same snapshot Exposure and device posture use (``load_verified_snapshot``): an operator
    pin, else an installed signed bundle that verifies, else the snapshot built into the image.
    """
    query = {"cpe": str(cpe or "")[:500], "product": str(product or "")[:300], "version": str(version or "")[:200]}
    snapshot = device_advisories.load_verified_snapshot(
        os.environ.get("DEVICE_INTEL_DB_PATH"), os.environ.get("DEVICE_INTEL_DB_SHA256"),
    )
    status = str(snapshot.get("status") or "unavailable")
    result: dict[str, Any] = {"status": status, "query": query, "candidates": [], "runtime_egress": False,
                              "source": snapshot.get("source")}
    if status != "available":
        result.update({key: snapshot[key] for key in (
            "error", "expected_sha256", "actual_sha256", "size_bytes", "max_bytes") if key in snapshot})
        return result
    result["candidates"] = match_advisories(
        snapshot.get("advisories") or [],
        cpe=query["cpe"],
        product=query["product"],
        version=query["version"],
        limit=50,
    )
    result["snapshot_sha256"] = snapshot.get("snapshot_sha256")
    return result


def control_authorization_precondition_gaps(
    state: dict[str, Any], locus: dict[str, Any] | None = None,
) -> list[str]:
    """List exactly which server-side preconditions for a state-changing replay are missing."""
    gaps: list[str] = []
    if str(state.get("safety_profile") or "") != "authenticated_active":
        gaps.append("authenticated_active_safety_required")
    if not state.get("confirm_request_replay"):
        gaps.append("bound_request_replay_not_confirmed")
    locus = locus if isinstance(locus, dict) else {}
    refs = [ref for ref in state.get("device_request_collections") or [] if isinstance(ref, dict)]
    collection_id = str((locus or {}).get("collection_id") or "")
    request_id = str((locus or {}).get("request_id") or "")
    cleanup_request_id = str((locus or {}).get("cleanup_request_id") or "")
    cleanup_adapter = str((locus or {}).get("cleanup_adapter") or "explicit_bound_request").lower()
    if not collection_id:
        gaps.append("exact_collection_id_required")
    if not request_id:
        gaps.append("exact_request_id_required")
    if cleanup_adapter not in CONTROL_CLEANUP_ADAPTERS:
        gaps.append("supported_cleanup_adapter_required")
    elif cleanup_adapter == "explicit_bound_request" and not cleanup_request_id:
        gaps.append("exact_cleanup_request_id_required")
    elif cleanup_adapter != "explicit_bound_request":
        if not str(locus.get("mutation_field") or "").strip():
            gaps.append("cleanup_mutation_field_required")
        if not str(locus.get("state_json_pointer") or "").startswith("/"):
            gaps.append("cleanup_state_json_pointer_required")
    if collection_id:
        refs = [ref for ref in refs if str(ref.get("collection_id") or "") == collection_id]
    if not refs:
        gaps.append("no_bound_confirmed_request_collection")
    elif not any(int(ref.get("state_changing_request_count") or 0) > 0 for ref in refs):
        gaps.append("no_state_changing_request_in_bound_collection")
    if not state.get("allow_state_changing_requests"):
        gaps.append("state_changing_replay_not_authorized")
    return gaps


def control_replay_verdict(replay_status: int) -> str:
    """Classify one credential-stripped state-changing replay against the device."""
    status = int(replay_status or 0)
    if status in {401, 403, 404}:
        return "unauthorized_rejected"
    if 200 <= status < 300:
        return "unauthenticated_control_accepted"
    return "inconclusive"


def control_state_observation(response: dict[str, Any] | None) -> dict[str, Any]:
    """Build a content-safe state observation from one pinned HTTP response."""
    value = response if isinstance(response, dict) else {}
    try:
        status = int(value.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    body = value.get("body")
    if isinstance(body, str):
        body_bytes = body.encode("utf-8", "replace")
    elif isinstance(body, (bytes, bytearray)):
        body_bytes = bytes(body)
    else:
        body_bytes = b""
    return {
        "observable": status > 0,
        "status": status,
        "body_bytes": len(body_bytes),
        "body_sha256": keyed_response_digest(body_bytes),
        "truncated": bool(value.get("truncated")),
    }


def control_json_pointer_value(
    response: dict[str, Any] | None, pointer: Any,
) -> dict[str, Any]:
    """Resolve one bounded JSON Pointer and retain its raw scalar only for cleanup execution."""
    text = str(pointer or "")
    if not text.startswith("/") or len(text) > 512:
        return {"found": False, "reason": "invalid_json_pointer"}
    value = response if isinstance(response, dict) else {}
    if value.get("truncated"):
        return {"found": False, "reason": "truncated_state_response"}
    body = value.get("body")
    if isinstance(body, (bytes, bytearray)):
        raw = bytes(body).decode("utf-8", "strict")
    elif isinstance(body, str):
        raw = body
    else:
        return {"found": False, "reason": "state_body_unavailable"}
    try:
        current: Any = json.loads(raw)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        return {"found": False, "reason": "state_body_not_json"}
    tokens = text[1:].split("/")
    if len(tokens) > 16:
        return {"found": False, "reason": "json_pointer_too_deep"}
    for encoded in tokens:
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            return {"found": False, "reason": "json_pointer_not_found"}
    if isinstance(current, (dict, list)):
        return {"found": False, "reason": "cleanup_state_must_be_scalar"}
    encoded_value = json.dumps(current, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "found": True,
        "value": current,
        "value_type": type(current).__name__,
        "value_sha256": keyed_response_digest(encoded_value.encode()),
    }


def derive_control_cleanup_request(
    imported: dict[str, Any], locus: dict[str, Any], original_value: Any,
) -> dict[str, Any]:
    """Restore one exact imported mutation field to its pre-test scalar value."""
    adapter = str(locus.get("cleanup_adapter") or "").lower()
    field = str(locus.get("mutation_field") or "")
    if adapter not in CONTROL_CLEANUP_ADAPTERS - {"explicit_bound_request"}:
        raise ValueError("unsupported_cleanup_adapter")
    if not field or len(field) > 200 or any(ord(ch) < 32 or ch in "&=\x7f" for ch in field):
        raise ValueError("invalid_cleanup_mutation_field")
    method = str(imported.get("method") or "").upper()
    url = str(imported.get("url") or "")
    headers = dict(imported.get("headers") or {})
    body = imported.get("body") if isinstance(imported.get("body"), bytes) else b""
    scalar_text = (
        "true" if original_value is True else "false" if original_value is False
        else "null" if original_value is None else str(original_value)
    )
    if adapter == "restore_query_parameter":
        parsed = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if sum(1 for key, _value in pairs if key == field) != 1:
            raise ValueError("cleanup_query_field_must_exist_once")
        pairs = [(key, scalar_text if key == field else value) for key, value in pairs]
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(pairs), ""))
    elif adapter == "restore_json_field":
        try:
            decoded = json.loads(body.decode("utf-8", "strict"))
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("cleanup_json_body_invalid") from exc
        if not isinstance(decoded, dict) or field not in decoded:
            raise ValueError("cleanup_json_field_missing")
        decoded[field] = original_value
        body = json.dumps(decoded, ensure_ascii=False, separators=(",", ":")).encode()
    else:
        try:
            pairs = urllib.parse.parse_qsl(body.decode("utf-8", "strict"), keep_blank_values=True)
        except UnicodeError as exc:
            raise ValueError("cleanup_form_body_invalid") from exc
        if sum(1 for key, _value in pairs if key == field) != 1:
            raise ValueError("cleanup_form_field_must_exist_once")
        pairs = [(key, scalar_text if key == field else value) for key, value in pairs]
        body = urllib.parse.urlencode(pairs).encode()
    return {"method": method, "url": url, "headers": headers, "body": body, "adapter": adapter}


def control_state_transition(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    *, json_pointer: str | None = None,
) -> dict[str, Any]:
    """Compare two server-observed device states without trusting an HTTP 2xx alone."""
    before_observation = control_state_observation(before)
    after_observation = control_state_observation(after)
    if json_pointer:
        before_value = control_json_pointer_value(before, json_pointer)
        after_value = control_json_pointer_value(after, json_pointer)
        comparable = bool(before_value.get("found") and after_value.get("found"))
        changed = bool(
            comparable and before_value.get("value_sha256") != after_value.get("value_sha256")
        )
        before_observation.update({
            "state_selector": json_pointer,
            "selected_value_observed": bool(before_value.get("found")),
            "selected_value_type": before_value.get("value_type"),
            "selected_value_sha256": before_value.get("value_sha256"),
        })
        after_observation.update({
            "state_selector": json_pointer,
            "selected_value_observed": bool(after_value.get("found")),
            "selected_value_type": after_value.get("value_type"),
            "selected_value_sha256": after_value.get("value_sha256"),
        })
    else:
        comparable = bool(
        before_observation["observable"]
        and after_observation["observable"]
        and not before_observation["truncated"]
        and not after_observation["truncated"]
        )
        changed = bool(
            comparable
            and (
                before_observation["status"] != after_observation["status"]
                or before_observation["body_sha256"] != after_observation["body_sha256"]
            )
        )
    return {
        "comparable": comparable,
        "changed": changed,
        "before": before_observation,
        "after": after_observation,
    }

