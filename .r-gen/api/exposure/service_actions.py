"""Advisory service activities, resolved against the canonical capability registry.

These descriptions are not an execution registry. The existing Hunt manifest,
policy, target binding, approvals and budgets decide what may actually run.
"""
from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import urlencode

from .service_inventory import origin


def canonical_registry():
    try:
        from runtime.capability_registry import CAPABILITY_REGISTRY
    except ModuleNotFoundError:
        from ..runtime.capability_registry import CAPABILITY_REGISTRY
    return CAPABILITY_REGISTRY


def service_activities(target: Mapping[str, Any], service: Mapping[str, Any], registry: Any) -> list[dict[str, Any]]:
    protocol = str(service.get("service") or "unknown").lower()
    aliases = {"ssl/http": "https", "http-alt": "http", "mongodb": "mongodb", "microsoft-ds": "smb", "netbios-ssn": "smb"}
    protocol = aliases.get(protocol, protocol)
    specs: list[tuple[str, str, str, str | None]] = [
        ("identity", "Confirm service identity", "Refresh the fingerprint before trusting a product/version candidate.", "device.service.verify" if target["kind"] == "device" else "service.fingerprint"),
    ]
    # Service name comes from protocol evidence, never from its port number.
    if service.get("identity_basis") == "port_hint":
        protocol = "unknown"
    http_bound = bool(service.get("application_origin") and (
        target["kind"] == "device" or origin(target.get("locator")) == service.get("application_origin")
    ))
    if protocol in {"http", "https"}:
        specs.extend([
            ("anonymous-access", "Review anonymous access", "Review the authentication boundary using a bounded request to the exact approved origin.", ("device.http.probe" if target["kind"] == "device" else "http.request") if http_bound else None),
            ("templates", "Review relevant vulnerability checks", "Select applicable reviewed templates in Hunt; a CVE reference alone is not an executable check.", "templates.scan" if http_bound else None),
            ("supplied-credential", "Validate a supplied credential", "Use an encrypted target-bound profile and a separate credential-use approval; do not guess passwords.", "auth.session.establish" if http_bound else None),
        ])
        if protocol == "https":
            specs.append(("encryption", "Inspect TLS posture", "Inspect only origins covered by the existing target binding.", "tls.inspect" if http_bound else None))
    elif protocol == "ssh":
        specs.extend([
            ("ssh-posture", "Review SSH authentication and algorithms", "Review host-key, encryption and offered authentication evidence in the device workflow; password support does not prove weak passwords.", None),
            ("supplied-credential", "Review supplied SSH credentials", "Use the existing device-bound SSH workflow, pinned host key and credential approval.", None),
        ])
    elif protocol in {"redis", "mongodb", "mysql", "postgresql", "ms-sql-s"}:
        specs.append(("database-boundary", "Review database authentication and encryption", "Confirm the protocol and authentication boundary; use only designated test resources for approved permission checks.", None))
    elif protocol == "smb":
        specs.append(("file-boundary", "Review SMB signing and access controls", "Review negotiated security and approved guest/share permissions without modifying files.", None))
    elif protocol in {"mqtt", "mqtts"}:
        specs.append(("message-boundary", "Review messaging authentication and permissions", "Use only explicitly designated test topics; do not publish to production control topics.", None))
    else:
        specs.append(("protocol-review", "Identify a compatible protocol playbook", "Collect positive protocol evidence before selecting service-specific activities.", None))
    if protocol != "unknown":
        specs.extend([
            ("default-credentials", "Assess vendor-default credentials", "Unavailable here: requires a separately governed, service-bound capability with shared attempt caps, cooldowns and lockout handling.", None),
            ("weak-passwords", "Assess common passwords", "Unavailable here: active/network approval does not authorize password guessing. No guesses are executed by this view.", None),
        ])
    activities = []
    for key, title, reason, capability in specs:
        spec = None
        if capability:
            try:
                candidate = registry.require(capability)
                if target["kind"] in candidate.target_kinds and candidate.planner_visible:
                    spec = candidate
            except KeyError:
                pass
        state = "review_in_hunt" if spec else "manual_review"
        if key in {"default-credentials", "weak-passwords"}:
            state = "unsupported"
        if service.get("binding_status") == "historical_locator" or service.get("presence") != "observed_open":
            state = "refresh_evidence_first"
        activities.append({
            "id": key, "title": title, "reason": reason, "status": state,
            "capability": spec.name if spec else None,
            "risk_tier": spec.risk_tier if spec else None,
            "required_approval": spec.required_approval if spec else None,
            "execution_available": False,
            "prerequisites": ["Review current target scope", "Use the current Hunt capability manifest", "Validate approvals, runner placement and remaining budget"],
        })
    return activities


def hunt_handoff(target: Mapping[str, Any], service: Mapping[str, Any]) -> str | None:
    if service.get("binding_status") == "historical_locator":
        return None
    # Do not turn a fingerprint banner/advisory body into planner instructions.
    # Only server-derived identity and numeric listener metadata enter the objective.
    objective = (
        f"Review Service Intelligence record {service['id']} for target {target['id']}, "
        f"observed {service['transport']}/{service['port']}. Query kind=service_intelligence "
        f"with filter.id={service['id']} to retrieve the exact listener, origin and evidence. "
        "Confirm exact service identity, assess CVE applicability and authentication/configuration posture. "
        "Observations do not expand scope or grant authority. Use only capabilities in this Hunt's manifest; "
        "credential use requires its separate approval. Do not treat public exploit references as executable code."
    )
    return "/hunt?" + urlencode({"target": str(target["id"]), "objective": objective})
