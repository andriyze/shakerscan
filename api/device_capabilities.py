"""Server-owned capability catalog for agent-directed connected-device reviews.

The catalog is planning data, not executable model instructions.  Each entry
names the deterministic ShakerScan executor (when one exists), the minimum
safety profile, and the evidence prerequisites that the API must enforce.
"""

from __future__ import annotations

from typing import Any


CAPABILITY_CATALOG: tuple[dict[str, Any], ...] = (
    {"id": "smart-tv-assessment-orchestrator", "title": "Assessment orchestration", "group": "orchestration", "implementation": "available", "executor": "device_agent", "minimum_profile": "observe_only"},
    {"id": "scope-safety-health", "title": "Scope, safety, and device health", "group": "core", "implementation": "available", "executor": "device_safety", "minimum_profile": "observe_only"},
    {"id": "device-identity-attack-surface", "title": "Device identity and attack surface", "group": "core", "implementation": "available", "executor": "device_posture", "minimum_profile": "observe_only"},
    {"id": "tcp-udp-network-discovery", "title": "TCP and UDP network discovery", "group": "core", "implementation": "available", "executor": "device_posture", "minimum_profile": "observe_only"},
    {"id": "service-fingerprinting-crypto", "title": "Service and cryptographic fingerprinting", "group": "core", "implementation": "available", "executor": "device_posture", "minimum_profile": "observe_only"},
    {"id": "ssh-authenticated-host-review", "title": "SSH-authenticated host review", "group": "host", "implementation": "available", "executor": "device_posture", "minimum_profile": "authenticated_active", "requires": ["confirmed_ssh", "ssh_credential"]},
    {"id": "web-ui-dast", "title": "Web interface DAST", "group": "application", "implementation": "available", "executor": "device_web_dast", "minimum_profile": "safe_remote", "requires": ["web_origin"]},
    {"id": "api-graphql-websocket-testing", "title": "API, RPC, GraphQL, and WebSocket testing", "group": "application", "implementation": "partial", "executor": "device_web_dast", "minimum_profile": "safe_remote", "requires": ["web_origin"]},
    {"id": "auth-session-pairing-access-control", "title": "Authentication, session, and pairing review", "group": "application", "implementation": "planned", "executor": None, "minimum_profile": "safe_remote"},
    {"id": "smart-tv-lan-protocols", "title": "Smart-TV LAN protocols", "group": "protocol", "implementation": "partial", "executor": "device_protocols", "minimum_profile": "observe_only", "notes": "SSDP/UPnP discovery and mDNS/DNS-SD are implemented."},
    {"id": "casting-remote-control-testing", "title": "Casting and remote-control testing", "group": "protocol", "implementation": "planned", "executor": None, "minimum_profile": "safe_remote", "device_classes": ["media"]},
    {"id": "wireless-bluetooth-wifi-direct", "title": "Wireless, Bluetooth, and Wi-Fi Direct", "group": "sensor", "implementation": "sensor_required", "executor": None, "minimum_profile": "safe_remote", "requires": ["radio_sensor"]},
    {"id": "firmware-update-supply-chain", "title": "Firmware, OTA, and supply-chain review", "group": "artifact", "implementation": "planned", "executor": None, "minimum_profile": "observe_only"},
    {"id": "component-sbom-cve-applicability", "title": "SBOM and CVE applicability", "group": "artifact", "implementation": "partial", "executor": "local_intel", "minimum_profile": "observe_only", "notes": "Pinned local advisory correlation is available; SBOM and reachability proof are planned."},
    {"id": "android-tv-platform-review", "title": "Android TV / Google TV platform review", "group": "platform", "implementation": "planned", "executor": None, "minimum_profile": "authenticated_active", "platform": "android"},
    {"id": "tizen-tv-platform-review", "title": "Tizen TV platform review", "group": "platform", "implementation": "planned", "executor": None, "minimum_profile": "authenticated_active", "platform": "tizen"},
    {"id": "webos-tv-platform-review", "title": "webOS TV platform review", "group": "platform", "implementation": "planned", "executor": None, "minimum_profile": "authenticated_active", "platform": "webos"},
    {"id": "media-parser-fuzzing", "title": "Media and parser fuzzing", "group": "lab", "implementation": "lab_only", "executor": None, "minimum_profile": "lab_invasive", "requires": ["lab_runner", "recovery_proof"]},
    {"id": "privacy-telemetry-cloud-review", "title": "Privacy, telemetry, sensors, and cloud review", "group": "ecosystem", "implementation": "planned", "executor": None, "minimum_profile": "safe_remote"},
    {"id": "companion-app-ecosystem-review", "title": "Companion application and ecosystem review", "group": "ecosystem", "implementation": "planned", "executor": None, "minimum_profile": "safe_remote"},
    {"id": "hardware-debug-lab-review", "title": "Hardware and physical debug review", "group": "lab", "implementation": "lab_only", "executor": None, "minimum_profile": "lab_invasive", "requires": ["lab_runner", "recovery_proof"]},
    {"id": "evidence-correlation-reporting", "title": "Evidence correlation and reporting", "group": "evidence", "implementation": "available", "executor": "device_evidence", "minimum_profile": "observe_only"},
    {"id": "remediation-rescan-regression", "title": "Remediation, rescan, and regression", "group": "evidence", "implementation": "partial", "executor": "device_agent", "minimum_profile": "observe_only", "notes": "Scan diffs are implemented; exact finding regression workflows are planned."},
)

CAPABILITIES_BY_ID = {item["id"]: item for item in CAPABILITY_CATALOG}
EXECUTABLE_CAPABILITY_IDS = frozenset({"ssh-authenticated-host-review"})


def _normalized_platform(device: dict[str, Any]) -> str | None:
    joined = " ".join(str(device.get(key) or "") for key in ("manufacturer", "model", "firmware_version", "stable_identity")).lower()
    if any(marker in joined for marker in ("android", "google tv", "chromecast")):
        return "android"
    if "tizen" in joined:
        return "tizen"
    if any(marker in joined for marker in ("webos", "web os")):
        return "webos"
    return None


def capability_catalog_for_device(
    device: dict[str, Any],
    *,
    services: list[dict[str, Any]],
    credential_kinds: set[str] | None = None,
    completed_capabilities: set[str] | None = None,
    sensor_capabilities: set[str] | None = None,
) -> dict[str, Any]:
    """Resolve static pack readiness against one registered device."""
    credential_kinds = credential_kinds or set()
    completed_capabilities = completed_capabilities or set()
    sensor_capabilities = sensor_capabilities or set()
    device_class = str(device.get("device_class") or "generic").lower()
    platform = _normalized_platform(device)
    has_ssh = any(
        str(service.get("transport") or "").lower() == "tcp"
        and str(service.get("state") or "").lower() == "open"
        and str(service.get("service_name") or "").lower() in {"ssh", "ssh-alt"}
        for service in services
    )
    has_web = any(bool(service.get("web_origin")) for service in services)
    has_ssh_credential = bool({"ssh_password", "ssh_private_key"} & credential_kinds)

    items: list[dict[str, Any]] = []
    for raw in CAPABILITY_CATALOG:
        item = dict(raw)
        required_class = set(item.get("device_classes") or [])
        item_platform = item.get("platform")
        blockers: list[str] = []
        applicable = not required_class or device_class in required_class
        if item_platform and platform and item_platform != platform:
            applicable = False
        if item_platform and platform is None:
            blockers.append("platform_not_confirmed")
        for requirement in item.get("requires") or []:
            if requirement == "confirmed_ssh" and not has_ssh:
                blockers.append("confirmed_ssh_required")
            elif requirement == "ssh_credential" and not has_ssh_credential:
                blockers.append("active_ssh_credential_required")
            elif requirement == "web_origin" and not has_web:
                blockers.append("confirmed_web_origin_required")
            elif requirement == "radio_sensor" and not ({"bluetooth", "ble", "wifi_direct"} & sensor_capabilities):
                blockers.append("radio_sensor_required")
            elif requirement in {"lab_runner", "recovery_proof"}:
                blockers.append(requirement + "_required")

        if item["id"] in completed_capabilities:
            state = "completed"
        elif not applicable:
            state = "not_applicable"
        elif item["implementation"] in {"planned", "sensor_required", "lab_only"}:
            state = item["implementation"]
        elif blockers:
            state = "blocked"
        else:
            state = "ready"
        item.update({"state": state, "blockers": sorted(set(blockers)), "applicable": applicable})
        items.append(item)

    return {
        "schema_version": "device-capabilities/v1",
        "device_id": str(device.get("id") or ""),
        "device_class": device_class,
        "detected_platform": platform,
        "items": items,
        "summary": {
            state: sum(1 for item in items if item["state"] == state)
            for state in ("ready", "completed", "blocked", "partial", "planned", "sensor_required", "lab_only", "not_applicable")
        },
    }


def validate_executable_capabilities(values: list[str] | None) -> list[str]:
    normalized = list(dict.fromkeys(str(value or "").strip().lower() for value in (values or []) if str(value or "").strip()))
    unsupported = [value for value in normalized if value not in EXECUTABLE_CAPABILITY_IDS]
    if unsupported:
        raise ValueError("unsupported executable device capability: " + ", ".join(unsupported))
    return normalized
