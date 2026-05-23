from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import Any

from .corpus_loader import load_inline_probe_entries_with_diagnostics
from .models import Probe
from .probe_registry import PROBE_PACK_DEFINITIONS


_VALID_SCAN_PROFILES = ("smoke", "trace", "standard", "deep")
_PROFILE_RANK = {"smoke": 0, "trace": 1, "standard": 1, "deep": 2}
_PROFILE_TURN_CAP = {
    "smoke": 1,
    "trace": 1,
    "standard": 3,
    "deep": 8,
}


@dataclass(frozen=True)
class ProbePackPlan:
    probes: tuple[Probe, ...]
    manifest: dict[str, Any]
    validation_errors: tuple[str, ...] = ()


def normalize_scan_profile(value: object) -> str:
    if isinstance(value, str) and value in _VALID_SCAN_PROFILES:
        return value
    return "smoke"


def _probe_supported_in_profile(probe: Probe, scan_profile: str) -> bool:
    return _PROFILE_RANK[probe.minimum_profile] <= _PROFILE_RANK[scan_profile]


def _plan_probe(probe: Probe, scan_profile: str) -> Probe:
    turn_cap = _PROFILE_TURN_CAP[scan_profile]
    if turn_cap is None:
        return probe
    return replace(probe, max_turns=max(1, min(probe.max_turns, turn_cap)))


def _probe_manifest_entry(probe: Probe) -> dict[str, Any]:
    return {
        "id": probe.id,
        "family": probe.family,
        "title": probe.title,
        "minimum_profile": probe.minimum_profile,
        "technique": probe.technique,
        "owasp": probe.owasp,
        "source_name": probe.source_name,
        "source_reference": probe.source_reference,
        "tactics": list(probe.tactics),
        "expected_safe_behavior": probe.expected_safe_behavior,
        "expected_attack_success": probe.expected_attack_success,
        "severity_if_success": probe.severity_if_success,
        "max_turns": probe.max_turns,
        "safe_for_production": probe.safe_for_production,
        "principal": probe.principal,
        "turns": [
            {
                "role": turn.role,
                "principal": turn.principal,
                "message": turn.message,
            }
            for turn in probe.conversation_turns
        ],
    }


def _sha256_prefixed(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def plan_probe_pack_definitions(
    slug: str | None,
    scan_profile: object,
    metadata_json: dict[str, object] | None = None,
) -> tuple[Probe, ...]:
    return plan_probe_pack(slug, scan_profile, metadata_json).probes


def plan_probe_pack(
    slug: str | None,
    scan_profile: object,
    metadata_json: dict[str, object] | None = None,
    *,
    production_mode: bool = False,
) -> ProbePackPlan:
    normalized_slug = slug or "shaker-ai-smoke"
    normalized_profile = normalize_scan_profile(scan_profile)
    base_pack = PROBE_PACK_DEFINITIONS.get(
        normalized_slug,
        PROBE_PACK_DEFINITIONS["shaker-ai-smoke"],
    )
    base_probe_ids = {probe.id for probe in base_pack}
    custom_result = (
        load_inline_probe_entries_with_diagnostics(metadata_json.get("custom_probes"))
        if isinstance(metadata_json, dict)
        else load_inline_probe_entries_with_diagnostics(None)
    )
    validation_errors = list(custom_result.errors)
    custom_probes: list[Probe] = []
    for probe in custom_result.probes:
        if probe.id in base_probe_ids:
            validation_errors.append(
                f"custom probe id conflicts with base pack probe and was skipped: {probe.id}"
            )
            continue
        custom_probes.append(probe)
    raw_pack = base_pack + tuple(custom_probes)
    profile_probes = tuple(
        _plan_probe(probe, normalized_profile)
        for probe in raw_pack
        if _probe_supported_in_profile(probe, normalized_profile)
    )
    blocked_for_production = tuple(
        probe for probe in profile_probes if production_mode and not probe.safe_for_production
    )
    if blocked_for_production:
        validation_errors.extend(
            f"probe blocked in production mode because safe_for_production=false: {probe.id}"
            for probe in blocked_for_production
        )
    probes = tuple(
        probe
        for probe in profile_probes
        if not (production_mode and not probe.safe_for_production)
    )
    custom_probe_ids = {probe.id for probe in custom_probes}
    planned_custom_probes = tuple(probe for probe in probes if probe.id in custom_probe_ids)
    manifest = {
        "base_pack": normalized_slug,
        "scan_profile": normalized_profile,
        "production_mode": production_mode,
        "base_probe_count": len(base_pack),
        "custom_probe_count": len(custom_probes),
        "planned_custom_probe_count": len(planned_custom_probes),
        "planned_probe_count": len(probes),
        "blocked_for_production_count": len(blocked_for_production),
        "blocked_for_production_probe_ids": [probe.id for probe in blocked_for_production],
        "planned_probe_hash": _sha256_prefixed([_probe_manifest_entry(probe) for probe in probes]),
        "custom_probe_hash": (
            _sha256_prefixed([_probe_manifest_entry(probe) for probe in custom_probes])
            if custom_probes
            else None
        ),
    }
    return ProbePackPlan(probes=probes, manifest=manifest, validation_errors=tuple(validation_errors))


def resolve_max_turns_per_conversation(
    metadata_json: dict[str, object] | None,
    scan_profile: object,
) -> int:
    normalized_profile = normalize_scan_profile(scan_profile)
    default_turn_cap = _PROFILE_TURN_CAP[normalized_profile] or 8
    metadata = metadata_json if isinstance(metadata_json, dict) else {}
    raw_value = metadata.get("max_turns_per_conversation")
    if isinstance(raw_value, (int, float)):
        normalized = int(raw_value)
        if 1 <= normalized <= 8:
            return normalized
    return default_turn_cap
