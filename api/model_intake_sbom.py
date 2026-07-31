"""Export a completed Model Intake scan as a downloadable bill of materials.

Every input here is already produced by the scan: the CycloneDX dependency
components come from the generated ``shakerscan-sbom`` adapter, and the model,
tokenizer, base model, and dataset components come from the AIBOM. This module
composes them into one standards-conformant document; it never re-inspects an
artifact and never invents a component.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


CYCLONEDX_SPEC_VERSION = "1.5"
AIBOM_COMPONENT_TYPES = {
    # CycloneDX 1.5 has a first-class "machine-learning-model" type; everything
    # else the AIBOM tracks maps onto an existing type rather than a custom one.
    "model_artifact": "machine-learning-model",
    "base_model": "machine-learning-model",
    "adapter": "machine-learning-model",
    "tokenizer": "data",
    "dataset": "data",
    "dependency": "library",
}


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _digest(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _generated_sbom(model_intake: dict[str, Any]) -> dict[str, Any]:
    """The CycloneDX document produced by the generated SBOM adapter, if it ran."""
    results = _object(model_intake.get("generated_evidence")).get("results")
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        if str(_object(result.get("scanner")).get("name") or "") != "shakerscan-sbom":
            continue
        sbom = _object(_object(result.get("summary")).get("sbom"))
        if sbom:
            return sbom
    return {}


def _aibom_components(aibom: dict[str, Any]) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    raw = aibom.get("components")
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "").strip()
        name = str(item.get("name") or item.get("ref") or "").strip()
        if not name:
            continue
        component: dict[str, Any] = {
            "type": AIBOM_COMPONENT_TYPES.get(kind, "library"),
            "name": name,
            "bom-ref": f"shakerscan:{kind or 'component'}:{name}",
        }
        hashes = [
            {"alg": str(entry.get("alg") or "SHA-256"), "content": str(entry.get("content"))}
            for entry in (item.get("hashes") if isinstance(item.get("hashes"), list) else [])
            if isinstance(entry, dict) and entry.get("content")
        ]
        if hashes:
            component["hashes"] = hashes
        licenses = [
            {"license": {"id" if str(entry).count(" ") == 0 else "name": str(entry)}}
            for entry in (item.get("licenses") if isinstance(item.get("licenses"), list) else [])
            if entry
        ]
        if licenses:
            component["licenses"] = licenses
        if item.get("ref"):
            component["externalReferences"] = [{"type": "distribution", "url": str(item["ref"])}]
        properties = [
            {"name": f"shakerscan:{key}", "value": str(item[key])}
            for key in ("format", "role")
            if item.get(key)
        ]
        if kind:
            properties.append({"name": "shakerscan:aibom_type", "value": kind})
        if properties:
            component["properties"] = properties
        components.append(component)
    return components


def build_model_intake_cyclonedx(scan_result: Any, *, scan_id: str = "") -> dict[str, Any]:
    """Compose one CycloneDX 1.5 document from a completed Model Intake scan."""
    model_intake = _object(_object(scan_result).get("model_intake"))
    if not model_intake:
        raise ValueError("scan result does not contain Model Intake evidence")

    summary = _object(model_intake.get("summary"))
    aibom = _object(model_intake.get("aibom"))
    artifact = _object(model_intake.get("artifact"))
    fetch = _object(artifact.get("fetch"))
    generated = _generated_sbom(model_intake)

    artifact_sha256 = str(fetch.get("sha256") or summary.get("sha256") or "").strip()
    artifact_name = str(artifact.get("name") or summary.get("artifact_name") or "model").strip()
    root: dict[str, Any] = {
        "type": "machine-learning-model",
        "bom-ref": f"shakerscan:subject:{artifact_sha256 or artifact_name}",
        "name": artifact_name,
    }
    if artifact_sha256:
        root["hashes"] = [{"alg": "SHA-256", "content": artifact_sha256}]
    license_ref = _object(_object(model_intake.get("supply_chain")).get("license_policy")).get("declared")
    if license_ref:
        root["licenses"] = [{"license": {"name": str(license_ref)}}]

    # Dependency components from the generated adapter, then everything the
    # AIBOM knows. Deduplicate on bom-ref so a package listed in both appears once.
    components: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in generated.get("components") if isinstance(generated.get("components"), list) else []:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        ref = str(item.get("purl") or f"{item.get('name')}@{item.get('version')}")
        if ref in seen:
            continue
        seen.add(ref)
        component = {
            "type": str(item.get("type") or "library"),
            "name": str(item["name"]),
            "bom-ref": ref,
        }
        if item.get("version"):
            component["version"] = str(item["version"])
        if item.get("purl"):
            component["purl"] = str(item["purl"])
        components.append(component)
    for component in _aibom_components(aibom):
        ref = str(component["bom-ref"])
        if ref in seen or ref == root["bom-ref"]:
            continue
        seen.add(ref)
        components.append(component)

    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": root,
            "tools": [{"vendor": "ShakerScan", "name": "model-intake", "version": "1"}],
            "properties": [
                {"name": "shakerscan:scan_id", "value": str(scan_id)},
                {"name": "shakerscan:artifact_ref", "value": str(summary.get("artifact_ref") or "")},
                {"name": "shakerscan:checksum_status", "value": str(summary.get("checksum_status") or "unknown")},
                {"name": "shakerscan:acquisition_complete", "value": str(bool(summary.get("acquisition_complete"))).lower()},
                # A bounded-prefix scan cannot enumerate dependencies, so the
                # document must say so rather than read as a complete inventory.
                {"name": "shakerscan:dependency_inventory", "value": "generated" if generated else "not_generated"},
            ],
        },
        "components": components,
    }
    document["serialNumber"] = f"urn:uuid:{_digest(document)[:32]}"
    return document


def model_intake_bom_completeness(document: dict[str, Any]) -> dict[str, Any]:
    """Summarize the document for the UI so a thin BOM is not mistaken for a clean one."""
    components = document.get("components")
    components = components if isinstance(components, list) else []
    properties = {
        str(item.get("name")): str(item.get("value"))
        for item in _object(document.get("metadata")).get("properties") or []
        if isinstance(item, dict)
    }
    return {
        "component_count": len(components),
        "dependency_inventory": properties.get("shakerscan:dependency_inventory", "not_generated"),
        "acquisition_complete": properties.get("shakerscan:acquisition_complete") == "true",
        "checksum_status": properties.get("shakerscan:checksum_status", "unknown"),
    }


__all__ = [
    "CYCLONEDX_SPEC_VERSION",
    "build_model_intake_cyclonedx",
    "model_intake_bom_completeness",
]
