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
import re
from typing import Any


CYCLONEDX_SPEC_VERSION = "1.5"
SPDX_VERSION = "SPDX-2.3"
SPDX_DATA_LICENSE = "CC0-1.0"
AIBOM_COMPONENT_TYPES = {
    # CycloneDX 1.5 has a first-class "machine-learning-model" type; everything
    # else the AIBOM tracks maps onto an existing type rather than a custom one.
    "model_artifact": "machine-learning-model",
    "base_model": "machine-learning-model",
    "adapter": "machine-learning-model",
    "tokenizer": "data",
    "dataset": "data",
    "dependency": "library",
    "runtime_dependency": "library",
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


def _license_compliance(model_intake: dict[str, Any]) -> dict[str, Any]:
    return _object(_object(model_intake.get("supply_chain")).get("license_compliance"))


def _license_terms(model_intake: dict[str, Any]) -> list[dict[str, Any]]:
    terms = _license_compliance(model_intake).get("terms")
    return [item for item in terms if isinstance(item, dict)] if isinstance(terms, list) else []


def _display_license_term(value: Any) -> str:
    text = str(value or "").strip()
    canonical = {
        "mit": "MIT", "apache-2.0": "Apache-2.0", "bsd-2-clause": "BSD-2-Clause",
        "bsd-3-clause": "BSD-3-Clause", "mpl-2.0": "MPL-2.0", "gpl-2.0": "GPL-2.0",
        "gpl-3.0": "GPL-3.0", "lgpl-2.1": "LGPL-2.1", "lgpl-3.0": "LGPL-3.0",
    }
    return canonical.get(text.casefold(), text)


def model_intake_license_display(compliance: dict[str, Any]) -> dict[str, Any]:
    """Return stable, plain-language licensing status for UI and exports.

    The scanner's internal policy vocabulary remains evidence, but it is not a
    useful headline.  This summary tells an engineer what was found and what,
    if anything, is still missing.
    """
    policy_status = str(compliance.get("policy_status") or "").upper()
    missing = [str(item) for item in compliance.get("missing_evidence") or [] if item]
    terms = [item for item in compliance.get("terms") or [] if isinstance(item, dict)]
    declared = sorted({
        _display_license_term(item.get("declared"))
        for item in terms if str(item.get("declared") or "").strip()
    })
    term_label = ", ".join(declared) if declared else "No license declaration"
    if policy_status == "BLOCK":
        status = "BLOCKED"
        summary = "The configured license policy rejected one or more detected terms."
    elif policy_status == "REVIEW_REQUIRED":
        status = "REVIEW_REQUIRED"
        summary = f"{term_label}; one or more terms need licensing review."
    elif policy_status == "PASS" and missing:
        status = "SOURCE_TEXT_MISSING"
        summary = f"{term_label}; the repository did not include the expected license or notice source text."
    elif policy_status == "PASS":
        status = "PASS"
        summary = f"{term_label}; no configured license-policy issue was found."
    else:
        status = "INCOMPLETE"
        summary = "License evidence was not complete enough to evaluate."
    return {
        "status": status,
        "summary": summary,
        "follow_up_required": bool(missing) or policy_status in {"BLOCK", "REVIEW_REQUIRED"},
        "review_required": policy_status == "REVIEW_REQUIRED",
        "missing_evidence": missing,
        "declared_terms": declared,
    }


def _cyclonedx_license(value: Any) -> dict[str, Any] | None:
    text = _display_license_term(value)
    if not text:
        return None
    if re.fullmatch(r"[A-Za-z0-9.+-]+", text):
        return {"license": {"id": text}}
    if re.fullmatch(r"[A-Za-z0-9.+() -]+\s(?:AND|OR|WITH)\s[A-Za-z0-9.+() -]+", text):
        return {"expression": text}
    return {"license": {"name": text}}


def _component_license_terms(model_intake: dict[str, Any], component_name: str) -> list[dict[str, Any]]:
    wanted = component_name.strip().casefold()
    return [
        item for item in _license_terms(model_intake)
        if str(item.get("component") or "").strip().casefold() == wanted
    ]


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
        purl = str(item.get("purl") or "").strip()
        version = str(item.get("version") or "").strip()
        component: dict[str, Any] = {
            "type": AIBOM_COMPONENT_TYPES.get(kind, "library"),
            "name": name,
            # Resolved runtime dependencies already carry an exact package URL.
            # Preserve it as both the standard identity and the BOM reference so
            # downstream SCA tools do not receive a name-only component.
            "bom-ref": purl or f"shakerscan:{kind or 'component'}:{name}",
        }
        if version:
            component["version"] = version
        if purl:
            component["purl"] = purl
        hashes = [
            {"alg": str(entry.get("alg") or "SHA-256"), "content": str(entry.get("content"))}
            for entry in (item.get("hashes") if isinstance(item.get("hashes"), list) else [])
            if isinstance(entry, dict) and entry.get("content")
        ]
        if hashes:
            component["hashes"] = hashes
        licenses = [
            normalized
            for entry in (item.get("licenses") if isinstance(item.get("licenses"), list) else [])
            if entry
            for normalized in [_cyclonedx_license(entry)]
            if normalized
        ]
        if licenses:
            component["licenses"] = licenses
        if item.get("ref"):
            component["externalReferences"] = [{"type": "distribution", "url": str(item["ref"])}]
        properties = [
            {"name": f"shakerscan:{key}", "value": str(item[key])}
            for key in ("format", "role", "profile_id", "resolution")
            if item.get(key)
        ]
        if kind:
            properties.append({"name": "shakerscan:aibom_type", "value": kind})
        if properties:
            component["properties"] = properties
        components.append(component)
    return components


def _component_property(component: dict[str, Any], name: str) -> str:
    for item in component.get("properties") or []:
        if isinstance(item, dict) and str(item.get("name") or "") == name:
            return str(item.get("value") or "")
    return ""


def _component_hashes(component: dict[str, Any]) -> set[str]:
    return {
        str(item.get("content") or "").strip().casefold()
        for item in component.get("hashes") or []
        if isinstance(item, dict) and str(item.get("content") or "").strip()
    }


def _merge_component_evidence(target: dict[str, Any], source: dict[str, Any]) -> None:
    """Keep one package identity without discarding richer AIBOM evidence."""
    for key in ("version", "purl"):
        if source.get(key) and not target.get(key):
            target[key] = source[key]
    for key in ("hashes", "licenses", "properties", "externalReferences"):
        existing = target.get(key) if isinstance(target.get(key), list) else []
        incoming = source.get(key) if isinstance(source.get(key), list) else []
        if not incoming:
            continue
        merged: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in [*existing, *incoming]:
            if not isinstance(item, dict):
                continue
            identity = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
            if identity in seen:
                continue
            seen.add(identity)
            merged.append(item)
        if merged:
            target[key] = merged


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
    if not license_ref:
        license_ref = _object(_object(model_intake.get("supply_chain")).get("license_policy")).get("license")
    if not license_ref:
        license_ref = next(
            (item.get("declared") for item in _license_terms(model_intake) if item.get("scope") == "model"),
            None,
        )
    if license_ref:
        root_license = _cyclonedx_license(license_ref)
        if root_license:
            root["licenses"] = [root_license]

    # Dependency components from the generated adapter, then everything the
    # AIBOM knows. Deduplicate on bom-ref so a package listed in both appears once.
    components: list[dict[str, Any]] = []
    seen: set[str] = set()
    by_ref: dict[str, dict[str, Any]] = {}
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
        detected_licenses = list(dict.fromkeys(
            str(term.get("declared") or "").strip()
            for term in _component_license_terms(model_intake, str(item["name"]))
            if str(term.get("declared") or "").strip()
        ))
        licenses = [_cyclonedx_license(value) for value in detected_licenses]
        if licenses:
            component["licenses"] = [item for item in licenses if item]
        components.append(component)
        by_ref[ref] = component
    for component in _aibom_components(aibom):
        ref = str(component["bom-ref"])
        # The document metadata component is the authoritative top-level model
        # package. AIBOM also records that same subject as ``model_artifact``;
        # merge that identity instead of showing reviewers two copies of one
        # model. Base models, adapters, tokenizers, and datasets remain distinct.
        if _component_property(component, "shakerscan:aibom_type") == "model_artifact":
            same_name = str(component.get("name") or "").strip().casefold() == artifact_name.casefold()
            same_hash = bool(
                artifact_sha256
                and artifact_sha256.casefold() in _component_hashes(component)
            )
            if same_name or same_hash:
                continue
        if ref in seen:
            _merge_component_evidence(by_ref[ref], component)
            continue
        if ref == root["bom-ref"]:
            continue
        seen.add(ref)
        components.append(component)
        by_ref[ref] = component

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
                {"name": "shakerscan:license_status", "value": model_intake_license_display(_license_compliance(model_intake))["status"]},
                {"name": "shakerscan:license_policy_version", "value": str(_license_compliance(model_intake).get("policy_version") or "not_assessed")},
            ],
        },
        "components": components,
        "dependencies": [{
            "ref": root["bom-ref"],
            "dependsOn": [str(component["bom-ref"]) for component in components],
        }],
        "compositions": [{
            "aggregate": (
                "incomplete" if not generated or not bool(summary.get("acquisition_complete"))
                else "incomplete_first_party_only"
            ),
            "assemblies": [root["bom-ref"]],
        }],
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
    dependency_components = [item for item in components if isinstance(item, dict) and item.get("purl")]
    ai_components = [
        item for item in components
        if isinstance(item, dict)
        and _component_property(item, "shakerscan:aibom_type")
        not in {"", "dependency", "runtime_dependency"}
    ]
    composition = next(
        (item for item in document.get("compositions") or [] if isinstance(item, dict)), {}
    )
    return {
        "component_count": len(components),
        "dependency_component_count": len(dependency_components),
        "ai_component_count": len(ai_components) + 1,
        "dependency_inventory": properties.get("shakerscan:dependency_inventory", "not_generated"),
        "acquisition_complete": properties.get("shakerscan:acquisition_complete") == "true",
        "checksum_status": properties.get("shakerscan:checksum_status", "unknown"),
        "composition_aggregate": composition.get("aggregate") or "unknown",
        "inventory_note": (
            "Declared dependency manifests were inventoried; this is not an inventory of an installed serving image."
            if properties.get("shakerscan:dependency_inventory") == "generated"
            else "No dependency manifest inventory was generated; the BOM contains only model-system facts discovered elsewhere."
        ),
    }


def _spdx_id(prefix: str, value: str) -> str:
    """SPDXIDs allow only letters, digits, dot and dash."""
    safe = re.sub(r"[^A-Za-z0-9.-]", "-", value).strip("-") or "unnamed"
    return f"SPDXRef-{prefix}-{safe[:80]}"


def build_model_intake_spdx(
    scan_result: Any, *, scan_id: str = "", created: str = ""
) -> dict[str, Any]:
    """Render the same evidence as SPDX 2.3 JSON.

    Composed from the CycloneDX document so both exports describe exactly the
    same components; only the serialization differs.
    """
    cyclonedx = build_model_intake_cyclonedx(scan_result, scan_id=scan_id)
    root = _object(_object(cyclonedx.get("metadata")).get("component"))
    # SPDX requires a creation timestamp. Deriving it from the scan keeps the
    # export reproducible instead of changing on every download.
    created_at = created or "1970-01-01T00:00:00Z"

    def _licenses(component: dict[str, Any]) -> str:
        for entry in component.get("licenses") or []:
            if isinstance(entry, dict) and entry.get("expression"):
                return str(entry["expression"])
            license_object = _object(_object(entry).get("license"))
            declared = license_object.get("id") or license_object.get("name")
            if declared:
                return str(declared)
        return "NOASSERTION"

    root_id = _spdx_id("Package", str(root.get("name") or "model"))
    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id}
    ]

    root_package: dict[str, Any] = {
        "SPDXID": root_id,
        "name": str(root.get("name") or "model"),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": _licenses(root),
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "MACHINE_LEARNING_MODEL",
    }
    compliance = _license_compliance(_object(_object(scan_result).get("model_intake")))
    license_display = model_intake_license_display(compliance)
    root_package["licenseComments"] = (
        f"Scan result: {license_display['summary']} "
        "LicenseConcluded remains NOASSERTION because this document records discovered evidence, not a final license selection."
    )
    checksums = [
        {"algorithm": str(entry.get("alg") or "SHA256").replace("-", ""), "checksumValue": str(entry.get("content"))}
        for entry in root.get("hashes") or []
        if _object(entry).get("content")
    ]
    if checksums:
        root_package["checksums"] = checksums
    packages.append(root_package)

    seen_ids: set[str] = {root_id}
    for component in cyclonedx.get("components") or []:
        if not isinstance(component, dict):
            continue
        name = str(component.get("name") or "")
        if not name:
            continue
        package_id = _spdx_id("Package", str(component.get("bom-ref") or name))
        if package_id in seen_ids:
            continue
        seen_ids.add(package_id)
        package: dict[str, Any] = {
            "SPDXID": package_id,
            "name": name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": _licenses(component),
            "copyrightText": "NOASSERTION",
        }
        component_terms = _component_license_terms(
            _object(_object(scan_result).get("model_intake")), name,
        )
        if component_terms:
            classes = sorted({str(item.get("classification") or "unknown") for item in component_terms})
            package["licenseComments"] = (
                f"Detected by generated evidence; classifications: {', '.join(classes)}. "
                "LicenseConcluded remains NOASSERTION until the detected terms are resolved."
            )
        if component.get("version"):
            package["versionInfo"] = str(component["version"])
        if component.get("purl"):
            package["externalRefs"] = [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": str(component["purl"]),
            }]
        packages.append(package)
        relationships.append({
            "spdxElementId": root_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": package_id,
        })

    document = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": SPDX_DATA_LICENSE,
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"shakerscan-model-intake-{root.get('name') or 'model'}",
        "documentNamespace": f"https://shakerscan.invalid/spdx/{_digest(cyclonedx)[:32]}",
        "creationInfo": {
            "created": created_at,
            "creators": ["Tool: ShakerScan-model-intake-1", "Organization: ShakerScan"],
        },
        "comment": (
            f"License evidence: {license_display['summary']} "
            f"Evidence SHA-256: {compliance.get('evidence_sha256') or 'not available'}."
        ),
        "packages": packages,
        "relationships": relationships,
    }
    return document


def build_model_intake_license_bom(scan_result: Any, *, scan_id: str = "") -> dict[str, Any]:
    """Build a concise, evidence-bound license inventory for engineering review."""
    model_intake = _object(_object(scan_result).get("model_intake"))
    if not model_intake:
        raise ValueError("scan result does not contain Model Intake evidence")
    summary = _object(model_intake.get("summary"))
    compliance = _license_compliance(model_intake)
    if not compliance:
        raise ValueError("scan result does not contain reconciled license evidence")
    terms = _license_terms(model_intake)
    components: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in terms:
        key = (
            str(item.get("scope") or "unknown"),
            str(item.get("component") or item.get("path") or summary.get("artifact_name") or "model"),
            _display_license_term(item.get("declared")) or "UNKNOWN",
            str(item.get("source") or "unknown"),
        )
        if key in seen:
            continue
        seen.add(key)
        components.append({
            "scope": key[0],
            "name": key[1],
            "license": key[2],
            "classification": str(item.get("classification") or "unknown"),
            "source": key[3],
            "path": item.get("path"),
            "evidence_sha256": item.get("evidence_sha256") or item.get("sha256"),
            "copyright_notices": item.get("copyright_notices") or [],
        })
    unresolved = [
        {
            "code": str(item.get("code") or "review_required"),
            "summary": str(item.get("summary") or "Review is required."),
            "owner": "Licensing / open-source program office",
        }
        for item in compliance.get("reasons") or [] if isinstance(item, dict)
    ]
    display = model_intake_license_display(compliance)
    document = {
        "schema_version": "shakerscan-license-bom/v3",
        "scan_id": str(scan_id),
        "subject": {
            "name": summary.get("artifact_name"),
            "reference": summary.get("artifact_ref"),
            "sha256": summary.get("sha256"),
        },
        "decision": {
            "status": display["status"],
            "summary": display["summary"],
            "follow_up_required": display["follow_up_required"],
            "review_required": display["review_required"],
            "policy_status": compliance.get("policy_status"),
        },
        "policy_evidence": {
            "policy_version": compliance.get("policy_version"),
            "raw_outcome": compliance.get("outcome"),
            "reason_codes": [
                str(item.get("code") or "") for item in compliance.get("reasons") or []
                if isinstance(item, dict) and item.get("code")
            ],
            "reasons": compliance.get("reasons") or [],
        },
        "components": components,
        "classification_counts": compliance.get("classification_counts") or {},
        "obligations": compliance.get("obligations") or [],
        "evidence_search": compliance.get("evidence_sources") or [],
        "missing_evidence": compliance.get("missing_evidence") or [],
        "unresolved_items": unresolved,
        "engineering_summary": {
            "component_terms_identified": len(components),
            "license_or_notice_files_found": sum(
                int(item.get("files_discovered") or 0)
                for item in compliance.get("evidence_sources") or []
                if isinstance(item, dict) and item.get("source") == "native_license_files"
            ),
            "trivy_license_items_found": sum(
                int(item.get("items_found") or 0)
                for item in compliance.get("evidence_sources") or []
                if isinstance(item, dict) and item.get("source") == "trivy_full_license_scan"
            ),
            "notice_draft_generated": bool(components),
            "source_text_complete": not bool(compliance.get("missing_evidence")),
        },
        "limitations": [
            "The inventory records discovered declarations; it does not select a final LicenseConcluded value.",
            "When source files are present, exact license and NOTICE text should be copied from the digest-bound paths listed here.",
            "Dataset or intended-use terms appear only when the scanned revision publishes evidence for them.",
        ],
        "evidence_sha256": compliance.get("evidence_sha256"),
    }
    document["document_sha256"] = _digest(document)
    return document


def render_third_party_notices_draft(scan_result: Any, *, scan_id: str = "") -> str:
    """Render a bounded notice draft without inventing absent license text."""
    bom = build_model_intake_license_bom(scan_result, scan_id=scan_id)

    def line(value: Any) -> str:
        return re.sub(r"[\r\n]+", " ", str(value or "")).strip()

    subject = _object(bom.get("subject"))
    decision = _object(bom.get("decision"))
    output = [
        "THIRD-PARTY NOTICES — REVIEW DRAFT",
        "",
        f"Model: {line(subject.get('name')) or 'unknown'}",
        f"Reference: {line(subject.get('reference')) or 'unknown'}",
        f"SHA-256: {line(subject.get('sha256')) or 'not available'}",
        f"License evidence: {line(decision.get('summary')) or 'not assessed'}",
        "",
        "HOW TO USE THIS DRAFT",
        "This file lists terms detected in the scanned revision. Where source text is missing, obtain it from the publisher before distributing the model.",
        "",
        "DETECTED COMPONENTS AND TERMS",
    ]
    components = bom.get("components") if isinstance(bom.get("components"), list) else []
    if components:
        for item in components:
            output.append(
                f"- {line(item.get('name')) or 'unnamed'} — {line(item.get('license')) or 'UNKNOWN'} "
                f"[{line(item.get('classification')) or 'unknown'}; {line(item.get('source')) or 'unknown source'}]"
            )
            if item.get("path") or item.get("evidence_sha256"):
                output.append(
                    f"  Evidence: {line(item.get('path')) or 'no path'}; SHA-256 {line(item.get('evidence_sha256')) or 'not available'}"
                )
            for notice in item.get("copyright_notices") or []:
                output.append(f"  Attribution: {line(notice)}")
    else:
        output.append("- No component license evidence was recorded. Re-run a complete review or supply the missing declarations.")
    output.extend(["", "OBLIGATIONS TO VERIFY"])
    obligations = bom.get("obligations") if isinstance(bom.get("obligations"), list) else []
    output.extend(f"- {line(item)}" for item in obligations)
    if not obligations:
        output.append("- No automated obligations were identified; this does not mean no obligations exist.")
    output.extend(["", "OPEN ITEMS"])
    reasons = bom.get("unresolved_items") if isinstance(bom.get("unresolved_items"), list) else []
    output.extend(f"- {line(item.get('summary'))}" for item in reasons if isinstance(item, dict))
    if not reasons:
        output.append(
            "- Publisher terms were found; missing source material is listed below."
            if bom.get("missing_evidence")
            else "- No policy issue was detected in the available terms."
        )
    output.extend(["", "EVIDENCE SEARCH PERFORMED"])
    for item in bom.get("evidence_search") or []:
        output.append(
            f"- {line(item.get('source'))}: {line(item.get('status'))}; "
            f"items/files found: {line(item.get('items_found') if item.get('items_found') is not None else item.get('files_discovered')) or '0'}"
        )
    missing = bom.get("missing_evidence") if isinstance(bom.get("missing_evidence"), list) else []
    if missing:
        output.extend(["", "MISSING SOURCE MATERIAL"])
        output.extend(f"- {line(item).replace('_', ' ')}" for item in missing)
    output.extend(["", f"Evidence receipt: scan {line(scan_id) or 'not available'}; document SHA-256 {line(bom.get('document_sha256'))}", "", "END OF DRAFT", ""])
    return "\n".join(output)


__all__ = [
    "CYCLONEDX_SPEC_VERSION",
    "SPDX_DATA_LICENSE",
    "SPDX_VERSION",
    "build_model_intake_cyclonedx",
    "build_model_intake_license_bom",
    "build_model_intake_spdx",
    "model_intake_bom_completeness",
    "model_intake_license_display",
    "render_third_party_notices_draft",
]
