"""Deterministic corporate license reconciliation for Model Intake.

This module does not provide legal advice and never approves a model. It turns
recorded declarations and generated scanner evidence into a stable routing
decision: no detected blocker, legal review required, or policy blocked.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


POLICY_VERSION = "shakerscan-corporate-license-policy/1"
PERMISSIVE_IDS = {
    "0bsd", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "bsl-1.0",
    "cc0-1.0", "isc", "mit", "postgresql", "python-2.0", "unlicense", "zlib",
}
RECIPROCAL_IDS = {
    "agpl-3.0", "cddl-1.0", "epl-1.0", "epl-2.0", "gpl-2.0", "gpl-3.0",
    "lgpl-2.0", "lgpl-2.1", "lgpl-3.0", "mpl-1.1", "mpl-2.0", "osl-3.0",
}
ALIASES = {
    "apache 2.0": "apache-2.0", "apache2": "apache-2.0",
    "apache license 2.0": "apache-2.0", "bsd": "bsd-3-clause",
    "gplv2": "gpl-2.0", "gplv3": "gpl-3.0", "agplv3": "agpl-3.0",
    "lgplv3": "lgpl-3.0", "the unlicense": "unlicense", "cc-0": "cc0-1.0",
}
RESTRICTED_HINTS = (
    "non-commercial", "noncommercial", "research only", "no redistribution",
    "no commercial", "not for production", "evaluation only",
)
USE_CASE_HINTS = (
    "openrail", "llama", "responsible ai", "acceptable use", "community license",
    "use restriction", "usage restriction", "behavioral restriction",
)
TRIVY_CATEGORY_MAP = {
    "permissive": "permissive",
    "unencumbered": "permissive",
    "notice": "notice",
    "reciprocal": "reciprocal",
    "restricted": "restricted",
    "forbidden": "forbidden",
    "unknown": "unknown",
}


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _normalize(token: Any) -> str:
    value = str(token or "").strip().strip("()").lower()
    value = ALIASES.get(value, value)
    for suffix in ("-only", "-or-later", "+"):
        if value.endswith(suffix):
            return value[: -len(suffix)]
    return value


def classify_license_expression(value: Any) -> dict[str, Any]:
    """Conservatively classify an SPDX expression or publisher license label."""
    declared = str(value or "").strip()
    if not declared:
        return {"declared": value, "classification": "missing", "tokens": []}
    lowered = declared.lower()
    if any(hint in lowered for hint in RESTRICTED_HINTS):
        classification = "restricted"
    elif any(hint in lowered for hint in USE_CASE_HINTS):
        classification = "use_case_dependent"
    else:
        tokens = [
            token for token in re.split(r"\s+(?:and|or|with)\s+|[()]", declared, flags=re.I)
            if token.strip()
        ]
        normalized = [_normalize(token) for token in tokens]
        if normalized and all(token in PERMISSIVE_IDS for token in normalized):
            classification = "permissive"
        elif any(token in RECIPROCAL_IDS or token.startswith(("gpl-", "agpl-", "lgpl-")) for token in normalized):
            classification = "reciprocal"
        elif declared.startswith(("http://", "https://")) or "licenseref-" in lowered or any(char.isspace() for char in declared):
            classification = "custom"
        else:
            classification = "unknown"
        return {"declared": value, "classification": classification, "tokens": normalized}
    return {"declared": value, "classification": classification, "tokens": [_normalize(declared)]}


def _generated_result(results: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next(
        (
            item for item in results
            if isinstance(item, dict)
            and str((item.get("scanner") or {}).get("name") or "") == name
        ),
        {},
    )


def build_corporate_license_assessment(
    *,
    declared_license: Any,
    generated_results: list[dict[str, Any]],
    training_data_ref: Any = None,
    deployment_restrictions: Any = None,
) -> dict[str, Any]:
    """Reconcile model, repository, dependency, dataset, and use terms."""
    terms: list[dict[str, Any]] = []
    declared = classify_license_expression(declared_license)
    terms.append({"scope": "model", "source": "publisher_declaration", **declared})

    native = _generated_result(generated_results, "shakerscan-license-inventory")
    native_inventory = (native.get("summary") or {}).get("licenses")
    for item in native_inventory if isinstance(native_inventory, list) else []:
        if not isinstance(item, dict):
            continue
        candidates = item.get("spdx_candidates") if isinstance(item.get("spdx_candidates"), list) else []
        detected = candidates[0] if len(candidates) == 1 else None
        classified = classify_license_expression(detected)
        if not detected:
            classified = {"declared": None, "classification": "unknown", "tokens": []}
        terms.append({
            "scope": "repository_file",
            "source": "shakerscan_native",
            "path": str(item.get("path") or "")[:500] or None,
            "sha256": item.get("sha256"),
            **classified,
        })

    trivy = _generated_result(generated_results, "trivy")
    trivy_inventory = (trivy.get("summary") or {}).get("license_inventory")
    for item in trivy_inventory if isinstance(trivy_inventory, list) else []:
        if not isinstance(item, dict):
            continue
        raw_class = str(item.get("classification") or "unknown").lower()
        terms.append({
            "scope": "dependency" if item.get("package") else "repository_file",
            "source": "trivy",
            "component": str(item.get("package") or "")[:300] or None,
            "path": str(item.get("path") or "")[:500] or None,
            "declared": str(item.get("license") or "UNKNOWN")[:300],
            "classification": TRIVY_CATEGORY_MAP.get(raw_class, "unknown"),
            "tokens": [_normalize(item.get("license"))],
            "evidence_sha256": item.get("evidence_sha256"),
        })

    # Exact duplicates from native fingerprinting and Trivy full-license mode
    # are retained as separate evidence sources but do not inflate policy reasons.
    classifications = {str(item.get("classification") or "unknown") for item in terms}
    reasons: list[dict[str, str]] = []
    if declared["classification"] == "missing":
        reasons.append({"code": "model_terms_missing", "summary": "The model license was not declared."})
    for classification, code, summary in (
        ("unknown", "unknown_terms", "One or more license terms could not be identified."),
        ("custom", "custom_terms", "Custom publisher terms require legal interpretation."),
        ("reciprocal", "reciprocal_terms", "Reciprocal terms may impose source or distribution obligations."),
        ("use_case_dependent", "use_case_dependent_terms", "License permission depends on the intended use."),
    ):
        if classification in classifications:
            reasons.append({"code": code, "summary": summary})
    if training_data_ref not in (None, "", [], {}):
        reasons.append({
            "code": "dataset_terms_require_review",
            "summary": "Training or evaluation dataset terms require a separate legal lineage review.",
        })
    if deployment_restrictions not in (None, "", [], {}):
        reasons.append({
            "code": "deployment_use_restrictions",
            "summary": "Deployment restrictions make permission dependent on the corporate use case.",
        })

    repository_tokens = {
        token
        for item in terms if item.get("scope") == "repository_file"
        for token in (item.get("tokens") or [])
        if token
    }
    declared_tokens = set(declared.get("tokens") or [])
    if declared_tokens and repository_tokens and declared_tokens.isdisjoint(repository_tokens):
        reasons.append({
            "code": "declared_repository_license_mismatch",
            "summary": "The publisher declaration does not match detected repository license files.",
        })

    blocked = bool(classifications.intersection({"forbidden", "restricted"}))
    if blocked:
        policy_status = "BLOCK"
        outcome = "BLOCKED BY LICENSE POLICY"
    elif reasons:
        policy_status = "REVIEW_REQUIRED"
        outcome = "LEGAL REVIEW REQUIRED"
    else:
        policy_status = "PASS"
        outcome = "NO LEGAL BLOCKER DETECTED"

    obligations: list[str] = []
    all_tokens = {token for item in terms for token in (item.get("tokens") or []) if token}
    if all_tokens.intersection(PERMISSIVE_IDS) or "notice" in classifications:
        obligations.append("Preserve applicable copyright, license, attribution, and NOTICE material in distributions.")
    if "apache-2.0" in all_tokens:
        obligations.append("Carry forward Apache NOTICE content when the distribution includes attributable material.")
    if "reciprocal" in classifications:
        obligations.append("Determine source-offer, relinking, modification, and network-use obligations before distribution or service use.")

    counts = {
        classification: sum(1 for item in terms if item.get("classification") == classification)
        for classification in sorted(classifications)
    }
    result = {
        "schema_version": "model-intake-license-compliance/v1",
        "policy_version": POLICY_VERSION,
        "outcome": outcome,
        "policy_status": policy_status,
        "legal_review_required": policy_status == "REVIEW_REQUIRED",
        "terms": terms,
        "classification_counts": counts,
        "reasons": reasons,
        "obligations": obligations,
        "component_count": sum(1 for item in terms if item.get("component")),
        "dataset_terms_present": training_data_ref not in (None, "", [], {}),
        "use_restrictions_present": deployment_restrictions not in (None, "", [], {}),
        "disclaimer": "Automated evidence triage only; this is not legal advice or corporate legal approval.",
    }
    result["evidence_sha256"] = _digest(result)
    return result


__all__ = [
    "POLICY_VERSION",
    "build_corporate_license_assessment",
    "classify_license_expression",
]
