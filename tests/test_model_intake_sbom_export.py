"""The exportable bill of materials is composed from recorded scan evidence."""

import json
import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from model_intake_sbom import (  # noqa: E402
    build_model_intake_cyclonedx,
    build_model_intake_license_bom,
    model_intake_bom_completeness,
    render_third_party_notices_draft,
)


def _scan_result(*, with_generated_sbom=True, sha256="a" * 64):
    generated = {
        "results": [{
            "scanner": {"name": "shakerscan-sbom"},
            "summary": {"sbom": {"components": [
                {"type": "library", "name": "transformers", "version": "4.44.0",
                 "purl": "pkg:pypi/transformers@4.44.0"},
                {"type": "library", "name": "torch", "version": "2.4.0",
                 "purl": "pkg:pypi/torch@2.4.0"},
            ]}},
        }]
    } if with_generated_sbom else {"results": []}
    return {"model_intake": {
        "summary": {
            "artifact_name": "model.safetensors",
            "artifact_ref": "hf://nomic-ai/CodeRankEmbed",
            "checksum_status": "verified",
            "acquisition_complete": True,
        },
        "artifact": {"name": "model.safetensors", "fetch": {"sha256": sha256}},
        "supply_chain": {
            "license_policy": {"declared": "apache-2.0"},
            "license_compliance": {
                "outcome": "LEGAL REVIEW REQUIRED",
                "policy_status": "REVIEW_REQUIRED",
                "policy_version": "shakerscan-corporate-license-policy/1",
                "legal_review_required": True,
                "evidence_sha256": "e" * 64,
                "classification_counts": {"permissive": 2, "unknown": 1},
                "reasons": [{"code": "dataset_terms_require_review", "summary": "Dataset terms require review."}],
                "obligations": ["Preserve applicable license and NOTICE material."],
                "terms": [
                    {"scope": "model", "source": "publisher_declaration", "declared": "Apache-2.0", "classification": "permissive", "tokens": ["apache-2.0"]},
                    {"scope": "dependency", "source": "trivy", "component": "transformers", "declared": "Apache-2.0", "classification": "permissive", "tokens": ["apache-2.0"], "evidence_sha256": "c" * 64},
                    {"scope": "dataset", "source": "publisher_declaration", "component": "internal-approved:v1", "declared": None, "classification": "unknown", "tokens": []},
                ],
            },
        },
        "aibom": {"components": [
            {"type": "model_artifact", "name": "model.safetensors",
             "ref": "hf://nomic-ai/CodeRankEmbed",
             "hashes": [{"alg": "SHA-256", "content": sha256}],
             "licenses": ["apache-2.0"]},
            {"type": "base_model", "name": "nomic-ai/nomic-bert-2048"},
            {"type": "tokenizer", "name": "tokenizer.json"},
            {"type": "dataset", "name": "internal-approved:v1"},
        ]},
        "generated_evidence": generated,
    }}


def test_export_is_conformant_cyclonedx_rooted_on_the_scanned_model():
    document = build_model_intake_cyclonedx(_scan_result(), scan_id="s-1")

    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["serialNumber"].startswith("urn:uuid:")

    root = document["metadata"]["component"]
    assert root["type"] == "machine-learning-model"
    assert root["hashes"] == [{"alg": "SHA-256", "content": "a" * 64}]

    names = {component["name"] for component in document["components"]}
    # Dependencies from the generated adapter and model facts from the AIBOM.
    assert {"transformers", "torch", "nomic-ai/nomic-bert-2048", "tokenizer.json"} <= names
    # Every component carries a bom-ref, which CycloneDX consumers rely on.
    assert all(component.get("bom-ref") for component in document["components"])
    # The subject itself is the root, never duplicated into the component list.
    assert root["bom-ref"] not in {component["bom-ref"] for component in document["components"]}


def test_export_is_deterministic_for_the_same_evidence():
    first = build_model_intake_cyclonedx(_scan_result(), scan_id="s-1")
    second = build_model_intake_cyclonedx(_scan_result(), scan_id="s-1")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    # A different subject must not reuse the same serial number.
    other = build_model_intake_cyclonedx(_scan_result(sha256="b" * 64), scan_id="s-1")
    assert other["serialNumber"] != first["serialNumber"]


def test_a_quick_scan_says_it_has_no_dependency_inventory():
    # A bounded-prefix scan never enumerates dependencies. A thin BOM must not
    # read as a complete one that happens to have few components.
    document = build_model_intake_cyclonedx(_scan_result(with_generated_sbom=False), scan_id="s-1")
    completeness = model_intake_bom_completeness(document)

    assert completeness["dependency_inventory"] == "not_generated"
    assert not any(component["name"] == "transformers" for component in document["components"])

    full = model_intake_bom_completeness(build_model_intake_cyclonedx(_scan_result(), scan_id="s-1"))
    assert full["dependency_inventory"] == "generated"
    assert full["component_count"] > completeness["component_count"]


def test_a_scan_without_model_intake_evidence_is_rejected():
    for payload in ({}, {"model_intake": {}}, {"discovery": {}}):
        try:
            build_model_intake_cyclonedx(payload)
        except ValueError as exc:
            assert "Model Intake evidence" in str(exc)
        else:
            raise AssertionError(f"{payload} should not produce a bill of materials")


def test_spdx_export_describes_the_same_components_as_cyclonedx():
    from model_intake_sbom import build_model_intake_spdx

    result = _scan_result()
    cyclonedx = build_model_intake_cyclonedx(result, scan_id="s-1")
    spdx = build_model_intake_spdx(result, scan_id="s-1", created="2026-07-31T10:00:00Z")

    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["dataLicense"] == "CC0-1.0"
    assert spdx["SPDXID"] == "SPDXRef-DOCUMENT"
    assert spdx["creationInfo"]["created"] == "2026-07-31T10:00:00Z"

    # The document describes the model, and every component is a package.
    describes = [rel for rel in spdx["relationships"] if rel["relationshipType"] == "DESCRIBES"]
    assert len(describes) == 1
    root_id = describes[0]["relatedSpdxElement"]
    assert len(spdx["packages"]) == len(cyclonedx["components"]) + 1

    depends = {rel["relatedSpdxElement"] for rel in spdx["relationships"] if rel["relationshipType"] == "DEPENDS_ON"}
    package_ids = {package["SPDXID"] for package in spdx["packages"]}
    assert depends == package_ids - {root_id}
    # Every SPDXID is well formed and unique.
    assert len(package_ids) == len(spdx["packages"])
    assert all(re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", pid) for pid in package_ids)

    purls = {
        ref["referenceLocator"]
        for package in spdx["packages"]
        for ref in package.get("externalRefs", [])
    }
    assert "pkg:pypi/transformers@4.44.0" in purls
    transformers = next(package for package in spdx["packages"] if package["name"] == "transformers")
    assert transformers["licenseDeclared"] == "Apache-2.0"
    assert transformers["licenseConcluded"] == "NOASSERTION"
    assert "pending corporate review" in transformers["licenseComments"]
    assert "LEGAL REVIEW REQUIRED" in spdx["comment"]


def test_spdx_export_is_reproducible_and_anchored_to_the_scan():
    from model_intake_sbom import build_model_intake_spdx

    first = build_model_intake_spdx(_scan_result(), scan_id="s-1", created="2026-07-31T10:00:00Z")
    second = build_model_intake_spdx(_scan_result(), scan_id="s-1", created="2026-07-31T10:00:00Z")
    # Deriving `created` from the scan rather than now() keeps downloads identical.
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["documentNamespace"] != build_model_intake_spdx(
        _scan_result(sha256="b" * 64), scan_id="s-1", created="2026-07-31T10:00:00Z"
    )["documentNamespace"]


def test_license_bom_is_concise_deduplicated_and_evidence_bound():
    document = build_model_intake_license_bom(_scan_result(), scan_id="s-1")

    assert document["schema_version"] == "shakerscan-license-bom/v1"
    assert document["decision"]["outcome"] == "LEGAL REVIEW REQUIRED"
    assert document["decision"]["legal_review_required"] is True
    assert {item["name"] for item in document["components"]} >= {"model.safetensors", "transformers"}
    assert len(document["document_sha256"]) == 64
    assert any("not legal advice" in item.lower() for item in document["limitations"])


def test_third_party_notices_draft_is_clear_about_missing_legal_completion():
    notice = render_third_party_notices_draft(_scan_result(), scan_id="s-1")

    assert notice.startswith("THIRD-PARTY NOTICES — DRAFT")
    assert "License review status: LEGAL REVIEW REQUIRED" in notice
    assert "transformers — Apache-2.0" in notice
    assert "Dataset terms require review." in notice
    assert "not legal advice or a release-ready notice file" in notice
