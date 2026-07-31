"""The exportable bill of materials is composed from recorded scan evidence."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from model_intake_sbom import (  # noqa: E402
    build_model_intake_cyclonedx,
    model_intake_bom_completeness,
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
        "supply_chain": {"license_policy": {"declared": "apache-2.0"}},
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
