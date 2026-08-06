from scanner.scanner_tools.model_intake_licenses import (
    build_corporate_license_assessment,
    classify_license_expression,
)


def _result(name, summary):
    return {"scanner": {"name": name}, "summary": summary}


def test_classifier_routes_custom_reciprocal_and_use_dependent_terms():
    assert classify_license_expression("MIT OR Apache-2.0")["classification"] == "permissive"
    assert classify_license_expression("GPL-3.0-only")["classification"] == "reciprocal"
    assert classify_license_expression("vendor custom license")["classification"] == "custom"
    assert classify_license_expression("BigScience OpenRAIL-M")["classification"] == "use_case_dependent"
    assert classify_license_expression("research only non-commercial")["classification"] == "restricted"


def test_permissive_reconciled_terms_have_no_detected_legal_blocker():
    assessment = build_corporate_license_assessment(
        declared_license="Apache-2.0",
        generated_results=[
            _result("shakerscan-license-inventory", {"licenses": [{
                "path": "LICENSE", "sha256": "a" * 64, "spdx_candidates": ["Apache-2.0"],
            }]}),
            _result("trivy", {"license_inventory": [{
                "license": "MIT", "classification": "permissive", "package": "tokenizers",
            }]}),
        ],
    )

    assert assessment["outcome"] == "NO LEGAL BLOCKER DETECTED"
    assert assessment["policy_status"] == "PASS"
    assert assessment["legal_review_required"] is False
    assert assessment["component_count"] == 1
    assert len(assessment["evidence_sha256"]) == 64


def test_unknown_custom_reciprocal_dataset_or_use_terms_require_legal_review():
    scenarios = [
        {"declared_license": "LicenseRef-Acme"},
        {"declared_license": "GPL-3.0-only"},
        {"declared_license": "MIT", "training_data_ref": ["dataset/acme"]},
        {"declared_license": "MIT", "deployment_restrictions": ["internal-only"]},
        {"declared_license": "Mystery-1.0"},
    ]
    for scenario in scenarios:
        assessment = build_corporate_license_assessment(generated_results=[], **scenario)
        assert assessment["outcome"] == "LEGAL REVIEW REQUIRED"
        assert assessment["policy_status"] == "REVIEW_REQUIRED"
        assert assessment["legal_review_required"] is True


def test_restricted_or_forbidden_terms_block_policy():
    assessment = build_corporate_license_assessment(
        declared_license="MIT",
        generated_results=[_result("trivy", {"license_inventory": [{
            "license": "Proprietary", "classification": "forbidden",
        }]})],
    )

    assert assessment["outcome"] == "BLOCKED BY LICENSE POLICY"
    assert assessment["policy_status"] == "BLOCK"


def test_declared_and_repository_license_mismatch_requires_legal_review():
    assessment = build_corporate_license_assessment(
        declared_license="MIT",
        generated_results=[_result("shakerscan-license-inventory", {"licenses": [{
            "path": "LICENSE", "sha256": "b" * 64, "spdx_candidates": ["Apache-2.0"],
        }]})],
    )

    assert assessment["outcome"] == "LEGAL REVIEW REQUIRED"
    assert "declared_repository_license_mismatch" in {item["code"] for item in assessment["reasons"]}
