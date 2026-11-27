import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from evidence_triage import build_evidence_with_triage, redact_finding_evidence  # noqa: E402


def test_redact_finding_evidence_removes_nested_auth_material():
    evidence = build_evidence_with_triage({
        "evidence": {
            "request_headers": {
                "Authorization": "Bearer eyJabc123.def456.ghi789",
                "X-Test": "ok",
            },
            "body": "token=Bearer live-secret-token-12345",
            "nested": [{"Cookie": "session=secret"}],
        },
        "verified": True,
    })

    redacted = redact_finding_evidence(evidence)
    as_text = str(redacted)

    assert redacted["request_headers"]["Authorization"] == "[REDACTED]"
    assert redacted["request_headers"]["X-Test"] == "ok"
    assert redacted["nested"][0]["Cookie"] == "[REDACTED]"
    assert "eyJabc123" not in as_text
    assert "live-secret-token" not in as_text
    assert redacted["triage"]["verified"] is True


def test_build_evidence_preserves_structured_proof_contracts():
    evidence = build_evidence_with_triage({
        "evidence": {"url": "https://example.test/search"},
        "browser_proof": {
            "proven": True,
            "technique": "headless_xss_dialog",
            "request_headers": {"Authorization": "Bearer live-secret-token-12345"},
        },
        "poe_result": {"proven": True, "confidence": 0.99},
        "proof_state": "verified",
    })

    redacted = redact_finding_evidence(evidence)

    assert redacted["browser_proof"]["proven"] is True
    assert redacted["browser_proof"]["technique"] == "headless_xss_dialog"
    assert redacted["browser_proof"]["request_headers"]["Authorization"] == "[REDACTED]"
    assert redacted["poe_result"]["proven"] is True
    assert redacted["proof_state"] == "verified"


def test_build_evidence_keeps_the_checks_own_fix_guidance():
    # The findings table has no remediation column; the check's text survives only in evidence.
    assert build_evidence_with_triage({"evidence": {"a": 1}, "recommendation": "Do X"})["remediation"] == "Do X"
    assert build_evidence_with_triage({"evidence": {"a": 1}, "remediation": "Do Y"})["remediation"] == "Do Y"
    assert build_evidence_with_triage({"remediation": "Do Y", "recommendation": "Do X"})["remediation"] == "Do Y"
    # Attack chains and similar checks give a list of steps.
    assert build_evidence_with_triage({"remediation": ["a", "b"]})["remediation"] == ["a", "b"]
    # An empty value falls through to the next key.
    assert build_evidence_with_triage({"remediation": " ", "recommendation": "Do X"})["remediation"] == "Do X"
    # Lengths are bounded.
    assert len(build_evidence_with_triage({"remediation": "x" * 5000})["remediation"]) == 2000
    steps = build_evidence_with_triage({"remediation": ["y" * 900] * 30})["remediation"]
    assert len(steps) == 20 and all(len(step) == 500 for step in steps)


def test_build_evidence_does_not_fold_structured_or_overwrite_guidance():
    assert build_evidence_with_triage({"evidence": {"a": 1}, "remediation": {"x": 1}}) == {"a": 1}
    assert build_evidence_with_triage({"evidence": {"a": 1}, "remediation": ["a", {"x": 1}]}) == {"a": 1}
    assert build_evidence_with_triage({"evidence": {"a": 1}, "remediation": []}) == {"a": 1}
    assert build_evidence_with_triage({"remediation": None}) is None
    kept = build_evidence_with_triage({"evidence": {"remediation": "From evidence"}, "recommendation": "Top level"})
    assert kept["remediation"] == "From evidence"
