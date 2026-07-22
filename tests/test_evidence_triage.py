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
