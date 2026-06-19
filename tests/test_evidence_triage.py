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
