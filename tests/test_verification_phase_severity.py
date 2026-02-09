import asyncio
import sys
import types

from scanner.scanner_tools import verification_phase as vp


def test_verify_findings_respects_min_severity(monkeypatch):
    calls: list[str] = []

    async def fake_verify_xss_finding(finding, prove_xss_headless, max_attempts=3):
        calls.append(str(finding.get("id")))
        updated = dict(finding)
        updated["verification_attempted"] = True
        return updated

    # Ensure import guard in verify_high_severity_findings enables the XSS branch.
    fake_proof_module = types.SimpleNamespace(prove_xss_headless=object())
    monkeypatch.setitem(sys.modules, "scanner.scanner_tools.proof_of_exploit", fake_proof_module)
    monkeypatch.setitem(sys.modules, "scanner_tools.proof_of_exploit", fake_proof_module)
    monkeypatch.setattr(vp, "_verify_xss_finding", fake_verify_xss_finding)

    findings = [
        {"id": "high-xss", "type": "xss", "severity": "high", "url": "https://example.com", "param": "q", "payload": "x"},
        {"id": "medium-xss", "type": "xss", "severity": "medium", "url": "https://example.com", "param": "q", "payload": "x"},
        {"id": "low-xss", "type": "xss", "severity": "low", "url": "https://example.com", "param": "q", "payload": "x"},
    ]

    asyncio.run(
        vp.verify_high_severity_findings(
            findings=findings,
            verify_xss=True,
            verify_sqli=False,
            min_severity="high",
        )
    )
    assert calls == ["high-xss"]

    calls.clear()
    asyncio.run(
        vp.verify_high_severity_findings(
            findings=findings,
            verify_xss=True,
            verify_sqli=False,
            min_severity="medium",
        )
    )
    assert calls == ["high-xss", "medium-xss"]


def test_normalize_min_severity_defaults_to_high():
    assert vp._normalize_min_severity(None) == "high"
    assert vp._normalize_min_severity("invalid") == "high"
    assert vp._normalize_min_severity("medium") == "medium"
