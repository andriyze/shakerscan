"""Stored XSS workflow proof routing."""

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner", "scanner_tools"))

from scanner_tools import active_checks as ac  # noqa: E402


def _review_endpoint():
    return {
        "url": "http://h/api/reviews",
        "method": "POST",
        "body_params": ["comment"],
        "content_type": "application/json",
    }


def test_stored_xss_browser_execution_proof_marks_verified(monkeypatch):
    submitted_payloads: list[str] = []
    proof_calls: list[dict] = []

    async def fake_run(cmd, timeout=15):
        if "-X" in cmd:
            data = cmd[cmd.index("-d") + 1]
            submitted_payloads.append(json.loads(data)["comment"])
            return '{"ok":true}', "", 0
        if cmd[-1] == "http://h/reviews":
            return f"<html><body>{submitted_payloads[-1]}</body></html>", "", 0
        return "<html></html>", "", 0

    class _Proof:
        proven = True
        confidence = 0.99
        technique = "headless_xss_dialog"
        extracted_data = "Dialog triggered: 1"

        def to_dict(self):
            return {
                "proven": True,
                "confidence": self.confidence,
                "technique": self.technique,
                "extracted_data": self.extracted_data,
            }

    async def fake_proof(**kwargs):
        proof_calls.append(kwargs)
        return _Proof()

    monkeypatch.setattr(ac, "run", fake_run)
    monkeypatch.setattr(ac, "HAS_XSS_PROOF", True)
    monkeypatch.setattr(ac, "prove_xss_headless", fake_proof)

    res = asyncio.run(ac.stored_xss_workflow(
        "http://h",
        [_review_endpoint()],
        discovered_urls=["http://h/reviews"],
    ))

    assert res["vulnerable"] is True
    finding = res["findings"][0]
    assert finding["verified"] is True
    assert finding["severity"] == "high"
    assert finding["proof_state"] == "exploited"
    assert finding["cvss_score"] == 7.4
    assert finding["browser_proof"]["proven"] is True
    assert finding["poe_result"]["proven"] is True
    assert proof_calls[0]["prebuilt_url"] == "http://h/reviews"
    assert proof_calls[0]["payload"] == submitted_payloads[0]


def test_stored_xss_marker_only_render_does_not_claim_execution(monkeypatch):
    submitted_payloads: list[str] = []
    proof_attempted = False

    async def fake_run(cmd, timeout=15):
        if "-X" in cmd:
            data = cmd[cmd.index("-d") + 1]
            submitted_payloads.append(json.loads(data)["comment"])
            return '{"ok":true}', "", 0
        if cmd[-1] == "http://h/reviews":
            escaped = submitted_payloads[-1].replace("<", "&lt;").replace(">", "&gt;")
            return f"<html><body>{escaped}</body></html>", "", 0
        return "<html></html>", "", 0

    async def fake_proof(**kwargs):
        nonlocal proof_attempted
        proof_attempted = True
        raise AssertionError("marker-only render should not invoke browser proof")

    monkeypatch.setattr(ac, "run", fake_run)
    monkeypatch.setattr(ac, "HAS_XSS_PROOF", True)
    monkeypatch.setattr(ac, "prove_xss_headless", fake_proof)

    res = asyncio.run(ac.stored_xss_workflow(
        "http://h",
        [_review_endpoint()],
        discovered_urls=["http://h/reviews"],
    ))

    assert res["vulnerable"] is True
    finding = res["findings"][0]
    assert finding["payload_reflected"] is False
    assert finding["verified"] is False
    assert finding["severity"] == "medium"
    assert finding["proof_state"] == "likely_vulnerable"
    assert "browser_proof" not in finding
    assert "poe_result" not in finding
    assert proof_attempted is False
