"""GET /findings/{id} says whether a finding can be retested, why not, and whether it is active.

A finding whose tool names no prover of its kind of check is not retested, whether or not an AI
verifier is configured: the AI tier can never mark it fixed, so offering it only as an AI retest
was a button that could not conclude. ``retest_active`` says whether the retest may send active
requests (a prover's payloads, or the AI tier's own requests). Rows are unit fixtures.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import sys
import uuid

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import finding_routes.router as findings_router  # noqa: E402

FINDING = uuid.UUID("66666666-6666-4666-8666-666666666666")
AI_READY = {"ai_verify_enabled": True, "ai_url": "https://ai.fixture.invalid", "ai_api_key": "k"}


def _row(tool: str, title: str, **extra) -> dict:
    return {
        "id": FINDING, "title": title, "severity": "high", "tool": tool, "status": "active",
        "target_id": None, "target_url": "https://app.fixture.invalid",
        "url": "https://app.fixture.invalid/search?q=1", "source": "dast", "evidence": {},
        **extra,
    }


def _install(monkeypatch, row: dict, ai: dict) -> None:
    @asynccontextmanager
    async def acquire():
        yield object()

    class _Pool:
        def acquire(self):
            return acquire()

    async def record(_conn, _finding_id):
        return dict(row)

    async def no_exposures(_conn, _finding):
        return []

    monkeypatch.setattr(findings_router, "_pool_provider", lambda: _Pool())
    monkeypatch.setattr(findings_router, "get_finding_record", record)
    monkeypatch.setattr(findings_router, "related_exposures", no_exposures)
    monkeypatch.setattr(findings_router, "_load_effective_ai_settings", lambda: dict(ai))


def _hints(monkeypatch, row: dict, *, ai: dict | None = None) -> dict:
    _install(monkeypatch, row, ai or {})
    result = asyncio.run(findings_router.get_finding(str(FINDING)))
    return {key: result.get(key) for key in (
        "retest_supported", "retest_type", "retest_modes", "retest_unsupported_reason", "retest_active",
    )}


@pytest.mark.parametrize("ai", [{}, AI_READY])
@pytest.mark.parametrize("tool,title,reason", [
    ("nuclei", "Apache 2.4.49 - Path Traversal and Remote Code Execution", "retest_needs_template_replay"),
    ("nuclei", "SSL/SSH/TLS/JWT Keys - Detect", "retest_needs_template_replay"),
    ("shakerscan_exposure_probe", "Sensitive exposure: backup or source artifact", "retest_exposure_by_rescan"),
    ("http_baseline", "CORS policy trusts the null origin", "retest_by_rescan_only"),
    ("tls.inspect", "Weak TLS cipher negotiated", "retest_by_rescan_only"),
])
def test_a_finding_without_its_own_prover_is_not_retested(monkeypatch, ai, tool, title, reason):
    assert _hints(monkeypatch, _row(tool, title), ai=ai) == {
        "retest_supported": False, "retest_type": None, "retest_modes": [],
        "retest_unsupported_reason": reason, "retest_active": False,
    }


@pytest.mark.parametrize("ai", [{}, AI_READY])
def test_an_xss_retest_sends_active_requests(monkeypatch, ai):
    hints = _hints(monkeypatch, _row("shakerscan_browser_proof", "Verified cross-site scripting"), ai=ai)
    assert hints["retest_supported"] is True and hints["retest_type"] == "xss"
    assert hints["retest_active"] is True and hints["retest_unsupported_reason"] is None


def test_an_exposed_file_retest_is_active_only_when_the_ai_tier_can_run(monkeypatch):
    row = _row("exposed_files", "Exposed file: /.git/config")
    plain = _hints(monkeypatch, row)
    assert plain["retest_type"] == "exposed_file" and plain["retest_active"] is False
    # Its prover only re-fetches the file; the AI tier, when configured, may send requests of
    # its own choosing.
    assert _hints(monkeypatch, row, ai=AI_READY)["retest_active"] is True


def test_device_ai_gate_and_model_intake_findings_say_whether_they_are_active(monkeypatch):
    device = _hints(monkeypatch, _row("device_candidate_verifier", "x", source="device"))
    assert device["retest_supported"] is False and device["retest_active"] is False
    gate = _hints(monkeypatch, _row("shaker-ai-gate", "x", source="ai_gate"))
    assert gate["retest_supported"] is True and gate["retest_active"] is True
    intake = _hints(monkeypatch, _row("model_intake", "x"))
    assert intake["retest_unsupported_reason"] == "model_intake" and intake["retest_active"] is False


class _Redis:
    def ping(self):
        return True


def test_a_retest_request_for_a_finding_without_its_own_prover_is_refused(monkeypatch):
    # With an AI verifier configured the route used to queue an AI-only retest instead.
    _install(monkeypatch, _row("nuclei", "Apache 2.4.49 - Path Traversal and Remote Code Execution"), AI_READY)
    monkeypatch.setattr(findings_router, "get_redis", lambda: _Redis())

    async def never(*_args, **_kwargs):
        raise AssertionError("nothing is queued")

    monkeypatch.setattr(findings_router, "enqueue_finding_retest", never)
    monkeypatch.setattr(findings_router, "_validate_approval_receipt_for_action", never)
    for mode in (None, "ai"):
        with pytest.raises(HTTPException) as refused:
            asyncio.run(findings_router.retest_finding(str(FINDING), None, mode=mode))
        assert refused.value.status_code == 400
        assert refused.value.detail["error"] == "unsupported_finding_type"
        assert refused.value.detail["reason"] == "retest_needs_template_replay"
