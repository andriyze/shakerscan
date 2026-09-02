"""Tests for finalization / result-persistence reliability (docs proposed-next-steps §1).

A terminal scan must never leave `/result` as a 404: even a hang/crash with no
recoverable checkpoint should produce a self-describing *degraded* result that
carries the termination reason and explicit `grade_reliable=false` markers so a
degraded scan cannot masquerade as a clean security result.
"""

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

# api/api.py imports asyncpg/redis/fastapi at module load; stub the ones missing
# in the test environment (mirrors tests/test_api_helpers.py).
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *a, **k: None))

if "fastapi" not in sys.modules:
    fastapi_mod = types.ModuleType("fastapi")

    class _FakeFastAPI:
        def __init__(self, *a, **k):
            pass

        def add_middleware(self, *a, **k):
            return None

        def _decorator(self, *a, **k):
            def wrapper(fn):
                return fn
            return wrapper

        get = post = patch = put = delete = on_event = _decorator

    class _FakeHTTPException(Exception):
        def __init__(self, status_code: int = 500, detail=None, headers=None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail
            self.headers = headers

    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.Header = lambda default=None, **k: default
    fastapi_mod.HTTPException = _FakeHTTPException
    fastapi_mod.Query = lambda default=None, **k: default
    fastapi_mod.Request = type("_Req", (), {"__init__": lambda self, **k: None})
    sys.modules["fastapi"] = fastapi_mod

    cors_mod = types.ModuleType("fastapi.middleware.cors")
    cors_mod.CORSMiddleware = type("_CORS", (), {})
    sys.modules["fastapi.middleware"] = types.ModuleType("fastapi.middleware")
    sys.modules["fastapi.middleware.cors"] = cors_mod

    responses_mod = types.ModuleType("fastapi.responses")
    responses_mod.Response = type(
        "_Resp", (), {"__init__": lambda self, content=None, status_code=200, headers=None: None}
    )
    sys.modules["fastapi.responses"] = responses_mod

from tests.api_import_stubs import install_fastapi_exception_stubs  # noqa: E402

install_fastapi_exception_stubs()
import api as api_module  # noqa: E402


def test_degraded_result_is_self_describing_and_never_clean():
    r = api_module.synthesize_degraded_result(
        target_url="https://example.com",
        scan_type="standard",
        status="failed",
        phase="finalizing",
        progress=97,
        error_message="Scan terminated: Exceeded max duration (77 min > 45 min)",
    )
    # Must be a usable result dict (so /result returns 200, not 404).
    assert isinstance(r, dict)
    assert r["findings"] == []
    # A degraded scan can never look like a clean security result.
    assert r["degraded"] is True
    assert r["result"]["score_policy"] == "degraded_terminal/v1"
    assert r["result"]["grade_reliable"] is False
    meta = r["scan_metadata"]
    assert meta["degraded"] is True
    assert meta["grade_reliable"] is False
    assert meta["status"] == "failed"
    assert meta["terminated_at_phase"] == "finalizing"
    assert meta["progress_at_termination"] == 97
    # The reason is surfaced at the top of the report, not buried.
    assert "Exceeded max duration" in meta["finalization_error"]
    assert "Exceeded max duration" in r["result"]["summary"]


def test_degraded_result_preserves_recovered_findings_and_marks_partial():
    findings = [{"title": "SQLi", "severity": "critical"}]
    r = api_module.synthesize_degraded_result(
        scan_type="smart",
        status="completed",
        phase="finalizing",
        progress=97,
        error_message="finalize tail crashed",
        findings=findings,
    )
    assert r["findings"] == findings
    # With recovered findings it is a partial; without, it is just degraded.
    assert r["scan_metadata"]["partial"] is True
    empty = api_module.synthesize_degraded_result(status="failed", error_message="hang")
    assert empty["scan_metadata"]["partial"] is False


def test_degraded_result_long_reason_is_truncated_single_line():
    long_msg = "boom\n" + ("x" * 5000)
    r = api_module.synthesize_degraded_result(status="failed", error_message=long_msg)
    reason = r["scan_metadata"]["finalization_error"]
    assert "\n" not in reason
    assert len(reason) <= 300
    assert reason.startswith("boom")
