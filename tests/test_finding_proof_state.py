"""Single proof-state per finding so list and detail agree (docs §7).

An unproven High/Critical must render as "suspected" (a lead), and a
deterministically-proven finding as verified — both driven by ONE server-derived
field so the findings list and detail page can never disagree.
"""

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

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

    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.Header = lambda default=None, **k: default
    fastapi_mod.HTTPException = type("_HTTPExc", (Exception,), {})
    fastapi_mod.Query = lambda default=None, **k: default
    fastapi_mod.Request = type("_Req", (), {"__init__": lambda self, **k: None})
    sys.modules["fastapi"] = fastapi_mod
    cors_mod = types.ModuleType("fastapi.middleware.cors")
    cors_mod.CORSMiddleware = type("_CORS", (), {})
    sys.modules["fastapi.middleware"] = types.ModuleType("fastapi.middleware")
    sys.modules["fastapi.middleware.cors"] = cors_mod
    responses_mod = types.ModuleType("fastapi.responses")
    responses_mod.Response = type("_Resp", (), {"__init__": lambda self, **k: None})
    sys.modules["fastapi.responses"] = responses_mod

from tests.api_import_stubs import install_fastapi_exception_stubs  # noqa: E402

install_fastapi_exception_stubs()
import api as api_module  # noqa: E402

pf = api_module.finding_proof_fields


def test_exploited_verdict_is_verified():
    r = pf({"severity": "high", "last_verification_verdict": "exploited"})
    assert r["is_verified"] is True
    assert r["is_suspected"] is False
    assert r["proof_state"] == "verified"


def test_scan_time_generic_verified_flag_is_suspected():
    r = pf({"severity": "critical", "verified": True})
    assert r["is_verified"] is False
    assert r["is_suspected"] is True
    assert r["proof_state"] == "suspected"


def test_scan_time_typed_proof_is_verified():
    r = pf({"severity": "critical", "proof_of_exploitation": True})
    assert r["is_verified"] is True
    assert r["is_suspected"] is False
    assert r["proof_state"] == "verified"


def test_failed_browser_proof_is_not_verified():
    r = pf({"severity": "critical", "verified": True, "browser_proof": {"proven": False}})
    assert r["is_verified"] is False
    assert r["proof_state"] == "suspected"


def test_proven_browser_proof_is_verified():
    r = pf({"severity": "high", "browser_proof": {
        "proven": True,
        "confidence": 0.99,
        "proof_producer": "shakerscan",
        "evidence_type": "dom_execution",
        "technique": "headless_xss_dialog",
    }})
    assert r["is_verified"] is True
    assert r["proof_state"] == "verified"


def test_unproven_high_is_suspected():
    r = pf({"severity": "high", "last_verification_verdict": "inconclusive"})
    assert r["is_verified"] is False
    assert r["is_suspected"] is True
    assert r["proof_state"] == "suspected"


def test_unproven_critical_is_suspected():
    r = pf({"severity": "critical"})
    assert r["is_suspected"] is True
    assert r["proof_state"] == "suspected"


def test_unproven_medium_is_not_suspected():
    # Only High/Critical leads are the trust problem; medium/low are not "suspected".
    r = pf({"severity": "medium"})
    assert r["is_suspected"] is False
    assert r["proof_state"] == "unverified"


def test_blocked_verdict_high_is_suspected_not_verified():
    # blocked_by_security is not deterministic proof of exploitation.
    r = pf({"severity": "high", "last_verification_verdict": "blocked_by_security"})
    assert r["is_verified"] is False
    assert r["proof_state"] == "suspected"
