"""GET /findings severity and proof filters, and the fix guidance on a finding.

Compatibility import layout, like tests/test_finding_proof_state.py: the findings router runs on
the flat runtime path, so it is reached through the api module that composes it.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

import pytest

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

findings_router = sys.modules["finding_routes.router"]
from capabilities import exposure_probe  # noqa: E402
from finding_routes.list_filters import PROOF_FILTER_MAX_ROWS, parse_choice_list  # noqa: E402
from finding_routes.remediation import finding_remediation  # noqa: E402



class HTTPException(Exception):
    """Stands in for fastapi's, which the import stubs replace with one that takes no arguments."""

    def __init__(self, status_code=None, detail=None, headers=None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class _Request:
    def __init__(self, **params):
        self.query_params = params


class _Conn:
    def __init__(self, rows):
        self.rows = rows
        self.queries: list[tuple[str, tuple]] = []

    async def fetch(self, query, *args):
        self.queries.append((query, args))
        return [dict(row) for row in self.rows]

    async def fetchval(self, query, *args):
        return len(self.rows)


def _list(monkeypatch, rows, **params):
    conn = _Conn(rows)

    class _Pool:
        @asynccontextmanager
        async def acquire(self):
            yield conn

    monkeypatch.setattr(findings_router, "_pool", lambda: _Pool())
    monkeypatch.setattr(findings_router, "HTTPException", HTTPException)
    defaults = dict(severity=None, status=None, source_type=None, target_id=None, ai_target_id=None,
                    device_target_id=None, scan_id=None, hunt_id=None, root_domain=None,
                    verification_verdict=None, verification_mode=None, verified_only=False,
                    proof_state=None, driven_by=None, research_campaign_id=None, search=None,
                    seen_within_days=None, not_seen_within_days=None, first_seen_within_days=None,
                    resolved_within_days=None, sort_by=None, sort_order="desc",
                    include_candidates=False, limit=100, offset=0, include_details=False)
    defaults.update(params)
    request = _Request(**{key: value for key, value in params.items() if value not in (None, False)})
    result = asyncio.run(findings_router.list_findings(request, **defaults))
    return result, conn


def _row(identifier, severity, **fields):
    row = {"id": identifier, "title": f"finding {identifier}", "severity": severity, "status": "active",
           "evidence": None, "last_verification_verdict": None, "latest_retest_mode": None, "total_count": 3}
    row.update(fields)
    return row


def test_severity_takes_several_values_and_refuses_unknown_ones(monkeypatch):
    _, conn = _list(monkeypatch, [], severity="critical,HIGH,critical")
    query, args = conn.queries[0]
    assert "f.severity = ANY($1::text[])" in query
    assert args[0] == ["critical", "high"]
    with pytest.raises(HTTPException) as refused:
        _list(monkeypatch, [], severity="critical,severe")
    assert refused.value.status_code == 400 and "'severe'" in refused.value.detail


def test_the_proof_filter_returns_exactly_what_the_badge_says_and_paginates(monkeypatch):
    rows = [
        # Proven by a deterministic retest, exactly as finding_proof_fields decides it.
        _row("a", "high", last_verification_verdict="exploited", latest_retest_mode="deterministic"),
        # An AI verdict is not proof: suspected.
        _row("b", "critical", last_verification_verdict="exploited", latest_retest_mode="ai_driven"),
        _row("c", "medium"),
        _row("d", "high", last_verification_verdict="exploited", latest_retest_mode="deterministic"),
    ]
    proven, conn = _list(monkeypatch, rows, proof_state="verified", limit=1, offset=1)
    assert proven["total"] == 2
    assert [item["id"] for item in proven["findings"]] == ["d"]
    assert proven["findings"][0]["proof_state"] == "verified"
    # Every row the other filters leave is read; the page is cut after projection.
    query, args = conn.queries[0]
    assert "OFFSET" not in query and args[-1] == PROOF_FILTER_MAX_ROWS + 1
    leads, _ = _list(monkeypatch, rows, proof_state="suspected,unverified")
    assert [(item["id"], item["proof_state"]) for item in leads["findings"]] == [("b", "suspected"), ("c", "unverified")]


def test_the_proof_filter_refuses_rather_than_sampling(monkeypatch):
    monkeypatch.setattr(findings_router, "PROOF_FILTER_MAX_ROWS", 2)
    with pytest.raises(HTTPException) as refused:
        _list(monkeypatch, [_row(str(n), "low") for n in range(3)], proof_state="verified")
    assert refused.value.status_code == 422 and "Narrow the list" in refused.value.detail


def test_a_proof_filter_never_mixes_in_hunt_candidates(monkeypatch):
    result, conn = _list(monkeypatch, [], proof_state="verified", include_candidates=True)
    assert len(conn.queries) == 1
    assert result["candidates_total"] == 0


def test_choice_lists_parse_blank_as_no_filter():
    assert parse_choice_list(None, ("a",), "x") is None
    assert parse_choice_list(" , ", ("a",), "x") is None
    assert parse_choice_list("A, a", ("a",), "x") == ["a"]


# --- Fix guidance -------------------------------------------------------------------------------

def test_every_exposure_the_prover_promotes_has_class_guidance():
    promotable = [name for name in exposure_probe._CLASS_SEVERITY if exposure_probe.is_sensitive_exposure_class(name)]
    assert promotable, "the prover's promotable classes moved"
    for exposure_class in promotable:
        guidance = finding_remediation({"title": "anything", "evidence": {"exposure_class": exposure_class}})
        assert guidance and guidance["matched_by"] == "exposure_class" and guidance["steps"], exposure_class


def test_guidance_prefers_the_exposure_class_over_title_words():
    # The heap dump is classified environment_secret_file; its title says nothing a keyword knows.
    guidance = finding_remediation({
        "title": "Sensitive exposure: environment secret file",
        "evidence": json.dumps({"exposure_class": "environment_secret_file"}),
    })
    assert guidance["title"] == "Publicly Served File Containing Secrets"
    assert any("Rotate every secret" in step for step in guidance["steps"])
    assert {example["label"] for example in guidance["code_examples"]} >= {"nginx", "apache"}


def test_title_matches_are_labelled_and_unknown_findings_get_none():
    csp = finding_remediation({"title": "Missing HTTP response header: Content-Security-Policy"})
    assert csp["matched_by"] == "title" and "Content Security Policy" in csp["title"]
    assert finding_remediation({"title": "PII or credential pattern in response"}) is None


def test_a_path_in_the_title_does_not_choose_the_guidance():
    cors = finding_remediation({"title": "CORS allows credentialed cross-origin reads: /api/openapi.json"})
    assert cors["title"] == "CORS Misconfiguration"
    assert finding_remediation({"title": "JWT / bearer token exposed in response: /api/openapi.json"}) is None


def test_a_weak_policy_is_not_reported_as_a_missing_one():
    for title in ("CSP: style-src allows 'unsafe-inline'.", "CSP: script-src allows 'unsafe-eval'.",
                  "CSP: Trusted Types not required (optional)."):
        assert finding_remediation({"title": title})["title"] == "Content Security Policy Allows Unsafe Sources", title
    assert "Not Configured" in finding_remediation({"title": "CSP header missing"})["title"]
