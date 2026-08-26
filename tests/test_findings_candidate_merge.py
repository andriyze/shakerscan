"""Deep Hunt investigation candidates on the /findings surface.

Behavior tests exercise the pure mapping/merge helpers (no DB), and source-contract
assertions pin the endpoint wiring: which filters admit candidates, how verified
candidates stay excluded, and the dashboard lead counter. These follow the
stub-import pattern of tests/test_api_scan_option_masking.py.
"""

import os
import sys
import types
from datetime import datetime, timedelta, timezone


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

if "fastapi" not in sys.modules:
    fastapi_mod = types.ModuleType("fastapi")

    class _FakeFastAPI:
        def __init__(self, *args, **kwargs):
            pass

        def add_middleware(self, *args, **kwargs):
            return None

        def _decorator(self, *args, **kwargs):
            def wrapper(fn):
                return fn
            return wrapper

        get = post = patch = put = delete = on_event = exception_handler = _decorator

    class _FakeHTTPException(Exception):
        def __init__(self, status_code: int = 500, detail=None, headers=None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail
            self.headers = headers

    def _fake_query(default=None, **kwargs):
        return default

    class _FakeRequest:
        def __init__(self, query_params=None):
            self.query_params = query_params or {}

    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.Header = _fake_query
    fastapi_mod.HTTPException = _FakeHTTPException
    fastapi_mod.Query = _fake_query
    fastapi_mod.Request = _FakeRequest
    sys.modules["fastapi"] = fastapi_mod

    middleware_mod = types.ModuleType("fastapi.middleware")
    cors_mod = types.ModuleType("fastapi.middleware.cors")

    class _FakeCORSMiddleware:
        pass

    cors_mod.CORSMiddleware = _FakeCORSMiddleware
    sys.modules["fastapi.middleware"] = middleware_mod
    sys.modules["fastapi.middleware.cors"] = cors_mod

    responses_mod = types.ModuleType("fastapi.responses")

    class _FakeResponse:
        def __init__(self, content=None, status_code=200, headers=None, media_type=None):
            self.content = content
            self.status_code = status_code
            self.headers = headers or {}
            self.media_type = media_type

    responses_mod.Response = _FakeResponse
    responses_mod.JSONResponse = _FakeResponse
    sys.modules["fastapi.responses"] = responses_mod

from pathlib import Path

from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)

from tests.api_import_stubs import install_fastapi_exception_stubs  # noqa: E402

install_fastapi_exception_stubs()
import api as api_module  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 17, 12, 0, 0, tzinfo=timezone.utc)


def _candidate_row(**overrides):
    row = {
        "id": "11111111-1111-4111-8111-111111111111",
        "target_id": "22222222-2222-4222-8222-222222222222",
        "family": "bola",
        "canonical_locus": {"method": "GET", "route": "/api/users/1"},
        "title": "BOLA candidate",
        "claimed_severity": "high",
        "evidence_refs": ["resp_1", "resp_2"],
        "status": "new",
        "first_seen_at": NOW - timedelta(days=1),
        "last_seen_at": NOW,
        "target_url": "https://example.com",
        "target_name": "Production",
        "root_domain": "example.com",
    }
    row.update(overrides)
    return row


def test_candidate_maps_to_a_suspected_pseudo_finding():
    pseudo = api_module._candidate_to_pseudo_finding(_candidate_row())

    assert pseudo["id"] == "11111111-1111-4111-8111-111111111111"
    assert pseudo["is_candidate"] is True
    assert pseudo["source"] == "deep_hunt"
    assert pseudo["status"] == "active"
    assert pseudo["severity"] == "high"
    assert pseudo["title"] == "BOLA candidate"
    assert pseudo["url"] == "/api/users/1"
    assert pseudo["root_domain"] == "example.com"
    assert pseudo["verification_status"] == "new"
    assert pseudo["trust_tier"] == "suspected"
    assert pseudo["is_verified"] is False
    assert pseudo["is_suspected"] is True
    assert pseudo["first_seen_at"] == NOW - timedelta(days=1)
    assert pseudo["last_seen_at"] == NOW
    assert pseudo["cvss_score"] is None


def test_candidate_locus_survives_string_encoded_jsonb():
    pseudo = api_module._candidate_to_pseudo_finding(
        _candidate_row(canonical_locus='{"route": "/api/baskets/9"}')
    )

    assert pseudo["url"] == "/api/baskets/9"


def test_merge_interleaves_candidates_by_severity_and_recency():
    findings = [
        {"id": "f-high", "severity": "high", "last_seen_at": NOW - timedelta(hours=2)},
        {"id": "f-med", "severity": "medium", "last_seen_at": NOW},
    ]
    candidates = [
        api_module._candidate_to_pseudo_finding(
            _candidate_row(id="c-crit", claimed_severity="critical", status="verifying")
        ),
        api_module._candidate_to_pseudo_finding(
            _candidate_row(id="c-high", claimed_severity="high")
        ),
    ]

    page = api_module._merge_findings_and_candidates(
        findings, candidates, sort_by=None, sort_order="desc", limit=10, offset=0
    )

    assert [item["id"] for item in page] == ["c-crit", "c-high", "f-high", "f-med"]


def test_merge_applies_the_offset_limit_window_over_both_lists():
    findings = [{"id": f"f{i}", "severity": "low", "last_seen_at": NOW} for i in range(3)]
    candidates = [
        api_module._candidate_to_pseudo_finding(_candidate_row(id=f"c{i}", claimed_severity="low"))
        for i in range(3)
    ]

    page = api_module._merge_findings_and_candidates(
        findings, candidates, sort_by=None, sort_order="desc", limit=2, offset=4
    )

    # Ties keep the deterministic merge input order (findings, then candidates),
    # so the shared window [f0,f1,f2,c0,c1,c2] paginates to its last two rows.
    assert [item["id"] for item in page] == ["c1", "c2"]


def test_merge_sorts_first_seen_ascending():
    findings = [{"id": "f-new", "severity": "low", "first_seen_at": NOW}]
    candidates = [
        api_module._candidate_to_pseudo_finding(
            _candidate_row(id="c-old", first_seen_at=NOW - timedelta(days=5))
        ),
    ]

    page = api_module._merge_findings_and_candidates(
        findings, candidates, sort_by="first_seen", sort_order="asc", limit=10, offset=0
    )

    assert [item["id"] for item in page] == ["c-old", "f-new"]


def test_merge_sorts_cvss_desc_with_null_scores_last():
    findings = [
        {"id": "f-9", "severity": "low", "cvss_score": 9.0},
        {"id": "f-none", "severity": "low", "cvss_score": None},
    ]
    candidates = [
        api_module._candidate_to_pseudo_finding(_candidate_row(id="c", claimed_severity="low"))
    ]

    page = api_module._merge_findings_and_candidates(
        findings, candidates, sort_by="cvss", sort_order="desc", limit=10, offset=0
    )

    assert page[0]["id"] == "f-9"
    assert {item["id"] for item in page[1:]} == {"f-none", "c"}


def test_auto_verify_limit_is_raised_to_eight():
    assert api_module._AGENT_AUTO_VERIFY_LIMIT == 8


def test_findings_endpoint_keeps_candidates_opt_in_and_only_on_the_deep_hunt_surface():
    source = api_tree_source()
    endpoint = source[source.index('@app.get("/findings")'):]
    endpoint = endpoint[:endpoint.index('def _public_evidence_object_row')]

    assert "include_candidates: bool = False" in endpoint
    assert '"include_candidates"' in endpoint
    assert "include_details: bool = False" in endpoint
    assert '"include_details"' in endpoint
    assert "source_type in (None, \"deep_hunt\")" in endpoint
    assert "status in (None, \"active\")" in endpoint
    assert "verification_verdict" in endpoint and "resolved_within_days" in endpoint
    # Verified or already-materialized candidates must never ride along.
    assert "c.plane = 'web'" in endpoint
    assert "(c.verification_context->>'finding_id') IS NULL" in endpoint
    assert "c.status = ANY($1::text[])" in endpoint
    # Bounded fetch: the candidate query shares the same prefix window as findings.
    assert "COUNT(*) OVER() AS total_count" in endpoint
    # Pagination stays coherent: separate totals plus an explicit included count.
    assert "'candidates_total': candidates_total" in endpoint
    assert "'included_candidates': included_candidates" in endpoint
    # List rows retain proof derivation but shed detail-only evidence blobs.
    assert "row_dict.update(finding_proof_fields(row_dict))" in endpoint
    assert "for key in _FINDING_DETAIL_ONLY_FIELDS" in endpoint

    client = (ROOT / "ui" / "src" / "lib" / "api.ts").read_text()
    assert "params?.include_candidates === true" in client
    findings_page = (ROOT / "ui" / "src" / "app" / "findings" / "page.tsx").read_text()
    assert "if (finding.is_candidate) return '/findings/candidates'" in findings_page


def test_dashboard_counts_open_candidates_with_a_single_bounded_query():
    source = api_tree_source()
    dashboard = route_source("GET", "/dashboard")

    assert "suspected_candidates_count" in dashboard
    assert "SELECT COUNT(*) FROM investigation_candidates" in dashboard
    assert "status NOT IN ('verified','refuted','expired')" in dashboard
