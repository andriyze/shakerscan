"""A Hunt must be told what its deployment already knows about the target.

The knowledge was always reachable through ``POST /hunts/{id}/query``, but nothing in the context
pack said it existed, so an agent re-derived the attack surface from scratch and could re-hunt a
bug earlier runs had already proven. These tests pin the census that closes that gap: counts only,
no rows, no URLs, no secret material.
"""

from __future__ import annotations

import asyncio
import datetime
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from hunt import prior_knowledge  # noqa: E402


class _FakeConn:
    """Stand in for asyncpg: answer each query by matching a distinctive fragment."""

    def __init__(self, fetches: dict[str, list], values: dict[str, object], rows: dict[str, object]):
        self._fetches, self._values, self._rows = fetches, values, rows

    @staticmethod
    def _match(table: dict, query: str):
        for fragment, payload in table.items():
            if fragment in " ".join(query.split()):
                return payload
        raise AssertionError(f"unexpected query: {query}")

    async def fetch(self, query, *args):
        return self._match(self._fetches, query)

    async def fetchval(self, query, *args):
        return self._match(self._values, query)

    async def fetchrow(self, query, *args):
        return self._match(self._rows, query)


def _web_conn(**overrides):
    fetches = {
        "auth_state, count(*)": [
            {"auth_state": "anonymous", "count": 3000},
            {"auth_state": "user1", "count": 417},
        ],
        "test_status, count(*)": [
            {"test_status": "untested", "count": 1944},
            {"test_status": "tested", "count": 634},
            {"test_status": "stale", "count": 831},
            {"test_status": "gone", "count": 8},
        ],
        "severity, count(*)": [
            {"severity": "critical", "count": 67},
            {"severity": "high", "count": 115},
        ],
    }
    values = {"last_verification_verdict='exploited'": 64, "investigation_candidates": 6}
    rows = {
        "FROM scans": {
            "id": "aef2732c-5c58-4b15-9eb3-af3d593aec21",
            "completed_at": datetime.datetime(2026, 8, 25, 19, 40, 27, tzinfo=datetime.timezone.utc),
        }
    }
    fetches.update(overrides.get("fetches") or {})
    values.update(overrides.get("values") or {})
    rows.update(overrides.get("rows") or {})
    return _FakeConn(fetches, values, rows)


def test_web_census_reports_the_untested_frontier_and_settled_work():
    pack = asyncio.run(prior_knowledge.web_prior_knowledge(_web_conn(), "t1"))
    assert pack["schema_version"] == "hunt-prior-knowledge/v1"
    assert pack["endpoints"]["total"] == 3417
    # The frontier: what a Hunt should spend budget on rather than rediscovering.
    assert pack["endpoints"]["untested"] == 1944
    assert pack["endpoints"]["by_auth_state"] == {"anonymous": 3000, "user1": 417}
    # Settled work: a Hunt must not re-hunt what the deployment already proved.
    assert pack["findings"]["active"] == 182
    assert pack["findings"]["already_verified"] == 64
    assert pack["open_candidates"] == 6
    assert pack["last_completed_scan"]["completed_at"].startswith("2026-08-25T19:40:27")


def test_census_tells_the_agent_how_to_read_the_rows():
    # The census is a signpost, so it must name the query that returns the rows behind it.
    pack = asyncio.run(prior_knowledge.web_prior_knowledge(_web_conn(), "t1"))
    assert "POST /hunts/{hunt_id}/query" in pack["guidance"]
    assert {"endpoints", "findings", "candidates"} <= set(pack["query_kinds"])


def test_census_carries_counts_only_and_never_target_content():
    # Regression guard: this block lands in a planner-visible context pack, so a row, URL, payload
    # or parameter name leaking into it would put target content in front of the model.
    pack = asyncio.run(prior_knowledge.web_prior_knowledge(_web_conn(), "t1"))
    rendered = repr({k: v for k, v in pack.items() if k != "guidance"})
    for forbidden in ("http://", "https://", "/api/", "param", "secret", "token", "password"):
        assert forbidden not in rendered, forbidden


def test_empty_target_reports_zeroes_rather_than_failing():
    # A never-scanned target must still produce a well-formed census, not an error or a null block.
    conn = _FakeConn(
        {"auth_state, count(*)": [], "test_status, count(*)": [], "severity, count(*)": []},
        {"last_verification_verdict='exploited'": 0, "investigation_candidates": None},
        {"FROM scans": None},
    )
    pack = asyncio.run(prior_knowledge.web_prior_knowledge(conn, "t1"))
    assert pack["endpoints"]["total"] == 0
    assert pack["endpoints"]["untested"] == 0
    assert pack["findings"]["active"] == 0
    assert pack["open_candidates"] == 0
    assert pack["last_completed_scan"] == {"id": None, "completed_at": None}


def test_device_census_reports_services_instead_of_endpoints():
    conn = _FakeConn(
        {"severity, count(*)": [{"severity": "high", "count": 3}]},
        {"device_services": 12, "last_verification_verdict='exploited'": 1},
        {"FROM scans": None},
    )
    pack = asyncio.run(prior_knowledge.device_prior_knowledge(conn, "d1"))
    assert pack["open_services"] == 12
    assert "endpoints" not in pack, "a device target has services, not an HTTP endpoint inventory"
    assert pack["findings"]["active"] == 3
    assert pack["findings"]["already_verified"] == 1


# --- The census must be actionable, not just informative -------------------------------------
# Advertising "1944 untested endpoints" and "64 already verified" is only useful if the query the
# census points at can express those sets. The endpoints query filtered on path and method alone,
# and findings on severity alone, so an agent could read the census and still only page the top of
# the priority ranking. These pin the filters that close that gap.

def _query_source() -> str:
    from tests.api_sources import definition_source
    return definition_source("_agent_tool_query_kb")


def test_endpoint_query_can_select_the_untested_frontier():
    source = _query_source()
    assert 'test_status = str(flt.get("test_status") or "").strip().lower()' in source
    assert 'auth_state = str(flt.get("auth_state") or "").strip().lower()' in source
    # Bound as parameters, never interpolated: these reach a SQL WHERE clause.
    assert "lower(COALESCE(test_status,''))=$4" in source
    assert "lower(COALESCE(auth_state,''))=$5" in source
    assert "target_uuid, path_contains, method, test_status, auth_state, limit," in source


def test_findings_query_can_separate_proven_work_from_open_work():
    source = _query_source()
    assert 'finding_status = str(flt.get("status") or "").strip().lower()' in source
    assert 'verified_only = bool(flt.get("verified_only"))' in source
    assert "NOT $4::boolean OR last_verification_verdict='exploited'" in source
    assert "target_uuid, severity, finding_status, verified_only, limit," in source


def test_new_filters_default_to_the_previous_behaviour():
    # Every added predicate is guarded by an empty/false check, so a caller that sends no filter
    # gets exactly the rows it got before -- the filters widen expressiveness, never narrow default
    # results.
    source = _query_source()
    for guard in ("($4='' OR", "($5='' OR", "($3='' OR", "NOT $4::boolean OR"):
        assert guard in source, guard


def test_census_guidance_names_the_filters_it_promises():
    # A census that advertises a frontier without naming how to select it sends the agent back to
    # crawling, which is the behaviour this whole block exists to prevent.
    guidance = prior_knowledge._GUIDANCE
    for name in ("test_status", "auth_state", "verified_only", "status", "path_contains"):
        assert name in guidance, name


def test_every_knowledge_base_kind_is_reachable_from_a_hunt():
    # hypotheses / graph_nodes / graph_edges were implemented in _agent_tool_query_kb but omitted
    # from the request Literal and the routing set, so a Hunt could never ask for them. This pins
    # the two halves together: anything the knowledge base can answer must be requestable, or it is
    # dead code that silently returns an empty result instead of an error.
    import ast
    import re

    from tests.api_sources import definition_source

    query_source = definition_source("_agent_tool_query_kb")
    implemented = set(re.findall(r'kind == "([a-z_]+)"', query_source))
    # tool_receipts is reached through the "receipts" alias the route maps for it.
    implemented = (implemented - {"tool_receipts"}) | {"receipts"}

    router = Path("api/hunt/interaction_router.py").read_text(encoding="utf-8")
    declared: set[str] = set()
    for node in ast.walk(ast.parse(router)):
        if isinstance(node, ast.ClassDef) and node.name == "HuntQueryRequest":
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and getattr(stmt.target, "id", "") == "kind":
                    declared = {
                        element.value for element in stmt.annotation.slice.elts
                        if isinstance(element, ast.Constant)
                    }
    assert declared, "HuntQueryRequest.kind must declare its accepted values"
    missing = implemented - declared
    assert not missing, f"knowledge base answers these but a Hunt cannot ask for them: {sorted(missing)}"


def test_the_census_advertises_only_kinds_a_hunt_can_actually_request():
    # The inverse guard: pointing an agent at a kind the route rejects wastes a turn on a 422.
    import ast

    router = Path("api/hunt/interaction_router.py").read_text(encoding="utf-8")
    declared: set[str] = set()
    for node in ast.walk(ast.parse(router)):
        if isinstance(node, ast.ClassDef) and node.name == "HuntQueryRequest":
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and getattr(stmt.target, "id", "") == "kind":
                    declared = {
                        element.value for element in stmt.annotation.slice.elts
                        if isinstance(element, ast.Constant)
                    }
    pack = asyncio.run(prior_knowledge.web_prior_knowledge(_web_conn(), "t1"))
    assert set(pack["query_kinds"]) <= declared


def test_a_census_failure_never_blocks_a_hunt_from_starting():
    # The census is advisory context. A knowledge-base read that fails must degrade to an explicit
    # "unavailable" block, not raise out of the hunt-start transaction.
    class _Broken:
        async def fetch(self, *a):
            raise RuntimeError("knowledge base unavailable")

    pack = asyncio.run(prior_knowledge.safe_prior_knowledge(_Broken(), "t1"))
    assert pack["available"] is False
    assert pack["reason"] == "RuntimeError"
    # The exception message could carry target content into a planner-visible pack; only the type.
    assert "knowledge base unavailable" not in repr(pack)


def test_unavailable_is_distinguishable_from_a_genuinely_empty_target():
    # An agent told "zero endpoints" skips the query and crawls from scratch, so "nothing known"
    # and "could not ask" must not look alike.
    empty = _FakeConn(
        {"auth_state, count(*)": [], "test_status, count(*)": [], "severity, count(*)": []},
        {"last_verification_verdict='exploited'": 0, "investigation_candidates": 0},
        {"FROM scans": None},
    )
    built = asyncio.run(prior_knowledge.safe_prior_knowledge(empty, "t1"))
    assert built["available"] is True and built["endpoints"]["total"] == 0

    class _Broken:
        async def fetch(self, *a):
            raise RuntimeError("boom")

    broken = asyncio.run(prior_knowledge.safe_prior_knowledge(_Broken(), "t1"))
    assert broken["available"] is False
    assert "endpoints" not in broken, "an unavailable census must not imply an empty inventory"
    assert "query" in broken["guidance"].lower()


def test_device_plane_degrades_the_same_way():
    class _Broken:
        async def fetchval(self, *a):
            raise LookupError("no device tables")

    pack = asyncio.run(prior_knowledge.safe_prior_knowledge(_Broken(), "d1", device=True))
    assert pack["available"] is False and pack["reason"] == "LookupError"
