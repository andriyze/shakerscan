"""Compact scan-list reads use stored assessment state, not a stale grade."""
import asyncio
import fastapi  # Load the real framework before legacy optional-dependency test stubs.

from tests import test_api_helpers as cases


def test_compact_scan_list_withholds_explicitly_unexamined_grade(monkeypatch):
    api = cases.api_module

    class Conn:
        async def fetch(self, query, *args):
            assert "AS risk_assessment_state" in query
            assert "AS application_observed" in query
            return [{"id": "scan-1", "status": "completed", "run_kind": "web_dast",
                     "score": 100, "grade": "A*", "risk_assessment_state": "not_examined",
                     "application_observed": "false"}]

        async def fetchval(self, query, *args):
            return 1

    class Pool:
        def acquire(self):
            return self

        async def __aenter__(self):
            return Conn()

        async def __aexit__(self, *args):
            return False

    monkeypatch.setattr(api, "db_pool", Pool())
    result = asyncio.run(api.list_scans(status=None, target=None, root_domain=None,
        created_within_days=None, include_shards=False, include_internal=False,
        include_model_intake=False, include_devices=False, limit=50, offset=0,
        include_details=False))
    assert result["total"] == 1
    row = result["scans"][0]
    assert row["grade"] is None and row["score"] is None
    assert row["application_observed"] is False
    assert "result" not in row
