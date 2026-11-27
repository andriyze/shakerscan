import asyncio
import json

from scanner.scanner_tools import active_checks


def test_graphql_introspection_evidence_is_verified(monkeypatch):
    async def fake_run(cmd, timeout=10):
        url = cmd[-1]
        if url.endswith("/graphql"):
            return json.dumps({"data": {"__schema": {"types": [{"name": "Query"}]}}}), "", 0
        return json.dumps({"errors": [{"message": "not found"}]}), "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(active_checks.graphql_vulnerability_test("https://example.test"))

    assert result["vulnerable"] is True
    assert result["issues"] == ["introspection_enabled"]
    evidence = result["evidence"][0]
    assert evidence["verified"] is True
    assert evidence["schema_type_count"] == 1
    assert evidence["response_hash16"]
