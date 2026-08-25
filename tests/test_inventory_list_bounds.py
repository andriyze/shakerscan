import asyncio
import uuid

import pytest
from pydantic import ValidationError

from api import api


class _Acquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *_exc):
        return False


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return _Acquire(self.conn)


def test_scan_list_uses_summary_projection_and_compact_options(monkeypatch):
    class Conn:
        queries = []

        async def fetch(self, query, *_args):
            self.queries.append(query)
            return [{
                "id": uuid.uuid4(),
                "target_url": "https://example.test",
                "status": "completed",
                "options": {
                    "budget_profile": "thorough",
                    "auth_header": "secret",
                    "metadata_json": {
                        "provider_resolution": {"provider": "huggingface", "private": "drop"},
                        "large_manifest": "x" * 10_000,
                    },
                    "large_private_field": "x" * 10_000,
                },
                "scan_action_plan_json": {"actions": ["x" * 10_000]},
                "scan_job_payload": {"payload": "x" * 10_000},
                "execution_context": {"context": "x" * 10_000},
                "result": {"report": "x" * 10_000},
            }]

        async def fetchval(self, _query, *_args):
            return 1

    conn = Conn()
    monkeypatch.setattr(api, "db_pool", _Pool(conn))
    response = asyncio.run(api.list_scans(
        status=None,
        target=None,
        root_domain=None,
        created_within_days=None,
        include_shards=False,
        include_internal=False,
        include_model_intake=False,
        include_devices=False,
        limit=50,
        offset=0,
        include_details=False,
    ))

    row = response["scans"][0]
    assert "s.*" not in conn.queries[0]
    assert row["options"] == {
        "auth_header": "***",
        "budget_profile": "thorough",
        "metadata_json": {"provider_resolution": {"provider": "huggingface"}},
    }
    for key in ("result", "scan_action_plan_json", "scan_job_payload", "execution_context"):
        assert key not in row


def test_target_list_projection_bounds_historical_text():
    public = api._public_target_row({
        "id": uuid.uuid4(),
        "url": "https://" + ("a" * 10_000) + ".test",
        "name": "n" * 2_000,
        "root_domain": "r" * 1_000,
        "discovery_source": "manual",
        "origins": [],
    })

    assert len(public["url"]) == 2049
    assert len(public["name"]) == 512
    assert len(public["root_domain"]) == 253
    assert public["origins"] == []


def test_new_targets_reject_unbounded_urls_and_names():
    with pytest.raises(ValidationError):
        api.TargetCreate(url="https://" + ("a" * 2048))
    with pytest.raises(ValidationError):
        api.TargetCreate(url="https://example.test", name="n" * 513)


def test_hunt_list_summary_omits_repeated_capability_contracts():
    row = {
        "id": uuid.uuid4(),
        "target_id": uuid.uuid4(),
        "target_kind": "web",
        "objective": "inspect",
        "status": "completed",
        "budget_profile": "balanced",
        "policy_json": {"allowed_capabilities": ["web.probe"]},
        "budget_json": {},
        "budget_used_json": {},
        "context_pack": {"large": "x" * 10_000},
    }

    detail = api._hunt_public(row)
    summary = api._hunt_public(
        row,
        include_context=False,
        include_capabilities=False,
    )

    assert detail["capabilities"][0]["name"] == "web.probe"
    assert "context_pack" in detail
    assert "capabilities" not in summary
    assert "context_pack" not in summary
