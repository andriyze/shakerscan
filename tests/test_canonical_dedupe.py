"""Canonical target de-dupe: the canonical key + survivor selection that drive the
merge, find-or-create prevention, and the canonical-aware deploy gate. The SQL trigger
form must stay equivalent to _canonical_target_key (verified live); this covers the
Python side."""
import asyncio
import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
import api  # noqa: E402
import target_dedupe  # noqa: E402


def test_canonical_web_key_is_scheme_port_slash_case_insensitive():
    k = api._canonical_target_key
    assert k("https://Example.com/") == "web:example.com"
    assert k("http://example.com") == "web:example.com"
    assert k("http://example.com:8080") == "web:example.com"
    assert k("https://example.com:9090") == "web:example.com"
    assert k("example.com") == "web:example.com"
    assert k("https://example.com///", "manual") == "web:example.com"
    assert k("HTTP://Host.Docker.Internal:3001/") == "web:host.docker.internal"
    assert k("  https://example.com  ") == "web:example.com"


def test_canonical_key_keeps_path_drops_only_trailing_slash():
    # Path is part of the artifact identity (e.g. model-intake URLs); only the trailing
    # slash is stripped, not the whole path.
    assert api._canonical_target_key("https://hf.co/org/model/", "model-intake") == \
        "artifact:hf.co/org/model"
    assert api._canonical_target_key("https://hf.co/org/model", "model-intake") == \
        "artifact:hf.co/org/model"
    assert api._canonical_target_key("https://hf.co/org/other", "model-intake") != \
        api._canonical_target_key("https://hf.co/org/model", "model-intake")
    assert api._canonical_target_key("https://hf.co/a/dast/path", "manual") == "web:hf.co"


def _row(rid, url, active=True, findings=0, scans=0):
    return {"id": rid, "url": url, "discovery_source": "manual", "is_active": active,
            "active_findings_count": findings, "total_scans": scans}


def test_dedupe_collapses_canonical_variants_keeping_richest_survivor():
    rows = [
        _row("1", "host.docker.internal:3001", findings=0, scans=0),
        _row("2", "http://host.docker.internal:3001", findings=109, scans=5),
    ]
    out = api._dedupe_canonical_target_rows(rows)
    assert len(out) == 1
    assert out[0]["id"] == "2"  # survivor = the data-bearing row


def test_dedupe_survivor_prefers_active_then_findings_then_https():
    rows = [
        _row("inactive-https", "https://x.com", active=False, findings=50),
        _row("active-http", "http://x.com", active=True, findings=10),
    ]
    out = api._dedupe_canonical_target_rows(rows)
    assert len(out) == 1 and out[0]["id"] == "active-http"  # active beats more-findings-but-inactive


def test_dedupe_keeps_distinct_hosts():
    rows = [_row("1", "https://a.com"), _row("2", "https://b.com")]
    out = api._dedupe_canonical_target_rows(rows)
    assert {r["id"] for r in out} == {"1", "2"}


class _TargetBoundaryConn:
    def __init__(self):
        self.fetch_queries = []
        self.fetchval_queries = []

    async def fetch(self, query, *_args):
        self.fetch_queries.append(" ".join(query.split()))
        return []

    async def fetchval(self, query, *_args):
        self.fetchval_queries.append(" ".join(query.split()))
        return 0


def test_web_target_apis_exclude_model_intake_subjects_by_default(monkeypatch):
    conn = _TargetBoundaryConn()
    monkeypatch.setattr(api, "db_pool", _Pool(conn))

    flat = asyncio.run(api.list_targets(include_inactive=False, limit=100, offset=0))
    grouped = asyncio.run(api.list_targets_grouped(
        include_inactive=False, search=None, discovery_source=None, grade=None,
        has_findings=None, sort_by="root_domain", sort_order="asc",
    ))
    domains = asyncio.run(api.list_domains())

    assert flat["total"] == 0 and grouped["total_targets"] == 0 and domains["domains"] == []
    target_queries = [query for query in conn.fetch_queries if "FROM targets" in query]
    assert target_queries
    assert all("COALESCE(discovery_source, 'manual') <> 'model-intake'" in query or "COALESCE(t.discovery_source, 'manual') <> 'model-intake'" in query for query in target_queries)
    assert all("COALESCE(discovery_source, 'manual') <> 'model-intake'" in query for query in conn.fetchval_queries)


def test_target_dedupe_plan_excludes_model_intake_subjects():
    conn = _TargetBoundaryConn()

    assert asyncio.run(target_dedupe.plan_canonical_merges(conn)) == []
    assert "WHERE COALESCE(discovery_source, 'manual') <> 'model-intake'" in conn.fetch_queries[0]


class _BlockingMergeConn:
    def __init__(self, *, preview_id, preview_target_id):
        self.preview_id = preview_id
        self.preview_target_id = preview_target_id
        self.executed = []
        self.checked_target_ids = []

    async def fetch(self, query, *args):
        assert "FROM evidence_retention_previews" in query
        self.checked_target_ids = list(args[0])
        return [{"id": self.preview_id, "target_id": self.preview_target_id}]

    async def execute(self, query, *args):
        self.executed.append((query, args))


def test_merge_target_group_blocks_executing_retention_preview_before_mutation():
    survivor_id = uuid.uuid4()
    dupe_id = uuid.uuid4()
    preview_id = uuid.uuid4()
    conn = _BlockingMergeConn(preview_id=preview_id, preview_target_id=dupe_id)

    with pytest.raises(target_dedupe.TargetMergeBlockedError) as exc:
        asyncio.run(target_dedupe.merge_target_group(conn, survivor_id, [dupe_id]))

    assert set(conn.checked_target_ids) == {survivor_id, dupe_id}
    assert conn.executed == []
    assert exc.value.preview_ids == [str(preview_id)]
    assert exc.value.target_ids == [str(dupe_id)]


class _Acquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *_args):
        return False


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return _Acquire(self.conn)


def test_dedupe_api_accepts_json_body_and_resolves_conflicts_to_dry_run(monkeypatch):
    async def empty_plan(_conn):
        return []

    monkeypatch.setattr(api, "db_pool", _Pool(object()))
    monkeypatch.setattr(api, "plan_canonical_merges", empty_plan)

    body_result = asyncio.run(api.dedupe_targets(
        payload=api.DedupeTargetsRequest(dry_run=False),
    ))
    query_result = asyncio.run(api.dedupe_targets(
        payload=api.DedupeTargetsRequest(dry_run=False),
        dry_run=True,
    ))
    conflict_result = asyncio.run(api.dedupe_targets(
        payload=api.DedupeTargetsRequest(dry_run=True),
        dry_run=False,
    ))

    assert body_result["dry_run"] is False
    assert query_result["dry_run"] is True
    assert conflict_result["dry_run"] is True


def test_dedupe_api_returns_clear_409_for_executing_retention_preview(monkeypatch):
    survivor_id = uuid.uuid4()
    dupe_id = uuid.uuid4()
    preview_id = uuid.uuid4()
    plan = [{
        "canonical": "example.test",
        "survivor": {"id": str(survivor_id), "url": "https://example.test"},
        "merged": [{"id": str(dupe_id), "url": "http://example.test"}],
    }]

    async def fake_plan(_conn):
        return plan

    async def block_merge(_conn, target_ids):
        raise target_dedupe.TargetMergeBlockedError(target_ids, [preview_id])

    monkeypatch.setattr(api, "db_pool", _Pool(object()))
    monkeypatch.setattr(api, "plan_canonical_merges", fake_plan)
    monkeypatch.setattr(api, "_ensure_target_merge_safe", block_merge)

    with pytest.raises(api.HTTPException) as exc:
        asyncio.run(api.dedupe_targets(dry_run=False))

    assert exc.value.status_code == 409
    assert exc.value.detail["error"] == "target_merge_blocked_by_evidence_retention"
    assert exc.value.detail["preview_ids"] == [str(preview_id)]
    assert set(exc.value.detail["target_ids"]) == {str(survivor_id), str(dupe_id)}


class _RetentionConstraintViolation(Exception):
    constraint_name = target_dedupe.RETENTION_PREVIEW_FK_CONSTRAINT


class _RaceMergeConn:
    async def fetch(self, query, *_args):
        assert "FROM evidence_retention_previews" in query
        return []

    async def execute(self, query, *_args):
        if "DELETE FROM targets" in query:
            raise _RetentionConstraintViolation("retention preview became executing")
        return "OK"


def test_merge_target_group_translates_retention_fk_race_to_blocked_error():
    survivor_id = uuid.uuid4()
    dupe_id = uuid.uuid4()

    with pytest.raises(target_dedupe.TargetMergeBlockedError) as exc:
        asyncio.run(target_dedupe.merge_target_group(_RaceMergeConn(), survivor_id, [dupe_id]))

    assert set(exc.value.target_ids) == {str(survivor_id), str(dupe_id)}
    assert exc.value.preview_ids == []


class _RecordingMergeConn:
    def __init__(self):
        self.statements = []

    async def fetch(self, query, *_args):
        assert "FROM evidence_retention_previews" in query
        return []

    async def execute(self, query, *_args):
        self.statements.append(" ".join(query.split()))
        return "OK"


def test_merge_target_group_reassigns_deep_hunt_credentials_and_evidence_before_delete():
    conn = _RecordingMergeConn()
    asyncio.run(target_dedupe.merge_target_group(conn, uuid.uuid4(), [uuid.uuid4()]))
    sql = "\n".join(conn.statements)

    for table in (
        "agent_context_packs", "agent_hunt_runs", "research_episodes", "hypotheses",
        "target_credential_profiles", "target_principals", "target_endpoint_expectations",
        "evidence_instances", "export_events", "campaigns", "campaign_actions",
    ):
        assert table in sql
    assert sql.index("UPDATE agent_hunt_runs") < sql.index("DELETE FROM targets")
    assert sql.index("UPDATE evidence_instances") < sql.index("DELETE FROM targets")
    assert sql.index("DELETE FROM evidence_objects evidence") < \
        sql.index("UPDATE evidence_objects child SET finding_id")
    assert "PARTITION BY ranked.keep_id, evidence.object_type" in sql
    assert sql.index("UPDATE evidence_objects child SET finding_id") < sql.index("DELETE FROM findings")
    assert sql.index("UPDATE asm_endpoint_attempts child SET endpoint_id") < \
        sql.index("DELETE FROM target_endpoints")


def test_retention_preview_fk_is_present_in_fresh_and_upgrade_schemas():
    root = Path(__file__).resolve().parents[1]
    init_sql = (root / "db" / "init.sql").read_text()
    migrations = (root / "api" / "retest_contract.py").read_text()

    for source in (init_sql, migrations):
        assert "evidence_objects_retention_delete_preview_fk" in source
        assert "REFERENCES evidence_retention_previews(id)" in source
        assert "ON DELETE RESTRICT" in source
    assert "NOT VALID" in migrations
    assert "VALIDATE CONSTRAINT evidence_objects_retention_delete_preview_fk" in migrations
