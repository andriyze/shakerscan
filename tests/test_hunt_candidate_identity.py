"""Candidate identity: distinct issues never overwrite each other, and evidence must be this Hunt's.

Regression for soak defect 3 (2026-10-07): a critical ``.git-credentials`` candidate was replaced by
an unrelated RAG claim because ``canonical_locus`` dropped ``path``/``origin``/``principal`` and the
fingerprint conflict rewrote title, claim, severity and evidence. Evidence references naming
nonexistent records or another Hunt's records were accepted.

The upsert tests run the real SQL against SQLite (casts and row locks stripped, as the existing
selected-object fixture does). The PostgreSQL tests run the same code unmodified when
HUNT_TEST_POSTGRES_DSN names a disposable local database.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
import uuid
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import pytest

from api import investigation_candidates as candidates
from api.hunt import candidate_evidence
from api.hunt import interaction_router as router
from api.hunt.start_contract import hunt_start_public_contract
from tests.hunt_candidate_pg_schema import candidate_schema_sql

TARGET = str(uuid.uuid4())
HUNT = str(uuid.uuid4())

SQLITE_DDL = """
CREATE TABLE investigation_candidates(id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
 plane TEXT,target_id TEXT,device_target_id TEXT,research_episode_id TEXT,agent_hunt_run_id TEXT,
 device_agent_run_id TEXT,hunt_run_id TEXT,family TEXT,canonical_locus TEXT,title TEXT,claim TEXT,
 claimed_severity TEXT,evidence_refs TEXT,verifier_contract_id TEXT,source_kind TEXT,
 fingerprint TEXT UNIQUE,status TEXT,created_by TEXT,latest_verification_id TEXT,
 last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE investigation_candidate_observations(id INTEGER PRIMARY KEY AUTOINCREMENT,
 candidate_id TEXT,research_episode_id TEXT,agent_hunt_run_id TEXT,device_agent_run_id TEXT,
 hunt_run_id TEXT,source_kind TEXT,title TEXT,claim TEXT,claimed_severity TEXT,evidence_refs TEXT,
 verifier_contract_id TEXT,observation_context TEXT,created_by TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP);
"""


class _Row(dict):
    pass


class SqliteConnection:
    """Executes the module's SQL on SQLite; Postgres-only syntax is adapted, not reimplemented."""

    def __init__(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SQLITE_DDL)

    def _query(self, sql, args):
        sql = re.sub(r"::[a-zA-Z_]+", "", sql).replace(" FOR UPDATE", "")
        sql = sql.replace("NOW()", "CURRENT_TIMESTAMP").replace("(xmax = 0) AS inserted", "1 AS inserted")
        sql = re.sub(r"\$(\d+)", r"?\1", sql)
        return self.db.execute(sql, [str(v) if isinstance(v, uuid.UUID) else v for v in args])

    async def fetchrow(self, sql, *args):
        row = self._query(sql, args).fetchone()
        return _Row(dict(row)) if row is not None else None

    async def execute(self, sql, *args):
        self._query(sql, args)
        return "OK"

    def rows(self):
        return [dict(row) for row in self.db.execute("SELECT * FROM investigation_candidates ORDER BY rowid")]

    def observations(self):
        return [dict(row) for row in self.db.execute(
            "SELECT * FROM investigation_candidate_observations ORDER BY id")]


def _candidate(*, title, claim, severity="info", refs=None,
               family="sensitive_file_exposure", locus=None, hunt=HUNT):
    refs = refs or ["action:" + str(uuid.uuid4())]
    return candidates.normalize_candidate(
        plane="web", target_id=TARGET, hunt_run_id=hunt, family=family,
        locus=locus or {}, title=title, claim=claim, severity=severity,
        evidence_refs=list(refs), source_kind="hunt_v2",
    )


def test_locus_preserves_natural_keys_so_distinct_paths_have_distinct_identity():
    locus = {
        "origin": "https://honey.example", "path": "/.git-credentials", "principal": "anonymous",
        "address": "203.0.113.7", "paths": ["/b", "/a", "/a"], "Method": "get",
        "X-Tool": "rag.search",
    }
    normalized = candidates.canonical_locus(locus)
    assert normalized == {
        "origin": "https://honey.example", "path": "/.git-credentials",
        "principal": "anonymous", "address": "203.0.113.7", "paths": ["/a", "/b"],
        "method": "GET",
    }
    # A key outside the published vocabulary is kept, as metadata outside the identity (D4).
    assert candidates.locus_metadata(locus) == {"x_tool": "rag.search"}
    first = candidates.candidate_fingerprint(
        plane="web", target_ref=TARGET, family="sensitive_file_exposure",
        locus={"path": "/.git-credentials"},
    )
    second = candidates.candidate_fingerprint(
        plane="web", target_ref=TARGET, family="sensitive_file_exposure",
        locus={"path": "/.env"},
    )
    assert first != second
    assert candidates.canonical_locus({"paths": ["/b", "/a"]}) == candidates.canonical_locus(
        {"paths": ["/a", "/b"]}
    )


def test_extra_locus_keys_never_split_one_issue_into_several_candidates():
    """Soak D4: Hunts that described one issue with their own extra locus keys each made a
    candidate (.git x3, /actuator/env x2). Identity is the published vocabulary only; the extra
    keys are kept with the sighting and named in ignored_for_identity, never refused."""
    conn = SqliteConnection()
    claim = "GET /.git/config discloses the repository remote and credentials"
    first = asyncio.run(candidates.upsert_candidate(conn, _candidate(
        title=".git exposed", claim=claim, severity="critical",
        locus={"path": "/.git/config", "method": "GET"},
    ), created_by="hunt-a"))
    second = asyncio.run(candidates.upsert_candidate(conn, _candidate(
        title=".git exposed", claim=claim, severity="critical",
        locus={"path": "/.git/config", "method": "GET", "evidence": "config file", "note": "seen"},
        hunt=str(uuid.uuid4()),
    ), created_by="hunt-b"))
    third = asyncio.run(candidates.upsert_candidate(conn, _candidate(
        title=".git exposed", claim=claim, severity="critical",
        locus={"path": "/.git/config", "method": "get", "Exposure-Kind": "vcs"},
        hunt=str(uuid.uuid4()),
    ), created_by="hunt-c"))

    assert [first["outcome"], second["outcome"], third["outcome"]] == [
        "inserted", "merged", "merged"]
    assert first["id"] == second["id"] == third["id"]
    assert "ignored_for_identity" not in first
    assert second["ignored_for_identity"] == ["evidence", "note"]
    assert third["ignored_for_identity"] == ["exposure_kind"]
    rows = conn.rows()
    assert len(rows) == 1
    assert json.loads(rows[0]["canonical_locus"]) == {"method": "GET", "path": "/.git/config"}
    # Each sighting's extra keys are kept with that sighting.
    contexts = [json.loads(item["observation_context"] or "{}") for item in conn.observations()]
    assert [item.get("locus_metadata") for item in contexts] == [
        None, {"evidence": "config file", "note": "seen"}, {"exposure_kind": "vcs"},
    ]


def test_published_input_and_operation_keys_stay_part_of_the_identity():
    def fingerprint(locus):
        return candidates.candidate_fingerprint(
            plane="web", target_ref=TARGET, family="excessive_agency", locus=locus,
        )
    base = {"route": "/api/v1/agent/run", "method": "POST"}
    assert {"input", "operation", "object_id"} <= set(candidates.LOCUS_KEYS)
    assert fingerprint({**base, "input": "task"}) != fingerprint({**base, "input": "tool"})
    assert fingerprint({**base, "operation": "refund"}) != fingerprint({**base, "operation": "exec"})
    assert fingerprint({**base, "object_id": "7"}) != fingerprint({**base, "object_id": "8"})
    assert fingerprint({**base, "note": "a"}) == fingerprint({**base, "note": "b"}) == fingerprint(base)
    # A row stored before this change with only vocabulary keys keeps its fingerprint.
    assert fingerprint({**base, "input": "task"}) == candidates.candidate_fingerprint(
        plane="web", target_ref=TARGET, family="excessive_agency",
        locus={"route": "/api/v1/agent/run", "method": "post", "input": "task"},
    )


def test_documented_locus_fingerprints_are_unchanged_for_existing_rows():
    # Computed with the previous normalizer: existing candidates keep their identity.
    assert candidates.candidate_fingerprint(
        plane="web", target_ref="00000000-0000-0000-0000-000000000001", family="idor",
        locus={"route": "/users/1", "method": "get", "parameter": "id"},
    ) == "5b067c649dac52f191595a41d75e669774f350b2bbc2e510f0458fd14be26a0d"
    assert candidates.candidate_fingerprint(
        plane="device", target_ref="00000000-0000-0000-0000-000000000002",
        family="service_exposure", locus={"transport": "tcp", "port": "23"},
    ) == "cb98c173ff5b0c7a2181813e9ad0871ddb52e4e474c100977a187f79aadd69cf"


@pytest.mark.parametrize("locus", [
    {"bad key": "x"},
    {"path": "/a", "PATH": "/b"},
    {f"k{i}": "v" for i in range(40)},
    {f"note{i}": "x" * 1000 for i in range(20)},
    {"url": "https://h.example/" + "a" * 990 + "?id=1"},
    {"route": ["/r", "x" * 1001]},
    {"paths": [f"/p{i:03d}" for i in range(101)]},
    {"tags": [str(i) for i in range(101)]},
    {"port": 70000},
    {"port": 0},
    {"port": "abc"},
    {"port": True},
    {"port": 80.5},
])
def test_locus_that_cannot_be_kept_whole_is_refused_rather_than_truncated(locus):
    with pytest.raises(ValueError):
        candidates.canonical_locus(locus)
    with pytest.raises(ValueError):
        router.HuntCandidateRequest(
            family="x", locus=locus, title="t", claim="c", evidence_refs=["a"],
        )


def test_locus_bounds_apply_after_set_normalization_and_keep_existing_values():
    # Duplicates collapse and the set is sorted before the item bound applies.
    paths = [f"/p{i:03d}" for i in range(100)]
    assert candidates.canonical_locus({"paths": paths + paths[:50]}) == candidates.canonical_locus(
        {"paths": list(reversed(paths))}
    )
    # A value exactly at the bound (as stored by the previous normalizer) is still accepted.
    assert candidates.canonical_locus({"url": "u" * 1000}) == {"url": "u" * 1000}
    assert candidates.canonical_locus({"port": "443"}) == candidates.canonical_locus({"port": 443})


def test_distinct_claim_with_same_identity_never_overwrites_the_stored_candidate():
    conn = SqliteConnection()
    git_ref = "action:" + str(uuid.uuid4())
    critical = asyncio.run(candidates.upsert_candidate(conn, _candidate(
        title=".git-credentials exposed", claim="GET /.git-credentials returns a token",
        severity="critical", refs=[git_ref],
    ), created_by="test"))
    rag = asyncio.run(candidates.upsert_candidate(conn, _candidate(
        title="RAG returns other tenant documents", claim="Cross-tenant retrieval",
        severity="medium",
    ), created_by="test"))

    assert critical["outcome"] == "inserted" and critical["inserted"] is True
    assert rag["outcome"] == "inserted" and rag["inserted"] is True
    assert rag["id"] != critical["id"]
    assert rag["distinct_from_candidate_id"] == critical["id"]
    rows = {row["id"]: row for row in conn.rows()}
    assert len(rows) == 2
    stored = rows[critical["id"]]
    assert stored["title"] == ".git-credentials exposed"
    assert stored["claim"] == "GET /.git-credentials returns a token"
    assert stored["claimed_severity"] == "critical"
    assert json.loads(stored["evidence_refs"]) == [git_ref]
    assert rows[rag["id"]]["claimed_severity"] == "medium"


def test_same_claim_merges_evidence_without_replacing_the_claim():
    conn = SqliteConnection()
    first_ref, second_ref = "action:" + str(uuid.uuid4()), "receipt:" + str(uuid.uuid4())
    first = asyncio.run(candidates.upsert_candidate(conn, _candidate(
        title="Health endpoint discloses key hint", claim="GET /health returns key_hint",
        severity="medium", refs=[first_ref],
    ), created_by="test"))
    again = asyncio.run(candidates.upsert_candidate(conn, _candidate(
        title="health endpoint  discloses key hint", claim="Reworded claim", severity="low",
        refs=[second_ref, first_ref],
    ), created_by="test"))

    assert again["outcome"] == "merged" and again["inserted"] is False
    assert again["id"] == first["id"]
    (row,) = conn.rows()
    assert row["claim"] == "GET /health returns key_hint"
    assert row["claimed_severity"] == "medium"
    assert json.loads(row["evidence_refs"]) == [first_ref, second_ref]
    claims = [item["claim"] for item in conn.observations()]
    assert claims == ["GET /health returns key_hint", "Reworded claim"]


def test_terminal_candidate_is_only_observed_by_a_later_sighting():
    conn = SqliteConnection()
    first_ref = "action:" + str(uuid.uuid4())
    first = asyncio.run(candidates.upsert_candidate(conn, _candidate(
        title="Exposed", claim="Same claim", refs=[first_ref],
    ), created_by="test"))
    conn.db.execute("UPDATE investigation_candidates SET status='verified'")
    later = asyncio.run(candidates.upsert_candidate(conn, _candidate(
        title="Exposed", claim="Same claim", refs=["action:" + str(uuid.uuid4())],
    ), created_by="test"))
    assert later["outcome"] == "observed" and later["id"] == first["id"]
    (row,) = conn.rows()
    assert json.loads(row["evidence_refs"]) == [first_ref]
    assert len(conn.observations()) == 2


def test_repeated_distinct_claim_merges_into_its_own_row():
    conn = SqliteConnection()
    asyncio.run(candidates.upsert_candidate(conn, _candidate(title="A", claim="claim A"), created_by="t"))
    b1 = asyncio.run(candidates.upsert_candidate(conn, _candidate(title="B", claim="claim B"), created_by="t"))
    b2 = asyncio.run(candidates.upsert_candidate(conn, _candidate(title="B", claim="claim B"), created_by="t"))
    assert b1["outcome"] == "inserted" and b2["outcome"] == "merged"
    assert b2["id"] == b1["id"]
    assert len(conn.rows()) == 2


def _set_status(conn, candidate_id, status):
    conn.db.execute("UPDATE investigation_candidates SET status=? WHERE id=?", [status, candidate_id])


def test_post_after_patch_merges_into_the_claims_own_row_instead_of_failing():
    conn = SqliteConnection()
    first = asyncio.run(candidates.upsert_candidate(conn, _candidate(title="T1", claim="C1"), created_by="t"))
    second = asyncio.run(candidates.upsert_candidate(conn, _candidate(title="T2", claim="C2"), created_by="t"))
    assert second["distinct_from_candidate_id"] == first["id"]
    patched = asyncio.run(candidates.update_candidate_for_hunt(
        conn, hunt_run_id=HUNT, candidate_id=second["id"],
        changes={"claim": "C2 reworded"}, created_by="t",
    ))
    assert patched["id"] == second["id"]
    new_ref = "action:" + str(uuid.uuid4())
    again = asyncio.run(candidates.upsert_candidate(
        conn, _candidate(title="T5", claim="C2", refs=[new_ref]), created_by="t",
    ))
    assert again["outcome"] == "merged" and again["id"] == second["id"]
    assert again["unapplied_fields"] == ["title", "claim"]
    row = {item["id"]: item for item in conn.rows()}[second["id"]]
    assert row["claim"] == "C2 reworded" and new_ref in json.loads(row["evidence_refs"])
    assert len(conn.rows()) == 2


@pytest.mark.parametrize("status", ["verification_queued", "verifying"])
def test_sighting_never_changes_a_candidate_under_verification(status):
    conn = SqliteConnection()
    first_ref = "action:" + str(uuid.uuid4())
    first = asyncio.run(candidates.upsert_candidate(
        conn, _candidate(title="T1", claim="C1", refs=[first_ref]), created_by="t"))
    _set_status(conn, first["id"], status)
    sighting = _candidate(title="T1", claim="C1", refs=["action:" + str(uuid.uuid4())])
    with pytest.raises(candidates.CandidateLifecycleError) as exc:
        asyncio.run(candidates.upsert_candidate(conn, sighting, created_by="t"))
    assert exc.value.code == "candidate_verification_in_flight"
    observed = asyncio.run(candidates.upsert_candidate(conn, sighting, created_by="t", strict=False))
    assert observed["outcome"] == "observed"
    assert observed["reason"] == "candidate_verification_in_flight"
    assert observed["unapplied_fields"] == ["evidence_refs"]
    (row,) = conn.rows()
    assert json.loads(row["evidence_refs"]) == [first_ref]


def test_sighting_refuses_to_truncate_evidence_beyond_the_limit():
    conn = SqliteConnection()
    refs = ["action:" + str(uuid.uuid4()) for _ in range(candidates.MAX_EVIDENCE_REFS)]
    asyncio.run(candidates.upsert_candidate(conn, _candidate(title="T1", claim="C1", refs=refs), created_by="t"))
    extra = _candidate(title="T1", claim="C1", refs=["action:" + str(uuid.uuid4())])
    with pytest.raises(candidates.CandidateLifecycleError) as exc:
        asyncio.run(candidates.upsert_candidate(conn, extra, created_by="t"))
    assert exc.value.code == "candidate_evidence_limit"
    observed = asyncio.run(candidates.upsert_candidate(conn, extra, created_by="t", strict=False))
    assert observed["reason"] == "candidate_evidence_limit"
    (row,) = conn.rows()
    assert json.loads(row["evidence_refs"]) == refs


def test_merge_reports_the_severity_it_did_not_apply():
    conn = SqliteConnection()
    asyncio.run(candidates.upsert_candidate(
        conn, _candidate(title="T1", claim="C1", severity="low"), created_by="t"))
    merged = asyncio.run(candidates.upsert_candidate(
        conn, _candidate(title="T1", claim="C1", severity="critical"), created_by="t"))
    assert merged["outcome"] == "merged" and merged["unapplied_fields"] == ["severity"]
    (row,) = conn.rows()
    assert row["claimed_severity"] == "low"


def _advisory(severity, title, source_kind="automatic_device_advisory_correlation"):
    return candidates.normalize_candidate(
        plane="device", device_target_id=TARGET, family="device_firmware_advisory",
        locus={"transport": "tcp", "port": 443, "advisory_id": "CVE-2026-0001",
               "cpe": "cpe:2.3:o:vendor:fw:1.0", "version": "1.0"},
        title=title, claim="Offline advisory CVE-2026-0001 matched cpe version 1.0.",
        severity=severity, evidence_refs=[], source_kind=source_kind,
    )


def test_advisory_recorrelation_restates_severity_and_title_from_the_same_source():
    conn = SqliteConnection()
    first = asyncio.run(candidates.upsert_candidate(
        conn, _advisory("medium", "Old advisory title"), created_by="d",
        strict=False, refresh_same_source=True))
    again = asyncio.run(candidates.upsert_candidate(
        conn, _advisory("critical", "Revised advisory title"), created_by="d",
        strict=False, refresh_same_source=True))
    assert again["outcome"] == "merged" and again["id"] == first["id"]
    assert "unapplied_fields" not in again
    (row,) = conn.rows()
    assert (row["claimed_severity"], row["title"]) == ("critical", "Revised advisory title")
    # Another producer's sighting never restates the row, even when refresh is requested.
    other = asyncio.run(candidates.upsert_candidate(
        conn, _advisory("low", "Revised advisory title", source_kind="hunt_v2"), created_by="h",
        strict=False, refresh_same_source=True))
    assert other["unapplied_fields"] == ["severity"]
    (row,) = conn.rows()
    assert row["claimed_severity"] == "critical"


@pytest.mark.asyncio
async def test_candidate_route_answers_409_for_a_candidate_under_verification(monkeypatch):
    action = str(uuid.uuid4())

    class Store:
        @asynccontextmanager
        async def acquire(self):
            yield self

        @asynccontextmanager
        async def transaction(self, **_kwargs):
            yield self

        async def fetch(self, _sql, *args):
            return [{"id": action, "kind": "action", "status": "completed"}]

        async def execute(self, query, *args):
            raise AssertionError("a refused sighting must not charge the candidate budget")

    run = {**_run(), "status": "active", "objective": "o",
           "budget_used_json": {"candidates": 0}, "budget_json": {"max_candidates": 5}}

    async def lookup(_conn, _hunt_id, for_update=False):
        return run

    async def upsert(*_args, **kwargs):
        assert kwargs.get("strict", True) is True
        raise router.investigation_candidates.CandidateLifecycleError(
            "candidate_verification_in_flight", "busy",
        )

    monkeypatch.setattr(router, "_pool", lambda: Store())
    monkeypatch.setattr(router, "_hunt_run_or_404", lookup)
    monkeypatch.setattr(router.investigation_candidates, "upsert_candidate", upsert)
    request = router.HuntCandidateRequest(
        family="data_exposure", locus={"path": "/x"}, title="t", claim="c",
        evidence_refs=[action],
    )
    with pytest.raises(router.HTTPException) as exc:
        await router.create_hunt_candidate(HUNT, request)
    assert exc.value.status_code == 409
    assert exc.value.detail["error"] == "candidate_verification_in_flight"


class EvidenceConnection:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    async def fetch(self, sql, *args):
        self.calls.append((sql, args))
        return [row for row in self.rows if row["id"] in args[0]]


def _run(**extra):
    return {"id": HUNT, "target_id": TARGET, "device_target_id": None, "context_pack": {}, **extra}


def test_evidence_refs_must_resolve_to_this_hunts_records():
    action, receipt, other = (str(uuid.uuid4()) for _ in range(3))
    conn = EvidenceConnection([
        {"id": action, "kind": "action", "status": "completed"},
        {"id": receipt, "kind": "receipt", "status": "partial"},
    ])
    refs = [f"action:{action}", f"RECEIPT:{receipt}", action]
    assert asyncio.run(candidate_evidence.resolve_candidate_evidence(
        conn, run=_run(), references=refs,
    )) == refs
    sql, args = conn.calls[0]
    assert args[1:] == (HUNT, TARGET, None)
    assert "hunt_run_id = $2" in sql

    for bad in ([f"action:{other}"], [f"receipt:{action}"], ["not-a-uuid"], [f"scan:{action}"]):
        with pytest.raises(candidate_evidence.CandidateEvidenceError) as exc:
            asyncio.run(candidate_evidence.resolve_candidate_evidence(
                conn, run=_run(), references=bad,
            ))
        assert exc.value.references == bad


@pytest.mark.parametrize("status", ["failed", "blocked", "running", "reserved", "cancelled"])
def test_evidence_refs_must_name_a_completed_or_partial_action(status):
    unsettled, receipt, settled, transaction = (str(uuid.uuid4()) for _ in range(4))
    conn = EvidenceConnection([
        {"id": unsettled, "kind": "action", "status": status},
        {"id": receipt, "kind": "receipt", "status": status},
        {"id": settled, "kind": "action", "status": "completed"},
        {"id": transaction, "kind": "transaction", "status": None},
    ])
    for reference in (f"action:{unsettled}", unsettled, f"receipt:{receipt}"):
        with pytest.raises(candidate_evidence.CandidateEvidenceError) as exc:
            asyncio.run(candidate_evidence.resolve_candidate_evidence(
                conn, run=_run(), references=[f"action:{settled}", reference],
            ))
        assert exc.value.code == candidate_evidence.UNSETTLED
        assert exc.value.unsettled == [reference] and exc.value.references == []
    # A missing reference outranks an unsettled one, and both are reported.
    missing = str(uuid.uuid4())
    with pytest.raises(candidate_evidence.CandidateEvidenceError) as exc:
        asyncio.run(candidate_evidence.resolve_candidate_evidence(
            conn, run=_run(), references=[unsettled, missing],
        ))
    assert exc.value.code == candidate_evidence.UNRESOLVED
    assert exc.value.references == [missing] and exc.value.unsettled == [unsettled]
    # Captured traffic is evidence whatever became of its action.
    assert asyncio.run(candidate_evidence.resolve_candidate_evidence(
        conn, run=_run(), references=[f"transaction:{transaction}"],
    )) == [f"transaction:{transaction}"]


@pytest.mark.asyncio
async def test_candidate_route_refuses_an_admission_refused_action_as_evidence(monkeypatch):
    refused = str(uuid.uuid4())

    class Store:
        @asynccontextmanager
        async def acquire(self):
            yield self

        @asynccontextmanager
        async def transaction(self, **_kwargs):
            yield self

        async def fetch(self, _sql, *args):
            return [{"id": refused, "kind": "action", "status": "failed"}] if refused in args[0] else []

        async def execute(self, query, *args):
            raise AssertionError("an unsettled candidate must not be stored")

    run = {**_run(), "status": "active", "objective": "o",
           "budget_used_json": {"candidates": 0}, "budget_json": {"max_candidates": 5}}

    async def lookup(_conn, _hunt_id, for_update=False):
        return run

    monkeypatch.setattr(router, "_pool", lambda: Store())
    monkeypatch.setattr(router, "_hunt_run_or_404", lookup)
    request = router.HuntCandidateRequest(
        family="data_exposure", locus={"path": "/x"}, title="t", claim="c",
        evidence_refs=[f"action:{refused}"],
    )
    with pytest.raises(router.HTTPException) as exc:
        await router.create_hunt_candidate(HUNT, request)
    assert exc.value.status_code == 422
    assert exc.value.detail["error"] == "candidate_evidence_unsettled"
    assert exc.value.detail["unsettled_evidence_refs"] == [f"action:{refused}"]


def test_device_evidence_refs_resolve_against_this_hunts_device_runtime():
    run = _run(target_id=None, device_target_id=TARGET, context_pack=json.dumps({
        "device_runtime": {"evidence": {"devref_1": {"kind": "banner"}}},
    }))
    conn = EvidenceConnection([])
    assert asyncio.run(candidate_evidence.resolve_candidate_evidence(
        conn, run=run, references=["devref_1"],
    )) == ["devref_1"]
    with pytest.raises(candidate_evidence.CandidateEvidenceError):
        asyncio.run(candidate_evidence.resolve_candidate_evidence(
            conn, run=run, references=["devref_2"],
        ))
    with pytest.raises(candidate_evidence.CandidateEvidenceError):
        asyncio.run(candidate_evidence.resolve_candidate_evidence(
            conn, run=_run(), references=["devref_1"],
        ))


@pytest.mark.asyncio
async def test_candidate_route_refuses_unresolved_evidence_before_writing(monkeypatch):
    executed: list[str] = []

    class Store:

        @asynccontextmanager
        async def acquire(self):
            yield self

        @asynccontextmanager
        async def transaction(self, **_kwargs):
            yield self

        async def fetch(self, _sql, *_args):
            return []

        async def execute(self, query, *args):
            executed.append(query)

    run = {**_run(), "status": "active", "objective": "o",
           "budget_used_json": {"candidates": 0}, "budget_json": {"max_candidates": 5}}

    async def lookup(_conn, _hunt_id, for_update=False):
        return run

    async def upsert(*_args, **_kwargs):
        raise AssertionError("an unresolved candidate must not be stored")

    monkeypatch.setattr(router, "_pool", lambda: Store())
    monkeypatch.setattr(router, "_hunt_run_or_404", lookup)
    monkeypatch.setattr(router.investigation_candidates, "upsert_candidate", upsert)
    request = router.HuntCandidateRequest(
        family="data_exposure", locus={"path": "/x"}, title="t", claim="c",
        evidence_refs=[str(uuid.uuid4())],
    )
    with pytest.raises(router.HTTPException) as exc:
        await router.create_hunt_candidate(HUNT, request)
    assert exc.value.status_code == 422
    assert exc.value.detail["error"] == "candidate_evidence_unresolved"
    assert executed == []


def test_contract_documents_the_locus_schema_and_evidence_forms():
    contract = hunt_start_public_contract()["candidates"]
    assert {"path", "paths", "origin", "principal", "address", "input", "operation"} <= set(
        contract["locus_keys"])
    assert "ignored_for_identity" in contract["locus_other_keys"]
    assert contract["max_locus_keys"] == candidates.MAX_LOCUS_KEYS
    assert "action:<uuid>" in contract["evidence_ref_forms"]


DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
PG_DDL = candidate_schema_sql()


@asynccontextmanager
async def _postgres():
    import asyncpg
    assert urlsplit(DSN).hostname in {"localhost", "127.0.0.1", "::1", "postgres"}
    schema = "hunt_candidate_identity_" + uuid.uuid4().hex
    admin = await asyncpg.connect(DSN)
    try:
        await admin.execute(f'CREATE SCHEMA "{schema}"')
        await admin.execute(f'SET search_path TO "{schema}"')
        await admin.execute(PG_DDL)
        yield admin
    finally:
        await admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await admin.close()


@pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")
def test_postgres_upsert_and_evidence_resolution():
    async def scenario():
        async with _postgres() as conn:
            async with conn.transaction():
                first = await candidates.upsert_candidate(conn, _candidate(
                    title="git", claim="git creds", severity="critical"), created_by="t")
                second = await candidates.upsert_candidate(conn, _candidate(
                    title="rag", claim="rag leak", severity="low"), created_by="t")
                merged = await candidates.upsert_candidate(conn, _candidate(
                    title="git", claim="git creds", severity="info"), created_by="t")
            assert [first["outcome"], second["outcome"], merged["outcome"]] == [
                "inserted", "inserted", "merged"]
            row = await conn.fetchrow(
                "SELECT claim, claimed_severity, evidence_refs FROM investigation_candidates WHERE id=$1",
                uuid.UUID(first["id"]))
            assert row["claim"] == "git creds" and row["claimed_severity"] == "critical"
            assert len(json.loads(row["evidence_refs"])) == 2

            other_hunt = uuid.uuid4()
            action, receipt, foreign = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
            await _insert_action(conn, action, uuid.UUID(HUNT), "completed", receipt)
            await _insert_action(conn, foreign, other_hunt, "completed")
            run = _run()
            assert await candidate_evidence.resolve_candidate_evidence(
                conn, run=run, references=[f"action:{action}", f"receipt:{receipt}"],
            )
            with pytest.raises(candidate_evidence.CandidateEvidenceError) as exc:
                await candidate_evidence.resolve_candidate_evidence(
                    conn, run=run, references=[f"action:{foreign}", str(uuid.uuid4())],
                )
            assert len(exc.value.references) == 2
    asyncio.run(scenario())


async def _insert_action(conn, action_id, hunt_id, status, receipt_id=None):
    await conn.execute(
        """INSERT INTO hunt_actions (id, hunt_run_id, capability_name, status, receipt_id)
           VALUES ($1,$2,'http.request',$3,$4)""",
        action_id, hunt_id, status, receipt_id,
    )


@pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")
def test_postgres_evidence_must_cite_a_settled_action():
    async def scenario():
        async with _postgres() as conn:
            hunt = uuid.UUID(HUNT)
            ids = {status: (uuid.uuid4(), uuid.uuid4()) for status in (
                "completed", "partial", "failed", "blocked", "running",
            )}
            for status, (action, receipt) in ids.items():
                await _insert_action(conn, action, hunt, status, receipt)
            transaction = uuid.uuid4()
            await conn.execute(
                """INSERT INTO http_transactions (id, plane, hunt_run_id, method, url)
                   VALUES ($1,'hunt',$2,'GET','https://app.test/')""",
                transaction, hunt,
            )
            settled = [
                f"action:{ids['completed'][0]}", f"receipt:{ids['partial'][1]}",
                str(ids["partial"][0]), f"transaction:{transaction}",
            ]
            assert await candidate_evidence.resolve_candidate_evidence(
                conn, run=_run(), references=settled,
            ) == settled
            for status in ("failed", "blocked", "running"):
                action, receipt = ids[status]
                for reference in (f"action:{action}", f"receipt:{receipt}", str(action)):
                    with pytest.raises(candidate_evidence.CandidateEvidenceError) as exc:
                        await candidate_evidence.resolve_candidate_evidence(
                            conn, run=_run(), references=[settled[0], reference],
                        )
                    assert exc.value.code == "candidate_evidence_unsettled"
                    assert exc.value.unsettled == [reference] and exc.value.references == []
    asyncio.run(scenario())


@pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")
def test_postgres_sightings_after_patch_in_flight_and_refresh():
    async def scenario():
        async with _postgres() as conn:
            async with conn.transaction():
                first = await candidates.upsert_candidate(
                    conn, _candidate(title="T1", claim="C1"), created_by="t")
                second = await candidates.upsert_candidate(
                    conn, _candidate(title="T2", claim="C2"), created_by="t")
                await candidates.update_candidate_for_hunt(
                    conn, hunt_run_id=HUNT, candidate_id=second["id"],
                    changes={"claim": "C2 reworded", "title": "T2 reworded"}, created_by="t",
                )
                again = await candidates.upsert_candidate(
                    conn, _candidate(title="T5", claim="C2"), created_by="t")
                assert again["outcome"] == "merged" and again["id"] == second["id"]
                await conn.execute(
                    "UPDATE investigation_candidates SET status='verifying' WHERE id=$1",
                    uuid.UUID(first["id"]))
                with pytest.raises(candidates.CandidateLifecycleError):
                    async with conn.transaction():
                        await candidates.upsert_candidate(
                            conn, _candidate(title="T1", claim="C1"), created_by="t")
                observed = await candidates.upsert_candidate(
                    conn, _candidate(title="T1", claim="C1"), created_by="t", strict=False)
                assert observed["reason"] == "candidate_verification_in_flight"
                await candidates.upsert_candidate(
                    conn, _advisory("medium", "Old"), created_by="d", strict=False,
                    refresh_same_source=True)
                refreshed = await candidates.upsert_candidate(
                    conn, _advisory("critical", "New"), created_by="d", strict=False,
                    refresh_same_source=True)
                row = await conn.fetchrow(
                    "SELECT title, claimed_severity FROM investigation_candidates WHERE id=$1",
                    uuid.UUID(refreshed["id"]))
                assert (row["title"], row["claimed_severity"]) == ("New", "critical")
    asyncio.run(scenario())


def test_candidate_postgres_acceptance_runs_in_the_provisioned_ci_database():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / ".github/workflows/hunt-record-integrity.yml").read_text()
    for test_file in (
        "tests/test_hunt_candidate_identity.py", "tests/test_hunt_action_outcomes.py",
        "tests/test_hunt_budget_exhaustion.py", "tests/test_hunt_content_discover_replay.py",
    ):
        assert test_file in source
    assert "'tests/hunt_candidate_pg_schema.py'" in source and "'db/init.sql'" in source
