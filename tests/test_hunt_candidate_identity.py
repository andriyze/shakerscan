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

TARGET = str(uuid.uuid4())
HUNT = str(uuid.uuid4())

SQLITE_DDL = """
CREATE TABLE investigation_candidates(id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
 plane TEXT,target_id TEXT,device_target_id TEXT,research_episode_id TEXT,agent_hunt_run_id TEXT,
 device_agent_run_id TEXT,hunt_run_id TEXT,family TEXT,canonical_locus TEXT,title TEXT,claim TEXT,
 claimed_severity TEXT,evidence_refs TEXT,verifier_contract_id TEXT,source_kind TEXT,
 fingerprint TEXT UNIQUE,status TEXT,created_by TEXT,last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
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
        "method": "GET", "x_tool": "rag.search",
    }
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
])
def test_locus_that_cannot_be_kept_whole_is_refused_rather_than_truncated(locus):
    with pytest.raises(ValueError):
        candidates.canonical_locus(locus)
    with pytest.raises(ValueError):
        router.HuntCandidateRequest(
            family="x", locus=locus, title="t", claim="c", evidence_refs=["a"],
        )


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
        {"id": action, "kind": "action"}, {"id": receipt, "kind": "receipt"},
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
    assert {"path", "paths", "origin", "principal", "address"} <= set(contract["locus_keys"])
    assert contract["max_locus_keys"] == candidates.MAX_LOCUS_KEYS
    assert "action:<uuid>" in contract["evidence_ref_forms"]


DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
PG_DDL = """
CREATE TABLE investigation_candidates(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),plane text,target_id uuid,device_target_id uuid,
 research_episode_id uuid,agent_hunt_run_id uuid,device_agent_run_id uuid,hunt_run_id uuid,
 family text,canonical_locus jsonb,title text,claim text,claimed_severity text,evidence_refs jsonb,
 verifier_contract_id text,source_kind text,fingerprint text UNIQUE,status text,created_by text,
 last_seen_at timestamptz DEFAULT NOW(),created_at timestamptz DEFAULT NOW(),updated_at timestamptz DEFAULT NOW());
CREATE TABLE investigation_candidate_observations(
 id bigserial PRIMARY KEY,candidate_id uuid,research_episode_id uuid,agent_hunt_run_id uuid,
 device_agent_run_id uuid,hunt_run_id uuid,source_kind text,title text,claim text,claimed_severity text,
 evidence_refs jsonb,verifier_contract_id text,observation_context jsonb,created_by text,
 created_at timestamptz DEFAULT NOW());
CREATE TABLE hunt_actions(id uuid PRIMARY KEY,hunt_run_id uuid,receipt_id uuid);
CREATE TABLE http_transactions(id uuid PRIMARY KEY,hunt_run_id uuid);
CREATE TABLE findings(id uuid PRIMARY KEY,hunt_run_id uuid,target_id uuid,device_target_id uuid);
"""


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
            await conn.execute("INSERT INTO hunt_actions VALUES($1,$2,$3)", action, uuid.UUID(HUNT), receipt)
            await conn.execute("INSERT INTO hunt_actions VALUES($1,$2,NULL)", foreign, other_hunt)
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
