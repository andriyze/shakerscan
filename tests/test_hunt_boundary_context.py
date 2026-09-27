"""Exercise production ownership SQL against a real, read-only SQLite fixture.

Only the PostgreSQL UUID casts and UUID-array syntax are translated; joins,
filters, ordering and limits are the actual query strings used by the service.
There are no network targets, credentials, compilers or verifier invocations.
"""
from __future__ import annotations

import ast
import json
import re
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import UUID

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from api.hunt.boundary_context import (
    BoundaryContextError, inspect_candidate_boundary_context,
)


def uid(n):
    return str(UUID(int=n))


HUNT, OTHER, TARGET, OTHER_TARGET, CANDIDATE = map(uid, range(1, 6))
ACTION, RECEIPT, TRANSACTION, FOREIGN_ACTION = map(uid, range(20, 24))
SECRET = "sensitive-value-that-must-not-be-returned"
RUN = {"id": HUNT, "target_id": TARGET, "device_target_id": None}


class DB:
    def __init__(self):
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.queries = []
        self.transactions = []
        self.db.executescript("""
            CREATE TABLE investigation_candidates (
                id TEXT, plane TEXT, target_id TEXT, device_target_id TEXT,
                family TEXT, status TEXT, canonical_locus TEXT
            );
            CREATE TABLE investigation_candidate_observations (
                id TEXT, candidate_id TEXT, hunt_run_id TEXT,
                evidence_refs TEXT, observed_at INTEGER
            );
            CREATE TABLE hunt_actions(id TEXT, hunt_run_id TEXT, receipt_id TEXT);
            CREATE TABLE tool_receipts(id TEXT);
            CREATE TABLE http_transactions (
                id TEXT, hunt_run_id TEXT, plane TEXT, scan_id TEXT,
                target_id TEXT, device_target_id TEXT
            );
        """)
        self.db.execute("INSERT INTO investigation_candidates VALUES(?,?,?,?,?,?,?)", (
            CANDIDATE, "web", TARGET, None, "approval_bypass", "new",
            json.dumps({"ai_boundary_context": {
                "prompt": SECRET, "state_path": "status", "initial_value": None,
                "forbidden_value": "changed", "verifier_path": "/state",
                "approval_path": "/approval", "approval_state_path": "state",
                "required_approval_value": "approved", "unexpected_secret": SECRET,
            }}),
        ))
        self.db.execute("INSERT INTO investigation_candidate_observations VALUES(?,?,?,?,?)", (
            uid(100), CANDIDATE, HUNT, json.dumps([ACTION, RECEIPT, TRANSACTION]), 1,
        ))
        self.db.executemany("INSERT INTO hunt_actions VALUES(?,?,?)", [
            (ACTION, HUNT, RECEIPT), (FOREIGN_ACTION, OTHER, None),
        ])
        self.db.execute("INSERT INTO tool_receipts VALUES(?)", (RECEIPT,))
        self.db.execute("INSERT INTO http_transactions VALUES(?,?,?,?,?,?)", (
            TRANSACTION, HUNT, "hunt", None, TARGET, None,
        ))
        self.db.commit()

    @asynccontextmanager
    async def transaction(self, **kwargs):
        self.transactions.append(kwargs)
        yield self

    @asynccontextmanager
    async def acquire(self):
        yield self

    def guard(self):
        forbidden = {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
                     sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_DROP_TABLE}
        self.db.set_authorizer(lambda op, *args: sqlite3.SQLITE_DENY if op in forbidden else sqlite3.SQLITE_OK)

    def query(self, sql, args):
        self.queries.append(sql)
        assert sql.lstrip().startswith("SELECT")
        assert "FOR UPDATE" not in sql
        sql = re.sub(r"=ANY\(\$1::uuid\[\]\)", " IN (SELECT value FROM json_each($1))", sql)
        sql = re.sub(r"::uuid\b", "", sql)
        params = {str(i): json.dumps(value) if isinstance(value, list) else value
                  for i, value in enumerate(args, 1)}
        return self.db.execute(sql, params)

    async def fetchrow(self, sql, *args):
        return self.query(sql, args).fetchone()

    async def fetch(self, sql, *args):
        return self.query(sql, args).fetchall()


async def inspect(db, *, run=None):
    db.guard()
    return await inspect_candidate_boundary_context(db, run=run or RUN, candidate_id=CANDIDATE)


@pytest.mark.asyncio
async def test_candidate_id_resolves_real_hunt_local_links_without_returning_values():
    db = DB()
    result = await inspect(db)
    assert len(db.queries) == 3
    assert result["status"] == "context_available"
    assert {r["kind"] for r in result["evidence"]["resolved"]} == {
        "hunt_action", "tool_receipt", "http_transaction",
    }
    assert result["evidence"]["complete_for_inspected_references"] is True
    assert result["evidence"]["content_integrity_verified"] is False
    assert result["proposal_compiled"] is False
    assert result["execution_enabled"] is False
    assert result["promotion_authority"] is False
    assert result["verification_performed"] is False
    assert SECRET not in json.dumps(result)
    assert "unexpected_secret" not in json.dumps(result)
    assert "initial_value" in result["context"]["present_fields"]  # explicit JSON null is present


@pytest.mark.asyncio
async def test_foreign_hunt_cannot_read_candidate_even_with_same_target():
    db = DB()
    with pytest.raises(BoundaryContextError, match="candidate_not_found"):
        await inspect(db, run={**RUN, "id": OTHER})
    assert len(db.queries) == 1


@pytest.mark.asyncio
async def test_same_hunt_observation_cannot_authorize_a_foreign_target():
    db = DB()
    with pytest.raises(BoundaryContextError, match="candidate_not_found"):
        await inspect(db, run={**RUN, "target_id": OTHER_TARGET})


@pytest.mark.asyncio
async def test_shared_candidate_does_not_import_another_hunts_observation_refs():
    db = DB()
    db.db.execute("INSERT INTO investigation_candidate_observations VALUES(?,?,?,?,?)", (
        uid(101), CANDIDATE, OTHER, json.dumps([FOREIGN_ACTION]), 99,
    ))
    result = await inspect(db)
    assert result["evidence"]["observations_read"] == 1
    assert FOREIGN_ACTION not in json.dumps(result)


@pytest.mark.asyncio
async def test_forged_foreign_refs_and_missing_refs_are_indistinguishable():
    async def unavailable(reference):
        db = DB()
        db.db.execute("UPDATE investigation_candidate_observations SET evidence_refs=?", (json.dumps([reference]),))
        return await inspect(db)
    foreign, absent = await unavailable(FOREIGN_ACTION), await unavailable(uid(999))
    assert foreign == absent
    assert foreign["evidence"]["unavailable_count"] == 1
    assert foreign["status"] == "needs_context"


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [
    "UPDATE http_transactions SET target_id='wrong'",
    "UPDATE http_transactions SET hunt_run_id='wrong'",
    "UPDATE http_transactions SET plane='scan'",
    "UPDATE http_transactions SET scan_id='also-a-scan'",
    "UPDATE hunt_actions SET hunt_run_id='wrong' WHERE receipt_id IS NOT NULL",
])
async def test_evidence_association_checks_real_ownership_not_caller_claims(change):
    db = DB(); db.db.execute(change)
    result = await inspect(db)
    assert result["evidence"]["unavailable_count"] > 0
    assert result["evidence"]["complete_for_inspected_references"] is False


@pytest.mark.asyncio
async def test_deleted_evidence_does_not_become_a_clean_result():
    db = DB(); db.db.execute("DELETE FROM tool_receipts")
    result = await inspect(db)
    assert result["evidence"]["unavailable_count"] == 1
    assert result["status"] == "needs_context"


@pytest.mark.asyncio
async def test_ambiguous_reference_namespace_is_not_guessed():
    db = DB()
    db.db.execute("INSERT INTO hunt_actions VALUES(?,?,?)", (TRANSACTION, HUNT, None))
    result = await inspect(db)
    assert result["evidence"]["ambiguous_count"] == 1
    assert TRANSACTION not in json.dumps(result["evidence"]["resolved"])


@pytest.mark.asyncio
async def test_legacy_stringified_context_is_reported_not_evaluated():
    db = DB()
    db.db.execute("UPDATE investigation_candidates SET canonical_locus=?", (
        json.dumps({"ai_boundary_context": "{'prompt': '__import__(os).system(...)'}"}),
    ))
    result = await inspect(db)
    assert result["context"]["issues"] == ["boundary_context_not_structured"]
    assert result["status"] == "needs_context"
    assert "__import__" not in json.dumps(result)


@pytest.mark.asyncio
async def test_generic_bola_is_not_automatically_declared_an_ai_boundary():
    db = DB(); db.db.execute("UPDATE investigation_candidates SET family='bola'")
    result = await inspect(db)
    assert result["kind"] is None
    assert result["status"] == "needs_context"


@pytest.mark.asyncio
@pytest.mark.parametrize("refs", ["not json", json.dumps([SECRET]), json.dumps([{}, 17, None]), "[" * 2000])
async def test_malformed_or_sensitive_refs_are_not_echoed(refs):
    db = DB()
    db.db.execute("UPDATE investigation_candidate_observations SET evidence_refs=?", (refs,))
    result = await inspect(db)
    assert result["status"] == "needs_context"
    assert SECRET not in json.dumps(result)


@pytest.mark.asyncio
async def test_bounded_observation_window_reports_partial_coverage():
    db = DB()
    for n in range(51):
        db.db.execute("INSERT INTO investigation_candidate_observations VALUES(?,?,?,?,?)", (
            uid(200+n), CANDIDATE, HUNT, json.dumps([ACTION]), n+2,
        ))
    result = await inspect(db)
    assert result["evidence"]["observations_read"] == 50
    assert result["evidence"]["observations_truncated"] is True
    assert result["evidence"]["complete_for_inspected_references"] is False


@pytest.mark.asyncio
async def test_reference_cap_is_visible_not_a_silent_complete_result():
    db = DB()
    refs = [uid(1000+n) for n in range(101)]
    db.db.execute("UPDATE investigation_candidate_observations SET evidence_refs=?", (json.dumps(refs),))
    result = await inspect(db)
    assert result["evidence"]["references_truncated"] is True
    assert result["evidence"]["unavailable_count"] == 100


@pytest.mark.asyncio
async def test_device_candidate_remains_bound_to_device_identity():
    db = DB()
    db.db.execute("UPDATE investigation_candidates SET plane='device',target_id=NULL,device_target_id=?", (TARGET,))
    db.db.execute("UPDATE http_transactions SET target_id=NULL,device_target_id=?", (TARGET,))
    result = await inspect(db, run={**RUN, "target_id": None, "device_target_id": TARGET})
    assert result["evidence"]["complete_for_inspected_references"] is True
    with pytest.raises(BoundaryContextError, match="candidate_not_found"):
        await inspect(db, run=RUN)


def test_actual_route_uses_read_only_snapshot_and_publishes_no_body_or_dispatch():
    # Load the actual handler unchanged into a minimal ASGI app, without importing
    # the unrelated scanner/browser/device execution graph.
    source = Path(__file__).resolve().parents[1] / "api/hunt/interaction_router.py"
    tree = ast.parse(source.read_text())
    handler = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef)
                   and n.name == "get_hunt_candidate_boundary_context")
    db = DB(); app = FastAPI()

    async def run_lookup(conn, hunt_id):
        assert conn is db and hunt_id == HUNT
        return RUN

    def parse_id(value, _name):
        try: return UUID(value)
        except ValueError as exc: raise HTTPException(400, "invalid id") from exc

    ns = dict(router=app, _pool=lambda: db, _hunt_run_or_404=run_lookup,
              _uuid_or_400=parse_id, BoundaryContextError=BoundaryContextError,
              inspect_candidate_boundary_context=inspect_candidate_boundary_context,
              HTTPException=HTTPException)
    exec(compile(ast.Module(body=[handler], type_ignores=[]), str(source), "exec"), ns)
    db.guard()
    with TestClient(app) as client:
        response = client.get(f"/hunts/{HUNT}/candidates/{CANDIDATE}/boundary-context")
        assert response.status_code == 200
        assert response.json()["execution_enabled"] is False
        assert client.get(f"/hunts/{HUNT}/candidates/not-a-uuid/boundary-context").status_code == 400
        assert client.get(f"/hunts/{HUNT}/candidates/{uid(999)}/boundary-context").status_code == 404
        operation = client.get("/openapi.json").json()["paths"][
            "/hunts/{hunt_id}/candidates/{candidate_id}/boundary-context"]["get"]
        assert "requestBody" not in operation
    assert all(t == {"isolation": "repeatable_read", "readonly": True} for t in db.transactions)


@pytest.mark.asyncio
async def test_missing_structural_fields_are_reported_explicitly():
    db = DB()
    db.db.execute("UPDATE investigation_candidates SET canonical_locus=?", (
        json.dumps({"ai_boundary_context": {"state_path": "status"}}),
    ))
    result = await inspect(db)
    assert result["status"] == "needs_context"
    assert "verifier_path" in result["context"]["missing_fields"]
    assert "approval_path" in result["context"]["missing_fields"]


def test_canonical_candidate_context_survives_json_storage_with_types_intact():
    from api.investigation_candidates import canonical_locus
    context = {"initial_value": None, "forbidden_value": False, "limit": 12,
               "nested": {"value": "x" * 2000}, "items": [True, 1, None]}
    result = canonical_locus({"method": "get", "ai_boundary_context": context})
    persisted = json.loads(json.dumps(result))
    assert persisted["method"] == "GET"
    assert persisted["ai_boundary_context"] == context
    context["nested"]["value"] = "changed after normalization"
    assert result["ai_boundary_context"]["nested"]["value"] == "x" * 2000


@pytest.mark.parametrize("context", [{"value": float("nan")}, {"value": float("inf")}, {"value": "x" * 17000}])
def test_candidate_context_rejects_non_json_or_oversized_objects(context):
    from api.investigation_candidates import canonical_locus
    with pytest.raises(ValueError, match="ai_boundary_context"):
        canonical_locus({"ai_boundary_context": context})


def test_existing_scalar_loci_and_legacy_context_strings_are_unchanged():
    from api.investigation_candidates import canonical_locus
    assert canonical_locus({"method": "get", "port": "443", "route": "/a"}) == {
        "method": "GET", "port": 443, "route": "/a",
    }
    legacy = "{'prompt': 'old'}"
    assert canonical_locus({"ai_boundary_context": legacy})["ai_boundary_context"] == legacy


def test_real_candidate_request_model_rejects_bad_context_before_storage():
    from typing import Any, Literal, Optional
    from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
    from api import investigation_candidates
    source = Path(__file__).resolve().parents[1] / "api/hunt/interaction_router.py"
    tree = ast.parse(source.read_text())
    model = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "HuntCandidateRequest")
    namespace = dict(BaseModel=BaseModel, ConfigDict=ConfigDict, Field=Field,
                     model_validator=model_validator, Any=Any, Literal=Literal, Optional=Optional,
                     investigation_candidates=investigation_candidates)
    exec(compile(ast.Module(body=[model], type_ignores=[]), str(source), "exec"), namespace)
    request = namespace["HuntCandidateRequest"]
    base = dict(family="approval_bypass", title="review", claim="unverified", evidence_refs=[ACTION])
    with pytest.raises(ValidationError, match="JSON object"):
        request(**base, locus={"ai_boundary_context": "{'old': 'format'}"})
    with pytest.raises(ValidationError, match="16384"):
        request(**base, locus={"ai_boundary_context": {"value": "x" * 17000}})
    valid = request(**base, locus={"ai_boundary_context": {"initial_value": None}})
    assert valid.locus["ai_boundary_context"]["initial_value"] is None
