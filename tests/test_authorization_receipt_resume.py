"""Regression for the worker/reader persistence seam, not a convenient inline summary.

Use the real selected-object comparison, CapabilityReceipt serialization,
repository SQL and attribution. The worker queue and target transport are not
under test; response fixtures are deterministic, and SQLite executes read SQL.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
import hashlib
import json
import sqlite3
import uuid

import pytest

from api.capabilities.authz_selected import compare_selected_objects, request_digest
from api.hunt.authorization_evidence import AuthorizationWorkflowError, attributed_outcome, digest
from api.hunt.authorization_receipt import receipt_backed_action
from api.hunt.authorization_repository import PostgresAuthorizationRepository
from api.runtime.receipts import CapabilityReceipt


HUNT, TARGET, ACTION, RECEIPT, RESERVATION = [str(uuid.UUID(int=i)) for i in range(1, 6)]
SELECTED, OWN = "https://fixture.example.test/objects/101", "https://fixture.example.test/objects/202"
KEY = "receipt-backed-investigation"
INPUT = {"primary_session_ref": str(uuid.UUID(int=6)), "secondary_session_ref": str(uuid.UUID(int=7)),
         "routes": [SELECTED, OWN]}


class Database:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.calls = []
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS hunt_actions (
          id TEXT PRIMARY KEY,hunt_run_id TEXT,capability_name TEXT,status TEXT,
          input_summary TEXT,result_summary TEXT,receipt_id TEXT,started_at TEXT,completed_at TEXT);
        CREATE TABLE IF NOT EXISTS budget_reservations (
          id TEXT PRIMARY KEY,owner_kind TEXT,owner_id TEXT,action_id TEXT,action_digest TEXT,
          capability_name TEXT,status TEXT,execution_receipt_hash TEXT,receipt_json TEXT);
        """)

    async def fetchrow(self, sql, *args):
        self.calls.append((sql, args))
        return self.db.execute(sql, {str(i): str(v) if isinstance(v, uuid.UUID) else v
                                     for i, v in enumerate(args, 1)}).fetchone()

    def save(self, action, reservation):
        self.db.execute("INSERT INTO hunt_actions VALUES(?,?,?,?,?,?,?,?,?)", (
            action["id"], action["hunt_run_id"], action["capability_name"], action["status"],
            json.dumps(action["input_summary"]), json.dumps(action["result_summary"]),
            action["receipt_id"], "2026-09-08T00:00:00+00:00", action["completed_at"]))
        self.db.execute("INSERT INTO budget_reservations VALUES(?,?,?,?,?,?,?,?,?)", (
            reservation["id"], reservation["owner_kind"], reservation["owner_id"],
            reservation["action_id"], reservation["action_digest"], reservation["capability_name"],
            reservation["status"], reservation["execution_receipt_hash"],
            json.dumps(reservation["receipt_json"])))
        self.db.commit()


def evidence(*, denied=False, expected="denied"):
    transactions = []

    async def fetch(url, *, method, headers, timeout):
        assert url in {SELECTED, OWN} and method == "GET"
        slot = headers["fixture-principal"]
        code = 403 if denied and slot == "secondary" and url == SELECTED else 200
        obj = url.rsplit("/", 1)[1]
        transactions.append({"id": str(uuid.uuid4()), "hunt_run_id": HUNT,
            "hunt_action_id": ACTION, "method": "GET", "url": url, "request_body_bytes": 0,
            "status_code": code, "principal_slot": slot, "error": None})
        return {"status_code": code, "headers": {"content-type": "application/json"},
                "body": json.dumps({"data": {"id": obj, "items": ["fixture content"]}}),
                "complete": True, "error": None}

    observation = asyncio.run(compare_selected_objects([SELECTED, OWN], fetcher=fetch,
        primary_headers={"fixture-principal": "primary"},
        secondary_headers={"fixture-principal": "secondary"}))
    # Exactly the existing worker persistence layout: metadata-only action,
    # observations in a content-addressed capability receipt on its reservation.
    receipt = CapabilityReceipt(
        capability_name="authz.verify", adapter_name="authz.differential", adapter_version="v1",
        target_id=TARGET, hunt_id=HUNT, status="succeeded", input_digest="a" * 64,
        parser_version="authz-differential/v1", receipt_id=RECEIPT, worker_id="fixture-worker",
        started_at="2026-09-08T00:00:00+00:00", finished_at="2026-09-08T00:00:01+00:00",
        budget_reservation_id=RESERVATION, budget_reservation_state="committed",
        budget_reserved={"http_requests": 4, "tool_wall_seconds": 60},
        budget_consumed={"http_requests": len(transactions), "tool_wall_seconds": 1},
        observations=[observation],
    )
    action = {"id": ACTION, "hunt_run_id": HUNT, "capability_name": "authz.verify",
        "status": "completed", "receipt_id": RECEIPT, "completed_at": receipt.finished_at,
        "input_summary": {"input_digest": digest(INPUT),
                          "idempotency_key_sha256": hashlib.sha256(KEY.encode()).hexdigest()},
        "result_summary": {"ok": True, "status": "success", "record_count": 1,
            "budget_reservation_id": RESERVATION, "budget_reservation_state": "committed",
            "receipt_id": RECEIPT, "budget_consumed": dict(receipt.budget_consumed)}}
    reservation = {"id": RESERVATION, "owner_kind": "hunt", "owner_id": HUNT,
        "action_id": ACTION, "action_digest": receipt.input_digest, "capability_name": "authz.verify",
        "status": "committed", "execution_receipt_hash": receipt.receipt_hash,
        "receipt_json": receipt.public_dict()}
    proposal = {"hunt_id": HUNT, "baseline_kind": "own_object", "expected_access": expected,
        "capture_sha256": request_digest(SELECTED), "baseline_sha256": request_digest(OWN),
        "resource_id_sha256": hashlib.sha256(b"101").hexdigest(),
        "baseline_resource_id_sha256": hashlib.sha256(b"202").hexdigest()}
    attempt = {"action_id": ACTION, "input_digest": digest(INPUT), "idempotency_key": KEY}
    return action, reservation, proposal, attempt, transactions


def read(db):
    return asyncio.run(PostgresAuthorizationRepository().action(
        db, {"id": HUNT, "target_id": TARGET}, ACTION))


@pytest.mark.parametrize("denied,expected,assessment", [
    (False, "denied", "potential_violation"), (False, "allowed", "shared_access_as_declared"),
    (False, "unknown", "entitlement_unknown"), (True, "denied", "access_denied"),
])
def test_worker_receipt_reaches_exact_object_attribution(denied, expected, assessment):
    action, reservation, proposal, attempt, transactions = evidence(denied=denied, expected=expected)
    # Demonstrate the original failure on precisely the persisted worker summary.
    before = attributed_outcome(proposal, attempt, action, transactions)
    assert not before["selected_request_examined"]
    db = Database()
    try:
        db.save(action, reservation)
        fetched = read(db)
        after = attributed_outcome(proposal, attempt, fetched, transactions)
        assert after["selected_request_examined"]
        assert after["authorization_assessment"] == assessment
        assert after["cross_access_observed"] is (not denied)
        assert after["proof_state"] == "inconclusive"
        assert after["outcome"] == ("refuted" if denied else "inconclusive")
        assert len(after["transaction_ids"]) == len(transactions)
        persisted = json.loads(db.db.execute("SELECT result_summary FROM hunt_actions").fetchone()[0])
        assert "observations" not in persisted  # hydration never rewrites immutable evidence
        assert fetched["result_summary"]["observation_source"] == "canonical_capability_receipt"
    finally:
        db.db.close()


def test_restart_recovers_the_existing_attempt_without_more_target_requests(tmp_path):
    action, reservation, proposal, attempt, transactions = evidence()
    path = str(tmp_path / "receipt.db")
    first = Database(path)
    first.save(action, reservation)
    before = attributed_outcome(proposal, attempt, read(first), transactions)
    first.db.close()
    reopened = Database(path)
    try:
        after = attributed_outcome(proposal, attempt, read(reopened), transactions)
        assert after == before and after["cross_access_observed"]
        assert all(sql.startswith("SELECT ") for sql, _ in reopened.calls)
        assert reopened.db.execute("SELECT count(*) FROM hunt_actions").fetchone()[0] == 1
    finally:
        reopened.db.close()


@pytest.mark.parametrize("key,value", [
    ("owner_kind", "scan"), ("owner_id", TARGET), ("action_id", TARGET),
    ("action_digest", "b" * 64), ("capability_name", "http.request"),
    ("status", "running"), ("execution_receipt_hash", "b" * 64), ("id", TARGET),
])
def test_wrong_reservation_never_supplies_observations(key, value):
    action, reservation, *_ = evidence()
    reservation[key] = value
    with pytest.raises(AuthorizationWorkflowError, match="Canonical authorization receipt"):
        receipt_backed_action(action, reservation, target_id=TARGET)


@pytest.mark.parametrize("key,value", [
    ("receipt_id", TARGET), ("hunt_id", TARGET), ("scan_id", TARGET),
    ("target_id", HUNT), ("capability_name", "http.request"),
    ("adapter_name", "http.request"), ("input_digest", "b" * 64),
    ("budget_reservation_id", TARGET), ("status", "partial"),
])
def test_even_a_validly_hashed_receipt_must_match_its_action(key, value):
    action, reservation, *_ = evidence()
    raw = reservation["receipt_json"]
    raw.pop("receipt_hash")
    raw[key] = value
    changed = CapabilityReceipt.from_dict(raw)
    reservation["receipt_json"] = changed.public_dict()
    reservation["execution_receipt_hash"] = changed.receipt_hash
    with pytest.raises(AuthorizationWorkflowError):
        receipt_backed_action(action, reservation, target_id=TARGET)


@pytest.mark.parametrize("change", ["missing", "invalid_json", "hash", "content", "absent_hash"])
def test_missing_or_corrupt_worker_receipt_cannot_fall_back_to_inline_flags(change):
    action, reservation, *_ = evidence()
    action["result_summary"]["observation"] = {"proof_state": "verified"}
    if change == "missing": reservation = None
    elif change == "invalid_json": reservation["receipt_json"] = "not JSON"
    elif change == "hash": reservation["receipt_json"]["receipt_hash"] = "0" * 64
    elif change == "content": reservation["receipt_json"]["observations"][0]["mode"] = "other"
    else: reservation["receipt_json"].pop("receipt_hash")
    with pytest.raises(AuthorizationWorkflowError):
        receipt_backed_action(action, reservation, target_id=TARGET)


def test_repository_rejects_missing_receipt_even_with_a_successful_inline_summary():
    action, reservation, *_ = evidence()
    action["result_summary"]["observation"] = {"proof_state": "verified"}
    db = Database()
    try:
        db.save(action, reservation)
        db.db.execute("DELETE FROM budget_reservations")
        with pytest.raises(AuthorizationWorkflowError):
            read(db)
    finally:
        db.db.close()


def test_rehydration_is_detached_and_does_not_combine_competing_summaries():
    action, reservation, *_ = evidence()
    action["result_summary"].update(observation={"fake": True},
        result={"observations": [{"fake": True}]}, typed_output={"records": [{"fake": True}]})
    original = deepcopy(action)
    read_projection = receipt_backed_action(action, reservation, target_id=TARGET)
    assert action == original
    assert not ({"observation", "result", "typed_output"} & read_projection["result_summary"].keys())
    assert len(read_projection["result_summary"]["observations"]) == 1
    assert read_projection["result_summary"]["observations"][0]["mode"] == "selected_object"


@pytest.mark.parametrize("change", ["object", "url", "missing_transaction", "foreign_action"])
def test_receipt_recovery_does_not_weaken_selected_object_matching(change):
    action, reservation, proposal, attempt, transactions = evidence()
    if change == "object": proposal["resource_id_sha256"] = "0" * 64
    elif change == "url": proposal["capture_sha256"] = "0" * 64
    elif change == "missing_transaction": transactions.pop()
    else: transactions[-1]["hunt_action_id"] = TARGET
    hydrated = receipt_backed_action(action, reservation, target_id=TARGET)
    result = attributed_outcome(proposal, attempt, hydrated, transactions)
    assert not result.get("cross_access_observed")
    assert result["proof_state"] == result["outcome"] == "inconclusive"


def test_no_target_content_or_session_values_are_exposed():
    action, reservation, *_ = evidence()
    output = receipt_backed_action(action, reservation, target_id=TARGET)
    rendered = json.dumps(output)
    assert "fixture content" not in rendered
    assert "fixture-principal" not in rendered
