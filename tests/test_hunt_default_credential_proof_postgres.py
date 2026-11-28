"""The default-credential proof on real PostgreSQL: ledger, bounds, candidate status and promotion.

The attempt that is proven is admitted through the real lifecycle (the permission-request harness,
stopping at dispatch) and settled accepted, as the worker settles it. Labelled doubles: the proof's
sender (a fixture login: it accepts the pair and refuses anything else, or answers as each test sets),
the pacing sleep, the denied-login resolver (no DNS), and the finding writer (the finding tables are
covered by the deterministic-finding tests); the candidate table holds the columns the proof reads.
"""
from __future__ import annotations

import json
import uuid

import pytest

from hunt import default_credential_proof as proof
from hunt import default_credentials as dc
from hunt import deterministic_findings, secret_try
from tests.test_hunt_permission_requests_postgres import DSN, permission_environment

pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

ACTIVE = {"active_testing": True, "allow_state_changing_http": False, "approval_receipt_id": str(uuid.uuid4()),
          "authorization_confirmed": True, "scope_receipt_id": "scope-fixture"}
BUDGET = {"max_active_actions": 200, "max_state_changing_requests": 0}


@pytest.fixture
def env(monkeypatch):
    async def by_name(host, path, addresses=()):
        return secret_try.denied_destination(host, path, ())

    monkeypatch.setattr(secret_try, "denied_destination_resolved", by_name)
    monkeypatch.setattr(dc, "PACE_SECONDS", 0.0)
    monkeypatch.delenv("SHAKERSCAN_HUNT_DEFAULT_CREDENTIALS", raising=False)
    written = []

    async def writer(conn, records, **kwargs):  # labelled double: the finding tables are elsewhere
        written.append((records, kwargs))
        return [str(uuid.uuid4())]

    monkeypatch.setattr(deterministic_findings, "persist_verified_records", writer)
    for environment in permission_environment(monkeypatch):
        environment.loop.run_until_complete(environment.conn.execute(dc.HUNT_DEFAULT_CREDENTIALS_SCHEMA_SQL))
        environment.loop.run_until_complete(environment.conn.execute("""
            CREATE TABLE investigation_candidates (
                id UUID PRIMARY KEY, target_id UUID, hunt_run_id UUID, family TEXT NOT NULL,
                evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb, status TEXT NOT NULL DEFAULT 'new',
                verification_context JSONB NOT NULL DEFAULT '{}'::jsonb, updated_at TIMESTAMPTZ)"""))
        environment.written = written
        yield environment


def run(env, coroutine):
    return env.loop.run_until_complete(coroutine)


def attempt(pair="dc-01", **extra):
    values = {"method": "POST", "origin": "https://app.example.test", "path": "/hub/login",
              "form_body": {"username": "", "password": ""},
              "request_bindings": [
                  {"default_credential": pair, "credential_field": "username", "body_pointer": "/username"},
                  {"default_credential": pair, "credential_field": "secret", "body_pointer": "/password"}]}
    values.update(extra)
    return values


async def accepted_candidate(env, hunt, *, key="default-cred-0001", pair="dc-01", family="default_credentials"):
    assert await env.call(hunt, key, values=attempt(pair)) == "admitted"
    action_id = uuid.uuid5(uuid.UUID(str(hunt["id"])), f"hunt-capability:{key}")
    await dc.settle_attempt(env.pool, hunt_id=hunt["id"], action_id=action_id, verdict="accepted")
    candidate = uuid.uuid4()
    await env.conn.execute(
        "INSERT INTO investigation_candidates(id,target_id,hunt_run_id,family,evidence_refs) VALUES($1,$2,$3,$4,$5::jsonb)",
        candidate, hunt["target_id"], hunt["id"], family, json.dumps([str(action_id)]))
    return candidate


def login(answers):
    sent = []

    async def send(request):  # labelled double: the fixture login
        sent.append(request)
        body = request.get("form_body") or request.get("json_body") or {}
        if answers:
            return answers[len(sent) - 1]
        return "accepted" if (body.get("username"), body.get("password")) == ("admin", "admin") else "rejected"
    return send, sent


async def no_sleep(_seconds):
    return None


async def verify(env, hunt, candidate, send):
    # The candidate.verify action the proof runs in (admitted elsewhere; here its row only).
    action_id = uuid.uuid4()
    await env.conn.execute(
        "INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status) VALUES($1,$2,'candidate.verify','running')",
        action_id, hunt["id"])
    return await proof.verify_candidate(
        env.pool, run=await env.run(hunt), context=json.loads((await env.run(hunt))["context_pack"]),
        policy=ACTIVE, candidate_uuid=candidate, action_id=action_id, send=send, sleep=no_sleep)


async def ledger(env, hunt):
    return [dict(row) for row in await env.conn.fetch(
        "SELECT pair_id, verdict, request_shape FROM hunt_default_credential_attempts WHERE hunt_run_id=$1 "
        "ORDER BY attempted_at, pair_id", hunt["id"])]


def test_the_pair_again_and_a_refused_control_prove_it_and_promote_one_finding(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        candidate = await accepted_candidate(env, hunt)
        send, sent = login(None)
        result = await verify(env, hunt, candidate, send)
        assert result["verified"] is True and result["proof_state"] == "verified"
        assert result["default_credentials_proof"]["steps"] == {"pair": "accepted", "control": "rejected"}
        # Two steps on the same login: the pair, then the user with a random password.
        assert [r["form_body"]["username"] for r in sent] == ["admin", "admin"]
        assert sent[0]["form_body"]["password"] == "admin"
        # The control: random, of the pair's password's length and character classes, never listed.
        control = sent[1]["form_body"]["password"]
        assert control != "admin" and len(control) == 5 and control.isalpha() and control.islower()
        assert control not in {row[2] for row in dc.PAIRS}
        assert {r["origin"] + r["path"] for r in sent} == {"https://app.example.test:443/hub/login"}
        rows = await ledger(env, hunt)
        assert [(r["pair_id"], r["verdict"]) for r in rows][-2:] in (
            [("dc-00", "rejected"), ("dc-01", "accepted")], [("dc-01", "accepted"), ("dc-00", "rejected")])
        [(records, kwargs)] = env.written
        assert records[0]["cwe"] == "CWE-1392" and kwargs["target_id"] == hunt["target_id"]
        row = await env.conn.fetchrow("SELECT status, verification_context FROM investigation_candidates WHERE id=$1", candidate)
        assert row["status"] == "verified"
        assert control not in json.dumps(json.loads(row["verification_context"]))
        assert control not in json.dumps(records, default=str)

    run(env, scenario())


def test_an_accepted_control_refutes_and_a_refused_pair_stays_inconclusive(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        candidate = await accepted_candidate(env, hunt)
        send, sent = login(["accepted", "accepted"])
        result = await verify(env, hunt, candidate, send)
        assert result["verified"] is False and result["proof_state"] == "refuted"
        other = await accepted_candidate(env, hunt, key="default-cred-0002", pair="dc-02")
        send, sent = login(["rejected"])
        result = await verify(env, hunt, other, send)
        assert result["proof_state"] == "inconclusive" and len(sent) == 1   # no control after a refused pair
        assert env.written == []

    run(env, scenario())


def test_a_lockout_at_the_pair_stops_the_proof_and_every_later_attempt(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        candidate = await accepted_candidate(env, hunt)
        send, sent = login(["locked"])
        result = await verify(env, hunt, candidate, send)
        assert result["proof_state"] == "inconclusive" and result["default_credentials_proof"]["stopped"]
        assert len(sent) == 1
        with pytest.raises(proof.DefaultCredentialProofRefused) as stopped:
            await verify(env, hunt, candidate, login(None)[0])
        assert stopped.value.reason == "default_credentials_stopped"

    run(env, scenario())


def test_the_proof_needs_room_under_the_per_login_cap_and_sends_nothing_without_it(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        candidate = await accepted_candidate(env, hunt)
        for index, (pair_id, *_rest) in enumerate(dc.PAIRS[1:dc.MAX_ATTEMPTS_PER_LOGIN - 1]):
            key = f"default-cred-{index + 10:04d}"
            assert await env.call(hunt, key, values=attempt(pair_id)) == "admitted"
            await dc.settle_attempt(env.pool, hunt_id=hunt["id"],
                                    action_id=uuid.uuid5(uuid.UUID(str(hunt["id"])), f"hunt-capability:{key}"),
                                    verdict="rejected")
        assert len(await ledger(env, hunt)) == dc.MAX_ATTEMPTS_PER_LOGIN - 1   # room for one, the proof needs two
        send, sent = login(None)
        with pytest.raises(proof.DefaultCredentialProofRefused) as full:
            await verify(env, hunt, candidate, send)
        assert full.value.reason == "default_credentials_exhausted" and sent == []

    run(env, scenario())


def test_a_candidate_without_an_accepted_attempt_or_with_captured_values_is_refused(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        bare = uuid.uuid4()
        await env.conn.execute(
            "INSERT INTO investigation_candidates(id,target_id,family,evidence_refs) VALUES($1,$2,'default_credentials',$3::jsonb)",
            bare, hunt["target_id"], json.dumps([str(uuid.uuid4()), "not-a-uuid"]))
        with pytest.raises(proof.DefaultCredentialProofRefused) as missing:
            await verify(env, hunt, bare, login(None)[0])
        assert missing.value.reason == "default_credentials_evidence_missing"
        candidate = await accepted_candidate(env, hunt)
        await env.conn.execute(
            "UPDATE hunt_default_credential_attempts SET request_shape = request_shape || '{\"replayable\": false}'::jsonb")
        with pytest.raises(proof.DefaultCredentialProofRefused) as replay:
            await verify(env, hunt, candidate, login(None)[0])
        assert replay.value.reason == "default_credentials_not_replayable"

    run(env, scenario())


def test_the_first_step_is_paced_and_waits_for_an_attempt_without_an_answer(env, monkeypatch):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget=BUDGET)
        candidate = await accepted_candidate(env, hunt)
        # Another attempt on the same login (spelled differently) is admitted and not yet answered.
        assert await env.call(hunt, "default-cred-0002", values=attempt("dc-02", path="/hub/Login")) == "admitted"
        send, sent = login(None)
        with pytest.raises(proof.DefaultCredentialProofRefused) as waiting:
            await verify(env, hunt, candidate, send)
        assert waiting.value.reason == "default_credentials_paced" and sent == []
        await dc.settle_attempt(env.pool, hunt_id=hunt["id"], verdict="rejected",
                                action_id=uuid.uuid5(uuid.UUID(str(hunt["id"])), "hunt-capability:default-cred-0002"))
        monkeypatch.setattr(dc, "PACE_SECONDS", 60.0)
        with pytest.raises(proof.DefaultCredentialProofRefused) as paced:
            await verify(env, hunt, candidate, send)
        assert paced.value.reason == "default_credentials_paced" and sent == []

    run(env, scenario())
