"""Revoking a Hunt permission grant on real PostgreSQL (R1, external release audit, 2026-10-09).

Effective authority is the Hunt's immutable starting policy plus every grant still live, rebuilt
under the Hunt row lock whenever a grant is applied or revoked. 2.8.0 restored a whole historical
snapshot on revocation instead: after grant A (state-changing HTTP) and grant B (network
discovery), revoking A turned off B's discovery, and revoking B then brought A's write authority
back. These tests drive the real decision, revocation and admission paths. Labelled doubles, as in
``test_hunt_permission_requests_postgres``: the approval-receipt validator, the standing
authorization lookup and the destination resolver.
"""
from __future__ import annotations

import asyncio
import json
import uuid

import pytest
from fastapi import HTTPException
from hunt import permission_grants
from hunt.permission_admission import settle_refusal
from hunt.permission_grants import revoke_grant
from hunt.permission_reasons import HuntRefusal

from tests.test_hunt_permission_requests_postgres import (
    DSN,
    permission_environment,
    run,
)

pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

POST = {"method": "POST", "path": "/api/v1/items"}
FLAGS = ("active_testing", "allow_state_changing_http", "network_discovery", "allow_oob_interactions",
         "mutation_allowed")


@pytest.fixture
def env(monkeypatch):
    yield from permission_environment(monkeypatch)


@pytest.fixture
def standing(monkeypatch):
    approval = str(uuid.uuid4())

    async def lookup(_conn, _target):  # labelled double: the target's standing authorization
        return {"approval_receipt_id": approval, "scope_receipt_id": "scope-fixture"}

    monkeypatch.setattr(permission_grants, "standing_authorization", lookup)
    return approval


async def _raise(env, hunt, capability, flag):
    """The real refusal path for a withheld capability: one pending capability.enable request."""
    with pytest.raises(HTTPException):
        await settle_refusal(env.pool, hunt_id=hunt["id"], action_id=uuid.uuid4(), name=capability,
                             input_summary={}, input_digest="d" * 64, refusal=HuntRefusal(
                                 "capability_requires_active_testing", "withheld",
                                 subject={"capability": capability, "flag": flag}))
    rows = await env.conn.fetch(
        """SELECT * FROM hunt_permission_requests WHERE hunt_run_id=$1 AND status='pending'
           AND subject_json->>'capability'=$2 AND subject_json->>'flag'=$3""", hunt["id"], capability, flag)
    (row,) = rows
    return dict(row)


def grant(env, hunt, capability, flag, key):
    request = run(env, _raise(env, hunt, capability, flag))
    return run(env, env.decide(hunt, request, key=key))["grant"]["id"]


async def _revoke(env, hunt, grant_id):
    async with env.pool.acquire() as conn, conn.transaction():
        return await revoke_grant(conn, hunt["id"], grant_id, revoked_by="alice@example.test")


def revoke(env, hunt, grant_id):
    return run(env, _revoke(env, hunt, grant_id))


def policy(env, hunt):
    return json.loads(run(env, env.run(hunt))["policy_json"])


def flags(env, hunt):
    current = policy(env, hunt)
    return {key: bool(current.get(key)) for key in FLAGS}


def write_admitted(env, hunt, key):
    """A state-changing ``http.request`` through the real admission lifecycle."""
    try:
        return run(env, env.call(hunt, key, values=POST)) == "admitted"
    except HTTPException:  # refused: a fresh permission request, or a denial that stands
        return False


def _detail_of(exc):
    return exc.detail if isinstance(exc.detail, dict) else {}


PASSIVE = {key: False for key in FLAGS}


# ---------------------------------------------------------------------------------------------
# The audit's reproduction.

def test_the_audit_sequence_leaves_no_authority_from_a_revoked_grant(env, standing):
    hunt = run(env, env.hunt())
    assert "http.request" in policy(env, hunt)["allowed_capabilities"]
    assert not write_admitted(env, hunt, "write-before-0001")
    write = grant(env, hunt, "http.request", "state-changing", "decide-a")
    discovery = grant(env, hunt, "service.snmp.inspect", "tcp-discovery", "decide-b")
    assert flags(env, hunt) == {**PASSIVE, "active_testing": True, "allow_state_changing_http": True,
                                "network_discovery": True, "mutation_allowed": True}

    revoke(env, hunt, write)
    # B is live: discovery stays; A's writes are gone.
    assert flags(env, hunt) == {**PASSIVE, "active_testing": True, "network_discovery": True}
    assert "service.snmp.inspect" in policy(env, hunt)["allowed_capabilities"]

    revoke(env, hunt, discovery)
    print("final policy flags:", flags(env, hunt))
    assert flags(env, hunt) == PASSIVE
    current = policy(env, hunt)
    assert "http.request" in current["allowed_capabilities"]  # baseline, never a grant's
    assert "service.snmp.inspect" not in current["allowed_capabilities"]
    assert not write_admitted(env, hunt, "write-after-0002")


def test_revoking_the_discovery_grant_first_leaves_writes_and_then_nothing(env, standing):
    hunt = run(env, env.hunt())
    write = grant(env, hunt, "http.request", "state-changing", "decide-a")
    discovery = grant(env, hunt, "service.snmp.inspect", "tcp-discovery", "decide-b")
    revoke(env, hunt, discovery)
    assert flags(env, hunt) == {**PASSIVE, "active_testing": True, "allow_state_changing_http": True,
                                "mutation_allowed": True}
    assert "service.snmp.inspect" not in policy(env, hunt)["allowed_capabilities"]
    assert write_admitted(env, hunt, "write-live-0001")
    revoke(env, hunt, write)
    assert flags(env, hunt) == PASSIVE
    assert not write_admitted(env, hunt, "write-gone-0002")


def test_grants_sharing_a_field_keep_it_until_the_last_one_is_revoked(env, standing):
    hunt = run(env, env.hunt())
    write = grant(env, hunt, "http.request", "state-changing", "decide-a")      # active_testing + writes
    active = grant(env, hunt, "xss.verify", "active-testing", "decide-c")       # active_testing only
    revoke(env, hunt, write)
    assert flags(env, hunt) == {**PASSIVE, "active_testing": True}
    assert "xss.verify" in policy(env, hunt)["allowed_capabilities"]
    revoke(env, hunt, active)
    assert flags(env, hunt) == PASSIVE
    assert "xss.verify" not in policy(env, hunt)["allowed_capabilities"]


def test_two_capabilities_under_one_flag_are_revoked_independently(env, standing):
    hunt = run(env, env.hunt())
    xss = grant(env, hunt, "xss.verify", "active-testing", "decide-x")
    sqli = grant(env, hunt, "sqli.verify", "active-testing", "decide-s")
    revoke(env, hunt, xss)
    current = policy(env, hunt)
    assert current["active_testing"] is True
    assert "sqli.verify" in current["allowed_capabilities"] and "xss.verify" not in current["allowed_capabilities"]
    revoke(env, hunt, sqli)
    current = policy(env, hunt)
    assert current["active_testing"] is False
    assert not {"sqli.verify", "xss.verify"} & set(current["allowed_capabilities"])


def test_a_capability_two_grants_enable_stays_while_either_is_live(env, standing):
    """2.8.0 recorded ``capability_added`` false on the second grant and removed the capability
    with the first, although the second still held it."""
    hunt = run(env, env.hunt())
    first = grant(env, hunt, "xss.verify", "active-testing", "decide-first")
    second = grant(env, hunt, "xss.verify", "oob", "decide-second")
    revoke(env, hunt, first)
    current = policy(env, hunt)
    assert "xss.verify" in current["allowed_capabilities"]
    assert current["active_testing"] is True and current["allow_oob_interactions"] is True
    revoke(env, hunt, second)
    current = policy(env, hunt)
    assert "xss.verify" not in current["allowed_capabilities"] and flags(env, hunt) == PASSIVE


def test_authority_the_hunt_started_with_is_never_revoked(env, standing):
    hunt = run(env, env.hunt(policy={"active_testing": True, "network_discovery": True}))
    write = grant(env, hunt, "http.request", "state-changing", "decide-a")
    revoke(env, hunt, write)
    assert flags(env, hunt) == {**PASSIVE, "active_testing": True, "network_discovery": True}
    assert "http.request" in policy(env, hunt)["allowed_capabilities"]
    # Unrelated fields of the policy and the bound receipt are left as they are.
    current = policy(env, hunt)
    assert current["approval_receipt_id"] == standing and current["schema_version"] == "hunt-policy/v2"


def test_a_repeated_revocation_replays_and_changes_nothing(env, standing):
    hunt = run(env, env.hunt())
    write = grant(env, hunt, "http.request", "state-changing", "decide-a")
    discovery = grant(env, hunt, "service.snmp.inspect", "tcp-discovery", "decide-b")
    first = revoke(env, hunt, write)
    before = policy(env, hunt)
    again = revoke(env, hunt, write)
    assert first["replayed"] is False and again["replayed"] is True
    assert policy(env, hunt) == before
    assert before["network_discovery"] is True  # B is still live
    events = run(env, env.conn.fetch(
        "SELECT detail_json FROM hunt_permission_events WHERE hunt_run_id=$1 AND event='revoked'", hunt["id"]))
    assert len(events) == 1
    assert json.loads(events[0]["detail_json"])["authority"]["flags_off"] == [
        "allow_state_changing_http", "mutation_allowed"]
    assert discovery


def test_a_grant_and_a_revocation_racing_serialize_on_the_hunt_row(env, standing):
    for attempt in range(4):
        hunt = run(env, env.hunt())
        write = grant(env, hunt, "http.request", "state-changing", f"decide-a-{attempt}")
        request = run(env, _raise(env, hunt, "service.snmp.inspect", "tcp-discovery"))

        async def race(hunt, request, write, key):
            return await asyncio.gather(
                env.decide(hunt, request, key=key), _revoke(env, hunt, write), return_exceptions=True)

        results = run(env, race(hunt, request, write, f"decide-b-{attempt}"))
        assert not [item for item in results if isinstance(item, BaseException)], results
        assert flags(env, hunt) == {**PASSIVE, "active_testing": True, "network_discovery": True}
        current = policy(env, hunt)
        assert "service.snmp.inspect" in current["allowed_capabilities"]
        assert not write_admitted(env, hunt, f"write-race-{attempt:04d}")


def test_writes_are_refused_once_the_last_write_grant_is_revoked(env, standing):
    hunt = run(env, env.hunt())
    assert not write_admitted(env, hunt, "write-none-0001")
    direct = grant(env, hunt, "http.request", "state-changing", "decide-direct")
    replay = grant(env, hunt, "collections.replay_active", "active-replay", "decide-replay")
    assert write_admitted(env, hunt, "write-both-0002")
    revoke(env, hunt, replay)
    assert write_admitted(env, hunt, "write-one-0003")  # the http.request write grant is live
    revoke(env, hunt, direct)
    assert policy(env, hunt)["allow_state_changing_http"] is False
    assert not write_admitted(env, hunt, "write-last-0004")
    # The refusal is a fresh question for a person, not an admission.
    pending = run(env, env.conn.fetchval(
        """SELECT COUNT(*) FROM hunt_permission_requests WHERE hunt_run_id=$1 AND status='pending'
           AND subject_json->>'flag'='state-changing'""", hunt["id"]))
    assert pending == 1


def test_the_baseline_is_recorded_once_and_cannot_be_changed(env, standing):
    import asyncpg

    hunt = run(env, env.hunt())
    grant(env, hunt, "xss.verify", "active-testing", "decide-x")
    grant(env, hunt, "sqli.verify", "active-testing", "decide-s")
    rows = run(env, env.conn.fetch("SELECT * FROM hunt_permission_baselines WHERE hunt_run_id=$1", hunt["id"]))
    assert len(rows) == 1 and rows[0]["source"] == "first_grant"
    assert json.loads(rows[0]["policy_json"])["flags"]["active_testing"] is False
    with pytest.raises(asyncpg.RaiseError):
        run(env, env.conn.execute(
            "UPDATE hunt_permission_baselines SET source='reconstructed' WHERE hunt_run_id=$1", hunt["id"]))
    with pytest.raises(asyncpg.RaiseError):
        run(env, env.conn.execute("DELETE FROM hunt_permission_baselines WHERE hunt_run_id=$1", hunt["id"]))
    run(env, env.conn.execute("DELETE FROM hunt_runs WHERE id=$1", hunt["id"]))  # cascades
    assert run(env, env.conn.fetchval("SELECT COUNT(*) FROM hunt_permission_baselines")) == 0


# ---------------------------------------------------------------------------------------------
# Grants persisted by 2.8.0: whole-policy snapshots, no baseline row.

LEGACY_SNAPSHOT_KEYS = ("active_testing", "allow_state_changing_http", "allow_oob_interactions",
                        "network_discovery", "mutation_allowed", "approval_receipt_id", "scope_receipt_id",
                        "authorization_confirmed")


async def _legacy_grant(env, hunt, capability, flag, policy_before, *, added, revoked=False):
    """A grant row exactly as 2.8.0 stored it (fixture: written directly, not through 2.8.0 code)."""
    request = await _raise(env, hunt, capability, flag)
    effect = {"policy_before": {key: policy_before.get(key) for key in LEGACY_SNAPSHOT_KEYS}, "flag": flag,
              "capability": capability, "capability_added": added, "receipt_bound": False,
              "dimensions_set": {}, "amendment_id": None}
    row = await env.conn.fetchrow(
        """INSERT INTO hunt_permission_grants(hunt_run_id, request_id, kind, subject_json, subject_digest,
                                              scope, effect_json, created_by, revoked_at, revoked_by)
           VALUES($1,$2,'capability.enable',$3::jsonb,$4,'hunt',$5::jsonb,'alice@example.test',
                  CASE WHEN $6 THEN NOW() END, CASE WHEN $6 THEN 'alice@example.test' END) RETURNING id""",
        hunt["id"], request["id"], request["subject_json"], request["subject_digest"], json.dumps(effect), revoked)
    await env.conn.execute(
        "UPDATE hunt_permission_requests SET status='granted', decided_at=NOW(), grant_id=$2 WHERE id=$1",
        request["id"], row["id"])
    return row["id"]


async def _set_policy(env, hunt, **fields):
    current = json.loads(await env.conn.fetchval("SELECT policy_json FROM hunt_runs WHERE id=$1", hunt["id"]))
    current.update(fields)
    await env.conn.execute("UPDATE hunt_runs SET policy_json=$2::jsonb WHERE id=$1", hunt["id"], json.dumps(current))
    return current


def _legacy_audit_state(env, standing, *, revoked):
    """2.8.0 after grant A (writes) and grant B (discovery); ``revoked`` replays its revocations."""
    hunt = run(env, env.hunt(policy={"approval_receipt_id": standing, "authorization_confirmed": True}))
    start = policy(env, hunt)
    after_a = {**start, "active_testing": True, "allow_state_changing_http": True, "mutation_allowed": True}
    write = run(env, _legacy_grant(env, hunt, "http.request", "state-changing", start, added=False,
                                   revoked=revoked))
    discovery = run(env, _legacy_grant(env, hunt, "service.snmp.inspect", "tcp-discovery", after_a, added=True,
                                       revoked=revoked))
    if revoked:  # what 2.8.0 left: B's snapshot restored A's write flags
        run(env, _set_policy(env, hunt, **{**{key: after_a[key] for key in FLAGS}, "network_discovery": False}))
    else:
        run(env, _set_policy(env, hunt, **{**{key: after_a[key] for key in FLAGS}, "network_discovery": True},
                             allowed_capabilities=[*start["allowed_capabilities"], "service.snmp.inspect"]))
    # 2.8.0 also set the zeroed dimensions the grants permit (one amendment); budgets are not
    # authority and stay as they are on revocation.
    run(env, env.conn.execute(
        """UPDATE hunt_runs SET budget_json = budget_json || '{"max_state_changing_requests": 5,
               "max_active_actions": 4, "max_tcp_ports": 20, "max_hosts": 1}'::jsonb WHERE id=$1""",
        hunt["id"]))
    return hunt, write, discovery


def test_startup_repairs_a_hunt_2_8_0_left_with_a_revoked_grants_write_authority(env, standing):
    from hunt.grant_repair import repair_grant_authority

    hunt, _write, _discovery = _legacy_audit_state(env, standing, revoked=True)
    assert flags(env, hunt)["allow_state_changing_http"] is True  # the bad state
    assert write_admitted(env, hunt, "write-bad-0001"), "2.8.0 state: a revoked grant still admits writes"
    repaired = run(env, repair_grant_authority(env.conn))
    assert repaired == [str(hunt["id"])]
    assert flags(env, hunt) == PASSIVE
    assert not write_admitted(env, hunt, "write-repaired-0002")
    baseline = run(env, env.conn.fetchrow("SELECT * FROM hunt_permission_baselines WHERE hunt_run_id=$1", hunt["id"]))
    assert baseline["source"] == "reconstructed"
    assert run(env, repair_grant_authority(env.conn)) == []  # once
    context = json.loads(run(env, env.run(hunt))["context_pack"])
    assert "service.snmp.inspect" not in context["allowed_capabilities"]  # the list the workers re-read


def test_grants_2_8_0_persisted_revoke_correctly_after_the_upgrade(env, standing):
    hunt, write, discovery = _legacy_audit_state(env, standing, revoked=False)
    revoke(env, hunt, write)
    assert flags(env, hunt) == {**PASSIVE, "active_testing": True, "network_discovery": True}
    revoke(env, hunt, discovery)
    assert flags(env, hunt) == PASSIVE
    assert "service.snmp.inspect" not in policy(env, hunt)["allowed_capabilities"]
    assert "http.request" in policy(env, hunt)["allowed_capabilities"]
    assert policy(env, hunt)["approval_receipt_id"] == standing
    assert not write_admitted(env, hunt, "write-upgraded-0001")


def test_startup_leaves_finished_hunts_and_hunts_without_grants_alone(env, standing):
    from hunt.grant_repair import repair_grant_authority

    finished, _a, _b = _legacy_audit_state(env, standing, revoked=True)
    run(env, env.conn.execute("UPDATE hunt_runs SET status='completed', completed_at=NOW() WHERE id=$1",
                              finished["id"]))
    untouched = run(env, env.hunt())
    assert run(env, repair_grant_authority(env.conn)) == []
    assert run(env, env.conn.fetchval("SELECT COUNT(*) FROM hunt_permission_baselines")) == 0
    assert policy(env, untouched)["active_testing"] is False


# ---------------------------------------------------------------------------------------------
# Both directions, after every step: the Hunt has exactly its starting policy plus the union of
# its live grants. Freedom: nothing a live grant (or the start) gives is missing. Obedience:
# nothing a revoked grant gave remains, and a denial grants nothing.

SUBJECTS = (
    ("http.request", "state-changing"), ("service.snmp.inspect", "tcp-discovery"),
    ("xss.verify", "active-testing"), ("xss.verify", "oob"), ("sqli.verify", "active-testing"),
    ("collections.replay_active", "active-replay"),
)


def expected_authority(start, live):
    from hunt.permission_bounds import CAPABILITY_FLAGS

    fields = {key: start.get(key) is True for key in FLAGS}
    capabilities = list(start["allowed_capabilities"])
    for capability, flag in live:
        for field in CAPABILITY_FLAGS[flag]:
            fields[field] = True
        if capability not in capabilities:
            capabilities.append(capability)
    if fields["allow_state_changing_http"]:
        fields["mutation_allowed"] = True
    return fields, sorted(capabilities)


ROOMY = {"max_capability_calls": 500, "max_http_requests": 500, "max_state_changing_requests": 500,
         "max_active_actions": 500}


@pytest.mark.parametrize("seed", range(8))
def test_authority_is_the_start_plus_the_live_grants_after_every_grant_and_revocation(env, standing, seed):
    """Subjects repeat (a subject may be granted again while an earlier grant of it is live, or
    after it was revoked), and after every step both the stored authority and a real write
    through admission agree with the start plus the union of the live grants."""
    import random

    rng = random.Random(seed)
    start_flags = {"active_testing": seed % 3 == 0, "network_discovery": seed % 2 == 0}
    hunt = run(env, env.hunt(policy=start_flags, budget=ROOMY))  # budget is never what refuses here
    start = policy(env, hunt)
    live: dict[str, tuple[str, str]] = {}
    revoked: list[str] = []
    denied: set[tuple[str, str]] = set()
    for step in range(12):
        roll = rng.random()
        askable = [subject for subject in SUBJECTS if subject not in denied]
        if live and roll < 0.35:
            grant_id = rng.choice(sorted(live))
            revoke(env, hunt, grant_id)
            revoked.append(grant_id)
            del live[grant_id]
        elif roll < 0.45 and revoked:
            revoke(env, hunt, rng.choice(revoked))  # a repeated revocation changes nothing
        elif roll < 0.55 and askable:
            capability, flag = rng.choice(askable)
            request = run(env, _raise(env, hunt, capability, flag))
            run(env, env.decide(hunt, request, decision="deny", key=f"deny-{seed}-{step}"))
            denied.add((capability, flag))
            # A denial stays a denial: asking again inside the cooldown raises nothing new.
            with pytest.raises(HTTPException):
                run(env, settle_refusal(env.pool, hunt_id=hunt["id"], action_id=uuid.uuid4(), name=capability,
                                        input_summary={}, input_digest="d" * 64, refusal=HuntRefusal(
                                            "capability_requires_active_testing", "withheld",
                                            subject={"capability": capability, "flag": flag})))
            assert run(env, env.conn.fetchval(
                "SELECT status FROM hunt_permission_requests WHERE id=$1", request["id"])) == "denied"
        elif askable:
            # Repeats on purpose: the same subject may already be live or have been revoked.
            capability, flag = rng.choice(askable)
            live[grant(env, hunt, capability, flag, f"grant-{seed}-{step}")] = (capability, flag)
        fields, capabilities = expected_authority(start, live.values())
        current = policy(env, hunt)
        assert flags(env, hunt) == fields, (seed, step, live)
        assert sorted(current["allowed_capabilities"]) == capabilities, (seed, step, live)
        assert run(env, env.conn.fetchval(
            "SELECT COUNT(*) FROM hunt_permission_grants WHERE hunt_run_id=$1 AND revoked_at IS NULL",
            hunt["id"])) == len(live)  # no grant appears for a denied request
        assert sorted(json.loads(run(env, env.run(hunt))["context_pack"])["allowed_capabilities"]) == capabilities
        if live or revoked:  # the receipt the first grant bound is its own source, never revoked
            assert current["approval_receipt_id"] == standing
        # Admission agrees at every step: a write runs exactly while the start or a live grant
        # allows it.
        assert write_admitted(env, hunt, f"write-{seed:02d}-{step:04d}") is fields["allow_state_changing_http"], (
            seed, step, live)
    for grant_id in sorted(live):
        revoke(env, hunt, grant_id)
    fields, capabilities = expected_authority(start, ())
    assert flags(env, hunt) == fields and sorted(policy(env, hunt)["allowed_capabilities"]) == capabilities
    assert not write_admitted(env, hunt, f"write-none-{seed:04d}")


def test_granting_is_unchanged_a_grant_takes_effect_at_once_and_admits_the_write(env, standing):
    """Freedom: the fix adds no step, confirmation or narrowing to granting."""
    hunt = run(env, env.hunt())
    with pytest.raises(HTTPException) as refused:
        run(env, env.call(hunt, "write-asked-0001", values=POST))
    assert _detail_of(refused.value)["code"] == "permission_required"
    (request,) = run(env, env.requests(hunt))
    run(env, env.decide(hunt, request))
    assert run(env, env.call(hunt, "write-asked-0001", values=POST)) == "admitted"  # the same key, re-admitted


def test_the_same_subject_granted_twice_stays_until_both_are_revoked(env, standing):
    hunt = run(env, env.hunt())
    first = grant(env, hunt, "xss.verify", "active-testing", "decide-first")
    second = grant(env, hunt, "xss.verify", "active-testing", "decide-second")  # a new request, same subject
    assert first != second
    revoke(env, hunt, first)
    assert policy(env, hunt)["active_testing"] is True and "xss.verify" in policy(env, hunt)["allowed_capabilities"]
    revoke(env, hunt, second)
    assert flags(env, hunt) == PASSIVE and "xss.verify" not in policy(env, hunt)["allowed_capabilities"]


# ---------------------------------------------------------------------------------------------
# Pre-authorized grants: a person's revocation sticks (owner principle: Hunt obeys the user).

def _preauthorize(env, hunt, allow):
    from hunt.start_contract import normalize_hunt_start_payload
    from hunt.start_permissions import record_start_permissions

    async def record():
        contract = normalize_hunt_start_payload({
            "target_id": str(hunt["target_id"]), "target_kind": "web", "policy": {}, "allow": list(allow),
            "allow_asserted_by": {"person": "alice@example.test", "proof": "stepup"},
        })
        async with env.pool.acquire() as conn:
            await record_start_permissions(conn, hunt, contract, [])

    run(env, record())


def test_a_revoked_pre_authorized_grant_is_not_granted_again_by_the_start_bounds(env, standing):
    hunt = run(env, env.hunt(budget=ROOMY))
    _preauthorize(env, hunt, ["capability:state-changing", "capability:tcp-discovery"])
    assert write_admitted(env, hunt, "pre-write-0001")  # auto-granted from the start bounds
    (auto,) = run(env, env.conn.fetch(
        "SELECT * FROM hunt_permission_grants WHERE hunt_run_id=$1 AND kind='capability.enable'", hunt["id"]))
    assert auto["preauthorization_id"] is not None
    revoke(env, hunt, auto["id"])
    assert flags(env, hunt) == PASSIVE

    # The next write is a question for a person, not a silent re-grant.
    with pytest.raises(HTTPException) as parked:
        run(env, env.call(hunt, "pre-write-0002", values=POST))
    detail = _detail_of(parked.value)
    assert parked.value.status_code == 409 and detail["code"] == "permission_required"
    assert run(env, env.action(hunt, "pre-write-0002"))["status"] == "awaiting_permission"
    assert run(env, env.conn.fetchval(
        """SELECT COUNT(*) FROM hunt_permission_grants WHERE hunt_run_id=$1 AND kind='capability.enable'
           AND revoked_at IS NULL""", hunt["id"])) == 0
    pending = [item for item in run(env, env.requests(hunt)) if item["status"] == "pending"]
    (request,) = pending
    from hunt.permission_store import list_grants, public_request

    shown = public_request(request)  # what `shakerscan hunt permissions list|show` prints
    assert shown["auto_grant_withheld"]["coverage"] == "capability:state-changing"
    assert shown["auto_grant_withheld"]["revoked_grant_id"] == str(auto["id"])
    (listed,) = run(env, list_grants(env.conn, hunt["id"]))
    assert listed["auto_grant_withheld"] == "capability:state-changing"
    revoked_event = run(env, env.conn.fetchval(
        "SELECT detail_json FROM hunt_permission_events WHERE grant_id=$1 AND event='revoked'", auto["id"]))
    assert json.loads(revoked_event)["auto_grant_withheld"] == "capability:state-changing"

    # One approval in the terminal allows it again, and the same key is admitted.
    approved = run(env, env.decide(hunt, request, key="terminal-approve-0001"))
    assert approved["request"]["decision_via"] == "terminal_stepup"
    assert run(env, env.call(hunt, "pre-write-0002", values=POST)) == "admitted"

    # Everything else the start bounds cover is still granted automatically.
    run(env, _raise_or_auto(env, hunt, "service.snmp.inspect", "tcp-discovery"))
    assert policy(env, hunt)["network_discovery"] is True
    assert "service.snmp.inspect" in policy(env, hunt)["allowed_capabilities"]


async def _raise_or_auto(env, hunt, capability, flag):
    """A refusal inside the start bounds is granted in the same transaction (no exception)."""
    return await settle_refusal(env.pool, hunt_id=hunt["id"], action_id=uuid.uuid4(), name=capability,
                                input_summary={}, input_digest="d" * 64, refusal=HuntRefusal(
                                    "capability_requires_active_testing", "withheld",
                                    subject={"capability": capability, "flag": flag}))


def test_the_withheld_coverage_holds_across_a_restart_and_for_other_capabilities_of_that_flag(env, standing):
    hunt = run(env, env.hunt(budget=ROOMY))
    _preauthorize(env, hunt, ["capability:state-changing"])
    assert write_admitted(env, hunt, "pre-write-0001")
    (auto,) = run(env, env.conn.fetch("SELECT id FROM hunt_permission_grants WHERE hunt_run_id=$1", hunt["id"]))
    revoke(env, hunt, auto["id"])
    # Nothing is held in memory: a fresh read of the rows answers the same (an API restart).
    from hunt.permission_grants import revoked_coverage

    withheld = run(env, revoked_coverage(env.conn, hunt["id"], "capability.enable",
                                         {"capability": "collections.replay_active", "flag": "state-changing"}))
    assert withheld["revoked_grant_id"] == str(auto["id"])
    with pytest.raises(HTTPException) as parked:
        run(env, _raise_or_auto(env, hunt, "collections.replay_active", "state-changing"))
    assert _detail_of(parked.value)["code"] == "permission_required"
    assert policy(env, hunt)["allow_state_changing_http"] is False


# ---------------------------------------------------------------------------------------------
# Destinations.

@pytest.fixture
def resolver(monkeypatch):
    from hunt import permission_subjects

    answers = ["93.184.216.34"]

    async def resolve(_url, _environment):  # labelled double: DNS answers a public address
        return list(answers)

    monkeypatch.setattr(permission_subjects, "resolve_destination_addresses", resolve)
    return answers


OTHER = "https://api.example.test"


def _get_admitted(env, hunt, origin, key):
    try:
        return run(env, env.call(hunt, key, values={"method": "GET", "path": "/", "origin": origin})) == "admitted"
    except HTTPException:
        return False


def _destination_request(env, hunt, origin, key):
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, key, values={"method": "GET", "path": "/", "origin": origin}))
    (request,) = [item for item in run(env, env.requests(hunt))
                  if item["status"] == "pending" and item["kind"] == "target.authorize"]
    return request


def test_destination_and_capability_grants_interleave(env, standing, resolver):
    hunt = run(env, env.hunt())
    first = run(env, env.decide(hunt, _destination_request(env, hunt, OTHER, "dst-a-0001"), key="d-a"))
    write = grant(env, hunt, "http.request", "state-changing", "decide-w")
    second = run(env, env.decide(hunt, _destination_request(env, hunt, "https://other.example.test", "dst-b-0001"),
                                 key="d-b"))
    assert _get_admitted(env, hunt, OTHER, "ok-a-0001")
    revoke(env, hunt, first["grant"]["id"])
    assert not _get_admitted(env, hunt, OTHER, "ok-a-0002")
    assert _get_admitted(env, hunt, "https://other.example.test", "ok-b-0001")
    assert flags(env, hunt)["allow_state_changing_http"]
    revoke(env, hunt, write)
    assert flags(env, hunt) == PASSIVE
    assert len(policy(env, hunt)["granted_destinations"]) == 1
    revoke(env, hunt, second["grant"]["id"])
    assert policy(env, hunt)["granted_destinations"] == []


def test_two_live_grants_for_one_origin_keep_it_until_both_are_revoked(env, standing, resolver):
    hunt = run(env, env.hunt())
    first = run(env, env.decide(hunt, _destination_request(env, hunt, OTHER, "dst-one-0001"), key="d-one"))
    # The same origin asked again under another resolution: a second request, a second grant.
    resolver[:] = ["93.184.216.35"]

    async def ask_again():
        with pytest.raises(HTTPException):
            await settle_refusal(env.pool, hunt_id=hunt["id"], action_id=uuid.uuid4(), name="http.request",
                                 input_summary={}, input_digest="d" * 64, refusal=HuntRefusal(
                                     "scope_other_host", "another host", subject={
                                         "host": "api.example.test", "port": 443, "scheme": "https",
                                         "origin": "https://api.example.test:443", "same_host": False,
                                         "target_id": str(hunt["target_id"])}))
        return [item for item in await env.requests(hunt) if item["status"] == "pending"]

    (again,) = run(env, ask_again())
    second = run(env, env.decide(hunt, again, key="d-two"))
    assert first["grant"]["id"] != second["grant"]["id"]
    held = policy(env, hunt)["granted_destinations"]
    assert [item["request_id"] for item in held] == [first["request"]["id"]]
    revoke(env, hunt, first["grant"]["id"])
    held = policy(env, hunt)["granted_destinations"]
    # The entry now names the live grant, which is what dispatch re-checks.
    assert [item["request_id"] for item in held] == [second["request"]["id"]]
    assert _get_admitted(env, hunt, OTHER, "dst-ok-0001")
    revoke(env, hunt, second["grant"]["id"])
    assert policy(env, hunt)["granted_destinations"] == []
    assert not _get_admitted(env, hunt, OTHER, "dst-gone-0002")


def test_a_destination_past_the_cap_is_refused_with_a_reason_and_nothing_is_dropped(env, standing):
    from hunt.grant_authority import MAX_GRANTED_DESTINATIONS

    held = [{"host": f"h{index}.example.test", "port": 443, "scheme": "https",
             "origin": f"https://h{index}.example.test:443", "addresses": ["93.184.216.34"],
             "same_host": False, "request_id": str(uuid.uuid4())} for index in range(MAX_GRANTED_DESTINATIONS)]
    hunt = run(env, env.hunt(policy={"granted_destinations": held}))
    values = {"method": "GET", "path": "/", "origin": "https://app.example.test:8443"}
    with pytest.raises(HTTPException):
        run(env, env.call(hunt, "port-cap-0001", values=values))
    (request,) = run(env, env.requests(hunt))
    with pytest.raises(HTTPException) as refused:
        run(env, env.decide(hunt, request))
    assert refused.value.status_code == 409 and refused.value.detail["error"] == "destination_limit_reached"
    assert run(env, env.requests(hunt))[0]["status"] == "pending"  # nothing granted
    assert policy(env, hunt)["granted_destinations"] == held  # nothing dropped


# ---------------------------------------------------------------------------------------------
# Startup repair is per Hunt and fails closed for that Hunt only.

def test_a_hunt_whose_repair_fails_is_ended_and_the_others_are_repaired(env, standing, caplog):
    from hunt.grant_repair import REPAIR_FAILED_STOP_REASON, repair_grant_authority

    good, _a, _b = _legacy_audit_state(env, standing, revoked=True)
    broken, write, _d = _legacy_audit_state(env, standing, revoked=True)
    # A stored effect that is not an object (a corrupt row): rebuilding this Hunt raises.
    run(env, env.conn.execute("UPDATE hunt_permission_grants SET effect_json='[1]'::jsonb WHERE id=$1", write))
    assert write_admitted(env, broken, "broken-before-0001")
    with caplog.at_level("ERROR"):
        repaired = run(env, repair_grant_authority(env.conn))
    assert repaired == [str(good["id"])]
    assert flags(env, good) == PASSIVE
    row = run(env, env.run(broken))
    assert row["status"] == "failed" and row["stop_reason"] == REPAIR_FAILED_STOP_REASON
    assert row["completed_at"] is not None
    assert not write_admitted(env, broken, "broken-after-0002")
    assert any(str(broken["id"]) in record.getMessage() for record in caplog.records)
    assert not any("policy_before" in record.getMessage() for record in caplog.records)


def test_concurrent_repairs_settle_on_the_same_authority(env, standing):
    from hunt.grant_repair import repair_grant_authority

    hunt, _w, _d = _legacy_audit_state(env, standing, revoked=True)

    async def both():
        async def one():
            async with env.pool.acquire() as conn:
                return await repair_grant_authority(conn)
        return await asyncio.gather(one(), one(), return_exceptions=True)

    results = run(env, both())
    assert not [item for item in results if isinstance(item, BaseException)], results
    assert sorted(len(item) for item in results) == [0, 1]
    assert flags(env, hunt) == PASSIVE


def test_after_the_upgrade_a_revoked_2_8_0_grant_and_a_new_grant_revoke_cleanly(env, standing):
    hunt = run(env, env.hunt(policy={"approval_receipt_id": standing, "authorization_confirmed": True}))
    start = policy(env, hunt)
    run(env, _legacy_grant(env, hunt, "xss.verify", "oob", start, added=True, revoked=True))
    new = grant(env, hunt, "http.request", "state-changing", "decide-b")
    assert flags(env, hunt)["allow_state_changing_http"] and not flags(env, hunt)["allow_oob_interactions"]
    revoke(env, hunt, new)
    assert flags(env, hunt) == PASSIVE and "xss.verify" not in policy(env, hunt)["allowed_capabilities"]


def test_repair_restores_a_capability_2_8_0_removed_while_a_live_grant_held_it(env, standing):
    from hunt.grant_repair import repair_grant_authority

    hunt = run(env, env.hunt(policy={"approval_receipt_id": standing, "authorization_confirmed": True}))
    start = policy(env, hunt)
    run(env, _legacy_grant(env, hunt, "xss.verify", "active-testing", start, added=True, revoked=True))
    run(env, _legacy_grant(env, hunt, "xss.verify", "oob", {**start, "active_testing": True}, added=False))
    # 2.8.0 revoked A by restoring the start and removed xss.verify, though B was live.
    run(env, _set_policy(env, hunt, active_testing=False, allow_oob_interactions=True))
    assert run(env, repair_grant_authority(env.conn)) == [str(hunt["id"])]
    current = policy(env, hunt)
    assert "xss.verify" in current["allowed_capabilities"]
    assert current["active_testing"] is True and current["allow_oob_interactions"] is True


def test_only_the_hunts_own_deletion_removes_its_baseline(env):
    import asyncpg

    hunt = run(env, env.hunt())
    run(env, env.conn.execute(
        "INSERT INTO hunt_permission_baselines(hunt_run_id, policy_json, source) VALUES($1,'{}'::jsonb,'first_grant')",
        hunt["id"]))
    with pytest.raises(asyncpg.RaiseError):  # a delete from another trigger is refused too
        run(env, env.conn.execute("""
            CREATE TABLE probe_t(x int);
            CREATE FUNCTION probe_f() RETURNS trigger AS $$
            BEGIN DELETE FROM hunt_permission_baselines; RETURN NEW; END $$ LANGUAGE plpgsql;
            CREATE TRIGGER probe_tr AFTER INSERT ON probe_t FOR EACH ROW EXECUTE FUNCTION probe_f();
            INSERT INTO probe_t VALUES (1);
        """))
    assert run(env, env.conn.fetchval("SELECT COUNT(*) FROM hunt_permission_baselines")) == 1
    run(env, env.conn.execute("DELETE FROM hunt_runs WHERE id=$1", hunt["id"]))
    assert run(env, env.conn.fetchval("SELECT COUNT(*) FROM hunt_permission_baselines")) == 0
