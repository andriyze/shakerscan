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
    from hunt.grant_authority import repair_grant_authority

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
    from hunt.grant_authority import repair_grant_authority

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


@pytest.mark.parametrize("seed", range(6))
def test_authority_is_the_start_plus_the_live_grants_after_every_grant_and_revocation(env, standing, seed):
    import random

    rng = random.Random(seed)
    start_flags = {"active_testing": seed % 3 == 0, "network_discovery": seed % 2 == 0}
    hunt = run(env, env.hunt(policy=start_flags))
    start = policy(env, hunt)
    live: dict[str, tuple[str, str]] = {}
    revoked: list[str] = []
    denied: set[tuple[str, str]] = set()
    for step in range(10):
        roll = rng.random()
        unused = [subject for subject in SUBJECTS if subject not in live.values() and subject not in denied]
        if live and (roll < 0.4 or not unused):
            grant_id = rng.choice(sorted(live))
            revoke(env, hunt, grant_id)
            revoked.append(grant_id)
            del live[grant_id]
        elif roll < 0.5 and revoked:
            revoke(env, hunt, rng.choice(revoked))  # a repeated revocation changes nothing
        elif roll < 0.6 and unused:
            capability, flag = rng.choice(unused)
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
        else:
            capability, flag = rng.choice(unused)
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
    # Admission agrees with the stored authority: writes run exactly while some grant allows them.
    fields, _capabilities = expected_authority(start, live.values())
    assert write_admitted(env, hunt, f"write-final-{seed:04d}") is fields["allow_state_changing_http"]
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
