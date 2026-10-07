from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from uuid import UUID, uuid4

import pytest

from api.hunt.coverage_ledger import (
    COVERAGE_ANGLE_STATUSES,
    COVERAGE_LOCUS_KEYS,
    CoverageLedgerError,
    build_hunt_checkpoint,
    coverage_fingerprint,
    normalize_coverage_angle,
    record_coverage_angle,
)


def _angle(**overrides):
    base = {
        "family": "authorization",
        "locus": {
            "method": "get",
            "route": "/api/orders/{id}",
            "object_id": "order",
            "application_state": "authenticated",
        },
        "mechanism": "swap object id across principals",
        "principal_context": {"owner": "principal-a", "attacker": "principal-b"},
        "hypothesis": "Object authorization may depend only on the supplied id.",
        "status": "planned",
        "evidence_action_ids": [],
        "contradictory_evidence_action_ids": [],
        "candidate_id": None,
        "blocker": "",
        "proof_gap": "",
    }
    base.update(overrides)
    return base


def test_fingerprint_is_stable_for_ordering_but_changes_for_material_angle_dimensions():
    first = coverage_fingerprint(
        family="Authorization",
        locus={"route": "/a", "method": "get"},
        mechanism="object swap",
        principal_context={"attacker": "b", "owner": "a"},
    )
    reordered = coverage_fingerprint(
        family="authorization",
        locus={"method": "GET", "route": "/a"},
        mechanism="OBJECT SWAP",
        principal_context={"owner": "a", "attacker": "b"},
    )
    different_method = coverage_fingerprint(
        family="authorization",
        locus={"method": "POST", "route": "/a"},
        mechanism="object swap",
        principal_context={"owner": "a", "attacker": "b"},
    )
    different_principal = coverage_fingerprint(
        family="authorization",
        locus={"method": "GET", "route": "/a"},
        mechanism="object swap",
        principal_context={"owner": "a", "attacker": "c"},
    )
    assert first == reordered
    assert first != different_method
    assert first != different_principal


def test_family_level_claim_is_too_broad_to_close_coverage():
    with pytest.raises(CoverageLedgerError, match="concrete locus") as exc:
        normalize_coverage_angle(_angle(locus={}, mechanism=""))
    assert exc.value.code == "coverage_angle_too_broad"


@pytest.mark.parametrize("locus", [{}, {"route": "  ", "method": ""}, None])
def test_mechanism_alone_cannot_stand_in_for_an_empty_locus(locus):
    with pytest.raises(CoverageLedgerError) as exc:
        normalize_coverage_angle(_angle(locus=locus, mechanism="swap object id"))
    assert exc.value.code == "coverage_angle_too_broad"
    assert exc.value.details["accepted_locus_keys"] == list(COVERAGE_LOCUS_KEYS)


@pytest.mark.parametrize("key", ["header", "host", "endpoint", "object-id", "Route"])
def test_unknown_locus_key_is_refused_with_the_accepted_vocabulary(key):
    with pytest.raises(CoverageLedgerError) as exc:
        normalize_coverage_angle(_angle(locus={"route": "/api/orders/{id}", key: "x"}))
    assert exc.value.code == "coverage_locus_key_unsupported"
    assert exc.value.details["unsupported_locus_keys"] == [key]
    assert exc.value.details["accepted_locus_keys"] == list(COVERAGE_LOCUS_KEYS)
    assert "Accepted locus keys: method, route" in str(exc.value)


@pytest.mark.parametrize(
    "key,first,second",
    [
        ("object_id", "4121", "4122"),
        ("object", "invoice", "order"),
        ("input", "body.user_id", "query.id"),
        ("operation", "read", "delete"),
        ("origin", "https://a.example", "https://a.example:8443"),
        ("path", "/admin", "/api/users"),
        ("service", "https/443", "https/8443"),
        ("port", 443, 8443),
    ],
)
def test_planner_dimensions_keep_materially_different_angles_apart(key, first, second):
    left = normalize_coverage_angle(_angle(locus={"route": "/r", key: first}))
    right = normalize_coverage_angle(_angle(locus={"route": "/r", key: second}))
    assert left["locus"][key] == first
    assert left["fingerprint"] != right["fingerprint"]


@pytest.mark.parametrize(
    "locus,code",
    [
        ({"route": "/r", "port": "https"}, "coverage_locus_value_invalid"),
        ({"route": "/r", "port": 70000}, "coverage_locus_value_invalid"),
        ({"route": "/r", "object": {"id": 1}}, "coverage_locus_value_invalid"),
        ({"route": "/r", "variant": True}, "coverage_locus_value_invalid"),
        ({"route": "/r", "url": "https://a.example/" + "x" * 1000}, "coverage_locus_value_too_long"),
        (["route", "/r"], "coverage_locus_invalid"),
    ],
)
def test_locus_values_fail_closed_instead_of_being_dropped_or_cut(locus, code):
    with pytest.raises(CoverageLedgerError) as exc:
        normalize_coverage_angle(_angle(locus=locus))
    assert exc.value.code == code


def test_overlong_text_fields_are_refused_not_silently_truncated():
    with pytest.raises(CoverageLedgerError) as exc:
        normalize_coverage_angle(_angle(mechanism="m" * 1001))
    assert exc.value.code == "coverage_field_too_long"
    with pytest.raises(CoverageLedgerError) as exc:
        normalize_coverage_angle(_angle(evidence_action_ids=[str(uuid4()) for _ in range(51)]))
    assert exc.value.code == "coverage_evidence_too_many"


def test_published_locus_vocabulary_matches_the_accepted_one_in_both_directions():
    from api.hunt.run_router import HuntCoverageAngleRequest
    from api.hunt.start_contract import hunt_start_public_contract

    schema = HuntCoverageAngleRequest.model_json_schema()["properties"]["locus"]
    assert schema["propertyNames"]["enum"] == list(COVERAGE_LOCUS_KEYS)
    assert hunt_start_public_contract()["coverage_ledger"]["locus_keys"] == list(COVERAGE_LOCUS_KEYS)
    skill = (Path(__file__).resolve().parents[1] / "skills/hunt/SKILL.md").read_text()
    advertised = skill.split("Locus keys:", 1)[1].split(".\n", 1)[0]
    assert re.findall(r"`([a-z_]+)`", advertised) == list(COVERAGE_LOCUS_KEYS)
    for key in COVERAGE_LOCUS_KEYS:
        value = 443 if key == "port" else f"{key}-value"
        angle = normalize_coverage_angle(_angle(locus={key: value}))
        assert angle["locus"] == {key: value.upper() if key == "method" else value}


@pytest.mark.asyncio
async def test_coverage_route_returns_the_vocabulary_with_a_422(monkeypatch):
    from fastapi import HTTPException
    from api.hunt import run_router

    class Service:
        async def record_coverage_angle(self, hunt_id, *, values):
            return normalize_coverage_angle(values)

    monkeypatch.setattr(run_router, "_service_provider", lambda: Service())
    request = run_router.HuntCoverageAngleRequest(
        family="authorization", locus={"endpoint": "/api/orders"}, status="planned",
    )
    with pytest.raises(HTTPException) as exc:
        await run_router.record_hunt_coverage_angle(str(uuid4()), request)
    assert exc.value.status_code == 422
    assert exc.value.detail["error"] == "coverage_locus_key_unsupported"
    assert exc.value.detail["accepted_locus_keys"] == list(COVERAGE_LOCUS_KEYS)


@pytest.mark.parametrize(
    "context",
    [
        {"authorization": "Bearer abc"},
        {"nested": {"cookie_value": "abc"}},
        {"principal": {"api_key": "abc"}},
        {"password_hint": "abc"},
    ],
)
def test_principal_context_rejects_secret_bearing_fields(context):
    with pytest.raises(CoverageLedgerError) as exc:
        normalize_coverage_angle(_angle(principal_context=context))
    assert exc.value.code == "coverage_secret_context_forbidden"


@pytest.mark.parametrize("status", ["negative", "partial"])
def test_settled_test_states_require_evidence(status):
    with pytest.raises(CoverageLedgerError) as exc:
        normalize_coverage_angle(_angle(status=status))
    assert exc.value.code == "coverage_evidence_required"


def test_blocked_state_requires_a_specific_gap():
    with pytest.raises(CoverageLedgerError) as exc:
        normalize_coverage_angle(_angle(status="blocked"))
    assert exc.value.code == "coverage_blocker_required"

    result = normalize_coverage_angle(
        _angle(status="blocked", proof_gap="Second approved principal is unavailable")
    )
    assert result["status"] == "blocked"
    assert result["proof_gap"]


def test_candidate_state_requires_same_hunt_candidate_reference():
    evidence_id = str(uuid4())
    with pytest.raises(CoverageLedgerError) as exc:
        normalize_coverage_angle(
            _angle(status="candidate", evidence_action_ids=[evidence_id])
        )
    assert exc.value.code == "coverage_candidate_required"


def test_verified_is_deliberately_not_a_planner_coverage_state():
    assert "verified" not in COVERAGE_ANGLE_STATUSES
    with pytest.raises(CoverageLedgerError) as exc:
        normalize_coverage_angle(_angle(status="verified"))
    assert exc.value.code == "coverage_status_invalid"


class _Conn:
    def __init__(self, action_statuses: dict[str, str], *, candidate_owned: bool = True):
        self.action_statuses = action_statuses
        self.candidate_owned = candidate_owned
        self.inserted = None

    async def fetch(self, query, *args):
        assert "FROM hunt_actions" in query
        ids = args[1]
        return [
            {"id": value, "status": self.action_statuses[str(value)]}
            for value in ids
            if str(value) in self.action_statuses
        ]

    async def fetchval(self, query, *args):
        assert "investigation_candidate_observations" in query
        return 1 if self.candidate_owned else None

    async def fetchrow(self, query, *args):
        assert "INSERT INTO hunt_coverage_angle_events" in query
        self.inserted = args
        return {
            "id": uuid4(),
            "hunt_run_id": UUID(args[0]),
            "fingerprint": args[1],
            "family": args[2],
            "locus_json": args[3],
            "mechanism": args[4],
            "principal_context": args[5],
            "hypothesis": args[6],
            "status": args[7],
            "evidence_action_ids": args[8],
            "contradictory_evidence_action_ids": args[9],
            "candidate_id": UUID(args[10]) if args[10] else None,
            "blocker": args[11],
            "proof_gap": args[12],
            "created_at": datetime.now(timezone.utc),
        }


@pytest.mark.asyncio
async def test_negative_requires_completed_same_hunt_action_not_partial_work():
    hunt_id = str(uuid4())
    action_id = str(uuid4())
    conn = _Conn({action_id: "partial"})
    with pytest.raises(CoverageLedgerError) as exc:
        await record_coverage_angle(
            conn,
            hunt_run_id=hunt_id,
            values=_angle(status="negative", evidence_action_ids=[action_id]),
        )
    assert exc.value.code == "coverage_negative_requires_completed_actions"
    assert conn.inserted is None


@pytest.mark.asyncio
async def test_unknown_action_cannot_be_used_to_claim_coverage():
    hunt_id = str(uuid4())
    action_id = str(uuid4())
    conn = _Conn({})
    with pytest.raises(CoverageLedgerError) as exc:
        await record_coverage_angle(
            conn,
            hunt_run_id=hunt_id,
            values=_angle(status="negative", evidence_action_ids=[action_id]),
        )
    assert exc.value.code == "coverage_evidence_not_owned"


@pytest.mark.asyncio
async def test_candidate_event_binds_both_action_and_candidate_to_same_hunt():
    hunt_id = str(uuid4())
    action_id = str(uuid4())
    candidate_id = str(uuid4())
    conn = _Conn({action_id: "completed"}, candidate_owned=True)
    result = await record_coverage_angle(
        conn,
        hunt_run_id=hunt_id,
        values=_angle(
            status="candidate",
            evidence_action_ids=[action_id],
            candidate_id=candidate_id,
            proof_gap="Run the registered authorization verifier.",
        ),
    )
    assert result["schema_version"] == "hunt-coverage-ledger/v1"
    assert result["angle"]["candidate_id"] == candidate_id
    assert result["angle"]["authoritative"] is False
    assert conn.inserted is not None


@pytest.mark.asyncio
async def test_candidate_from_another_hunt_is_rejected():
    hunt_id = str(uuid4())
    action_id = str(uuid4())
    candidate_id = str(uuid4())
    conn = _Conn({action_id: "completed"}, candidate_owned=False)
    with pytest.raises(CoverageLedgerError) as exc:
        await record_coverage_angle(
            conn,
            hunt_run_id=hunt_id,
            values=_angle(
                status="candidate",
                evidence_action_ids=[action_id],
                candidate_id=candidate_id,
            ),
        )
    assert exc.value.code == "coverage_candidate_not_owned"

@pytest.mark.asyncio
async def test_negative_cannot_close_an_angle_with_contradictory_evidence():
    hunt_id = str(uuid4())
    proof_action = str(uuid4())
    contradictory_action = str(uuid4())
    conn = _Conn({
        proof_action: "completed",
        contradictory_action: "completed",
    })
    with pytest.raises(CoverageLedgerError) as exc:
        await record_coverage_angle(
            conn,
            hunt_run_id=hunt_id,
            values=_angle(
                status="negative",
                evidence_action_ids=[proof_action],
                contradictory_evidence_action_ids=[contradictory_action],
            ),
        )
    assert exc.value.code == "coverage_negative_has_contradictory_evidence"
    assert conn.inserted is None


class _CheckpointConn:
    def __init__(self):
        self.candidate_id = uuid4()
        self.angle_id = uuid4()
        self.now = datetime.now(timezone.utc)

    async def fetch(self, query, *args):
        if "LEFT JOIN investigation_candidates" in query:
            return [{
                "id": self.angle_id,
                "fingerprint": "f" * 64,
                "family": "authorization",
                "locus_json": '{"method":"GET","route":"/api/orders/{id}"}',
                "mechanism": "object swap",
                "principal_context": '{"owner":"a","attacker":"b"}',
                "hypothesis": "cross-principal access",
                "status": "candidate",
                "evidence_action_ids": "[]",
                "contradictory_evidence_action_ids": "[]",
                "candidate_id": self.candidate_id,
                "candidate_status": "verified",
                "blocker": None,
                "proof_gap": None,
                "created_at": self.now,
                "total_count": 1,
            }]
        if "FROM investigation_candidates c" in query:
            return [{
                "id": self.candidate_id,
                "family": "authorization",
                "title": "Cross-principal order read",
                "status": "verified",
                "claimed_severity": "high",
                "fingerprint": "c" * 64,
                "canonical_locus": '{"method":"GET","route":"/api/orders/{id}"}',
                "verifier_contract_id": "authz.verify",
                "last_seen_at": self.now,
                "total_count": 1,
            }]
        if "FROM hunt_actions" in query:
            return [{"status": "completed", "count": 2}]
        if "SELECT status, COUNT(*) AS count" in query:
            return [{"status": "candidate", "count": 1}]
        if "SELECT family, COUNT(*) AS count" in query:
            return [{"family": "authorization", "count": 1}]
        raise AssertionError(query)


@pytest.mark.asyncio
async def test_checkpoint_does_not_requeue_a_terminal_candidate():
    hunt_id = uuid4()
    conn = _CheckpointConn()
    checkpoint = await build_hunt_checkpoint(
        conn,
        run={
            "id": hunt_id,
            "status": "active",
            "target_kind": "web",
            "objective": "Investigate authorization",
            "budget_json": {"requests": 50},
            "budget_used_json": {"requests": 2},
        },
    )
    assert checkpoint["coverage"]["angle_count"] == 1
    assert checkpoint["coverage"]["latest_angles"][0]["candidate_status"] == "verified"
    assert checkpoint["candidates"][0]["status"] == "verified"
    assert checkpoint["continuation_queue"] == []
    assert checkpoint["review_queue"] == []
    assert checkpoint["candidates"][0]["fingerprint"] == "c" * 64
    assert checkpoint["candidates"][0]["canonical_locus"]["route"] == "/api/orders/{id}"
    assert checkpoint["advisory_only"] is True


@pytest.mark.asyncio
async def test_checkpoint_queues_nonterminal_candidate_for_adversarial_review():
    hunt_id = uuid4()
    conn = _CheckpointConn()
    original_fetch = conn.fetch

    async def fetch(query, *args):
        rows = await original_fetch(query, *args)
        if "FROM investigation_candidates c" in query:
            rows[0]["status"] = "new"
        if "LEFT JOIN investigation_candidates" in query:
            rows[0]["candidate_status"] = "new"
        return rows

    conn.fetch = fetch
    checkpoint = await build_hunt_checkpoint(
        conn,
        run={
            "id": hunt_id,
            "status": "active",
            "target_kind": "web",
            "objective": "Investigate authorization",
            "budget_json": {"requests": 50},
            "budget_used_json": {"requests": 2},
        },
    )
    assert len(checkpoint["review_queue"]) == 1
    review = checkpoint["review_queue"][0]
    assert review["candidate_id"] == str(conn.candidate_id)
    assert review["fingerprint"] == "c" * 64
    assert review["challenge"] == [
        "attacker_prerequisite",
        "alternative_explanation",
        "impact_ceiling",
        "duplicate_identity",
        "smallest_falsifying_action",
    ]
    assert checkpoint["continuation_queue"][0]["candidate_status"] == "new"

