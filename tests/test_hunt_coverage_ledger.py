from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from api.hunt.coverage_ledger import (
    COVERAGE_ANGLE_STATUSES,
    CoverageLedgerError,
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
    with pytest.raises(CoverageLedgerError, match="concrete locus or mechanism") as exc:
        normalize_coverage_angle(_angle(locus={}, mechanism=""))
    assert exc.value.code == "coverage_angle_too_broad"


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
