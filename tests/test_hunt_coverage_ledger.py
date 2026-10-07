from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any
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


EXECUTED = {"budget_accounting": {"actual": {"http_requests": 1, "tool_wall_seconds": 1}}}


class _Conn:
    """Fake connection; each action is a status or a (status, result_summary) pair."""

    def __init__(
        self,
        action_statuses: dict[str, Any],
        *,
        candidate_owned: bool = True,
        latest_candidate_id: str | None = None,
        recorded_events: int = 0,
    ):
        self.actions = {
            key: value if isinstance(value, tuple) else (
                value, EXECUTED if value in {"completed", "partial"} else {}
            )
            for key, value in action_statuses.items()
        }
        self.candidate_owned = candidate_owned
        self.latest_candidate_id = latest_candidate_id
        self.recorded_events = recorded_events
        self.inserted = None

    async def fetch(self, query, *args):
        assert "FROM hunt_actions" in query
        return [
            {"id": value, "status": self.actions[str(value)][0],
             "result_summary": json.dumps(self.actions[str(value)][1])}
            for value in args[1]
            if str(value) in self.actions
        ]

    async def fetchval(self, query, *args):
        if "SELECT COUNT(*) FROM hunt_coverage_angle_events" in query:
            return self.recorded_events
        assert "investigation_candidate_observations" in query
        return 1 if self.candidate_owned else None

    async def fetchrow(self, query, *args):
        if query.lstrip().startswith("SELECT candidate_id"):
            if self.latest_candidate_id is None:
                return None
            return {"candidate_id": UUID(self.latest_candidate_id)}
        assert "INSERT INTO hunt_coverage_angle_events" in query
        self.inserted = args
        return {
            "id": uuid4(),
            "event_seq": 1,
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


# A confirmed SSH plan and a device posture queue both settle their action as
# "completed" while the downstream scan is only queued; the device queue even books
# its port charges at enqueue time.
SSH_PLAN_HANDOFF = {
    "ok": True, "status": "queued", "scan_id": str(uuid4()),
    "receipt_observations": [{"kind": "confirmed_ssh_execution_queue", "status": "queued"}],
    "budget_consumed": {"tool_wall_seconds": 3},
}
DEVICE_QUEUE_HANDOFF = {
    "ok": True, "partial": True,
    "queued": {"scan_id": str(uuid4()), "status": "queued", "run_kind": "device_posture"},
    "budget_accounting": {"actual": {"tcp_ports_attempted": 1000, "tool_wall_seconds": 2}},
}


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["negative", "partial", "blocked", "planned", "candidate"])
@pytest.mark.parametrize("handoff", [SSH_PLAN_HANDOFF, DEVICE_QUEUE_HANDOFF])
async def test_queue_handoffs_are_never_coverage_evidence(status, handoff):
    action_id = str(uuid4())
    conn = _Conn({action_id: ("completed", handoff)})
    with pytest.raises(CoverageLedgerError) as exc:
        await record_coverage_angle(conn, hunt_run_id=str(uuid4()), values=_angle(
            status=status, evidence_action_ids=[action_id], candidate_id=str(uuid4()),
            blocker="device scan pending",
        ))
    assert exc.value.code == "coverage_evidence_queued_handoff"
    assert conn.inserted is None


@pytest.mark.asyncio
@pytest.mark.parametrize("summary", [
    {},
    {"budget_accounting": {"actual": {"tool_wall_seconds": 4, "agent_actions": 1}}},
    {"budget_consumed": {"http_requests": 0, "active_actions": 1}},
    {"budget_consumed": {"http_requests": True}},
])
async def test_negative_needs_an_action_that_sent_target_traffic(summary):
    action_id = str(uuid4())
    conn = _Conn({action_id: ("completed", summary)})
    with pytest.raises(CoverageLedgerError) as exc:
        await record_coverage_angle(conn, hunt_run_id=str(uuid4()), values=_angle(
            status="negative", evidence_action_ids=[action_id],
        ))
    assert exc.value.code == "coverage_negative_requires_executed_actions"


@pytest.mark.asyncio
@pytest.mark.parametrize("summary", [
    EXECUTED,
    {"budget_consumed": {"hosts_attempted": 2, "tool_wall_seconds": 1}},
    {"budget_accounting": {"actual": {"browser_actions": 3}}},
])
async def test_negative_accepts_completed_actions_with_measured_traffic(summary):
    action_id = str(uuid4())
    conn = _Conn({action_id: ("completed", summary)})
    result = await record_coverage_angle(conn, hunt_run_id=str(uuid4()), values=_angle(
        status="negative", evidence_action_ids=[action_id],
    ))
    assert result["angle"]["status"] == "negative"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["partial", "blocked"])
async def test_partial_and_blocked_citations_need_one_executed_action(status):
    refused, quiet = str(uuid4()), str(uuid4())
    conn = _Conn({refused: "blocked", quiet: ("completed", {})})
    values = _angle(status=status, evidence_action_ids=[refused, quiet], blocker="scope refusal")
    with pytest.raises(CoverageLedgerError) as exc:
        await record_coverage_angle(conn, hunt_run_id=str(uuid4()), values=values)
    assert exc.value.code == "coverage_evidence_not_executed"
    ran = str(uuid4())
    conn = _Conn({refused: "blocked", ran: "partial"})
    result = await record_coverage_angle(conn, hunt_run_id=str(uuid4()), values={
        **values, "evidence_action_ids": [refused, ran],
    })
    assert result["angle"]["status"] == status


@pytest.mark.asyncio
async def test_blocked_may_still_be_recorded_from_its_blocker_alone():
    conn = _Conn({})
    result = await record_coverage_angle(conn, hunt_run_id=str(uuid4()), values=_angle(
        status="blocked", blocker="Second approved principal is unavailable",
    ))
    assert result["angle"]["evidence_action_ids"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("action_status", ["running", "failed"])
async def test_unsettled_or_failed_actions_are_not_evidence(action_status):
    action_id = str(uuid4())
    conn = _Conn({action_id: (action_status, EXECUTED)})
    with pytest.raises(CoverageLedgerError) as exc:
        await record_coverage_angle(conn, hunt_run_id=str(uuid4()), values=_angle(
            status="partial", evidence_action_ids=[action_id],
        ))
    assert exc.value.code == "coverage_evidence_not_terminal"


@pytest.mark.asyncio
async def test_candidate_coverage_cannot_cite_a_refused_action():
    refused, ran = str(uuid4()), str(uuid4())
    conn = _Conn({refused: "blocked", ran: "completed"})
    with pytest.raises(CoverageLedgerError) as exc:
        await record_coverage_angle(conn, hunt_run_id=str(uuid4()), values=_angle(
            status="candidate", evidence_action_ids=[ran, refused], candidate_id=str(uuid4()),
        ))
    assert exc.value.code == "coverage_candidate_requires_executed_evidence"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["planned", "testing", "blocked"])
async def test_evidence_free_event_cannot_drop_the_bound_candidate(status):
    bound = str(uuid4())
    conn = _Conn({}, latest_candidate_id=bound)
    values = _angle(status=status, blocker="waiting on a second principal")
    with pytest.raises(CoverageLedgerError) as exc:
        await record_coverage_angle(conn, hunt_run_id=str(uuid4()), values=values)
    assert exc.value.code == "coverage_candidate_binding_superseded"
    assert exc.value.status_code == 409
    assert exc.value.details["candidate_id"] == bound
    assert conn.inserted is None
    kept = await record_coverage_angle(
        conn, hunt_run_id=str(uuid4()), values={**values, "candidate_id": bound},
    )
    assert kept["angle"]["candidate_id"] == bound


@pytest.mark.asyncio
async def test_new_executed_evidence_may_change_a_candidate_bound_angle():
    action_id = str(uuid4())
    conn = _Conn({action_id: "completed"}, latest_candidate_id=str(uuid4()))
    result = await record_coverage_angle(conn, hunt_run_id=str(uuid4()), values=_angle(
        status="negative", evidence_action_ids=[action_id],
    ))
    assert result["angle"]["status"] == "negative"


def test_traffic_dimensions_are_canonical_budget_dimensions():
    from api.hunt.coverage_evidence import EXECUTED_TRAFFIC_DIMENSIONS
    from api.runtime.budgets import BUDGET_DIMENSIONS

    assert EXECUTED_TRAFFIC_DIMENSIONS <= BUDGET_DIMENSIONS
    assert not EXECUTED_TRAFFIC_DIMENSIONS & {"tool_wall_seconds", "agent_actions", "active_actions"}


class _CheckpointConn:
    """Answers the checkpoint queries; the continuation query applies the SQL's filter."""

    def __init__(self, candidate_status="verified"):
        self.candidate_id = uuid4()
        self.angle_id = uuid4()
        self.candidate_status = candidate_status
        self.now = datetime.now(timezone.utc)

    def _angle_row(self):
        return {
            "id": self.angle_id,
            "event_seq": 1,
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
            "candidate_status": self.candidate_status,
            "blocker": None,
            "proof_gap": None,
            "created_at": self.now,
        }

    async def fetch(self, query, *args):
        if "continuation_total" in query:
            if self.candidate_status in {"verified", "refuted", "expired"}:
                return []
            return [{**self._angle_row(), "continuation_total": 1}]
        if "LEFT JOIN investigation_candidates" in query:
            return [{**self._angle_row(), "total_count": 1}]
        if "FROM investigation_candidates c" in query:
            return [{
                "id": self.candidate_id,
                "family": "authorization",
                "title": "Cross-principal order read",
                "status": self.candidate_status,
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
    conn = _CheckpointConn(candidate_status="new")
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



class _RunConn(_Conn):
    """_Conn plus the locked hunt_runs row the service reads before writing."""

    def __init__(self, run, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.run = run
        self.locked = False

    def transaction(self, **_kwargs):
        conn = self

        class _Txn:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *exc):
                return False

        return _Txn()

    async def fetchrow(self, query, *args):
        if query.startswith("SELECT * FROM hunt_runs"):
            self.locked = "FOR UPDATE" in query
            return self.run
        return await super().fetchrow(query, *args)


def _service_for(conn):
    from api.hunt.run_service import HuntRunService

    class _Acquire:
        async def __aenter__(self):
            return conn

        async def __aexit__(self, *exc):
            return False

    class _Pool:
        def acquire(self):
            return _Acquire()

    return HuntRunService(lambda: _Pool())


def _run(status, *, finished=False):
    return {"id": uuid4(), "status": status,
            "completed_at": datetime.now(timezone.utc) if finished else None}


@pytest.mark.asyncio
@pytest.mark.parametrize("status,finished,shown", [
    ("completed", True, "Hunt is completed;"),
    ("cancelled", True, "Hunt is cancelled;"),
    ("failed", True, "Hunt is failed;"),
    ("created", False, "Hunt is created;"),
    ("budget_exhausted", True, "Hunt is budget_exhausted and finished;"),
])
async def test_finished_cancelled_or_unstarted_hunts_refuse_coverage_writes(status, finished, shown):
    from fastapi import HTTPException

    action_id = str(uuid4())
    run = _run(status, finished=finished)
    conn = _RunConn(run, {action_id: "completed"})
    with pytest.raises(HTTPException) as exc:
        await _service_for(conn).record_coverage_angle(str(run["id"]), values=_angle(
            status="negative", evidence_action_ids=[action_id],
        ))
    assert exc.value.status_code == 409
    assert shown in exc.value.detail
    assert "read-only" in exc.value.detail
    assert conn.locked and conn.inserted is None


@pytest.mark.asyncio
async def test_unfinished_budget_exhausted_hunt_accepts_evidence_bound_coverage():
    action_id = str(uuid4())
    run = _run("budget_exhausted")
    conn = _RunConn(run, {action_id: "completed"})
    service = _service_for(conn)
    settled = await service.record_coverage_angle(str(run["id"]), values=_angle(
        status="negative", evidence_action_ids=[action_id],
    ))
    assert settled["angle"]["status"] == "negative"
    conn.inserted = None
    with pytest.raises(CoverageLedgerError) as exc:
        await service.record_coverage_angle(str(run["id"]), values=_angle(status="planned"))
    assert exc.value.code == "coverage_budget_exhausted_requires_evidence"
    assert exc.value.status_code == 409
    assert conn.inserted is None


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["active", "awaiting_planner"])
async def test_active_hunts_accept_planned_coverage(status):
    run = _run(status)
    conn = _RunConn(run, {})
    result = await _service_for(conn).record_coverage_angle(
        str(run["id"]), values=_angle(status="planned"),
    )
    assert result["angle"]["status"] == "planned"


class _WindowConn(_CheckpointConn):
    """Simulates SQL that matched more open angles than the checkpoint returns."""

    async def fetch(self, query, *args):
        if "continuation_total" in query:
            assert args[1] == 200
            return [{**self._angle_row(), "fingerprint": f"{n:064x}", "status": "planned",
                     "continuation_total": 201} for n in range(args[1])]
        return await super().fetch(query, *args)


@pytest.mark.asyncio
async def test_checkpoint_reports_a_truncated_continuation_queue():
    checkpoint = await build_hunt_checkpoint(
        _WindowConn(candidate_status="new"), run={"id": uuid4(), "status": "active"},
    )
    assert checkpoint["continuation_count"] == 200
    assert checkpoint["continuation_total"] == 201
    assert checkpoint["continuation_truncated"] is True


@pytest.mark.asyncio
async def test_checkpoint_selects_the_continuation_queue_over_every_open_angle():
    class Recording(_CheckpointConn):
        queries = []

        async def fetch(self, query, *args):
            self.queries.append(query)
            return await super().fetch(query, *args)

    conn = Recording(candidate_status="new")
    checkpoint = await build_hunt_checkpoint(conn, run={"id": uuid4(), "status": "active"})
    continuation = next(q for q in conn.queries if "continuation_total" in q)
    # Not the newest-first 200-angle window: every open angle is counted and ranked.
    assert "ORDER BY latest.event_seq DESC" not in continuation
    assert "WHEN 'candidate' THEN 0" in continuation
    assert checkpoint["continuation_total"] == 1 and checkpoint["continuation_truncated"] is False


@pytest.mark.asyncio
async def test_record_export_carries_the_event_history_with_an_explicit_bound():
    from api.hunt import run_service

    superseded = uuid4()

    class Conn:
        async def fetch(self, query, *args):
            assert "FROM hunt_coverage_angle_events e" in query
            assert args[1] == run_service.MAX_EXPORT_ROWS
            first = {
                "id": superseded, "event_seq": 1, "fingerprint": "f" * 64,
                "family": "authorization", "locus_json": '{"route":"/r"}', "status": "candidate",
                "candidate_id": uuid4(), "evidence_action_ids": "[]",
                "contradictory_evidence_action_ids": "[]", "total_count": 2,
            }
            later = {**first, "id": uuid4(), "event_seq": 2, "status": "negative"}
            return [{**first, "superseded_by_event_id": later["id"]},
                    {**later, "superseded_by_event_id": None}]

    history = await run_service._coverage_history(
        Conn(), hunt_run_id=str(uuid4()), limit=run_service.MAX_EXPORT_ROWS,
    )
    assert [(event["status"], event["superseded"]) for event in history["events"]] == [
        ("candidate", True), ("negative", False),
    ]
    assert history["events"][0]["superseded_by_event_id"] == str(history["events"][1]["id"])
    assert history["event_total"] == 2 and history["events_truncated"] is False
    assert history["event_limit"] == run_service.MAX_EXPORT_ROWS


def test_secret_values_are_redacted_before_storage_and_fingerprinting():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl"
    first = normalize_coverage_angle(_angle(
        locus={"route": "/cb", "url": "https://a.example/cb?access_token=abc123&state=1"},
        mechanism="replay with password=hunter2",
        hypothesis=f"session {jwt} is accepted after logout",
        principal_context={"owner": "Authorization: Bearer abcdef0123456789"},
        status="blocked", blocker="needs token Zm9vYmFyYmF6cXV4MTIz rotated",
    ))
    second = normalize_coverage_angle(_angle(
        locus={"route": "/cb", "url": "https://a.example/cb?access_token=zzz999&state=1"},
        mechanism="replay with password=other-pass",
        principal_context={"owner": "Authorization: Bearer 9876543210fedcba"},
    ))
    stored = json.dumps(first)
    for secret in ("abc123", "hunter2", jwt, "abcdef0123456789", "Zm9vYmFyYmF6cXV4MTIz"):
        assert secret not in stored
    assert "state=1" in first["locus"]["url"]
    assert first["fingerprint"] == second["fingerprint"]
    # Redaction is stable, so a stored angle re-normalizes to the same fingerprint.
    again = normalize_coverage_angle({**first, "evidence_action_ids": []})
    assert again["fingerprint"] == first["fingerprint"]


def test_oversized_principal_context_is_refused():
    with pytest.raises(CoverageLedgerError) as exc:
        normalize_coverage_angle(_angle(principal_context={"note": "x" * 17_000}))
    assert exc.value.code == "coverage_context_too_large"


@pytest.mark.asyncio
async def test_per_hunt_event_cap_refuses_further_events():
    from api.hunt.coverage_ledger import MAX_COVERAGE_EVENTS_PER_HUNT
    from api.runtime.http_archive_reader import MAX_EXPORT_ROWS

    from api.hunt.start_contract import hunt_start_public_contract

    assert MAX_COVERAGE_EVENTS_PER_HUNT < MAX_EXPORT_ROWS
    contract = hunt_start_public_contract()["coverage_ledger"]
    assert contract["max_events_per_hunt"] == MAX_COVERAGE_EVENTS_PER_HUNT
    skill = (Path(__file__).resolve().parents[1] / "skills/hunt/SKILL.md").read_text()
    assert f"at most {MAX_COVERAGE_EVENTS_PER_HUNT:,} coverage events" in skill
    conn = _Conn({}, recorded_events=MAX_COVERAGE_EVENTS_PER_HUNT)
    with pytest.raises(CoverageLedgerError) as exc:
        await record_coverage_angle(conn, hunt_run_id=str(uuid4()), values=_angle())
    assert exc.value.code == "coverage_event_limit_reached"
    assert exc.value.status_code == 409
    assert exc.value.details["max_events_per_hunt"] == MAX_COVERAGE_EVENTS_PER_HUNT
    assert conn.inserted is None
    conn.recorded_events -= 1
    assert (await record_coverage_angle(conn, hunt_run_id=str(uuid4()), values=_angle()))["angle"]
