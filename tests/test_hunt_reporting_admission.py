"""Execute production admission with exhausted traffic dimensions and bounded recording."""
import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from api.hunt.recording import recording_run_allowed
from api.hunt import interaction_router as router
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from tests.test_hunt_authz_verification_limit import HUNT, AdmissionStore, Lifecycle, admission
from tests.test_hunt_thorough_scanner_holds import _LedgerReservation


def _admit(*, candidates=0, finished=False, status="budget_exhausted", **overrides):
    store = AdmissionStore()
    store.run.update(status=status, completed_at="finished" if finished else None)
    store.run["budget_json"].update(max_candidates=2)
    store.run["budget_used_json"].update(agent_actions=100, active_actions=100,
        http_requests=1000, tool_wall_seconds=1000, candidates=candidates)
    name = "findings.create"
    lifecycle = Lifecycle(name)
    lifecycle.placement = "inline"
    lifecycle.specification = CAPABILITY_REGISTRY.require(name)
    recorded = []
    def reserve(**kwargs):
        recorded.append(kwargs['amounts'])
        return _LedgerReservation(kwargs['amounts'])
    asyncio.run(admission(store,
        _hunt_public=lambda *a, **k: {"capabilities": [{"name": name}]},
        DurableBudgetReservation=SimpleNamespace(request=reserve),
        BudgetExceeded=router.BudgetExceeded, **overrides,
    )(str(HUNT), name, SimpleNamespace(input={}, idempotency_key="recording-fixture"), lifecycle))
    return store, recorded


def test_finding_recording_reserves_only_the_shared_candidate_allowance():
    store, holds = _admit()
    assert holds == [{"candidates": 1}]
    assert store.run['budget_used_json']['candidates'] == 1
    assert store.run['budget_used_json']['agent_actions'] == 100
    assert store.run['status'] == 'budget_exhausted'


def test_recording_cannot_bypass_its_own_budget_or_finish():
    with pytest.raises(HTTPException):
        _admit(candidates=2)
    with pytest.raises(HTTPException):
        _admit(finished=True)


def test_exhaustion_never_enables_target_traffic():
    run = {'status': 'budget_exhausted', 'completed_at': None}
    for name in ('http.request', 'xss.verify', 'sqli.verify', 'ssh.exec', 'unknown.tool'):
        assert not recording_run_allowed(run, name)
    assert recording_run_allowed(run, 'findings.create')


@pytest.mark.parametrize('name,allowed', [('findings.create', True), ('http.request', False)])
def test_parked_recording_rechecks_an_amended_allowance_without_resuming_traffic(monkeypatch, name, allowed):
    async def pending(*args):
        return 'pending', {'id': 'fixture'}
    monkeypatch.setattr(router, 'parked_outcome', pending)
    monkeypatch.setattr(router, 'permission_required', lambda *args: HTTPException(409, 'permission_required'))
    class Connection:
        deleted = False
        async def execute(self, query, *args):
            assert query.lstrip().startswith('DELETE FROM hunt_actions')
            self.deleted = True
    conn = Connection()
    call = router._resume_parked_action(conn,
        {'id': HUNT, 'status': 'budget_exhausted', 'completed_at': None}, HUNT,
        {'capability_name': name, 'result_summary': {}}, [])
    if allowed:
        assert asyncio.run(call) is None and conn.deleted
    else:
        with pytest.raises(HTTPException):
            asyncio.run(call)
        assert not conn.deleted


@pytest.mark.parametrize("status", ["active", "awaiting_planner", "budget_exhausted"])
def test_a_full_record_allowance_refuses_the_write_without_stopping_the_hunt(status):
    """A full ``max_candidates`` refuses one finding write; it never records a budget shortage, so
    settlement cannot mark the Hunt ``budget_exhausted:candidates`` and stop its testing."""
    refused = []

    async def settle_refusal(*_args, refusal, **_kwargs):
        refused.append(refusal)
        raise refusal

    with pytest.raises(HTTPException):
        _admit(candidates=2, status=status, settle_refusal=settle_refusal)
    assert len(refused) == 1
    assert refused[0].detail["error"] == "budget_exhausted:candidates"
    assert getattr(refused[0], "budget_state", None) is None


def test_settlement_never_records_a_shortage_for_a_recording_capability(monkeypatch):
    """Even a refusal that carries a budget state leaves the Hunt's status alone when the refused
    action only records evidence."""
    from api.hunt import permission_admission
    from api.hunt.permission_reasons import HuntRefusal

    recorded, executed = [], []

    async def record_budget_shortage(*args, **kwargs):
        recorded.append(kwargs)

    async def credential_use_refusal(conn, run, refusal):
        return refusal

    async def complete_destination_subject(run, refusal):
        return refusal

    class Connection:
        def __init__(self):
            self.run = {"id": HUNT, "status": "active", "completed_at": None}

        async def fetchrow(self, query, *args):
            return dict(self.run)

        async def execute(self, query, *args):
            executed.append(query)

        def transaction(self):
            return _Transaction()

    class _Transaction:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    class Pool:
        def acquire(self):
            return _Acquire()

    class _Acquire:
        async def __aenter__(self):
            return Connection()

        async def __aexit__(self, *args):
            return False

    monkeypatch.setattr(permission_admission, "record_budget_shortage", record_budget_shortage)
    monkeypatch.setattr(permission_admission, "credential_use_refusal", credential_use_refusal)
    monkeypatch.setattr(permission_admission, "complete_destination_subject", complete_destination_subject)
    refusal = HuntRefusal("budget_exhausted", "full", error="budget_exhausted:candidates")
    refusal.budget_state = {"limits": {"candidates": 2}, "used": {"candidates": 2},
                            "shortages": {"candidates": 1}}
    with pytest.raises(HuntRefusal):
        asyncio.run(permission_admission.settle_refusal(
            Pool(), hunt_id=HUNT, action_id=HUNT, name="findings.create", input_summary={},
            input_digest="d" * 64, refusal=refusal))
    assert recorded == []
