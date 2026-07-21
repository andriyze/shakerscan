"""Host tests for the typed-invariant live binder (zero-FP promotion gate).

Feeds `_trusted_invariant_execution_evidence` / `_trusted_workflow_family_proof` synthetic
two-run observations and asserts the ONLY paths to `verified` are sound:

- verified requires both runs stable + restored + no errors;
- supported_unverified when the replay disagrees (no stable predicates);
- refuted when the forbidden role is denied / the constraint is enforced / the transition held;
- never promotable without restoration;
- workflow_transition fires ONLY when the object started in the approved from_state AND the
  app persisted the contract-declared forbidden probe_state (audit F1: a wrong starting state
  or a coerced write must NOT verify).

Pure host tests (fastapi/asyncpg stubbed, per tests/test_api_helpers.py).
"""

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

if "fastapi" not in sys.modules:
    fastapi_mod = types.ModuleType("fastapi")

    class _FakeFastAPI:
        def __init__(self, *args, **kwargs):
            pass

        def add_middleware(self, *args, **kwargs):
            return None

        def _decorator(self, *args, **kwargs):
            def wrapper(fn):
                return fn
            return wrapper

        get = post = patch = put = delete = on_event = exception_handler = _decorator

    class _FakeHTTPException(Exception):
        def __init__(self, status_code: int = 500, detail=None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    def _fake_query(default=None, **kwargs):
        return default

    class _FakeRequest:
        def __init__(self, query_params=None):
            self.query_params = query_params or {}

    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.HTTPException = _FakeHTTPException
    fastapi_mod.Query = _fake_query
    fastapi_mod.Request = _FakeRequest
    sys.modules["fastapi"] = fastapi_mod

    middleware_mod = types.ModuleType("fastapi.middleware")
    cors_mod = types.ModuleType("fastapi.middleware.cors")

    class _FakeCORSMiddleware:
        pass

    cors_mod.CORSMiddleware = _FakeCORSMiddleware
    sys.modules["fastapi.middleware"] = middleware_mod
    sys.modules["fastapi.middleware.cors"] = cors_mod

    responses_mod = types.ModuleType("fastapi.responses")

    class _FakeResponse:
        def __init__(self, content=None, status_code=200, headers=None, media_type=None):
            self.content = content
            self.status_code = status_code
            self.headers = headers or {}
            self.media_type = media_type

    responses_mod.Response = _FakeResponse
    responses_mod.JSONResponse = _FakeResponse
    sys.modules["fastapi.responses"] = responses_mod

import api as api_module  # noqa: E402


# ---------------------------------------------------------------------------
# Synthetic builders
# ---------------------------------------------------------------------------

def _obs(label, method, path, *, principal="user1", checkpoint="action", status=200,
         selected=None, error=None):
    return {
        "label": label,
        "kind": "http",
        "principal": principal,
        "checkpoint": checkpoint,
        "request": {"method": method, "path": path},
        "response": ({"status": status, "selected_json": selected or {}} if not error else {}),
        "error": error,
    }


def _workflow_result(steps_obs, *, restoration=True):
    return {
        "proof_family": "workflow",
        "observations": steps_obs,
        "principal_receipts": [
            {"slot": "user1", "role": "user", "identity_fingerprint": "id-aaaa"},
            {"slot": "user2", "role": "mechanic", "identity_fingerprint": "id-bbbb"},
        ],
        "restoration_verified": restoration,
    }


def _wf_normalized(route="/api/orders/7", write_method="PUT", field="status", probe="archived",
                   read_sel="$.status"):
    return {
        "proof_family": "workflow",
        "steps": [
            {"label": "before", "kind": "http", "principal": "user1", "checkpoint": "before",
             "method": "GET", "path": route, "select_json": [read_sel]},
            {"label": "mutate", "kind": "http", "principal": "user1", "checkpoint": "mutation",
             "method": write_method, "path": route, "json_body": {field: probe}},
            {"label": "violation", "kind": "http", "principal": "user1", "checkpoint": "action",
             "method": "GET", "path": route, "select_json": [read_sel]},
            {"label": "rollback", "kind": "http", "principal": "user1", "checkpoint": "rollback",
             "method": write_method, "path": route, "json_body": {field: "${baseline}"}},
            {"label": "after", "kind": "http", "principal": "user1", "checkpoint": "after",
             "method": "GET", "path": route, "select_json": [read_sel]},
        ],
    }


def _wf_contract(route="/api/orders/{id}", write_method="PUT", field="status",
                 from_state="pending", to_state="shipped", probe="archived", read_path=None):
    conditions = {"from_state": from_state, "to_state": to_state, "probe_state": probe}
    if read_path:
        conditions["read_path"] = read_path
    return {
        "id": "11111111-1111-1111-1111-111111111111",
        "contract_kind": "workflow_transition",
        "method": write_method,
        "path": route,
        "field_name": field,
        "conditions": conditions,
        "status": "approved",
        "title": "orders may only go pending->shipped",
    }


def _wf_run(route, write_method, field, before_state, violation_state, *, restoration=True):
    """One two-step-state run: before=before_state, mutation ok, violation-read=violation_state,
    rollback ok, after=before_state."""
    obs = [
        _obs("before", "GET", route, checkpoint="before", selected={"$.status": before_state}),
        _obs("mutate", write_method, route, checkpoint="mutation", status=200),
        _obs("violation", "GET", route, checkpoint="action", selected={"$.status": violation_state}),
        _obs("rollback", write_method, route, checkpoint="rollback", status=200),
        _obs("after", "GET", route, checkpoint="after", selected={"$.status": before_state}),
    ]
    return _workflow_result(obs, restoration=restoration)


# ---------------------------------------------------------------------------
# workflow_transition — the F1 guards
# ---------------------------------------------------------------------------

def test_workflow_transition_verified_only_forbidden_probe_from_approved_state():
    contract = _wf_contract()
    normalized = _wf_normalized()
    first = _wf_run("/api/orders/7", "PUT", "status", "pending", "archived")
    replay = _wf_run("/api/orders/7", "PUT", "status", "pending", "archived")
    proof = api_module._trusted_workflow_family_proof(
        first, replay, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] == "verified"
    assert proof["promotable"] is True
    assert "transition_invariant_broken" in proof["stable_predicates"]
    assert "before_after_state" in proof["stable_predicates"]


def test_workflow_transition_wrong_starting_state_never_verifies():
    """Audit F1: object in a state OTHER than from_state — any transition it makes is
    not the contract's declared one, but must NOT count as a broken invariant."""
    contract = _wf_contract()  # pending -> shipped only; probe archived
    normalized = _wf_normalized()
    first = _wf_run("/api/orders/7", "PUT", "status", "shipped", "archived")
    replay = _wf_run("/api/orders/7", "PUT", "status", "shipped", "archived")
    proof = api_module._trusted_workflow_family_proof(
        first, replay, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] != "verified"
    assert "transition_invariant_broken" not in proof["stable_predicates"]


def test_workflow_transition_coerced_write_never_verifies():
    """Audit F1: the app resisted the forbidden state by coercing the write to a third
    (legal) state — it never entered probe_state, so it must NOT be reported broken."""
    contract = _wf_contract()
    normalized = _wf_normalized()
    first = _wf_run("/api/orders/7", "PUT", "status", "pending", "review")
    replay = _wf_run("/api/orders/7", "PUT", "status", "pending", "review")
    proof = api_module._trusted_workflow_family_proof(
        first, replay, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] != "verified"
    assert "transition_invariant_broken" not in proof["stable_predicates"]


def test_workflow_transition_legal_transition_is_refuted():
    contract = _wf_contract()
    normalized = _wf_normalized()
    first = _wf_run("/api/orders/7", "PUT", "status", "pending", "shipped")
    replay = _wf_run("/api/orders/7", "PUT", "status", "pending", "shipped")
    proof = api_module._trusted_workflow_family_proof(
        first, replay, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] == "refuted"
    assert "invariant_held" in proof["stable_predicates"]


def test_workflow_transition_not_promotable_without_restoration():
    contract = _wf_contract()
    normalized = _wf_normalized()
    first = _wf_run("/api/orders/7", "PUT", "status", "pending", "archived", restoration=False)
    replay = _wf_run("/api/orders/7", "PUT", "status", "pending", "archived", restoration=False)
    proof = api_module._trusted_workflow_family_proof(
        first, replay, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] != "verified"
    assert proof["promotable"] is False


def test_workflow_transition_unstable_replay_stays_unverified():
    """A single successful run is a claim, not proof: the replay must independently
    derive the same predicates."""
    contract = _wf_contract()
    normalized = _wf_normalized()
    first = _wf_run("/api/orders/7", "PUT", "status", "pending", "archived")
    replay = _wf_run("/api/orders/7", "PUT", "status", "pending", "pending")  # app resisted
    proof = api_module._trusted_workflow_family_proof(
        first, replay, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] != "verified"
    assert "transition_invariant_broken" not in proof["stable_predicates"]


def test_workflow_transition_read_path_redirects_projection():
    """Wrapping API: write {status: v}; read $.data.status."""
    contract = _wf_contract(read_path="data.status")
    normalized = _wf_normalized(read_sel="$.data.status")
    obs = [
        _obs("before", "GET", "/api/orders/7", checkpoint="before",
             selected={"$.data.status": "pending"}),
        _obs("mutate", "PUT", "/api/orders/7", checkpoint="mutation", status=200),
        _obs("violation", "GET", "/api/orders/7", checkpoint="action",
             selected={"$.data.status": "archived"}),
        _obs("rollback", "PUT", "/api/orders/7", checkpoint="rollback", status=200),
        _obs("after", "GET", "/api/orders/7", checkpoint="after",
             selected={"$.data.status": "pending"}),
    ]
    result = _workflow_result(obs)
    proof = api_module._trusted_workflow_family_proof(
        result, result, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] == "verified"


# ---------------------------------------------------------------------------
# field_constraint
# ---------------------------------------------------------------------------

def _fc_contract(route="/api/basket/3", write_method="PUT", field="quantity",
                 operator="lte", expected=3):
    return {
        "id": "22222222-2222-2222-2222-222222222222",
        "contract_kind": "field_constraint",
        "method": write_method,
        "path": route,
        "field_name": field,
        "operator": operator,
        "expected_value": expected,
        "conditions": {},
        "status": "approved",
    }


def _fc_normalized(route="/api/basket/3", write_method="PUT", field="quantity", probe=4):
    return {
        "proof_family": "field_constraint",
        "steps": [
            {"label": "before", "kind": "http", "principal": "user1", "checkpoint": "before",
             "method": "GET", "path": route, "select_json": ["$.quantity"]},
            {"label": "mutate", "kind": "http", "principal": "user1", "checkpoint": "mutation",
             "method": write_method, "path": route, "json_body": {field: probe}},
            {"label": "violation", "kind": "http", "principal": "user1", "checkpoint": "action",
             "method": "GET", "path": route, "select_json": ["$.quantity"]},
            {"label": "rollback", "kind": "http", "principal": "user1", "checkpoint": "rollback",
             "method": write_method, "path": route, "json_body": {field: "${baseline}"}},
            {"label": "after", "kind": "http", "principal": "user1", "checkpoint": "after",
             "method": "GET", "path": route, "select_json": ["$.quantity"]},
        ],
    }


def _fc_run(route, write_method, before_value, violation_value, *, mutate_status=200,
            restoration=True):
    obs = [
        _obs("before", "GET", route, checkpoint="before", selected={"$.quantity": before_value}),
        _obs("mutate", write_method, route, checkpoint="mutation", status=mutate_status),
        _obs("violation", "GET", route, checkpoint="action", selected={"$.quantity": violation_value}),
        _obs("rollback", write_method, route, checkpoint="rollback", status=200),
        _obs("after", "GET", route, checkpoint="after", selected={"$.quantity": before_value}),
    ]
    result = _workflow_result(obs, restoration=restoration)
    result["proof_family"] = "field_constraint"
    return result


def test_field_constraint_verified_when_violation_persists_and_restores():
    contract = _fc_contract()
    normalized = _fc_normalized()
    first = _fc_run("/api/basket/3", "PUT", 1, 4)
    replay = _fc_run("/api/basket/3", "PUT", 1, 4)
    proof = api_module._trusted_workflow_family_proof(
        first, replay, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] == "verified"
    assert "constraint_baseline_observed" in proof["stable_predicates"]
    assert "constraint_violation_persisted" in proof["stable_predicates"]


def test_field_constraint_clamped_value_stays_unverified():
    """The app accepted the write but clamped 4 -> 3: the violation never persisted."""
    contract = _fc_contract()
    normalized = _fc_normalized()
    first = _fc_run("/api/basket/3", "PUT", 1, 3)
    replay = _fc_run("/api/basket/3", "PUT", 1, 3)
    proof = api_module._trusted_workflow_family_proof(
        first, replay, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] != "verified"
    assert "constraint_violation_persisted" not in proof["stable_predicates"]


def test_field_constraint_rejected_write_is_refuted():
    contract = _fc_contract()
    normalized = _fc_normalized()
    first = _fc_run("/api/basket/3", "PUT", 1, 1, mutate_status=422)
    replay = _fc_run("/api/basket/3", "PUT", 1, 1, mutate_status=422)
    proof = api_module._trusted_workflow_family_proof(
        first, replay, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] == "refuted"
    assert "constraint_enforced" in proof["stable_predicates"]


def test_field_constraint_legal_baseline_required():
    """A baseline ALREADY out of bounds cannot prove the constraint is missing (the app
    may simply have legacy data); only an in-bounds baseline -> persisted violation proves it."""
    contract = _fc_contract()
    normalized = _fc_normalized()
    first = _fc_run("/api/basket/3", "PUT", 9, 4)  # baseline 9 violates lte 3
    replay = _fc_run("/api/basket/3", "PUT", 9, 4)
    proof = api_module._trusted_workflow_family_proof(
        first, replay, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] != "verified"
    assert "constraint_baseline_observed" not in proof["stable_predicates"]


# ---------------------------------------------------------------------------
# access_control
# ---------------------------------------------------------------------------

def _ac_contract(route="/workshop/api/mechanic/report", role="mechanic"):
    return {
        "id": "33333333-3333-3333-3333-333333333333",
        "contract_kind": "access_control",
        "method": "GET",
        "path": route,
        "subject_role": role,
        "expected_access": "requires_role",
        "conditions": {},
        "status": "approved",
    }


def _ac_normalized(route="/workshop/api/mechanic/report"):
    return {
        "proof_family": "access_control",
        "steps": [
            {"label": "role_a", "kind": "http", "principal": "user1", "checkpoint": "action",
             "method": "GET", "path": route},
            {"label": "role_b", "kind": "http", "principal": "user2", "checkpoint": "action",
             "method": "GET", "path": route, "compare_to": "role_a"},
        ],
    }


def _ac_run(route, *, user1_status, user2_status):
    obs = [
        _obs("role_a", "GET", route, principal="user1", status=user1_status),
        _obs("role_b", "GET", route, principal="user2", status=user2_status),
    ]
    result = _workflow_result(obs)
    result["proof_family"] = "access_control"
    return result


def test_access_control_verified_when_forbidden_role_succeeds():
    # receipts: user1=user, user2=mechanic. mechanic succeeds (control), user succeeds (violation).
    contract = _ac_contract()
    normalized = _ac_normalized()
    first = _ac_run("/workshop/api/mechanic/report", user1_status=200, user2_status=200)
    replay = _ac_run("/workshop/api/mechanic/report", user1_status=200, user2_status=200)
    proof = api_module._trusted_workflow_family_proof(
        first, replay, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] == "verified"
    assert "authorized_role_control" in proof["stable_predicates"]
    assert "forbidden_role_access" in proof["stable_predicates"]
    assert "distinct_identity" in proof["stable_predicates"]


def test_access_control_refuted_when_forbidden_role_denied():
    contract = _ac_contract()
    normalized = _ac_normalized()
    first = _ac_run("/workshop/api/mechanic/report", user1_status=403, user2_status=200)
    replay = _ac_run("/workshop/api/mechanic/report", user1_status=403, user2_status=200)
    proof = api_module._trusted_workflow_family_proof(
        first, replay, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] == "refuted"
    assert "forbidden_role_denied" in proof["stable_predicates"]


# ---------------------------------------------------------------------------
# fail-closed guards
# ---------------------------------------------------------------------------

def test_draft_contract_binds_nothing():
    contract = _wf_contract()
    contract["status"] = "draft"
    normalized = _wf_normalized()
    result = _wf_run("/api/orders/7", "PUT", "status", "pending", "archived")
    evidence = api_module._trusted_invariant_execution_evidence(contract, normalized, result)
    assert evidence["predicates"] == set()


def test_malformed_contract_binds_nothing():
    normalized = _wf_normalized()
    result = _wf_run("/api/orders/7", "PUT", "status", "pending", "archived")
    evidence = api_module._trusted_invariant_execution_evidence(
        {"contract_kind": "nonsense"}, normalized, result)
    assert evidence["predicates"] == set()
    evidence = api_module._trusted_invariant_execution_evidence({}, normalized, result)
    assert evidence["predicates"] == set()


def test_execution_errors_block_verification():
    contract = _wf_contract()
    normalized = _wf_normalized()
    first = _wf_run("/api/orders/7", "PUT", "status", "pending", "archived")
    replay = _wf_run("/api/orders/7", "PUT", "status", "pending", "archived")
    replay["observations"][2] = _obs("violation", "GET", "/api/orders/7", checkpoint="action",
                                     error="timeout")
    proof = api_module._trusted_workflow_family_proof(
        first, replay, invariant_contract=contract, normalized=normalized)
    assert proof["verdict"] != "verified"
