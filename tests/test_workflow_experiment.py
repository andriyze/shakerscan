import asyncio
import sys
from pathlib import Path

import httpx
import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import workflow_experiment as workflow  # noqa: E402


def _contexts(*, same_identity=False):
    return {
        "user1": {"principal_id": "p1", "profile_id": "c1", "identity_fingerprint": "same" if same_identity else "i1", "role": "user", "tenant_id": "a", "headers": {"Authorization": "Bearer one"}},
        "user2": {"principal_id": "p2", "profile_id": "c2", "identity_fingerprint": "same" if same_identity else "i2", "role": "user", "tenant_id": "b", "headers": {"Authorization": "Bearer two"}},
    }


def test_same_account_principals_are_rejected_before_requests():
    calls = []
    with pytest.raises(workflow.WorkflowContractError, match="principal_accounts_not_distinct"):
        asyncio.run(workflow.execute_workflow(
            "https://example.test",
            {"steps": [{"label": "one", "principal": "user1", "path": "/a"}, {"label": "two", "principal": "user2", "path": "/b"}]},
            principal_contexts=_contexts(same_identity=True),
            transport=httpx.MockTransport(lambda request: calls.append(request) or httpx.Response(200)),
        ))
    assert calls == []


def test_principal_workflow_chains_api_and_browser_state_without_exposing_secrets():
    seen_auth = []

    def handler(request):
        seen_auth.append(request.headers.get("authorization"))
        if request.url.path == "/objects":
            return httpx.Response(200, json={"data": {"id": 7}})
        return httpx.Response(200, json={"owner": "other"})

    browser_calls = []

    async def browser_action(principal, action, data):
        browser_calls.append((principal, action, data))
        return {"success": True, "url": "https://example.test/objects/7", "value": "ready"}

    result = asyncio.run(workflow.execute_workflow(
        "https://example.test",
        {"steps": [
            {"label": "create", "kind": "http", "principal": "user1", "checkpoint": "before", "method": "GET", "path": "/objects", "extract": [{"name": "object_id", "source": "json", "path": "$.data.id"}]},
            {"label": "open", "kind": "browser", "principal": "user1", "checkpoint": "mutation", "action": "navigate", "data": {"path": "/objects/${object_id}"}},
            {"label": "cross", "kind": "http", "principal": "user2", "checkpoint": "after", "method": "GET", "path": "/objects/${object_id}", "compare_to": "create"},
        ]},
        principal_contexts=_contexts(),
        browser_action=browser_action,
        transport=httpx.MockTransport(handler),
    ))

    assert seen_auth == ["Bearer one", "Bearer two"]
    assert browser_calls[0][2]["path"] == "/objects/7"
    assert result["variable_names"] == ["object_id"]
    assert "Bearer one" not in str(result)
    assert result["principal_receipts"][0]["identity_verified"] is True
    assert result["proof_state"] == "unverified_workflow_signal"
    assert result["finding_created"] is False


def test_workflow_cancellation_stops_before_next_step():
    checks = iter([False, True])
    calls = []
    result = asyncio.run(workflow.execute_workflow(
        "https://example.test",
        {"steps": [{"label": "one", "path": "/a"}, {"label": "two", "path": "/b"}]},
        principal_contexts={},
        cancelled=lambda: next(checks),
        transport=httpx.MockTransport(lambda request: calls.append(request) or httpx.Response(200)),
    ))

    assert len(calls) == 1
    assert result["cancelled"] is True
    assert result["observations"][-1]["error"] == "workflow_cancelled_or_timed_out"


@pytest.mark.parametrize("payload,error", [
    ({"steps": [{"label": "a", "path": "/a", "extract": [{"name": "id", "source": "json", "path": "$.id"}]}, {"label": "b", "path": "/${missing}"}]}, "variable_not_declared"),
    ({"steps": [{"label": "a", "path": "/a"}, {"label": "b", "kind": "browser", "action": "fill", "data": {"selector": "#password", "value": "raw"}}]}, "sensitive_fill_forbidden"),
    ({"steps": [{"label": "a", "principal": "root", "path": "/a"}, {"label": "b", "path": "/b"}]}, "principal_slot_invalid"),
])
def test_workflow_contract_rejects_unsafe_shapes(payload, error):
    with pytest.raises(workflow.WorkflowContractError, match=error):
        workflow.normalize_workflow("https://example.test", payload)


def test_rendered_workflow_header_cannot_become_authorization():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"field": "Authorization"})

    result = asyncio.run(workflow.execute_workflow(
        "https://example.test",
        {"steps": [
            {"label": "discover", "path": "/field", "extract": [{"name": "field_name", "source": "json", "path": "$.field"}]},
            {"label": "mutate", "path": "/objects", "headers": {"${field_name}": "model-value"}},
        ]},
        principal_contexts={},
        transport=httpx.MockTransport(handler),
    ))

    assert len(calls) == 1
    assert result["observations"][1]["error"] == "rendered_header_forbidden"


def test_browser_action_data_is_strictly_typed():
    with pytest.raises(workflow.WorkflowContractError, match="browser_data_field_not_allowed"):
        workflow.normalize_workflow("https://example.test", {"steps": [
            {"label": "one", "path": "/a"},
            {"label": "two", "kind": "browser", "action": "navigate", "data": {"path": "/ok", "allow_out_of_scope": True}},
        ]})


def test_mutating_workflow_requires_and_verifies_restoration():
    state = {"owner": "user1"}

    def handler(request):
        if request.method == "PATCH":
            state["owner"] = "user2"
        elif request.method == "PUT":
            state["owner"] = "user1"
        return httpx.Response(200, json={"owner": state["owner"]})

    payload = {
        "proof_family": "workflow",
        "steps": [
            {"label": "before", "checkpoint": "before", "method": "GET", "path": "/object"},
            {"label": "mutate", "checkpoint": "mutation", "method": "PATCH", "path": "/object", "json_body": {"owner": "user2"}, "compare_to": "before"},
            {"label": "cleanup", "checkpoint": "cleanup", "method": "PUT", "path": "/object", "json_body": {"owner": "user1"}},
            {"label": "restored", "checkpoint": "after", "method": "GET", "path": "/object", "compare_to": "before"},
        ],
        "assertions": [
            {"type": "comparison_changed", "control": "before", "candidate": "mutate", "predicate": "transition_invariant_broken"},
            {"type": "restored", "control": "before", "candidate": "restored", "predicate": "before_after_state"},
        ],
    }
    result = asyncio.run(workflow.execute_workflow(
        "https://example.test", payload, principal_contexts={}, transport=httpx.MockTransport(handler)
    ))
    assert result["mutating"] is True
    assert result["assertions_passed"] is True
    assert result["restoration_verified"] is True
    assert state["owner"] == "user1"

    unsafe = {**payload, "steps": payload["steps"][:2], "assertions": payload["assertions"][:1]}
    with pytest.raises(workflow.WorkflowContractError, match="cleanup_or_rollback"):
        workflow.normalize_workflow("https://example.test", unsafe)


# --- P0: promotion predicates must be server-corroborated, never trusted from the model label ---

def test_generic_200_cannot_be_labelled_a_sensitive_value_finding():
    # Reproduced P0: a public endpoint returning {"status":"ok"} twice, with a status_in:[200]
    # assertion the model LABELS sensitive_value_present, must NOT corroborate data_exposure.
    result = {
        "observations": [
            {"label": "read", "principal": "anonymous",
             "response": {"status": 200, "json_keys": ["status"]},
             "sensitive_value_categories": []},
        ],
        "comparisons": [],
        "assertion_results": [
            {"id": "a1", "type": "status_in", "step": "read", "values": [200],
             "predicate": "sensitive_value_present", "passed": True},
        ],
    }
    assert workflow.server_corroborated_predicates(result) == set()


def test_real_sensitive_value_corroborates_data_exposure():
    # A response carrying an actual server-classified sensitive VALUE corroborates data_exposure.
    # The P0 fix keeps this grounded in a real value (the /health case above stays fail-closed),
    # while data_exposure remains a promotable family (not narrowed to BOLA-only).
    result = {
        "observations": [
            {"label": "read", "principal": "anonymous",
             "response": {"status": 200, "json_keys": ["token"]},
             "sensitive_value_categories": ["private_key"]},
        ],
        "comparisons": [],
        "assertion_results": [
            {"id": "a1", "type": "status_in", "step": "read", "values": [200],
             "predicate": "sensitive_value_present", "passed": True},
        ],
    }
    assert "sensitive_value_present" in workflow.server_corroborated_predicates(result)


def test_sensitive_value_classifier_matches_values_not_names():
    assert workflow._classify_sensitive_values('{"status":"ok"}') == []
    assert workflow._classify_sensitive_values('{"token_name":"my token"}') == []  # name only, no value
    assert "jwt" in workflow._classify_sensitive_values(
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij')
    assert "ssn" in workflow._classify_sensitive_values('{"ssn":"123-45-6789"}')


def test_cross_principal_access_requires_distinct_authenticated_principals_and_equivalence():
    shared = {
        "principal_receipts": [
            {"slot": "user1", "identity_fingerprint": "owner-id"},
            {"slot": "user2", "identity_fingerprint": "attacker-id"},
        ],
        "observations": [
            {"label": "owner", "principal": "user1", "response": {"status": 200}},
            {"label": "attacker", "principal": "user2", "response": {"status": 200}},
        ],
        "comparisons": [{"control": "owner", "candidate": "attacker", "comparable": True,
                         "state_changed": False, "status_changed": False, "body_changed": False}],
        "assertion_results": [{"id": "x", "type": "comparison_equivalent", "control": "owner",
                               "candidate": "attacker", "predicate": "cross_principal_access", "passed": True}],
    }
    assert "cross_principal_access" in workflow.server_corroborated_predicates(shared)

    # Two ANONYMOUS identical public responses must NOT corroborate cross-principal access.
    anon = {
        "observations": [
            {"label": "a", "principal": "anonymous", "response": {"status": 200}},
            {"label": "b", "principal": "anonymous", "response": {"status": 200}},
        ],
        "comparisons": [{"control": "a", "candidate": "b", "comparable": True, "body_changed": False}],
        "assertion_results": [{"id": "x", "type": "comparison_equivalent", "control": "a",
                               "candidate": "b", "predicate": "cross_principal_access", "passed": True}],
    }
    assert "cross_principal_access" not in workflow.server_corroborated_predicates(anon)


def test_public_success_and_generic_mutation_never_become_family_proof():
    public = {
        "observations": [
            {"label": "public", "principal": "anonymous", "response": {"status": 200}},
            {"label": "variant", "principal": "anonymous", "response": {"status": 200}},
        ],
        "comparisons": [
            {"control": "public", "candidate": "variant", "comparable": True, "body_changed": True},
        ],
        "assertion_results": [
            {"id": "p", "type": "status_in", "step": "public", "values": [200],
             "predicate": "protected_resource_accessed", "passed": True},
            {"id": "u", "type": "comparison_changed", "control": "public", "candidate": "variant",
             "predicate": "unauthenticated_control", "passed": True},
            {"id": "f", "type": "status_in", "step": "public", "values": [200],
             "predicate": "forbidden_field_accepted", "passed": True},
            {"id": "s", "type": "comparison_changed", "control": "public", "candidate": "variant",
             "predicate": "observable_state_change", "passed": True},
            {"id": "c", "type": "comparison_changed", "control": "public", "candidate": "variant",
             "predicate": "control_rejected", "passed": True},
        ],
    }
    corroborated = workflow.server_corroborated_predicates(public)
    # The re-enabled families are promotable, but a generic public read + body diff still cannot
    # COMPLETE one: auth_bypass needs a real authenticated access and mass_assignment needs a real
    # state-changing mutation -- neither of which a public read provides.
    assert "protected_resource_accessed" not in corroborated
    assert "forbidden_field_accepted" not in corroborated


def test_reenabled_families_corroborate_on_real_signals():
    # auth_bypass: an authenticated access establishes a real protected resource; an anonymous
    # request SUCCEEDS returning actual sensitive DATA -> it reached protected content (a bypass).
    auth = {
        "trusted_protected_routes": [{"method": "GET", "path": "/private"}],
        "observations": [
            {"label": "authed", "principal": "user1", "request": {"method": "GET", "path": "/private"},
             "response": {"status": 200}},
            {"label": "anon", "principal": "anonymous", "request": {"method": "GET", "path": "/private"},
             "response": {"status": 200},
             "sensitive_value_categories": ["jwt"]},
        ],
        "comparisons": [],
        "assertion_results": [
            {"id": "p", "type": "status_in", "step": "authed", "values": [200],
             "predicate": "protected_resource_accessed", "passed": True},
            {"id": "u", "type": "status_not_in", "step": "anon", "values": [401, 403],
             "predicate": "unauthenticated_control", "passed": True},
        ],
    }
    assert {"protected_resource_accessed", "unauthenticated_control"} <= workflow.server_corroborated_predicates(auth)

    # mass_assignment: a mutation SUBMITTED a field and the server ECHOED it back (accepted it), with
    # an observable state change.
    mass = {
        "observations": [
            {"label": "before", "principal": "user1", "checkpoint": "before", "response": {"status": 200}},
            {"label": "mutate", "principal": "user1", "checkpoint": "mutation",
             "submitted_fields": ["role"], "response": {"status": 200, "json_keys": ["role", "id"]}},
        ],
        "comparisons": [{"control": "before", "candidate": "mutate", "comparable": True, "body_changed": True}],
        "assertion_results": [
            {"id": "f", "type": "status_in", "step": "mutate", "values": [200],
             "predicate": "forbidden_field_accepted", "passed": True},
            {"id": "s", "type": "comparison_changed", "control": "before", "candidate": "mutate",
             "predicate": "observable_state_change", "passed": True},
        ],
    }
    assert {"forbidden_field_accepted", "observable_state_change"} <= workflow.server_corroborated_predicates(mass)


def test_strengthened_family_proofs_reject_benign_behavior():
    # data_exposure: a principal reading its OWN authenticated data (its own JWT) is not exposure.
    own = {
        "observations": [{"label": "self", "principal": "user1", "response": {"status": 200},
                          "sensitive_value_categories": ["jwt"]}],
        "comparisons": [],
        "assertion_results": [{"id": "a", "type": "status_in", "step": "self", "values": [200],
                               "predicate": "sensitive_value_present", "passed": True}],
    }
    assert "sensitive_value_present" not in workflow.server_corroborated_predicates(own)

    # auth_bypass: an anonymous 200 on a public endpoint (no sensitive data) is not a bypass.
    public = {
        "observations": [{"label": "anon", "principal": "anonymous",
                          "response": {"status": 200, "json_keys": ["status"]}, "sensitive_value_categories": []}],
        "comparisons": [],
        "assertion_results": [{"id": "u", "type": "status_not_in", "step": "anon", "values": [401, 403],
                               "predicate": "unauthenticated_control", "passed": True}],
    }
    assert "unauthenticated_control" not in workflow.server_corroborated_predicates(public)

    # workflow: two reads of a changing endpoint with NO mutation is not a transition-invariant break.
    clock = {
        "observations": [
            {"label": "t1", "principal": "anonymous", "checkpoint": "before", "response": {"status": 200}},
            {"label": "t2", "principal": "anonymous", "checkpoint": "after", "response": {"status": 200}},
        ],
        "comparisons": [{"control": "t1", "candidate": "t2", "comparable": True, "body_changed": True}],
        "assertion_results": [{"id": "w", "type": "comparison_changed", "control": "t1", "candidate": "t2",
                               "predicate": "transition_invariant_broken", "passed": True}],
    }
    assert "transition_invariant_broken" not in workflow.server_corroborated_predicates(clock)


def test_family_proofs_do_not_combine_unrelated_routes_or_allowed_fields():
    auth = {
        "observations": [
            {"label": "authed", "principal": "user1", "request": {"method": "GET", "path": "/private"},
             "response": {"status": 200}},
            {"label": "anon", "principal": "anonymous", "request": {"method": "GET", "path": "/docs/sample"},
             "response": {"status": 200}, "sensitive_value_categories": ["jwt"]},
        ],
        "comparisons": [],
        "assertion_results": [
            {"passed": True, "predicate": "protected_resource_accessed", "step": "authed"},
            {"passed": True, "predicate": "unauthenticated_control", "step": "anon"},
        ],
    }
    assert workflow.server_corroborated_predicates(auth).isdisjoint({
        "protected_resource_accessed", "unauthenticated_control",
    })

    mass = {
        "observations": [
            {"label": "before", "principal": "user1", "checkpoint": "before",
             "request": {"method": "GET", "path": "/profile"}, "response": {"status": 200}},
            {"label": "mutate", "principal": "user1", "checkpoint": "mutation",
             "request": {"method": "PATCH", "path": "/profile"}, "submitted_fields": ["display_name"],
             "response": {"status": 200, "json_keys": ["display_name"]}},
            {"label": "verify", "principal": "user1", "checkpoint": "after",
             "request": {"method": "GET", "path": "/profile"},
             "response": {"status": 200, "json_keys": ["display_name"]}},
            {"label": "control", "principal": "user1", "checkpoint": "mutation",
             "request": {"method": "PATCH", "path": "/profile"}, "response": {"status": 400}},
        ],
        "comparisons": [{"control": "before", "candidate": "verify", "comparable": True, "body_changed": True}],
        "assertion_results": [
            {"passed": True, "predicate": "forbidden_field_accepted", "step": "mutate"},
            {"passed": True, "predicate": "observable_state_change", "control": "before", "candidate": "verify"},
            {"passed": True, "predicate": "control_rejected", "step": "control"},
        ],
    }
    corroborated = workflow.server_corroborated_predicates(mass)
    assert "forbidden_field_accepted" not in corroborated
    assert not {"forbidden_field_accepted", "observable_state_change", "control_rejected"} <= corroborated


def test_restoration_read_must_follow_cleanup():
    payload = {
        "proof_family": "workflow",
        "steps": [
            {"label": "before", "checkpoint": "before", "method": "GET", "path": "/object"},
            {"label": "after", "checkpoint": "after", "method": "GET", "path": "/object", "compare_to": "before"},
            {"label": "mutate", "checkpoint": "mutation", "method": "POST", "path": "/object", "json_body": {"v": 1}},
            {"label": "cleanup", "checkpoint": "cleanup", "method": "PUT", "path": "/object", "json_body": {"v": 0}},
        ],
        "assertions": [{"type": "restored", "control": "before", "candidate": "after", "predicate": "before_after_state"}],
    }
    with pytest.raises(workflow.WorkflowContractError, match="restoration_order_invalid"):
        workflow.normalize_workflow("https://example.test", payload)


def test_bola_predicates_require_created_object_identity_and_denial_control():
    result = {
        "principal_receipts": [
            {"slot": "user1", "identity_fingerprint": "owner-id"},
            {"slot": "user2", "identity_fingerprint": "attacker-id"},
        ],
        "observations": [
            {"label": "create", "principal": "user1", "checkpoint": "mutation",
             "request": {"method": "POST", "path": "/objects"}, "response": {"status": 201},
             "extracted_names": ["object_id"]},
            {"label": "owner", "principal": "user1", "request": {
                "method": "GET", "path": "/objects/42", "variable_references": ["object_id"],
             }, "response": {"status": 200}},
            {"label": "attacker", "principal": "user2",
             "request": {"method": "GET", "path": "/objects/42"}, "response": {"status": 200}},
            {"label": "anonymous", "principal": "anonymous",
             "request": {"method": "GET", "path": "/objects/42"}, "response": {"status": 403}},
        ],
        "comparisons": [{
            "control": "owner", "candidate": "attacker", "comparable": True,
            "body_changed": False, "status_changed": False,
        }],
        "assertion_results": [
            {"id": "ids", "type": "distinct_principals", "steps": ["owner", "attacker"],
             "predicate": "distinct_identity", "passed": True},
            {"id": "own", "type": "comparison_equivalent", "control": "owner", "candidate": "attacker",
             "predicate": "ownership_established", "passed": True},
            {"id": "cross", "type": "comparison_equivalent", "control": "owner", "candidate": "attacker",
             "predicate": "cross_principal_access", "passed": True},
            {"id": "deny", "type": "status_not_in", "step": "anonymous", "values": [200, 201, 204],
             "predicate": "denial_control", "passed": True},
        ],
    }
    assert workflow.server_corroborated_predicates(result) == {
        "distinct_identity", "ownership_established", "cross_principal_access", "denial_control",
    }

    # Authentication plus anonymous denial does not establish ownership of a pre-existing object.
    read_existing = {**result, "observations": result["observations"][1:]}
    assert "ownership_established" not in workflow.server_corroborated_predicates(read_existing)

    # But an UNAUTHENTICATED "owner" does not establish ownership (distinct authenticated identities
    # are required), so the benign case stays unproven.
    anon_owner = {**read_existing, "observations": [
        ({**o, "principal": "anonymous"} if o["label"] == "owner" else o)
        for o in read_existing["observations"]
    ]}
    corroborated = workflow.server_corroborated_predicates(anon_owner)
    assert "ownership_established" not in corroborated
    assert "cross_principal_access" not in corroborated


def test_injection_predicates_are_never_workflow_corroborated():
    result = {
        "observations": [{"label": "p", "principal": "anonymous", "response": {"status": 200}}],
        "comparisons": [{"control": "c", "candidate": "p", "comparable": True, "body_changed": True}],
        "assertion_results": [
            {"id": "i1", "type": "comparison_changed", "control": "c", "candidate": "p",
             "predicate": "payload_control_differential", "passed": True},
            {"id": "i2", "type": "status_in", "step": "p", "values": [200],
             "predicate": "deterministic_family_proof", "passed": True},
        ],
    }
    assert workflow.server_corroborated_predicates(result) == set()
