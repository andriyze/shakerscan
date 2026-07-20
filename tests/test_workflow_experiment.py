import asyncio
import hashlib
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


def test_mutation_blocked_when_baseline_extract_failed():
    """Audit F2: a failed before-read must STOP the mutation — without the gate the mutation
    fired and the rollback failed to render ${baseline}, leaving the target mutated."""
    state = {"quantity": 1}
    sent_methods: list[str] = []

    def handler(request):
        sent_methods.append(request.method)
        if request.url.path == "/missing":
            return httpx.Response(404, json={"error": "gone"})
        if request.method == "PUT":
            state["quantity"] = 4
        return httpx.Response(200, json={"quantity": state["quantity"]})

    payload = {
        "proof_family": "field_constraint",
        "steps": [
            {"label": "before", "checkpoint": "before", "method": "GET", "path": "/missing",
             "select_json": ["$.quantity"],
             "extract": [{"name": "baseline", "source": "json", "path": "$.quantity"}]},
            {"label": "mutate", "checkpoint": "mutation", "method": "PUT", "path": "/object",
             "json_body": {"quantity": 4}},
            {"label": "rollback", "checkpoint": "rollback", "method": "PUT", "path": "/object",
             "json_body": {"quantity": "${baseline}"}},
            {"label": "after", "checkpoint": "after", "method": "GET", "path": "/object",
             "select_json": ["$.quantity"], "compare_to": "before"},
        ],
        "assertions": [
            {"type": "restored", "control": "before", "candidate": "after",
             "predicate": "before_after_state", "field_scoped": True},
        ],
    }
    result = asyncio.run(workflow.execute_workflow(
        "https://example.test", payload, principal_contexts={}, transport=httpx.MockTransport(handler)
    ))
    assert state["quantity"] == 1  # never mutated
    assert "PUT" not in sent_methods  # neither mutation nor rollback sent a request
    by_label = {obs["label"]: obs for obs in result["observations"]}
    # The before-read 404s, so baseline never binds; the mutation is then blocked by the F2 gate
    # (the exact guard error surfaces as a contract error from the failed variable reference).
    assert by_label["before"]["error"]
    assert by_label["mutate"]["error"]
    assert "restoration_unrenderable_pre_mutation" in by_label["mutate"]["error"] or \
        "ExperimentContractError" in by_label["mutate"]["error"]


def test_mutation_allowed_when_cleanup_needs_later_produced_variable():
    """Create-MA shape: the cleanup references the created id extracted from the MUTATION
    response — legitimately unbound pre-mutation — so the gate must not block it."""
    state: dict[str, Any] = {"created": None, "deleted": None}

    def handler(request):
        if request.method == "POST":
            state["created"] = "obj-9"
            return httpx.Response(201, json={"id": "obj-9"})
        if request.method == "DELETE":
            state["deleted"] = request.url.path.rsplit("/", 1)[-1]
            return httpx.Response(204)
        return httpx.Response(200, json={})

    payload = {
        "proof_family": "mass_assignment",
        "steps": [
            {"label": "list_before", "checkpoint": "before", "method": "GET", "path": "/objects"},
            {"label": "create", "checkpoint": "mutation", "method": "POST", "path": "/objects",
             "json_body": {"name": "probe"},
             "extract": [{"name": "created_id", "source": "json", "path": "$.id"}]},
            {"label": "cleanup", "checkpoint": "cleanup", "method": "DELETE",
             "path": "/objects/${created_id}"},
            {"label": "list_after", "checkpoint": "after", "method": "GET", "path": "/objects",
             "compare_to": "list_before"},
        ],
        "assertions": [
            {"type": "restored", "control": "list_before", "candidate": "list_after",
             "predicate": "before_after_state"},
        ],
    }
    result = asyncio.run(workflow.execute_workflow(
        "https://example.test", payload, principal_contexts={}, transport=httpx.MockTransport(handler)
    ))
    assert state["created"] == "obj-9"
    assert state["deleted"] == "obj-9"
    assert all(not obs.get("error") for obs in result["observations"])


def test_full_body_restore_replays_sibling_fields_and_types():
    """Audit F3/F4: the restore must replay the captured parent object verbatim — sibling fields
    recovered on a replace-semantics API, numeric baseline restored as a number (not "1")."""
    resource = {"quantity": 1, "name": "juice", "updatedAt": "2026-07-20T00:00:00Z"}
    sent_bodies: list[dict] = []

    def handler(request):
        if request.method == "PUT":
            body = __import__("json").loads(request.content.decode())
            sent_bodies.append(body)
            # Replace semantics: the stored resource becomes exactly the sent body, with a bumped
            # server timestamp (the field_scoped restored assertion tolerates that bump).
            stored = dict(body)
            stored["updatedAt"] = "2026-07-20T01:00:00Z"
            resource.clear()
            resource.update(stored)
        return httpx.Response(200, json=dict(resource))

    payload = {
        "proof_family": "field_constraint",
        "steps": [
            {"label": "before", "checkpoint": "before", "method": "GET", "path": "/item",
             "select_json": ["$.quantity"],
             "extract": [{"name": "baseline_body", "source": "json_object", "path": "$"}]},
            {"label": "mutate", "checkpoint": "mutation", "method": "PUT", "path": "/item",
             "json_body": {"quantity": 4}},
            {"label": "violation", "checkpoint": "action", "method": "GET", "path": "/item",
             "select_json": ["$.quantity"]},
            {"label": "rollback", "checkpoint": "rollback", "method": "PUT", "path": "/item",
             "json_body": "${baseline_body}"},
            {"label": "after", "checkpoint": "after", "method": "GET", "path": "/item",
             "select_json": ["$.quantity"], "compare_to": "before"},
        ],
        "assertions": [
            {"type": "restored", "control": "before", "candidate": "after",
             "predicate": "before_after_state", "field_scoped": True},
        ],
    }
    result = asyncio.run(workflow.execute_workflow(
        "https://example.test", payload, principal_contexts={}, transport=httpx.MockTransport(handler)
    ))
    assert len(sent_bodies) == 2
    assert sent_bodies[0] == {"quantity": 4}                      # minimal probe write
    # restore replays the FULL captured object: sibling name recovered, quantity back as an int
    assert sent_bodies[1] == {"quantity": 1, "name": "juice", "updatedAt": "2026-07-20T00:00:00Z"}
    assert isinstance(sent_bodies[1]["quantity"], int)
    assert resource["name"] == "juice" and resource["quantity"] == 1
    assert result["restoration_verified"] is True


def test_restore_body_at_wrapped_projection_and_sensitive_key_blocks_mutation():
    """json_object at a nested path ($.data); a captured body carrying a sensitive key must stop
    the mutation PRE-flight (F2 gate), not fail after the target changed."""
    # 1) wrapped projection: restore replays $.data, not the envelope
    sent_bodies: list[dict] = []

    def handler(request):
        if request.method == "PUT":
            sent_bodies.append(__import__("json").loads(request.content.decode()))
        return httpx.Response(200, json={"data": {"quantity": 1, "name": "x"}, "status": "ok"})

    payload = {
        "proof_family": "field_constraint",
        "steps": [
            {"label": "before", "checkpoint": "before", "method": "GET", "path": "/item",
             "select_json": ["$.data.quantity"],
             "extract": [{"name": "baseline_body", "source": "json_object", "path": "$.data"}]},
            {"label": "mutate", "checkpoint": "mutation", "method": "PUT", "path": "/item",
             "json_body": {"quantity": 4}},
            {"label": "rollback", "checkpoint": "rollback", "method": "PUT", "path": "/item",
             "json_body": "${baseline_body}"},
            {"label": "after", "checkpoint": "after", "method": "GET", "path": "/item",
             "select_json": ["$.data.quantity"], "compare_to": "before"},
        ],
        "assertions": [
            {"type": "restored", "control": "before", "candidate": "after",
             "predicate": "before_after_state", "field_scoped": True},
        ],
    }
    asyncio.run(workflow.execute_workflow(
        "https://example.test", payload, principal_contexts={}, transport=httpx.MockTransport(handler)
    ))
    assert sent_bodies[1] == {"quantity": 1, "name": "x"}  # inner object replayed, envelope dropped

    # 2) sensitive key in the captured body -> mutation never fires
    state = {"v": 1}

    def leaky_handler(request):
        if request.method == "PUT":
            state["v"] = 4
        return httpx.Response(200, json={"v": 1, "password": "hunter2"})

    payload2 = {
        "proof_family": "field_constraint",
        "steps": [
            {"label": "before", "checkpoint": "before", "method": "GET", "path": "/item",
             "extract": [{"name": "baseline_body", "source": "json_object", "path": "$"}]},
            {"label": "mutate", "checkpoint": "mutation", "method": "PUT", "path": "/item",
             "json_body": {"v": 4}},
            {"label": "rollback", "checkpoint": "rollback", "method": "PUT", "path": "/item",
             "json_body": "${baseline_body}"},
            {"label": "after", "checkpoint": "after", "method": "GET", "path": "/item",
             "compare_to": "before"},
        ],
        "assertions": [
            {"type": "restored", "control": "before", "candidate": "after",
             "predicate": "before_after_state", "field_scoped": True},
        ],
    }
    result2 = asyncio.run(workflow.execute_workflow(
        "https://example.test", payload2, principal_contexts={}, transport=httpx.MockTransport(leaky_handler)
    ))
    assert state["v"] == 1  # mutation blocked pre-flight
    by_label = {obs["label"]: obs for obs in result2["observations"]}
    assert by_label["mutate"]["error"] == "restoration_sensitive_key_pre_mutation"


def test_browser_mutation_success_and_restoration_use_hashed_extracted_state():
    state = {"value": "off"}

    async def browser_action(_principal, action, data):
        if action == "click" and data["selector"] == "#enable":
            state["value"] = "on"
        elif action == "click" and data["selector"] == "#disable":
            state["value"] = "off"
        if action == "extract":
            return {"success": True, "value": state["value"], "url": "https://example.test/settings"}
        return {"success": True, "url": "https://example.test/settings"}

    payload = {
        "proof_family": "workflow",
        "steps": [
            {"label": "before", "kind": "browser", "principal": "anonymous", "checkpoint": "before",
             "action": "extract", "data": {"selector": "#state", "attribute": "text"},
             "extract": [{"name": "state_before", "source": "browser", "selector": "#state"}]},
            {"label": "mutate", "kind": "browser", "principal": "anonymous", "checkpoint": "mutation",
             "action": "click", "data": {"selector": "#enable"}},
            {"label": "changed", "kind": "browser", "principal": "anonymous", "checkpoint": "action",
             "action": "extract", "data": {"selector": "#state", "attribute": "text"},
             "extract": [{"name": "state_changed", "source": "browser", "selector": "#state"}],
             "compare_to": "before"},
            {"label": "cleanup", "kind": "browser", "principal": "anonymous", "checkpoint": "cleanup",
             "action": "click", "data": {"selector": "#disable"}},
            {"label": "after", "kind": "browser", "principal": "anonymous", "checkpoint": "after",
             "action": "extract", "data": {"selector": "#state", "attribute": "text"},
             "extract": [{"name": "state_after", "source": "browser", "selector": "#state"}],
             "compare_to": "before"},
        ],
        "assertions": [
            {"type": "comparison_changed", "control": "before", "candidate": "changed"},
            {"type": "restored", "control": "before", "candidate": "after",
             "predicate": "before_after_state"},
        ],
    }

    result = asyncio.run(workflow.execute_workflow(
        "https://example.test",
        payload,
        principal_contexts={},
        browser_action=browser_action,
    ))

    assert result["assertions_passed"] is True
    assert result["restoration_verified"] is True
    assert result["observations"][3]["response"]["success"] is True
    assert result["observations"][0]["response"]["value_sha256"] == workflow._value_fingerprint("off")
    assert result["observations"][2]["response"]["value_sha256"] == workflow._value_fingerprint("on")
    assert "off" not in str(result["observations"][0]["response"])
    assert "on" not in str(result["observations"][2]["response"])


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
             "trusted_protected_resource": True,
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
    assert "password_hash" in workflow._classify_sensitive_values(
        '{"password":"$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"}'
    )
    assert "credentialed_database_uri" in workflow._classify_sensitive_values(
        '{"database_url":"postgres://service:correct-horse@db.internal/app"}'
    )


def test_data_exposure_accepts_policy_bound_tokens_and_denied_authenticated_roles():
    protected_jwt = {
        "observations": [{
            "label": "anon",
            "principal": "anonymous",
            "trusted_protected_resource": True,
            "response": {"status": 200},
            "sensitive_value_categories": ["jwt"],
        }],
        "assertion_results": [{
            "passed": True,
            "predicate": "sensitive_value_present",
            "type": "status_in",
            "step": "anon",
        }],
    }
    denied_customer = {
        "observations": [{
            "label": "billing",
            "principal": "user2",
            "trusted_denied_access": True,
            "response": {"status": 200},
            "sensitive_value_categories": ["credit_card"],
        }],
        "assertion_results": [{
            "passed": True,
            "predicate": "sensitive_value_present",
            "type": "status_in",
            "step": "billing",
        }],
    }
    public_jwt = {
        **protected_jwt,
        "observations": [{
            **protected_jwt["observations"][0],
            "trusted_protected_resource": False,
        }],
    }

    assert "sensitive_value_present" in workflow.server_corroborated_predicates(protected_jwt)
    assert "sensitive_value_present" in workflow.server_corroborated_predicates(denied_customer)
    assert "sensitive_value_present" not in workflow.server_corroborated_predicates(public_jwt)


def test_data_exposure_rejects_public_samples_and_unsuccessful_responses():
    base = {
        "observations": [{
            "label": "sample", "principal": "anonymous",
            "response": {"status": 200, "json_keys": ["ssn"]},
            "sensitive_value_categories": ["ssn"],
        }],
        "assertion_results": [{
            "passed": True, "predicate": "sensitive_value_present",
            "type": "status_in", "step": "sample",
        }],
    }
    assert "sensitive_value_present" not in workflow.server_corroborated_predicates(base)

    protected_error = {
        **base,
        "observations": [{
            **base["observations"][0],
            "trusted_protected_resource": True,
            "response": {"status": 500, "json_keys": ["ssn"]},
        }],
    }
    assert "sensitive_value_present" not in workflow.server_corroborated_predicates(protected_error)


def test_auth_bypass_uses_protected_route_policy_not_secret_content():
    result = {
        "trusted_protected_routes": [{"method": "GET", "path": "/admin/stats"}],
        "observations": [
            {
                "label": "authed", "principal": "admin",
                "request": {"method": "GET", "path": "/admin/stats"},
                "response": {
                    "status": 200, "content_length": 32, "json_keys": ["active_users"],
                    "content_semantically_populated": True,
                },
            },
            {
                "label": "anon", "principal": "anonymous",
                "request": {"method": "GET", "path": "/admin/stats"},
                "response": {
                    "status": 200, "content_length": 32, "json_keys": ["active_users"],
                    "content_semantically_populated": True,
                },
                "sensitive_value_categories": [],
            },
        ],
        "comparisons": [{
            "control": "authed", "candidate": "anon", "comparable": True,
            "status_changed": False, "body_changed": False, "body_similarity": 1.0,
        }],
        "assertion_results": [
            {"passed": True, "predicate": "protected_resource_accessed", "type": "status_in", "step": "authed"},
            {"passed": True, "predicate": "unauthenticated_control", "type": "status_not_in", "step": "anon"},
        ],
    }

    assert workflow.server_corroborated_predicates(result) >= {
        "protected_resource_accessed", "unauthenticated_control",
    }


def test_auth_bypass_rejects_soft_200_denial_or_shell():
    result = {
        "trusted_protected_routes": [{"method": "GET", "path": "/admin/stats"}],
        "observations": [
            {"label": "authed", "principal": "admin",
             "request": {"method": "GET", "path": "/admin/stats"},
             "response": {"status": 200, "content_length": 120, "json_keys": ["active_users"]}},
            {"label": "anon", "principal": "anonymous",
             "request": {"method": "GET", "path": "/admin/stats"},
             "response": {"status": 200, "content_length": 40, "json_keys": ["error"]}},
        ],
        "comparisons": [{
            "control": "authed", "candidate": "anon", "comparable": True,
            "status_changed": False, "body_changed": True, "body_similarity": 0.18,
        }],
        "assertion_results": [
            {"passed": True, "predicate": "protected_resource_accessed", "step": "authed"},
            {"passed": True, "predicate": "unauthenticated_control", "step": "anon"},
        ],
    }
    assert workflow.server_corroborated_predicates(result).isdisjoint({
        "protected_resource_accessed", "unauthenticated_control",
    })


def test_auth_bypass_rejects_identical_empty_shell_public_endpoint():
    # Regression for the live false positive on Juice Shop /rest/user/whoami: it returns {"user":{}}
    # (11 bytes, empty nested shell) to BOTH the authenticated and anonymous principal -- identical
    # bodies (body_changed False, similarity 1.0). That is a public endpoint exposing nothing, not a
    # bypassed protected resource, and must NOT promote even though the route is policy-protected.
    result = {
        "trusted_protected_routes": [{"method": "GET", "path": "/rest/user/whoami"}],
        "observations": [
            {"label": "authed", "principal": "user1",
             "request": {"method": "GET", "path": "/rest/user/whoami"},
             "response": {"status": 200, "content_length": 11, "json_keys": ["user"], "selected_json": {}}},
            {"label": "anon", "principal": "anonymous",
             "request": {"method": "GET", "path": "/rest/user/whoami"},
             "response": {"status": 200, "content_length": 11, "json_keys": ["user"], "selected_json": {}}},
        ],
        "comparisons": [{
            "control": "authed", "candidate": "anon", "comparable": True,
            "status_changed": False, "body_changed": False, "body_similarity": 1.0,
        }],
        "assertion_results": [
            {"passed": True, "predicate": "protected_resource_accessed", "step": "authed"},
            {"passed": True, "predicate": "unauthenticated_control", "step": "anon"},
        ],
    }
    assert workflow.server_corroborated_predicates(result).isdisjoint({
        "protected_resource_accessed", "unauthenticated_control",
    })


def test_meaningful_equivalent_response_uses_semantics_not_serialized_size():
    comparison = {
        "comparable": True, "status_changed": False,
        "body_changed": False, "body_similarity": 1.0,
    }
    long_empty_shell = {
        "response": {
            "content_length": 40,
            "json_keys": ["authenticatedUser"],
            "selected_json": {"$.authenticatedUser": {}},
            "content_semantically_populated": False,
        },
    }
    assert workflow._meaningful_equivalent_response(
        long_empty_shell, long_empty_shell, comparison,
    ) is False

    for value in (0, False, {"id": 1}):
        populated = {
            "response": {
                "content_length": 8,
                "selected_json": {"$.value": value},
                "content_semantically_populated": True,
            },
        }
        assert workflow._meaningful_equivalent_response(
            populated, populated, comparison,
        ) is True


def test_cross_principal_access_requires_distinct_authenticated_principals_and_equivalence():
    shared = {
        "principal_receipts": [
            {"slot": "user1", "identity_fingerprint": "owner-id"},
            {"slot": "user2", "identity_fingerprint": "attacker-id"},
        ],
        "observations": [
            {"label": "owner", "principal": "user1",
             "request": {"method": "GET", "path": "/orders/42"}, "response": {"status": 200}},
            {"label": "attacker", "principal": "user2",
             "request": {"method": "GET", "path": "/orders/42"}, "response": {"status": 200}},
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
            {"id": "c", "type": "status_in", "step": "public", "values": [200],
             "predicate": "benign_control_accepted", "passed": True},
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
             "response": {
                 "status": 200, "content_length": 80, "json_keys": ["token"],
                 "content_semantically_populated": True,
             }},
            {"label": "anon", "principal": "anonymous", "request": {"method": "GET", "path": "/private"},
             "response": {
                 "status": 200, "content_length": 80, "json_keys": ["token"],
                 "content_semantically_populated": True,
             },
             "sensitive_value_categories": ["jwt"]},
        ],
        "comparisons": [{"control": "authed", "candidate": "anon", "comparable": True,
                         "status_changed": False, "body_changed": False, "body_similarity": 1.0}],
        "assertion_results": [
            {"id": "p", "type": "status_in", "step": "authed", "values": [200],
             "predicate": "protected_resource_accessed", "passed": True},
            {"id": "u", "type": "status_not_in", "step": "anon", "values": [401, 403],
             "predicate": "unauthenticated_control", "passed": True},
        ],
    }
    assert {"protected_resource_accessed", "unauthenticated_control"} <= workflow.server_corroborated_predicates(auth)

    # mass_assignment: the endpoint accepts a benign control, then an overposted security field's
    # exact submitted value persists in a separate read.
    mass = {
        "observations": [
            {"label": "before", "principal": "user1", "checkpoint": "before",
             "request": {"method": "GET", "path": "/profile"},
             "response": {"status": 200, "selected_json": {"$.role": "user"}}},
            {"label": "control", "principal": "user1", "checkpoint": "mutation",
             "request": {"method": "PATCH", "path": "/profile"},
             "submitted_fields": ["display_name"],
             "submitted_field_hashes": {"display_name": workflow._value_fingerprint("research")},
             "response": {"status": 200}},
            {"label": "mutate", "principal": "user1", "checkpoint": "mutation",
             "request": {"method": "PATCH", "path": "/profile"},
             "submitted_fields": ["role"],
             "submitted_field_hashes": {"role": workflow._value_fingerprint("admin")},
             "response": {"status": 200, "json_keys": ["role", "id"]}},
            {"label": "verify", "principal": "user1", "checkpoint": "action",
             "request": {"method": "GET", "path": "/profile"},
             "response": {"status": 200, "selected_json": {"$.role": "admin"}}},
        ],
        "comparisons": [{"control": "before", "candidate": "verify", "comparable": True,
                         "selected_json_changed": {"$.role": ["user", "admin"]}}],
        "assertion_results": [
            {"id": "c", "type": "status_in", "step": "control", "values": [200],
             "predicate": "benign_control_accepted", "passed": True},
            {"id": "f", "type": "status_in", "step": "mutate", "values": [200],
             "predicate": "forbidden_field_accepted", "passed": True},
            {"id": "s", "type": "comparison_changed", "control": "before", "candidate": "verify",
             "predicate": "observable_state_change", "passed": True},
        ],
    }
    assert {
        "forbidden_field_accepted", "observable_state_change", "benign_control_accepted",
    } <= workflow.server_corroborated_predicates(mass)

    mismatched = {
        **mass,
        "observations": [
            {**item, "response": {**item.get("response", {}), "selected_json": {"$.role": "user"}}}
            if item["label"] == "verify" else item
            for item in mass["observations"]
        ],
    }
    assert workflow.server_corroborated_predicates(mismatched).isdisjoint({
        "forbidden_field_accepted", "observable_state_change", "benign_control_accepted",
    })


def test_mass_assignment_create_based_binds_readback_to_created_object():
    # Create-based overposting: POST /api/Users creates the object; the forbidden privilege field is
    # read back at /api/Users/{created_id}. Mutation and read-back paths differ, so the proof must
    # accept the create->object-read binding -- but ONLY when the read-back id was EXTRACTED from the
    # create's own response (hash-verified), or a read of a pre-existing admin would mint a false positive.
    created_id, control_id = "42", "43"
    created_hash = hashlib.sha256(created_id.encode()).hexdigest()
    control_hash = hashlib.sha256(control_id.encode()).hexdigest()

    def _result(readback_path):
        return {
            "observations": [
                {"label": "control", "principal": "user1", "checkpoint": "mutation",
                 "request": {"method": "POST", "path": "/api/Users"},
                 "submitted_fields": ["display_name"],
                 "submitted_field_hashes": {"display_name": workflow._value_fingerprint("research")},
                 "extracted": {"control_id": {"sha256": control_hash}},
                 "response": {"status": 201}},
                {"label": "mutate", "principal": "user1", "checkpoint": "mutation",
                 "request": {"method": "POST", "path": "/api/Users"},
                 "submitted_fields": ["role"],
                 "submitted_field_hashes": {"role": workflow._value_fingerprint("admin")},
                 "extracted": {"created_id": {"sha256": created_hash}},
                 "response": {"status": 201, "json_keys": ["role", "id"]}},
                {"label": "control_verify", "principal": "user1", "checkpoint": "action",
                 "request": {"method": "GET", "path": "/api/Users/" + control_id},
                 "response": {"status": 200, "selected_json": {"$.role": "user"}}},
                {"label": "verify", "principal": "user1", "checkpoint": "action",
                 "request": {"method": "GET", "path": readback_path},
                 "response": {"status": 200, "selected_json": {"$.role": "admin"}}},
            ],
            "comparisons": [{"control": "control_verify", "candidate": "verify", "comparable": True,
                             "selected_json_changed": {"$.role": ["user", "admin"]}}],
            "assertion_results": [
                {"id": "c", "type": "status_in", "step": "control", "values": [201],
                 "predicate": "benign_control_accepted", "passed": True},
                {"id": "f", "type": "status_in", "step": "mutate", "values": [201],
                 "predicate": "forbidden_field_accepted", "passed": True},
                {"id": "s", "type": "comparison_changed", "control": "control_verify", "candidate": "verify",
                 "predicate": "observable_state_change", "passed": True},
            ],
        }

    bound = _result("/api/Users/" + created_id)
    assert {
        "forbidden_field_accepted", "observable_state_change", "benign_control_accepted",
    } <= workflow.server_corroborated_predicates(bound)

    unbound = _result("/api/Users/999")
    assert workflow.server_corroborated_predicates(unbound).isdisjoint({
        "forbidden_field_accepted", "observable_state_change", "benign_control_accepted",
    })


def _registration_workflow(password_value, declare_cred=True):
    # Minimal valid create-based mass_assignment: register (POST) with an overposted role, then
    # best-effort cleanup. Registration requires a `password` -- a sensitive key.
    return {
        "proof_family": "mass_assignment",
        "objective": "o", "expected_signal": "e", "falsifier": "f",
        "principal_variables": (
            [{"name": "reg_cred", "principal": "user1", "ref": "reg_cred"}] if declare_cred else []
        ),
        "steps": [
            {"label": "list_before", "kind": "http", "principal": "user1", "checkpoint": "before",
             "method": "GET", "path": "/api/Users"},
            {"label": "mutate", "kind": "http", "principal": "user1", "checkpoint": "mutation",
             "method": "POST", "path": "/api/Users",
             "json_body": {"email": "x@y.test", "password": password_value, "role": "admin"},
             "extract": [{"name": "created_id", "source": "json", "path": "$.id"}]},
            {"label": "cleanup", "kind": "http", "principal": "user1", "checkpoint": "cleanup",
             "method": "DELETE", "path": "/api/Users/${created_id}"},
            {"label": "list_after", "kind": "http", "principal": "user1", "checkpoint": "after",
             "method": "GET", "path": "/api/Users", "compare_to": "list_before"},
        ],
        "assertions": [
            {"type": "restored", "control": "list_before", "candidate": "list_after",
             "predicate": "before_after_state"},
        ],
    }


def test_managed_credential_body_allowed_but_literal_secret_blocked():
    # A managed reference (a server-resolved ${reg_cred}, persisted only as a sha256 receipt) may back
    # a sensitive body key -- this is what lets registration mass_assignment send a password.
    workflow.normalize_workflow("https://x.test", _registration_workflow("${reg_cred}"))
    # A literal secret in that same key still fails closed -- the moat never stores a plaintext secret.
    with pytest.raises(workflow.WorkflowContractError):
        workflow.normalize_workflow("https://x.test", _registration_workflow("literal-password-123"))
    # A reference to an UNDECLARED variable is not managed, so it is not exempted either.
    with pytest.raises(workflow.WorkflowContractError):
        workflow.normalize_workflow("https://x.test", _registration_workflow("${reg_cred}", declare_cred=False))


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
            {"passed": True, "predicate": "benign_control_accepted", "step": "control"},
        ],
    }
    corroborated = workflow.server_corroborated_predicates(mass)
    assert "forbidden_field_accepted" not in corroborated
    assert not {"forbidden_field_accepted", "observable_state_change", "benign_control_accepted"} <= corroborated


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
             "extracted_names": ["object_id"], "extracted": {"object_id": {"sha256": "a" * 64}}},
            {"label": "create_attacker", "principal": "user2", "checkpoint": "mutation",
             "request": {"method": "POST", "path": "/objects"}, "response": {"status": 201},
             "extracted_names": ["object_id"], "extracted": {"object_id": {"sha256": "b" * 64}}},
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
    read_existing = {**result, "observations": result["observations"][2:]}
    assert "ownership_established" not in workflow.server_corroborated_predicates(read_existing)

    # A server-resolved object reference captured from User1's managed login context is also
    # ownership provenance. The planner names the ref but never supplies its value.
    captured_owner = {
        **read_existing,
        "principal_variable_receipts": [
            {"name": "owner_object_id", "principal": "user1", "ref": "basket_id",
             "sha256": "a" * 64, "length": 2},
            {"name": "attacker_object_id", "principal": "user2", "ref": "basket_id",
             "sha256": "b" * 64, "length": 2},
        ],
        "observations": [
            {**item, "request": {
                **item.get("request", {}),
                "variable_references": ["owner_object_id"] if item["label"] == "owner" else [],
            }}
            for item in read_existing["observations"]
        ],
    }
    assert "ownership_established" in workflow.server_corroborated_predicates(captured_owner)

    # But an UNAUTHENTICATED "owner" does not establish ownership (distinct authenticated identities
    # are required), so the benign case stays unproven.
    anon_owner = {**read_existing, "observations": [
        ({**o, "principal": "anonymous"} if o["label"] == "owner" else o)
        for o in read_existing["observations"]
    ]}
    corroborated = workflow.server_corroborated_predicates(anon_owner)
    assert "ownership_established" not in corroborated
    assert "cross_principal_access" not in corroborated


def test_bola_rejects_get_mislabeled_as_mutation_and_shared_owner_reference():
    base = {
        "principal_receipts": [
            {"slot": "user1", "identity_fingerprint": "owner-id"},
            {"slot": "user2", "identity_fingerprint": "attacker-id"},
        ],
        "observations": [
            {"label": "fake_create", "principal": "user1", "checkpoint": "mutation",
             "request": {"method": "GET", "path": "/objects/42"}, "response": {"status": 200},
             "extracted_names": ["object_id"], "extracted": {"object_id": {"sha256": "a" * 64}}},
            {"label": "owner", "principal": "user1",
             "request": {"method": "GET", "path": "/objects/42", "variable_references": ["object_id"]},
             "response": {"status": 200}},
            {"label": "attacker", "principal": "user2",
             "request": {"method": "GET", "path": "/objects/42"}, "response": {"status": 200}},
        ],
        "comparisons": [{"control": "owner", "candidate": "attacker", "comparable": True,
                         "status_changed": False, "body_changed": False}],
        "assertion_results": [{
            "passed": True, "predicate": "ownership_established",
            "control": "owner", "candidate": "attacker",
        }],
    }
    assert "ownership_established" not in workflow.server_corroborated_predicates(base)

    shared_ref = {
        **base,
        "observations": base["observations"][1:],
        "principal_variable_receipts": [
            {"name": "object_id", "principal": "user1", "ref": "basket_id", "sha256": "a" * 64},
            {"name": "other_object_id", "principal": "user2", "ref": "basket_id", "sha256": "a" * 64},
        ],
    }
    assert "ownership_established" not in workflow.server_corroborated_predicates(shared_ref)

    invalid_workflow = {
        "steps": [
            {"label": "read", "checkpoint": "mutation", "method": "GET", "path": "/objects/42"},
            {"label": "after", "checkpoint": "action", "method": "GET", "path": "/objects/42"},
        ],
        "assertions": [],
    }
    with pytest.raises(workflow.WorkflowContractError, match="http_mutation_checkpoint_requires_write_method"):
        workflow.normalize_workflow("https://example.test", invalid_workflow)


def test_mass_assignment_requires_privileged_value_elevation():
    def result_for(field, before, submitted):
        return {
            "observations": [
                {"label": "before", "principal": "user1", "checkpoint": "before",
                 "request": {"method": "GET", "path": "/profile"},
                 "response": {"status": 200, "selected_json": {f"$.{field}": before}}},
                {"label": "control", "principal": "user1", "checkpoint": "mutation",
                 "request": {"method": "PATCH", "path": "/profile"},
                 "submitted_fields": ["display_name"],
                 "submitted_field_hashes": {"display_name": workflow._value_fingerprint("research")},
                 "response": {"status": 200}},
                {"label": "mutate", "principal": "user1", "checkpoint": "mutation",
                 "request": {"method": "PATCH", "path": "/profile"},
                 "submitted_fields": [field],
                 "submitted_field_hashes": {field: workflow._value_fingerprint(submitted)},
                 "response": {"status": 200}},
                {"label": "verify", "principal": "user1", "checkpoint": "action",
                 "request": {"method": "GET", "path": "/profile"},
                 "response": {"status": 200, "selected_json": {f"$.{field}": submitted}}},
            ],
            "comparisons": [{"control": "before", "candidate": "verify", "comparable": True,
                             "selected_json_changed": {f"$.{field}": [before, submitted]}}],
            "assertion_results": [
                {"passed": True, "predicate": "benign_control_accepted", "step": "control"},
                {"passed": True, "predicate": "forbidden_field_accepted", "step": "mutate"},
                {"passed": True, "predicate": "observable_state_change",
                 "control": "before", "candidate": "verify"},
            ],
        }

    for field, before, submitted in (
        ("price", 10, 1),
        ("owner_id", 7, 8),
        ("role", "member", "member"),
    ):
        assert not {
            "forbidden_field_accepted", "observable_state_change", "benign_control_accepted",
        } <= workflow.server_corroborated_predicates(result_for(field, before, submitted))

    assert {
        "forbidden_field_accepted", "observable_state_change", "benign_control_accepted",
    } <= workflow.server_corroborated_predicates(result_for("role", "member", "admin"))


def test_read_existing_bola_resolves_owner_ref_without_exposing_value():
    requested_paths = []

    def handler(request):
        requested_paths.append(request.url.path)
        if request.headers.get("authorization"):
            return httpx.Response(200, json={"id": 42, "owner": "user1"})
        return httpx.Response(403, json={"error": "denied"})

    contexts = _contexts()
    contexts["user1"]["captured_refs"] = {"basket_id": "42"}
    contexts["user2"]["captured_refs"] = {"basket_id": "84"}
    payload = {
        "proof_family": "bola",
        "principal_variables": [
            {"name": "owner_object_id", "principal": "user1", "ref": "basket_id"},
            {"name": "attacker_object_id", "principal": "user2", "ref": "basket_id"},
        ],
        "steps": [
            {"label": "owner", "kind": "http", "principal": "user1", "checkpoint": "action",
             "method": "GET", "path": "/objects/${owner_object_id}"},
            {"label": "attacker_own", "kind": "http", "principal": "user2", "checkpoint": "before",
             "method": "GET", "path": "/objects/${attacker_object_id}"},
            {"label": "attacker", "kind": "http", "principal": "user2", "checkpoint": "action",
             "method": "GET", "path": "/objects/${owner_object_id}", "compare_to": "owner"},
            {"label": "anonymous", "kind": "http", "principal": "anonymous", "checkpoint": "action",
             "method": "GET", "path": "/objects/${owner_object_id}"},
        ],
        "assertions": [
            {"type": "distinct_principals", "steps": ["owner", "attacker"],
             "predicate": "distinct_identity"},
            {"type": "comparison_equivalent", "control": "owner", "candidate": "attacker",
             "predicate": "ownership_established"},
            {"type": "comparison_equivalent", "control": "owner", "candidate": "attacker",
             "predicate": "cross_principal_access"},
            {"type": "status_not_in", "step": "anonymous", "values": [200, 201, 202, 203, 204],
             "predicate": "denial_control"},
        ],
    }

    result = asyncio.run(workflow.execute_workflow(
        "https://example.test",
        payload,
        principal_contexts=contexts,
        transport=httpx.MockTransport(handler),
    ))

    assert requested_paths == ["/objects/42", "/objects/84", "/objects/42", "/objects/42"]
    assert result["mutating"] is False
    assert result["restoration_verified"] is True
    assert result["principal_variable_receipts"] == [
        {"name": "owner_object_id", "principal": "user1", "ref": "basket_id",
         "sha256": hashlib.sha256(b"42").hexdigest(), "length": 2},
        {"name": "attacker_object_id", "principal": "user2", "ref": "basket_id",
         "sha256": hashlib.sha256(b"84").hexdigest(), "length": 2},
    ]
    assert "42" not in str(result["principal_variable_receipts"])
    assert workflow.server_corroborated_predicates(result) >= {
        "distinct_identity", "ownership_established", "cross_principal_access", "denial_control",
    }


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


def _field_scoped_restore_workflow(field_scoped, restore_value):
    return {
        "proof_family": "field_constraint",
        "steps": [
            {"label": "before", "checkpoint": "before", "method": "GET", "path": "/o", "select_json": ["$.quantity"]},
            {"label": "mutate", "checkpoint": "mutation", "method": "PATCH", "path": "/o", "json_body": {"quantity": 999}},
            {"label": "violation", "checkpoint": "action", "method": "GET", "path": "/o", "select_json": ["$.quantity"]},
            {"label": "rollback", "checkpoint": "rollback", "method": "PUT", "path": "/o", "json_body": {"quantity": restore_value}},
            {"label": "after", "checkpoint": "after", "method": "GET", "path": "/o", "select_json": ["$.quantity"], "compare_to": "before"},
        ],
        "assertions": [
            {"type": "restored", "control": "before", "candidate": "after",
             "predicate": "before_after_state", "field_scoped": field_scoped},
        ],
    }


def _run_field_scoped(field_scoped, restore_value):
    # Object read carries a monotonically-bumping updated_at, so any write changes the full body even
    # when the constraint field (quantity) is restored to baseline.
    state = {"quantity": 5, "clock": 0}

    def handler(request):
        state["clock"] += 1
        if request.method in ("PUT", "PATCH"):
            import json as _json
            body = _json.loads((request.content or b"{}").decode() or "{}")
            if "quantity" in body:
                state["quantity"] = body["quantity"]
        return httpx.Response(200, json={"quantity": state["quantity"], "updated_at": state["clock"]})

    return asyncio.run(workflow.execute_workflow(
        "https://example.test", _field_scoped_restore_workflow(field_scoped, restore_value),
        principal_contexts={}, transport=httpx.MockTransport(handler)))


def test_field_scoped_restored_ignores_incidental_body_change():
    # Non-scoped: the updated_at bump makes before/after bodies differ -> restoration NOT verified,
    # even though quantity is back to baseline. This is the snag field-scoping fixes.
    assert _run_field_scoped(field_scoped=False, restore_value=5)["restoration_verified"] is False
    # Field-scoped: quantity returned to baseline (5) -> restoration verified, timestamp ignored.
    assert _run_field_scoped(field_scoped=True, restore_value=5)["restoration_verified"] is True


def test_field_scoped_restored_still_fails_on_genuine_non_restore():
    # Fail-closed: if the rollback does NOT restore the field (quantity left at 42), the field-scoped
    # comparison sees $.quantity changed and restoration is NOT verified.
    assert _run_field_scoped(field_scoped=True, restore_value=42)["restoration_verified"] is False
