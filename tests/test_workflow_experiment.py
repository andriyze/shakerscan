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
