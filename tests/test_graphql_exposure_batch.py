"""The read-only exposure batch discovers GraphQL endpoints and proves introspection and IDEs.

Driven through ``DatabaseNeutralScanActionDispatcher`` with a fake transport that answers as
DVGA does: introspection over GET at ``/graphql``, GraphiQL at ``/graphiql`` only for a
browser's ``Accept: text/html``. A non-GraphQL single-page app that answers every path with
its shell yields nothing, and every request stays a GET without redirects.
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse
import uuid

import scan.action_adapter as action_adapter_module
from capabilities.graphql_probe import INTROSPECTION_QUERY
from runtime.models import ScanPolicy
from runtime.request_replay_executor import ReplayTransportResult
from scan.action_plan import ScanActionPlan

from tests.test_exposure_probe_batch_controls import _manifest
from tests.graphql_fixtures import DVGA_GRAPHIQL, DVGA_INTROSPECTION, SPA_SHELL
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop


class _Transport:
    def __init__(self, answer):
        self.answer = answer
        self.sent: list[tuple[str, dict[str, str]]] = []

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        assert follow_redirects is False and request.method == "GET" and not request.body
        headers = dict(request.headers)
        self.sent.append((request.url, headers))
        status, content_type, body = self.answer(request.url, headers)
        return ReplayTransportResult(
            status_code=status, connected_address="192.0.2.10", final_url=request.url,
            response_headers={"Content-Type": content_type}, response_body=body, elapsed_ms=3,
        )


def _dvga(url, headers):
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parts.query).get("query")
    if parts.path in {"/graphql", "/api/v2/graphql"}:
        if query == [INTROSPECTION_QUERY]:
            return 200, "application/json", json.dumps(DVGA_INTROSPECTION).encode()
        return 400, "application/json", b'{"errors":[{"message":"Must provide query string."}]}'
    if parts.path == "/graphiql" and headers.get("Accept") == "text/html":
        return 200, "text/html; charset=utf-8", DVGA_GRAPHIQL
    return 404, "text/html", b"<html><body>Not Found</body></html>"


def _run(monkeypatch, answer, *, paths=("/app",)):
    scan_id = str(uuid.uuid4())
    manifest = _manifest(scan_id, paths)
    transport = _Transport(answer)
    monkeypatch.setattr(action_adapter_module, "PinnedAiohttpReplayTransport", lambda **_: transport)
    action = _action(
        "verify.exposure", "exposure.verify_batch", 0,
        capability_args={
            "endpoint_manifest_ref": manifest.reference().canonical_dict(),
            "slice": {"start": 0, "count": 100},
            "profile": "balanced",
            "proof_policy": "deterministic_proof_contract_required",
        },
    )
    action = type(action)(**{**action.__dict__, "requested_budget": {
        "http_requests": 300, "tool_wall_seconds": 180,
    }})
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    backend = Backend(manifests={manifest.manifest_id: manifest})
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy())  # passive: no active authority
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    verified = [
        item for item in receipt.observations
        if item.get("kind") == "sensitive_exposure_proof" and item.get("proof_state") == "verified"
    ]
    return receipt, verified, transport


def test_dvga_introspection_and_graphiql_are_found_by_the_passive_batch(monkeypatch):
    receipt, verified, transport = _run(monkeypatch, _dvga, paths=("/app", "/api/v2/graphql"))
    found = {
        (item["exposure_class"], urllib.parse.urlsplit(item["request_url"]).path)
        for item in verified
    }
    assert found == {
        ("graphql_introspection_enabled", "/graphql"),
        ("graphql_introspection_enabled", "/api/v2/graphql"),  # discovered, not a seed
        ("graphql_ide_exposure", "/graphiql"),
    }
    assert receipt.status == "success"
    graphql_requests = [(url, headers) for url, headers in transport.sent
                        if "query=" in url]
    # Every GraphQL request carries only the fixed introspection document.
    for url, headers in graphql_requests:
        assert urllib.parse.parse_qs(urllib.parse.urlsplit(url).query) == {"query": [INTROSPECTION_QUERY]}
        assert headers["Accept"].startswith("application/graphql-response+json")
    assert len(graphql_requests) == 6  # five conventional endpoints and the discovered one


def test_a_spa_answering_every_path_with_its_shell_has_no_graphql_finding(monkeypatch):
    _receipt, verified, _transport = _run(
        monkeypatch, lambda _url, _headers: (200, "text/html", SPA_SHELL),
        paths=("/app", "/graphql"),
    )
    assert verified == []


def test_an_api_that_answers_json_everywhere_has_no_graphql_finding(monkeypatch):
    def echo(url, _headers):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        return 200, "application/json", json.dumps({"ok": True, "echo": query}).encode()

    _receipt, verified, _transport = _run(monkeypatch, echo)
    assert [item for item in verified if item["exposure_class"].startswith("graphql")] == []


def test_introspection_served_for_every_path_is_not_path_specific(monkeypatch):
    """A host answering every path with the same schema body is caught by the absent controls."""
    body = json.dumps(DVGA_INTROSPECTION).encode()
    receipt, verified, _transport = _run(
        monkeypatch, lambda _url, _headers: (200, "application/json", body),
    )
    assert verified == []
    assert receipt.redacted_execution["indistinguishable_from_absent"] >= 5
