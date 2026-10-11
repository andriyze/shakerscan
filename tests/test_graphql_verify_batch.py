"""The ``graphql.verify_batch`` action end to end over a fake transport (no target contacted).

The DVGA-shaped fixture answers GraphQL over GET at ``/graphql``: ``__typename``, the
introspection document, a validation error with a suggestion for a misspelt root field, and
every alias or duplicate of ``__typename``. The batch must prove the three checks there, send
only GETs of fixed documents that select no application field, stop at its request ceiling,
resume from its checkpoints, and find nothing on a non-GraphQL app or a hardened server.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import re
import urllib.parse
import uuid

import scan.action_adapter as action_adapter_module
from capabilities.graphql_probe import INTROSPECTION_QUERY, TYPENAME_QUERY
from runtime.models import ScanPolicy
from runtime.request_replay_executor import ReplayTransportResult
from scan.action_plan import ScanActionPlan

from tests.graphql_fixtures import DVGA_INTROSPECTION, SPA_SHELL
from tests.test_exposure_probe_batch_controls import _manifest
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop

# Root fields of the fixture schema; a request selecting any of them would run its resolver.
APPLICATION_FIELDS = {"pastes", "paste", "systemUpdate", "deleteAllPastes", "me"}
_ALIAS_RE = re.compile(r"a(\d+):__typename")


class _Transport:
    def __init__(self, answer):
        self.answer = answer
        self.sent: list[str] = []

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        assert follow_redirects is False and request.method == "GET" and not request.body
        self.sent.append(request.url)
        status, body = self.answer(request.url)
        return ReplayTransportResult(
            status_code=status, connected_address="192.0.2.10", final_url=request.url,
            response_headers={"Content-Type": "application/json"}, response_body=body,
            elapsed_ms=3,
        )


def _document(url: str) -> str | None:
    values = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get("query")
    return values[0] if values else None


def dvga(url: str, *, limits: bool = False):
    if urllib.parse.urlsplit(url).path not in {"/graphql", "/api/v2/graphql"}:
        return 404, b"<html>Not Found</html>"
    document = _document(url)
    if document is None:
        return 400, b'{"errors":[{"message":"Must provide query string."}]}'
    if document == TYPENAME_QUERY:
        return 200, b'{"data":{"__typename":"Query"}}'
    if document == INTROSPECTION_QUERY:
        return 200, json.dumps(DVGA_INTROSPECTION).encode()
    aliases = _ALIAS_RE.findall(document)
    if aliases:
        if limits:
            return 400, b'{"errors":[{"message":"Too many aliases"}]}'
        return 200, json.dumps({"data": {f"a{i}": "Query" for i in aliases}}).encode()
    if document.count("__typename") > 1:
        if limits:
            return 400, b'{"errors":[{"message":"Duplicate fields are not allowed"}]}'
        return 200, b'{"data":{"__typename":"Query"}}'
    field = document[len("query{"):-1]
    if limits:
        return 400, json.dumps({"errors": [{"message": f"Cannot query field '{field}' on type 'Query'."}]}).encode()
    return 400, json.dumps({"errors": [{"message": (
        f"Cannot query field '{field}' on type 'Query'. Did you mean 'pastes' or 'paste'?"
    )}]}).encode()


def _run(monkeypatch, answer, *, paths=("/app",), http=200, backend=None, manifest=None, scan_id=None):
    scan_id = scan_id or str(uuid.uuid4())
    manifest = manifest or _manifest(scan_id, paths)
    transport = _Transport(answer)
    monkeypatch.setattr(action_adapter_module, "PinnedAiohttpReplayTransport", lambda **_: transport)
    action = _action(
        "verify.graphql", "graphql.verify_batch", 0,
        capability_args={
            "endpoint_manifest_ref": manifest.reference().canonical_dict(),
            "slice": {"start": 0, "count": 100},
            "profile": "balanced",
            "proof_policy": "deterministic_proof_contract_required",
        },
    )
    action = replace(action, requested_budget={"http_requests": http, "tool_wall_seconds": 120},
                     action_digest=None)
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    backend = backend or Backend(manifests={manifest.manifest_id: manifest})
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy(active_testing=True))
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    proofs = [item for item in receipt.observations if item.get("kind") == "graphql_proof"]
    return receipt, proofs, transport, backend, manifest, scan_id


def _no_application_field_selected(sent):
    for url in sent:
        document = _document(url)
        if document is None:
            continue
        assert not document.startswith("mutation"), document
        selected = set(re.findall(r"[_A-Za-z][_0-9A-Za-z]*", document)) - {"query"}
        assert not selected & APPLICATION_FIELDS, document


def test_dvga_has_field_suggestions_and_no_alias_or_duplicate_limit(monkeypatch):
    receipt, proofs, transport, *_ = _run(monkeypatch, dvga, paths=("/app", "/api/v2/graphql"))
    found = {(item["check"], urllib.parse.urlsplit(item["endpoint"]).path) for item in proofs}
    assert found == {
        (check, path)
        for check in ("field_suggestions", "alias_limit_absent", "duplicate_field_limit_absent")
        for path in ("/graphql", "/api/v2/graphql")
    }
    suggestion = next(item for item in proofs if item["check"] == "field_suggestions")
    assert suggestion["suggested_fields"] == ["pastes", "paste"]
    assert suggestion["misspelling"] not in APPLICATION_FIELDS
    assert receipt.status == "success"
    _no_application_field_selected(transport.sent)
    # Six fixed GETs per GraphQL endpoint, one per conventional location that is not.
    assert len(transport.sent) == 2 * 6 + 4
    assert receipt.budget_consumed["http_requests"] == len(transport.sent)
    # The slice entry that is not a GraphQL route is recorded as inapplicable, so family
    # coverage does not count it as an unattempted candidate.
    inapplicable = [item for item in receipt.observations if item.get("kind") == "candidate_inapplicable"]
    assert [item["reason"] for item in inapplicable] == ["not_a_graphql_route"]


def test_a_hardened_server_and_a_non_graphql_app_yield_nothing(monkeypatch):
    _receipt, proofs, transport, *_ = _run(monkeypatch, lambda url: dvga(url, limits=True))
    assert proofs == []
    _no_application_field_selected(transport.sent)
    _receipt, proofs, transport, *_ = _run(monkeypatch, lambda _url: (200, SPA_SHELL),
                                          paths=("/app", "/graphql"))
    assert proofs == []
    # A route that does not answer __typename as GraphQL costs exactly one request.
    assert len(transport.sent) == 5

    def echo(url):
        return 200, json.dumps({"data": {"__typename": "Query"}, "echo": url}).encode()

    _receipt, proofs, _transport, *_ = _run(monkeypatch, echo)
    assert proofs == []

    # A static GraphQL-shaped answer to every request is not a validating server: the control
    # document is answered too, so no limit is claimed.
    _receipt, proofs, transport, *_ = _run(
        monkeypatch, lambda _url: (200, b'{"data":{"__typename":"Query"}}'),
    )
    assert proofs == [] and len(transport.sent) == 2 * 5


def test_the_request_ceiling_stops_the_batch_partial_and_resume_finishes_it(monkeypatch):
    receipt, proofs, transport, backend, manifest, scan_id = _run(monkeypatch, dvga, http=3)
    assert receipt.status == "partial"
    assert receipt.errors[0] == "http_request_budget_exhausted"
    assert len(transport.sent) == 3
    # The interrupted endpoint was not checkpointed; a resumed batch checks it again in full.
    receipt, proofs, transport, *_ = _run(
        monkeypatch, dvga, http=200, backend=backend, manifest=manifest, scan_id=scan_id,
    )
    assert {item["check"] for item in proofs} == {
        "field_suggestions", "alias_limit_absent", "duplicate_field_limit_absent",
    }
    assert receipt.status == "success"


def test_no_misspelling_is_sent_when_the_root_field_list_is_incomplete(monkeypatch):
    """A field list cut short could hide the very name a misspelling would hit."""
    cut = {"data": {"__schema": {
        "queryType": {"name": "Query", "fields": [{"name": "pastes"}, {"name": "not a name"}]},
        "types": [{"name": "Query"}],
    }}}

    def answer(url):
        if _document(url) == INTROSPECTION_QUERY:
            return 200, json.dumps(cut).encode()
        return dvga(url)

    _receipt, proofs, transport, *_ = _run(monkeypatch, answer)
    assert "field_suggestions" not in {item["check"] for item in proofs}
    assert not [url for url in transport.sent if "zq" in (_document(url) or "") and "__typenamezq" not in (_document(url) or "")]
