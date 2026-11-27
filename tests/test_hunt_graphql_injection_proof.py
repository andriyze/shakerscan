"""An injection in a GraphQL argument is proven like a query parameter (driven DVGA Hunt, 2026-11).

The planner confirmed ``systemDebug(arg: "; echo ...")`` ran a shell and ``pastes(filter: "a'")``
broke the SQL, but candidate.verify refused both: the proofs only mutated a GET parameter.
"""
from __future__ import annotations

import asyncio
import json
import re

import pytest

from api.capabilities import graphql_argument
from api.capabilities.request_mutation import replace_private_request_field
from api.hunt import injection_proof
from api.hunt.candidate_verification_preflight import web_candidate_preflight
from api.runtime.request_replay_executor import ReplayTransportResult
from scanner.scanner_tools.request_replay import ReplayRequest

RUN = {"id": "20000000-0000-4000-8000-000000000001", "target_kind": "web",
       "target_id": "10000000-0000-4000-8000-000000000001", "device_target_id": None}
CONTEXT = {"target": {"url": "https://app.example.test", "origins": ["https://app.example.test"]}}
DEBUG = 'query{systemDebug(arg:"x")}'


def test_the_named_string_argument_is_read_and_rewritten_escaped_and_nothing_else_changes():
    document = '# pastes(filter:"comment")\nquery Q($filter: String = "default") { a: pastes(filter: "a\\"b", limit: "3") { title } }'
    assert graphql_argument.argument_value(document, "graphql:filter") == 'a"b'
    rewritten = graphql_argument.with_argument(document, "graphql:filter", "x'\"; id\n")
    assert graphql_argument.argument_value(rewritten, "graphql:filter") == "x'\"; id\n"
    assert rewritten.replace(json.dumps("x'\"; id\n"), '"a\\"b"') == document
    assert graphql_argument.argument_value(rewritten, "graphql:limit") == "3"


@pytest.mark.parametrize("document", [
    'query{pastes(public:true){id}}',                       # absent
    'query{a:search(keyword:"x"){id} b:search(keyword:"y"){id}}',  # twice: ambiguous
    'query{search(keyword:"""x"""){id}}',                   # block string
])
def test_a_document_without_exactly_one_plain_string_argument_is_refused(document):
    with pytest.raises(graphql_argument.GraphQLArgumentError):
        graphql_argument.argument_value(document, "graphql:keyword" if "search" in document else "graphql:filter")


def test_the_shared_mutator_rewrites_the_argument_inside_the_json_body():
    request = ReplayRequest(
        request_id="r", ordinal=0, name="n", folder="", method="POST", url="https://app.example.test/graphql",
        headers=(("Content-Type", "application/json"),),
        body=json.dumps({"query": DEBUG, "variables": {}}).encode(), body_mode="raw",
        auth_type="none", has_sensitive_material=False)
    mutated, encoding = replace_private_request_field(request, field_path="graphql:arg", replacement="x; id")
    body = json.loads(mutated.body)
    assert encoding == "json" and body["variables"] == {}
    assert body["query"] == 'query{systemDebug(arg:"x; id")}'


def _candidate(family, operation=DEBUG, parameter="arg", method="POST"):
    return {"id": "30000000-0000-4000-8000-000000000001", "family": family,
            "canonical_locus": {"route": "/graphql", "method": method, "parameter": parameter,
                                "operation": operation},
            "verification_context": {}, "status": "open", "target_id": RUN["target_id"]}


class Resolver:
    """A GraphQL endpoint whose ``arg`` reaches ``sh -c "ps x <arg>"``."""

    def __init__(self):
        self.requests = []

    async def send(self, request, **_kwargs):
        self.requests.append(request)
        document = json.loads(request.body)["query"]
        value = graphql_argument.argument_value(document, "graphql:arg")
        output = "PID TTY STAT TIME COMMAND\n"
        for separator in re.finditer(r"[;|&\n]\s*echo (\w+)\$\(\((\d+)\+(\d+)\)\)(\w+)", value):
            output += f"{separator.group(1)}{int(separator.group(2)) + int(separator.group(3))}{separator.group(4)}\n"
        body = json.dumps({"data": {"systemDebug": output}}).encode()
        return ReplayTransportResult(
            status_code=200, connected_address="192.0.2.10", final_url=request.url,
            response_headers={"Content-Type": "application/json"}, response_body=body, elapsed_ms=8)


def test_a_command_injection_in_a_graphql_argument_is_verified_by_the_servers_own_proof():
    resolver = Resolver()
    proof = asyncio.run(injection_proof.run_proof(
        run=RUN, context=CONTEXT, policy={}, candidate=_candidate("command_injection"),
        action_id="40000000-0000-4000-8000-000000000001", transport=resolver))
    assert proof["promotable"] and proof["verified"]["kind"] == "command_injection"
    assert all(request.method == "POST" for request in resolver.requests)
    assert proof["traffic"]["state_changing_requests"] == 0  # a query is a read
    record = injection_proof.finding_record(
        proof["verified"], kind="command_injection", hunt_id=RUN["id"],
        action_id="40000000-0000-4000-8000-000000000001", url=proof["url"])
    assert record["evidence"]["method"] == "POST" and record["evidence"]["field_path"] == "graphql:arg"
    assert record["severity"] == "critical"


def test_a_graphql_query_that_only_echoes_its_argument_is_not_reproduced():
    class Echo(Resolver):
        async def send(self, request, **_kwargs):
            self.requests.append(request)
            value = graphql_argument.argument_value(json.loads(request.body)["query"], "graphql:arg")
            return ReplayTransportResult(
                status_code=200, connected_address="192.0.2.10", final_url=request.url,
                response_headers={"Content-Type": "application/json"},
                response_body=json.dumps({"data": {"systemDebug": value}}).encode(), elapsed_ms=8)

    proof = asyncio.run(injection_proof.run_proof(
        run=RUN, context=CONTEXT, policy={}, candidate=_candidate("command_injection"),
        action_id="40000000-0000-4000-8000-000000000001", transport=Echo()))
    assert not proof["promotable"]


def test_a_mutation_needs_the_state_changing_permission():
    candidate = _candidate("command_injection", operation='mutation{importPaste(host:"h"){result}}', parameter="host")
    with pytest.raises(injection_proof.InjectionProofRefused) as refused:
        asyncio.run(injection_proof.run_proof(
            run=RUN, context=CONTEXT, policy={}, candidate=candidate,
            action_id="40000000-0000-4000-8000-000000000001", transport=Resolver()))
    assert refused.value.reason == "injection_proof_write_not_permitted"


def test_preflight_admits_a_graphql_argument_and_explains_a_bad_one():
    family, route, method = web_candidate_preflight(_candidate("sqli"), injection_proofs=True)
    assert (route, method) == ("/graphql", "POST")
    with pytest.raises(Exception) as refused:
        web_candidate_preflight(_candidate("sqli", parameter="missing"), injection_proofs=True)
    assert "operation" in str(refused.value.args) or "operation" in str(getattr(refused.value, "detail", ""))
