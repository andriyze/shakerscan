"""GraphQL endpoint discovery, introspection and IDE proofs (pure, hostile data).

The nightly lab scan of DVGA (Damn Vulnerable GraphQL Application) reported no GraphQL finding
at all: no V2 capability sent a GraphQL request. The read-only exposure batch now reads each
conventional GraphQL endpoint with a fixed introspection document over GET and each IDE
location as a browser would. These tests pin the proofs over hostile bodies and non-GraphQL
applications; the batch itself is driven in ``test_graphql_exposure_batch.py``.
"""
from __future__ import annotations

import json
import urllib.parse

import pytest

from api.capabilities import graphql_probe as gql
from api.capabilities.exposure_probe import (
    EXPOSURE_PROOF_CONTRACTS,
    classify_exposure,
    graphql_seed_probes,
    is_sensitive_exposure_class,
)
from api.proof_contracts import CANONICAL_PROOF_CONTRACTS
from api.scan.action_plan import ScanActionPlan
from api.scan.finalizer import finalize_scan_report
from scanner.scanner_tools.remediation_kb import get_remediation_for_exposure_class
from tests.test_scan_finalizer import _result_with_observation_count
from tests.graphql_fixtures import DVGA_GRAPHIQL, DVGA_INTROSPECTION, SPA_SHELL
from tests.test_scan_orchestrator import SCAN_ID, _action

def _json(document) -> bytes:
    return json.dumps(document).encode()


def _classify(path, body, content_type, status=200):
    return classify_exposure(
        path=f"https://app.example.test{path}", status=status,
        headers={"Content-Type": content_type}, body=body,
    )


# --- introspection ----------------------------------------------------------------------------


def test_an_introspection_answer_proves_introspection_is_enabled():
    summary = gql.introspection_summary(DVGA_INTROSPECTION)
    assert summary["query_type"] == "Query" and summary["type_count"] == 5
    assert summary["query_fields"][:2] == ("pastes", "paste")
    url = gql.graphql_request_url("https://app.example.test/graphql", gql.INTROSPECTION_QUERY)
    signature = _classify(url.split("app.example.test", 1)[1], _json(DVGA_INTROSPECTION),
                          "application/json")
    assert signature.exposure_class == "graphql_introspection_enabled"
    assert signature.severity == "low" and is_sensitive_exposure_class(signature.exposure_class)


@pytest.mark.parametrize("document", [
    # Introspection disabled (Apollo, graphql-core, Hasura wording).
    {"errors": [{"message": "GraphQL introspection is not allowed by Apollo Server"}]},
    {"errors": [{"message": "Cannot query field '__schema' on type 'Query'."}], "data": None},
    {"data": {"__schema": None}},
    {"data": {"__schema": {"queryType": None, "types": []}}},
    # The root type must be one of the returned types; an echo or a forged shape is not.
    {"data": {"__schema": {"queryType": {"name": "Query"}, "types": [{"name": "User"}]}}},
    {"data": {"__schema": {"queryType": {"name": "Query"}, "types": "Query"}}},
    {"data": {"__schema": {"queryType": {"name": "1nvalid name"}, "types": [{"name": "1nvalid name"}]}}},
    {"data": {"__schema": {"queryType": {"name": ["Query"]}, "types": [{"name": ["Query"]}]}}},
    {"query": "query{__schema{queryType{name fields{name}}types{name}}}"},
    [DVGA_INTROSPECTION], "Query", None, 7,
])
def test_anything_short_of_a_real_schema_proves_nothing(document):
    assert gql.introspection_summary(document) is None
    if isinstance(document, (dict, list)):
        assert _classify("/graphql", _json(document), "application/json") is None


def test_hostile_schema_bodies_are_bounded_and_never_trusted():
    huge = {"data": {"__schema": {
        "queryType": {"name": "Query", "fields": [
            {"name": "x" * 500}, {"name": "<script>"}, {"name": 5}, None, {"name": "ok_field"},
        ] + [{"name": f"f{i}"} for i in range(5_000)]},
        "types": [{"name": "Query"}] + [{"name": f"T{i}"} for i in range(20_000)],
    }}}
    summary = gql.introspection_summary(huge)
    assert summary["type_count"] <= 10_000
    assert "<script>" not in summary["query_fields"] and "x" * 500 not in summary["query_fields"]
    assert summary["query_fields"][0] == "ok_field" and len(summary["query_fields"]) <= 2_000
    # Not JSON, truncated JSON and JSON inside HTML prove nothing.
    for body in (b'{"data":{"__schema":', b"<html>" + _json(DVGA_INTROSPECTION) + b"</html>",
                 b"\x00\xff" * 100):
        assert _classify("/graphql", body, "application/json") is None


def test_only_a_200_answer_counts():
    for status in (400, 401, 403, 404, 500):
        assert _classify("/graphql", _json(DVGA_INTROSPECTION), "application/json", status) is None


# --- the endpoint probe -----------------------------------------------------------------------


def test_typename_proves_a_graphql_endpoint_and_nothing_else_does():
    assert gql.typename_root({"data": {"__typename": "Query"}}) == "Query"
    assert gql.typename_root({"data": {"__typename": "query_root"}}) == "query_root"
    for document in (
        {"data": {"__typename": "Query"}, "errors": [{"message": "x"}]},
        {"data": {"__typename": "<b>Query</b>"}},
        {"data": {"__typename": "Query", "extra": 1}},
        {"data": {"__typename": None}},
        {"errors": [{"message": "Must provide query string."}]},
        {"query": "query{__typename}"},  # an echo of the request
        "Query", None, [],
    ):
        assert gql.typename_root(document) is None


def test_request_urls_carry_only_the_fixed_document():
    url = gql.graphql_request_url("https://app.example.test/api/graphql?token=abc#frag",
                                  gql.TYPENAME_QUERY)
    parts = urllib.parse.urlsplit(url)
    assert parts.path == "/api/graphql" and parts.fragment == ""
    assert urllib.parse.parse_qs(parts.query) == {"query": [gql.TYPENAME_QUERY]}
    assert gql.endpoint_of(url) == "https://app.example.test/api/graphql"


@pytest.mark.parametrize(("url", "expected"), [
    ("https://app.example.test/graphql", True),
    ("https://app.example.test/api/v2/GraphQL/", True),
    ("https://app.example.test/gql", True),
    ("https://app.example.test/graphql.js", False),
    ("https://app.example.test/docs/graphql-guide", False),
    ("https://app.example.test/graphiql", False),
    ("https://app.example.test/?q=graphql", False),
    ("http://[::1", False),
    ("", False),
])
def test_discovered_graphql_routes_are_recognised_by_their_last_segment(url, expected):
    assert gql.is_graphql_endpoint_url(url) is expected


def test_the_seed_probes_are_fixed_reads():
    probes = graphql_seed_probes("https://app.example.test")
    assert len(probes) == 8
    for url, headers in probes:
        parts = urllib.parse.urlsplit(url)
        assert parts.netloc == "app.example.test"
        query = urllib.parse.parse_qs(parts.query)
        if query:
            # Only the reviewed introspection document, which selects only __schema.
            assert query == {"query": [gql.INTROSPECTION_QUERY]}
            assert "mutation" not in gql.INTROSPECTION_QUERY
            assert dict(headers)["Accept"].startswith("application/graphql-response+json")
        else:
            assert dict(headers) == {"Accept": "text/html"}


# --- the IDE ----------------------------------------------------------------------------------


def test_a_graphiql_page_proves_the_ide_is_served():
    signature = _classify("/graphiql", DVGA_GRAPHIQL, "text/html; charset=utf-8")
    assert signature.exposure_class == "graphql_ide_exposure" and signature.severity == "low"
    playground = (b'<html><head><title>GraphQL Playground</title><script src="//cdn.jsdelivr.net/'
                  b'npm/graphql-playground-react@1.7.26/build/static/js/middleware.js"></script>'
                  b"</head><body><script>GraphQLPlayground.init(document.getElementById('root'), {})"
                  b"</script></body></html>")
    assert _classify("/playground", playground, "text/html").exposure_class == "graphql_ide_exposure"


@pytest.mark.parametrize("body", [
    SPA_SHELL,
    b"<html><body><h1>How to disable GraphiQL in production</h1><p>Remove graphiql.min.js and "
    b"never call React.createElement(GraphiQL) on a public page.</p></body></html>",
    b'<html><body><a href="https://cdn.example/graphiql/graphiql.min.js">download</a></body></html>',
    b"<html><body><pre>ReactDOM.render(React.createElement(GraphiQL))</pre></body></html>",
])
def test_pages_about_or_linking_to_an_ide_prove_nothing(body):
    assert _classify("/graphiql", body, "text/html") is None


# --- promotion and remediation ----------------------------------------------------------------


def test_graphql_classes_have_contracts_and_guidance():
    for exposure_class in ("graphql_introspection_enabled", "graphql_ide_exposure"):
        assert EXPOSURE_PROOF_CONTRACTS[exposure_class] in CANONICAL_PROOF_CONTRACTS
        assert get_remediation_for_exposure_class(exposure_class) is not None


def _observation(url: str, body: bytes, content_type: str) -> dict:
    from types import SimpleNamespace

    from api.runtime.receipts import redact_receipt_value
    from api.scan.action_adapter import _exposure_observation

    signature = classify_exposure(path=url, status=200, headers={"Content-Type": content_type},
                                  body=body)
    result = SimpleNamespace(status_code=200, response_headers={"Content-Type": content_type},
                             response_body=body)
    observation = _exposure_observation(url, "graphql_seed", signature, result)
    return dict(redact_receipt_value(dict(observation)))


def test_findings_are_reported_on_the_endpoint_with_the_request_as_evidence():
    request_url = gql.graphql_request_url("https://app.example.test/graphql", gql.INTROSPECTION_QUERY)
    probe = _action("verify.exposure", 0, capability_name="exposure.verify_batch")
    final = _action("finalize.report", 1, dependencies=(probe.action_id,))
    plan = ScanActionPlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64,
                          target_binding_digest="a" * 64, actions=(probe, final))
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results={probe.action_id: _result_with_observation_count(probe, 2)},
        observations={probe.action_id: (
            _observation(request_url, _json(DVGA_INTROSPECTION), "application/json"),
            _observation("https://app.example.test/graphiql", DVGA_GRAPHIQL, "text/html"),
        )},
    )
    findings = {finding["title"]: finding for finding in report["findings"]}
    introspection = findings["GraphQL introspection enabled"]
    assert introspection["url"] == "https://app.example.test/graphql"
    assert introspection["severity"] == "low" and introspection["cwe"] == "CWE-200"
    # The request URL is evidence; its query value passes the shared receipt redactor.
    evidence_url = urllib.parse.urlsplit(introspection["evidence"]["request_url"])
    assert evidence_url.path == "/graphql" and evidence_url.query.startswith("query=")
    assert introspection["evidence"]["proof_contract"] == "graphql_introspection_exposure/v1"
    ide = findings["GraphQL IDE served publicly"]
    assert ide["url"] == "https://app.example.test/graphiql"
    assert ide["evidence"]["proof_contract"] == "graphql_ide_exposure/v1"


# --- the active checks' proofs -----------------------------------------------------------------


def test_a_misspelling_is_never_a_real_root_field():
    pair = gql.misspelt_field(("me", "pastes", "pastezq", "pasteqz", "paste"))
    assert pair is not None
    real, misspelt = pair
    assert real == "pastes" and misspelt not in {"me", "pastes", "pastezq", "pasteqz", "paste"}
    assert gql.misspelt_field(("me", "id", "__type")) is None  # nothing long enough to misspell
    assert gql.misspelt_field(("<script>", 7, None)) is None
    with pytest.raises(ValueError):
        gql.suggestion_query("x}mutation{deleteAll")


def test_a_suggestion_must_name_a_real_field_for_the_misspelling():
    known = ("pastes", "paste", "me")
    graphql_core = {"errors": [{"message": "Cannot query field 'pastezq' on type 'Query'. "
                                           "Did you mean 'pastes' or 'paste'?"}]}
    graphql_js = {"errors": [{"message": 'Cannot query field "pastezq" on type "Query". '
                                         'Did you mean "pastes"?'}]}
    assert gql.suggested_fields(graphql_core, misspelling="pastezq", known_fields=known) == (
        "pastes", "paste")
    assert gql.suggested_fields(graphql_js, misspelling="pastezq", known_fields=known) == ("pastes",)
    for document in (
        {"errors": [{"message": "Cannot query field 'pastezq' on type 'Query'."}]},
        {"errors": [{"message": "Did you mean 'pastes'?"}]},  # not about the misspelling
        {"errors": [{"message": "Cannot query field 'pastezq'. Did you mean 'secret'?"}]},
        {"errors": [{"message": "Cannot query field 'pastezq'. Did you mean 'pastezq'?"}]},
        {"data": {"pastezq": 1}, "errors": [{"message": "pastezq Did you mean 'pastes'"}]},
        {"errors": "Did you mean 'pastes'"}, None, "x",
    ):
        assert gql.suggested_fields(document, misspelling="pastezq", known_fields=known) == ()


def test_alias_and_duplicate_proofs_need_every_answer_and_no_error():
    query = gql.alias_query()
    assert query.count(":__typename") == gql.ALIAS_COUNT and "mutation" not in query
    full = {"data": {f"a{i}": "Query" for i in range(gql.ALIAS_COUNT)}}
    assert gql.aliases_answered(full)
    partial = {"data": {f"a{i}": "Query" for i in range(gql.ALIAS_COUNT - 1)}}
    limited = {"data": None, "errors": [{"message": "Too many aliases"}]}
    erroring = {**full, "errors": [{"message": "cost exceeded"}]}
    forged = {"data": {f"a{i}": "<x>" for i in range(gql.ALIAS_COUNT)}}
    for document in (partial, limited, erroring, forged, None, []):
        assert not gql.aliases_answered(document)
    assert gql.duplicate_field_query().count("__typename") == gql.DUPLICATE_FIELD_COUNT
    assert gql.duplicates_answered({"data": {"__typename": "Query"}})
    assert not gql.duplicates_answered({"errors": [{"message": "duplicate fields limit"}]})


# --- review hardening -------------------------------------------------------------------------


def test_a_static_schema_file_is_not_introspection_and_a_docs_page_is_not_an_ide():
    # A committed schema.json holds the same document; only the answer to the request proves
    # the server answers introspection.
    assert _classify("/schema.json", _json(DVGA_INTROSPECTION), "application/json") is None
    # A documentation page showing GraphiQL setup code is not an IDE location.
    assert _classify("/docs/graphql", DVGA_GRAPHIQL, "text/html") is None
    assert gql.is_ide_location("https://app.example.test/graphiql/")
    assert not gql.is_ide_location("https://app.example.test/blog/graphiql-setup")


def test_deeply_nested_json_is_rejected_not_raised():
    hostile = b"[" * 200_000 + b"]" * 200_000
    assert gql.json_body(hostile) is None
    url = gql.graphql_request_url("https://app.example.test/graphql", gql.INTROSPECTION_QUERY)
    assert _classify(url.split("app.example.test", 1)[1], hostile, "application/json") is None


def test_introspection_reads_deprecated_root_fields_and_flags_a_cut_list():
    assert "includeDeprecated:true" in gql.INTROSPECTION_QUERY
    assert gql.introspection_summary(DVGA_INTROSPECTION)["query_fields_complete"] is True
    cut = {"data": {"__schema": {
        "queryType": {"name": "Query", "fields": [{"name": f"f{i}"} for i in range(2_001)]},
        "types": [{"name": "Query"}],
    }}}
    assert gql.introspection_summary(cut)["query_fields_complete"] is False
    odd = {"data": {"__schema": {
        "queryType": {"name": "Query", "fields": [{"name": "pastes"}, {"name": "bad name"}]},
        "types": [{"name": "Query"}],
    }}}
    assert gql.introspection_summary(odd)["query_fields_complete"] is False
