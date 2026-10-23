"""A body-bearing endpoint must be able to become a candidate.

`build_candidate_manifest` skipped every non-GET endpoint and hardcoded `body_field_names: []`, so
an application whose injectable surface is a JSON login body -- the shape of most modern APIs --
produced no candidates at all. The endpoint manifest already carries `body_field_names` and
`content_type`; this makes the candidate builder use them.

Body candidates are state-changing by nature, so they are ranked and emitted here but only planned
when the scan holds mutation authority; that gate lives in the planner, not in the manifest.
"""

from __future__ import annotations

import pytest

from api.scan.work_manifests import (
    ScanWorkManifest,
    ScanWorkManifestError,
    ScanWorkManifestKind,
    build_candidate_manifest,
    execution_request_for_manifest_candidate,
)
from api.scan.action_adapter import _candidate_for_synthetic_proof

DIGEST = "d" * 64
SCAN = "10000000-0000-4000-8000-000000000001"


def _endpoint(**overrides):
    from api.scan.work_manifests import route_id

    base = {
        "method": "POST", "scheme": "https", "host": "target.test", "port": 443,
        "canonical_path": "/rest/user/login", "query_parameter_names": [],
        "content_type": "application/json", "body_field_names": ["email", "password"],
        "source_tool": "known_endpoints", "discovery_depth": 0, "auth_lane": "anonymous",
        "selected_shard": None, "request_ref_ids": [],
    }
    base.update(overrides)
    base["route_id"] = route_id(
        target_binding_digest=DIGEST, method=base["method"], scheme=base["scheme"],
        host=base["host"], port=base["port"], canonical_path=base["canonical_path"],
        query_parameter_names=base["query_parameter_names"],
    )
    return base


def _manifest(entries):
    return ScanWorkManifest(
        scan_id=SCAN, kind=ScanWorkManifestKind.ENDPOINT, target_binding_digest=DIGEST,
        source_action_ids=("discover.crawl",), entries=tuple(entries), status="complete",
    )


def test_a_json_body_endpoint_produces_one_candidate_for_the_whole_body():
    """One candidate, not one per field.

    The verifier tests every field in a single run and stops at the first vulnerable one, so
    per-field candidates cost N runs for the coverage of one. Measured: testing both fields of a
    login body costs the same 410 requests as testing either alone. Worse, when two fields tied on
    score, which one received the budget came down to a digest comparison -- and on Juice Shop that
    picked `password` while the injection was in `email`.
    """
    manifest = build_candidate_manifest(
        _manifest([_endpoint()]), source_action_ids=("discover.crawl",), maximum=50,
        allow_state_changing_http=True)
    assert len(manifest.entries) == 1
    entry = manifest.entries[0]
    assert entry["method"] == "POST"
    assert entry["content_type"] == "application/json"
    # The whole body is carried and tested; the anchor only labels the candidate.
    assert list(entry["body_field_names"]) == ["email", "password"]
    assert entry["parameter_name"] == "email", "the likeliest field anchors the identity"


def test_query_candidates_are_unchanged():
    endpoint = _endpoint(method="GET", query_parameter_names=["q"],
                         content_type=None, body_field_names=[])
    manifest = build_candidate_manifest(
        _manifest([endpoint]), source_action_ids=("discover.crawl",), maximum=50)
    assert [item["parameter_name"] for item in manifest.entries] == ["q"]
    assert list(manifest.entries[0]["body_field_names"]) == []
    assert manifest.entries[0]["content_type"] is None


def test_a_non_get_endpoint_with_no_declared_body_yields_nothing():
    # Without field names there is nothing to inject into; inventing them would be guessing.
    endpoint = _endpoint(content_type=None, body_field_names=[])
    manifest = build_candidate_manifest(
        _manifest([endpoint]), source_action_ids=("discover.crawl",), maximum=50)
    assert manifest.entries == ()


def test_a_body_candidate_resolves_to_a_request_not_a_url():
    endpoints = _manifest([_endpoint()])
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.crawl",), maximum=50,
        allow_state_changing_http=True)
    index = 0
    request = execution_request_for_manifest_candidate(endpoints, candidates, index)
    assert request["method"] == "POST"
    assert request["url"] == "https://target.test/rest/user/login"
    assert request["content_type"] == "application/json"
    assert request["field_name"] == "email"
    # Every declared field is present so the body is well-formed; only the tested field is marked.
    assert sorted(request["body_field_names"]) == ["email", "password"]


def test_synthetic_body_proof_does_not_claim_an_exact_private_request():
    candidate = {"candidate_id": "a" * 64, "request_ref_id": "private-request-1"}

    proof_candidate = _candidate_for_synthetic_proof(candidate)

    assert proof_candidate["request_ref_id"] is None
    assert candidate["request_ref_id"] == "private-request-1"


def test_a_query_candidate_still_resolves_to_a_url_with_the_parameter():
    endpoint = _endpoint(method="GET", query_parameter_names=["q"],
                         content_type=None, body_field_names=[])
    endpoints = _manifest([endpoint])
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.crawl",), maximum=50)
    request = execution_request_for_manifest_candidate(endpoints, candidates, 0)
    assert request["method"] == "GET"
    assert "q=" in request["url"]
    assert request["content_type"] is None
    assert list(request["body_field_names"]) == []


def test_a_candidate_whose_field_is_not_on_its_endpoint_is_refused():
    endpoints = _manifest([_endpoint()])
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.crawl",), maximum=50,
        allow_state_changing_http=True)
    forged = dict(candidates.entries[0], parameter_name="admin")
    with pytest.raises(ScanWorkManifestError):
        ScanWorkManifest(
            scan_id=SCAN, kind=ScanWorkManifestKind.CANDIDATE, target_binding_digest=DIGEST,
            source_action_ids=("discover.crawl",), entries=(forged,), status="complete",
        )
    # It cannot even be assembled into a manifest: the field is not on the endpoint's body and the
    # id no longer matches the identity it claims. Content addressing refuses it at construction,
    # so no resolver ever sees it.


def test_body_candidates_require_stated_mutation_authority():
    """The default is closed.

    A body candidate can only be tested by a state-changing request. A caller that does not state
    that authority gets the query-only surface it would have got before body candidates existed,
    so adding this capability cannot silently widen what an existing scan sends.
    """
    endpoints = _manifest([_endpoint()])
    assert build_candidate_manifest(
        endpoints, source_action_ids=("discover.crawl",), maximum=50).entries == ()
    assert build_candidate_manifest(
        endpoints, source_action_ids=("discover.crawl",), maximum=50,
        allow_state_changing_http=False).entries == ()
    assert build_candidate_manifest(
        endpoints, source_action_ids=("discover.crawl",), maximum=50,
        allow_state_changing_http=True).entries != ()


def test_query_candidates_are_unaffected_by_mutation_authority():
    # A GET parameter needs no mutation authority, so the gate must not touch it either way.
    endpoint = _endpoint(method="GET", query_parameter_names=["q"],
                         content_type=None, body_field_names=[])
    for authority in (False, True):
        manifest = build_candidate_manifest(
            _manifest([endpoint]), source_action_ids=("discover.crawl",), maximum=50,
            allow_state_changing_http=authority)
        assert [item["parameter_name"] for item in manifest.entries] == ["q"], authority


def test_both_production_call_sites_pass_their_scan_authority():
    # The gate is only real if the callers state their authority; a missing argument silently
    # falls back to the closed default and the surface quietly disappears.
    from tests.api_sources import definition_source

    for handler in (
        "_compile_scan_admission_surface_work_manifests",
        "_compile_parallel_child_work_manifests",
        # Continuation rebuilds the manifest the plan executes; when it disagreed with admission
        # the plan ran against an empty candidate set and the family reported not_applicable.
        "build_discovery_continuation_manifests",
    ):
        source = definition_source(handler)
        assert "build_candidate_manifest(" in source, handler
        assert "allow_state_changing_http=" in source, handler


def test_authentication_field_names_rank_as_injection_candidates():
    """The authentication query is the canonical SQL injection site.

    `username` was in the semantic set while `email` -- its modern equivalent -- and `password`
    were not, so a login body scored below a socket.io `transport` parameter and a constrained
    budget dropped exactly the candidate most likely to be vulnerable. Ranking by likelihood, not
    by how cheap the request is to make.
    """
    login = build_candidate_manifest(
        _manifest([_endpoint()]), source_action_ids=("discover.crawl",), maximum=50,
        allow_state_changing_http=True)
    assert len(login.entries) == 1
    login_score = login.entries[0]["score"]

    plumbing = _endpoint(method="GET", canonical_path="/socket.io/",
                         query_parameter_names=["transport"],
                         content_type=None, body_field_names=[], source_tool="web.crawl")
    transport = build_candidate_manifest(
        _manifest([plumbing]), source_action_ids=("discover.crawl",), maximum=50).entries[0]

    assert login_score > transport["score"], (login_score, transport["score"])
    for item in login.entries:
        assert "sqli_semantic_parameter" in item["ranking_rationale"]


def test_a_body_candidate_resolves_when_a_replayed_request_shares_its_route():
    """A replayed collection request and a declared endpoint can name the same route.

    The replay producer records only method and URL, so its entry declares no body fields, and it
    is collected first. Resolving a body candidate against the first entry with the candidate's
    route refused the login form's candidate as an identity conflict, and the XSS and SQL injection
    batches that held it ended with no request sent.
    """
    replayed = _endpoint(
        source_tool="collections.replay", content_type=None, body_field_names=[],
    )
    declared = _endpoint(content_type="application/x-www-form-urlencoded",
                         body_field_names=["password", "username"])
    assert replayed["route_id"] == declared["route_id"]
    endpoints = _manifest([replayed, declared])
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.crawl",), maximum=50,
        allow_state_changing_http=True)
    assert len(candidates.entries) == 1

    request = execution_request_for_manifest_candidate(endpoints, candidates, 0)

    assert request["method"] == "POST"
    assert request["url"] == "https://target.test/rest/user/login"
    assert request["content_type"] == "application/x-www-form-urlencoded"
    assert request["field_name"] == "username"
    assert request["body_field_names"] == ["password", "username"]


# Two bodies posted to one action (a login page's form and a sidebar widget, a search form seen
# twice): both are endpoints of their own (the identity names the body), and the same route,
# method and anchoring field make them one candidate id with one score.
_SAME_ACTION_FORMS = {
    "a login page and a sidebar widget": ("/wp-login.php", "web.crawl", (
        ["log", "pwd", "rememberme", "wp-submit", "redirect_to", "testcookie"],
        ["log", "pwd", "rememberme", "wp-submit", "redirect_to"],
    )),
    "a login page and a header box": ("/login", "web.browser_crawl", (
        ["username", "password", "_csrf"], ["username", "password", "_csrf", "return_to"],
    )),
    "a search form seen twice": ("/search", "web.crawl", (["q", "category"], ["q"])),
}


def _crawled_forms(path, source, bodies):
    from api.scan.surface_manifest import build_scan_surface_manifest
    from api.scan.work_manifests import build_endpoint_manifest
    from tests.test_scan_continuation import _target

    target = _target()
    empty = {"status": "success", "observations": []}
    routes = {"status": "success", "observations": [
        {"kind": "discovered_route", "method": "POST", "url": f"https://app.example.test{path}",
         "content_type": "application/x-www-form-urlencoded", "body_field_names": list(fields)}
        for fields in bodies
    ]}
    surface = build_scan_surface_manifest(
        target_url="https://app.example.test", target=target, options={},
        collection_replay=empty, subdomains=empty, probe=empty,
        crawl=routes if source == "web.crawl" else empty,
        browser=routes if source == "web.browser_crawl" else empty,
        content=empty, max_endpoints=100,
    )
    return build_endpoint_manifest(
        scan_id="00000000-0000-4000-8000-0000000000d2", target_binding_digest=target.digest,
        surface_manifest=surface, source_action_ids=(f"discover.{source.split('.')[1]}",),
        auth_lane="anonymous",
    )


@pytest.mark.parametrize("case", sorted(_SAME_ACTION_FORMS))
def test_two_bodies_of_one_action_that_tie_on_score_are_both_candidates(case):
    """Building the candidate manifest compared the two variants' candidate dicts when their score
    and id tied, and raised TypeError: admission, continuation planning and the parallel fan-out
    of a scan allowed state-changing requests failed to plan any verifier for the target."""
    path, source, bodies = _SAME_ACTION_FORMS[case]
    endpoints = _crawled_forms(path, source, bodies)
    posts = [entry for entry in endpoints.entries if entry["method"] == "POST"]
    assert sorted(tuple(entry["body_field_names"]) for entry in posts) == sorted(
        tuple(sorted(fields)) for fields in bodies
    )
    first = build_candidate_manifest(endpoints, source_action_ids=("discover.crawl",),
                                     maximum=100, allow_state_changing_http=True)
    variants = [entry for entry in first.entries if entry.get("body_field_names")]
    assert len(variants) == 2 and len({entry["candidate_id"] for entry in variants}) == 1
    assert len({entry["score"] for entry in variants}) == 1
    assert sorted(tuple(entry["body_field_names"]) for entry in variants) == sorted(
        tuple(sorted(fields)) for fields in bodies
    )
    # The same endpoints always make the same manifest, its variants in the same order.
    again = build_candidate_manifest(endpoints, source_action_ids=("discover.crawl",),
                                     maximum=100, allow_state_changing_http=True)
    assert again.reference().manifest_digest == first.reference().manifest_digest
    # Without mutation authority a body is no candidate, as before.
    assert not [entry for entry in build_candidate_manifest(
        endpoints, source_action_ids=("discover.crawl",), maximum=100,
        allow_state_changing_http=False,
    ).entries if entry.get("body_field_names")]


def test_a_full_manifest_keeps_the_variant_it_met_first_when_two_tie():
    """At the candidate limit a tie is never better than what the manifest holds: the variant met
    first stays, the other is left out, and the manifest says it was cut."""
    endpoints = _crawled_forms(*_SAME_ACTION_FORMS["a search form seen twice"])
    posts = [entry for entry in endpoints.entries if entry["method"] == "POST"]
    full = build_candidate_manifest(endpoints, source_action_ids=("discover.crawl",),
                                    maximum=100, allow_state_changing_http=True)
    body_count = len([entry for entry in full.entries if entry.get("body_field_names")])
    limited = build_candidate_manifest(endpoints, source_action_ids=("discover.crawl",),
                                       maximum=len(full.entries) - 1,
                                       allow_state_changing_http=True)
    kept = [entry for entry in limited.entries if entry.get("body_field_names")]
    assert body_count == 2 and len(kept) == 1
    assert kept[0]["body_field_names"] == posts[0]["body_field_names"]
    assert limited.status == "partial" and limited.reason_code == "candidate_limit_reached"


def test_a_better_candidate_met_later_evicts_the_variant_met_last():
    """A full manifest that meets a better candidate drops the tied variant it met last."""
    declared = _endpoint(content_type="application/x-www-form-urlencoded",
                         body_field_names=["password", "username"])
    widget = _endpoint(content_type="application/x-www-form-urlencoded",
                       body_field_names=["password", "remember", "username"])
    better = _endpoint(method="GET", canonical_path="/items", query_parameter_names=["id"],
                       content_type=None, body_field_names=[])
    every = build_candidate_manifest(_manifest([declared, widget, better]),
                                     source_action_ids=("discover.crawl",), maximum=3,
                                     allow_state_changing_http=True)
    variants = [entry for entry in every.entries if entry["body_field_names"]]
    assert len(variants) == 2 and len({(entry["candidate_id"], entry["score"]) for entry in variants}) == 1
    assert max(entry["score"] for entry in every.entries) > variants[0]["score"]
    kept = build_candidate_manifest(_manifest([declared, widget, better]),
                                    source_action_ids=("discover.crawl",), maximum=2,
                                    allow_state_changing_http=True)
    assert [tuple(entry["body_field_names"]) for entry in kept.entries] == [(), ("password", "username")]
