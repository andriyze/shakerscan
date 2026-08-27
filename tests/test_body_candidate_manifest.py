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


def test_a_json_body_endpoint_produces_one_candidate_per_field():
    manifest = build_candidate_manifest(
        _manifest([_endpoint()]), source_action_ids=("discover.crawl",), maximum=50,
        allow_state_changing_http=True)
    fields = sorted(item["parameter_name"] for item in manifest.entries)
    assert fields == ["email", "password"]
    for item in manifest.entries:
        assert item["method"] == "POST"
        assert item["content_type"] == "application/json"
        assert list(item["body_field_names"]) == ["email", "password"]


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
    index = next(i for i, item in enumerate(candidates.entries)
                 if item["parameter_name"] == "password")
    request = execution_request_for_manifest_candidate(endpoints, candidates, index)
    assert request["method"] == "POST"
    assert request["url"] == "https://target.test/rest/user/login"
    assert request["content_type"] == "application/json"
    assert request["field_name"] == "password"
    # Every declared field is present so the body is well-formed; only the tested field is marked.
    assert sorted(request["body_field_names"]) == ["email", "password"]


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
