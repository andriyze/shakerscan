from __future__ import annotations

import json
import urllib.parse

from api.capabilities.browser import XSSBrowserProofAdapter
from api.runtime.models import TargetBinding
from api.scan.work_manifests import (
    ScanWorkManifest,
    build_candidate_manifest,
    build_endpoint_manifest,
    execution_request_for_manifest_candidate,
)
from scanner.manifests import normalize_endpoint


SCAN_ID = "10000000-0000-4000-8000-000000000001"
TARGET = TargetBinding(
    target_id="target-1",
    target_kind="web",
    canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",),
    allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",),
)


def _fragment_work():
    record = normalize_endpoint(
        method="GET",
        url="https://app.example.test/#/search?q=private-discovery-value",
        source="web.browser_crawl",
    )
    surface = {
        "schema_version": "endpoint-manifest/v1",
        "status": "complete",
        "reason": None,
        "endpoints": [record.public_dict()],
    }
    endpoints = build_endpoint_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET.digest,
        surface_manifest=surface,
        source_action_ids=("discover.browser_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints,
        source_action_ids=("discover.browser_crawl",),
        maximum=10,
    )
    return record, endpoints, candidates


def test_spa_fragment_shape_survives_the_canonical_manifest_pipeline():
    record, endpoints, candidates = _fragment_work()

    assert record.normalized_path == "/"
    assert record.query_keys == ()
    assert record.browser_fragment_path == "/search"
    assert record.browser_fragment_query_keys == ("q",)
    assert "private-discovery-value" not in json.dumps(record.public_dict())

    endpoint = endpoints.entries[0]
    candidate = candidates.entries[0]
    assert endpoint["browser_fragment_path"] == "/search"
    assert endpoint["browser_fragment_query_parameter_names"] == ("q",)
    assert candidate["browser_fragment_path"] == "/search"
    assert candidate["browser_fragment_query_parameter_names"] == ("q",)
    assert candidate["family_hints"] == ("xss",)
    assert candidate["ranking_rationale"][0] == "parameterized_fragment"
    assert execution_request_for_manifest_candidate(
        endpoints, candidates, 0,
    )["url"] == "https://app.example.test/#/search?q=1"
    assert ScanWorkManifest.from_dict(endpoints.canonical_dict()) == endpoints
    assert ScanWorkManifest.from_dict(candidates.canonical_dict()) == candidates


def test_browser_proof_injects_the_fragment_parameter_without_server_query():
    _record, endpoints, candidates = _fragment_work()
    request = execution_request_for_manifest_candidate(endpoints, candidates, 0)
    candidate = candidates.entries[0]

    prepared = XSSBrowserProofAdapter.prepare(
        target=TARGET,
        execution_url=request["url"],
        candidate_id=str(candidate["candidate_id"]),
        parameter_name="q",
    )

    parsed = urllib.parse.urlsplit(prepared.url)
    fragment = urllib.parse.urlsplit(parsed.fragment)
    injected = dict(urllib.parse.parse_qsl(fragment.query))
    assert parsed.query == ""
    assert fragment.path == "/search"
    assert prepared.injection_location == "fragment"
    assert prepared.marker in injected["q"]
    assert prepared.marker not in json.dumps(prepared.redacted_execution)
    assert prepared.redacted_execution["request_url"] == (
        "https://app.example.test/#/search?q="
    )


def test_anchor_fragments_do_not_become_browser_execution_authority():
    anchor = normalize_endpoint(
        method="GET",
        url="https://app.example.test/docs#installation",
        source="web.crawl",
    )

    assert anchor.browser_fragment_path is None
    assert anchor.browser_fragment_query_keys == ()
