"""Discovery tolerance must not weaken security or manufacture coverage evidence."""
from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlsplit

import pytest

from api.scan.negative_control import indistinguishable_from_absent, negative_control_entries
from api.scan.work_manifests import (
    ScanWorkManifest, ScanWorkManifestError, ScanWorkManifestUnrepresentableError,
    build_candidate_manifest, build_endpoint_manifest, execution_url_for_manifest_candidate,
)

SCAN_ID = "40000000-0000-4000-8000-000000000001"
DIGEST = "a" * 64


def endpoint(path="/search", names=("q",), **extra):
    return {"method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
            "normalized_path": path, "concrete_path": path, "query_keys": list(names),
            "source": "web.crawl", **extra}


def build(rows, **extra):
    return build_endpoint_manifest(scan_id=SCAN_ID, target_binding_digest=DIGEST,
        surface_manifest={"schema_version": "endpoint-manifest/v2", "status": "complete",
                          "endpoints": rows}, source_action_ids=("discover.web_crawl",), **extra)


@pytest.mark.parametrize("name", ["filter[status]", "$filter", "_rsc", "items[]", "a&admin=true"])
def test_query_names_are_opaque_encoded_names_not_internal_tokens(name):
    manifest = build([endpoint(names=(name,))])
    assert manifest.status == "complete"
    assert manifest.entries[0]["query_parameter_names"] == (name,)
    candidate = build_candidate_manifest(manifest, source_action_ids=("discover.web_crawl",), maximum=128)
    assert candidate.entries
    url = execution_url_for_manifest_candidate(manifest, candidate, 0)
    assert [key for key, _ in parse_qsl(urlsplit(url).query)] == [name]
    assert ScanWorkManifest.from_dict(manifest.canonical_dict()) == manifest
    assert ScanWorkManifest.from_dict(candidate.canonical_dict()) == candidate


@pytest.mark.parametrize("secret", [{"authorization": "Bearer never-persist"},
                                   {"nested": {"password": "never-persist"}}])
def test_security_violation_wins_even_when_same_observation_is_unrepresentable(secret):
    with pytest.raises(ScanWorkManifestError) as caught:
        build([endpoint("/good"), endpoint(names=("bad name",), **secret)])
    assert not isinstance(caught.value, ScanWorkManifestUnrepresentableError)


def test_unrepresentable_path_cannot_hide_a_sensitive_fragment():
    with pytest.raises(ScanWorkManifestError) as caught:
        build([endpoint("/good"), endpoint("/bad?query=1",
            browser_fragment_path="/reset/secret_abcdefghijklmnopqrstuvwxyz")])
    assert not isinstance(caught.value, ScanWorkManifestUnrepresentableError)


@pytest.mark.parametrize("context", [{"auth_lane": "primary!"}, {"selected_shard": -1},
    {"request_ref_ids_by_route": {"a" * 64: ["bad reference"]}}])
def test_unsupported_query_cannot_mask_invalid_internal_context(context):
    with pytest.raises(ScanWorkManifestError):
        build([endpoint(names=("bad name",))], **context)


def test_dropping_all_unsupported_observations_is_explicitly_partial():
    manifest = build([endpoint(names=("bad name",))])
    assert not manifest.entries
    assert manifest.status == "partial"
    assert "unrepresentable_endpoints:1" in manifest.reason_code
    assert "bad name" not in json.dumps(manifest.canonical_dict())


def test_secret_path_check_precedes_path_length_rejection():
    with pytest.raises(ScanWorkManifestError) as caught:
        build([endpoint("/" + "normal/" * 600 + "secret_abcdefghijklmnopqrstuvwxyz")])
    assert not isinstance(caught.value, ScanWorkManifestUnrepresentableError)


def control_row(path, *, host="app.example.test", target="www.app.example.test", status=301):
    return {"kind": "content_discovery", "url": f"https://{host}{path}",
            "redirect_location": f"https://{target}{path}", "status": status,
            "redirect_preserves_request_target": True}


def test_duplicate_control_rows_cannot_manufacture_confirmation():
    control = control_row("/" + negative_control_entries(1, seed="dedup-test")[0])
    real = control_row("/admin")
    assert indistinguishable_from_absent([control, control.copy(), real]) == frozenset()


def test_control_query_variants_and_explicit_default_port_are_one_measurement():
    path = "/" + negative_control_entries(1, seed="dedup-test")[0]
    rows = [control_row(path), control_row(path + "?variant=1", host="app.example.test:443"),
            control_row("/admin")]
    assert indistinguishable_from_absent(rows) == frozenset()


def test_distinct_agreeing_controls_still_confirm_origin_rewrite():
    controls = [control_row("/" + path) for path in negative_control_entries(2, seed="dedup-test")]
    assert indistinguishable_from_absent([*controls, control_row("/admin")]) == frozenset({
        "https://app.example.test/admin"})


def test_conflicting_control_evidence_never_increases_suppression():
    paths = negative_control_entries(3, seed="dedup-test")
    controls = [control_row("/" + path) for path in paths]
    controls[-1]["status"] = 200
    assert indistinguishable_from_absent([*controls, control_row("/admin")]) == frozenset()


def test_same_origin_redirect_loop_is_not_an_origin_move():
    controls = [control_row("/" + path, target="app.example.test")
                for path in negative_control_entries(2, seed="dedup-test")]
    assert indistinguishable_from_absent([*controls, control_row("/admin", target="app.example.test")]) == frozenset()
