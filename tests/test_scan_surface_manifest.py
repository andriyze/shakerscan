from __future__ import annotations

import json

from api.runtime.models import TargetBinding
from api.scan.surface_manifest import build_scan_surface_manifest
from api.scan.work_manifests import build_candidate_manifest, build_endpoint_manifest


TARGET = TargetBinding(
    target_id="target-1",
    target_kind="web",
    canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",),
    allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",),
)


def _summary(status: str, observations: list[dict] | None = None) -> dict:
    return {
        "status": status,
        "observations": list(observations or []),
    }


def test_surface_manifest_unifies_producers_and_redacts_values():
    secret = "worker-private-query-value"
    manifest = build_scan_surface_manifest(
        target_url=f"https://app.example.test/start?tenant={secret}",
        target=TARGET,
        options={
            "custom_endpoints": [
                f"GET /api/orders?owner={secret}",
                "POST /api/orders",
            ],
        },
        collection_replay=_summary("success", [{
            "kind": "request_replay",
            "method": "GET",
            "redacted_url": "https://app.example.test/replayed?token=%3Credacted%3E",
            "final_url": "https://app.example.test/replayed?token=%3Credacted%3E",
        }]),
        probe=_summary("success", [{
            "kind": "http_fingerprint",
            "url": "https://app.example.test/start",
        }]),
        crawl=_summary("success", [{
            "kind": "discovered_route",
            "method": "GET",
            "url": "https://app.example.test/api/orders?owner=%3Credacted%3E",
        }]),
        content=_summary("success", [{
            "kind": "content_discovery",
            "url": "https://app.example.test/admin",
        }]),
        subdomains=_summary("success", [{
            "kind": "subdomain", "host": "api.example.test",
        }]),
        max_endpoints=20,
    )

    encoded = json.dumps(manifest, sort_keys=True)
    assert manifest["schema_version"] == "endpoint-manifest/v1"
    assert manifest["status"] == "complete"
    assert manifest["endpoint_count"] == 7
    assert set(manifest["producers"]) == {
        "seed", "known_endpoints", "collections.replay", "web.probe",
        "web.crawl", "web.browser_crawl", "web.content_discover", "web.spec_ingest",
        "subdomains.discover",
    }
    assert secret not in encoded
    assert "owner" in encoded
    assert "tenant" in encoded


def test_surface_manifest_marks_out_of_scope_or_truncated_output_partial():
    manifest = build_scan_surface_manifest(
        target_url="https://app.example.test",
        target=TARGET,
        options={"custom_endpoints": ["GET /one", "GET /two"]},
        collection_replay=_summary("skipped"),
        probe=_summary("success"),
        crawl=_summary("success", [{
            "kind": "discovered_route",
            "method": "GET",
            "url": "https://evil.example/escape",
        }]),
        content=_summary("skipped"),
        subdomains=_summary("success", [{
            "kind": "subdomain", "host": "outside.invalid",
        }]),
        max_endpoints=2,
    )

    assert manifest["status"] == "partial"
    assert manifest["endpoint_count"] == 2
    assert manifest["producers"]["known_endpoints"]["status"] == "partial"
    assert manifest["producers"]["web.crawl"]["status"] == "partial"
    assert manifest["producers"]["subdomains.discover"]["status"] == "partial"
    assert "out_of_scope_observations" in (
        manifest["producers"]["web.crawl"]["reason"] or ""
    )


def test_browser_observed_post_body_shape_survives_without_values():
    secret = "browser-private-password"
    manifest = build_scan_surface_manifest(
        target_url="https://app.example.test",
        target=TARGET,
        options={},
        collection_replay=_summary("skipped"),
        probe=_summary("success"),
        crawl=_summary("success"),
        browser=_summary("success", [{
            "kind": "discovered_route",
            "method": "POST",
            "url": "https://app.example.test/rest/user/login",
            "content_type": "application/json",
            "body_field_names": ["email", "password"],
            "discarded_example_value": secret,
        }]),
        content=_summary("skipped"),
        subdomains=_summary("skipped"),
        max_endpoints=20,
    )

    login = next(
        item for item in manifest["endpoints"]
        if item["method"] == "POST" and item["concrete_path"] == "/rest/user/login"
    )
    assert login["content_type"] == "application/json"
    assert list(login["body_field_names"]) == ["email", "password"]
    assert secret not in json.dumps(manifest, sort_keys=True)

    endpoints = build_endpoint_manifest(
        scan_id="10000000-0000-4000-8000-000000000001",
        target_binding_digest=TARGET.digest,
        surface_manifest=manifest,
        source_action_ids=("discover.browser_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints,
        source_action_ids=("discover.browser_crawl",),
        maximum=50,
        allow_state_changing_http=True,
    )
    assert len(candidates.entries) == 1
    assert candidates.entries[0]["method"] == "POST"
    assert candidates.entries[0]["content_type"] == "application/json"
    assert list(candidates.entries[0]["body_field_names"]) == ["email", "password"]


def test_surface_manifest_ingests_declared_spec_routes_including_body_endpoints():
    """A spec declares routes a black-box crawl never exercises, body endpoints above all."""
    manifest = build_scan_surface_manifest(
        target_url="https://app.example.test",
        target=TARGET,
        options={},
        collection_replay=_summary("skipped"),
        probe=_summary("skipped"),
        crawl=_summary("skipped"),
        content=_summary("skipped"),
        subdomains=_summary("skipped"),
        spec=_summary("success", [
            {"kind": "discovered_route", "method": "GET",
             "url": "https://app.example.test/rest/products/1/reviews"},
            {"kind": "discovered_route", "method": "POST",
             "url": "https://app.example.test/rest/user/login",
             "content_type": "application/json",
             "body_field_names": ["email", "password"]},
        ]),
        max_endpoints=20,
    )
    assert "web.spec_ingest" in manifest["producers"]
    endpoint_manifest = build_endpoint_manifest(
        scan_id="10000000-0000-0000-0000-000000000009",
        target_binding_digest=TARGET.digest,
        surface_manifest=manifest,
        source_action_ids=("discover.spec",),
    )
    endpoints = {
        (item["method"], item["canonical_path"]): item
        for item in endpoint_manifest.entries
    }
    # A path-templated route becomes an addressable {int} endpoint, deduped like a crawl route.
    assert ("GET", "/rest/products/{int}/reviews") in endpoints
    login = endpoints[("POST", "/rest/user/login")]
    assert list(login["body_field_names"]) == ["email", "password"]
    assert login["content_type"] == "application/json"
    # The spec is a first-party declaration, ranked at depth 0 like a seeded endpoint.
    assert login["discovery_depth"] == 0


def _wildcard_content_observations(paths, *, status=301):
    """ffuf counts a 3xx as a hit, so an apex-wide redirect 'finds' every path."""
    return [
        {
            "kind": "content_discovery",
            "url": f"https://app.example.test{path}",
            "status": status,
            "length": 0,
            "redirect_location": f"https://www.app.example.test{path}",
        }
        for path in paths
    ]


def test_suspected_blanket_redirects_are_retained_as_uncertain_surface():
    """Several moved routes do not prove that nonexistent paths also redirect.

    Measured on a static site whose apex 301s to its www origin: content
    discovery reported 108 endpoints -- /graphql, /api-docs, /coupon -- none of
    which existed, and every one was persisted into the ASM inventory as real
    attack surface with no evidence behind it.
    """
    wordlist = [
        "/admin", "/graphql", "/api-docs", "/coupon", "/login", "/config", "/.env",
    ]
    manifest = build_scan_surface_manifest(
        target_url="https://app.example.test",
        target=TARGET,
        options={},
        collection_replay=_summary("skipped"),
        probe=_summary("success"),
        crawl=_summary("success"),
        browser=_summary("skipped"),
        content=_summary("success", _wildcard_content_observations(wordlist)),
        spec=_summary("skipped"),
        subdomains=_summary("skipped"),
        max_endpoints=200,
    )

    discovered = {
        entry["concrete_path"] for entry in manifest["endpoints"]
        if entry.get("source") == "web.content_discover"
    }
    # ffuf provides no negative-control observation in this profile. Preserve
    # possibly real moved routes, but do not claim that this discovery is complete.
    assert discovered == set(wordlist)
    producer = manifest["producers"]["web.content_discover"]
    # The uncertainty is recorded, never silent: coverage must not read as complete.
    assert producer["status"] == "partial"
    assert f"unverified_redirect_observations:{len(wordlist)}" in producer["reason"]


def test_individual_redirects_remain_discovered_surface():
    """A per-path redirect carries real information and is kept."""
    observations = [
        {
            "kind": "content_discovery",
            "url": "https://app.example.test/admin",
            "status": 302,
            "redirect_location": "https://app.example.test/admin/login",
        },
        {
            "kind": "content_discovery",
            "url": "https://app.example.test/dashboard",
            "status": 200,
        },
    ]
    manifest = build_scan_surface_manifest(
        target_url="https://app.example.test",
        target=TARGET,
        options={},
        collection_replay=_summary("skipped"),
        probe=_summary("success"),
        crawl=_summary("success"),
        browser=_summary("skipped"),
        content=_summary("success", observations),
        spec=_summary("skipped"),
        subdomains=_summary("skipped"),
        max_endpoints=200,
    )

    discovered = {
        entry["concrete_path"] for entry in manifest["endpoints"]
        if entry.get("source") == "web.content_discover"
    }
    assert discovered == {"/admin", "/dashboard"}


def test_unexpanded_client_template_routes_are_not_discovered_surface():
    """A route string the client has not substituted yet is not a route.

    Parsing an application's own JavaScript recovers template literals before
    substitution. Measured on a real site, that persisted /js/${PGP_PATH} and
    /js/${paths[f]} into the endpoint manifest and the durable ASM inventory as
    attack surface -- routes that exist in no deployment, which every later
    probe can only 404.
    """
    manifest = build_scan_surface_manifest(
        target_url="https://app.example.test",
        target=TARGET,
        options={},
        collection_replay=_summary("skipped"),
        probe=_summary("success"),
        crawl=_summary("success", [
            {"kind": "discovered_route", "method": "GET",
             "url": "https://app.example.test/js/$%7BPGP_PATH%7D"},
            {"kind": "discovered_route", "method": "GET",
             "url": "https://app.example.test/js/$%7Bpaths%5Bf%5D%7D"},
            {"kind": "discovered_route", "method": "GET",
             "url": "https://app.example.test/tools/tax.html"},
            {"kind": "discovered_route", "method": "GET",
             "url": "https://app.example.test/api/v1/tax?country=US"},
        ]),
        browser=_summary("skipped"),
        content=_summary("skipped"),
        spec=_summary("skipped"),
        subdomains=_summary("skipped"),
        max_endpoints=200,
    )

    crawled = {
        entry["concrete_path"] for entry in manifest["endpoints"]
        if entry.get("source") == "web.crawl"
    }
    assert crawled == {"/tools/tax.html", "/api/v1/tax"}
    # Dropped, and counted rather than silently absent.
    assert "invalid_observations:2" in manifest["producers"]["web.crawl"]["reason"]


def _redirect_row(path, *, host="apex.example.test", to="www.apex.example.test", status=301):
    return {
        "kind": "content_discovery",
        "url": f"https://{host}{path}",
        "status": status,
        "length": 0,
        "redirect_location": f"https://{to}{path}",
    }


APEX = TargetBinding(
    target_id="target-2",
    target_kind="web",
    canonical_host="apex.example.test",
    allowed_origins=("https://apex.example.test",),
    allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",),
)


def _apex_surface(observations):
    return build_scan_surface_manifest(
        target_url="https://apex.example.test",
        target=APEX,
        options={},
        collection_replay=_summary("skipped"),
        probe=_summary("success"),
        crawl=_summary("success"),
        browser=_summary("skipped"),
        content=_summary("success", observations),
        spec=_summary("skipped"),
        subdomains=_summary("skipped"),
        max_endpoints=200,
    )


def _content_paths(manifest):
    return sorted(
        entry["concrete_path"] for entry in manifest["endpoints"]
        if entry.get("source") == "web.content_discover"
    )


def test_a_measured_absent_path_disproves_the_hits_that_look_like_it():
    """The control probe is the proof the inference alone could not supply.

    Measured on a real apex that 301s its whole path space to its www origin:
    content discovery reported 108 endpoints, none of which existed, and every
    one was persisted into the ASM inventory as attack surface.
    """
    from api.scan.negative_control import negative_control_entries

    wordlist = ["/admin", "/graphql", "/api-docs", "/coupon", "/login", "/.env"]
    controls = negative_control_entries(3, seed="surface-test")
    manifest = _apex_surface(
        [_redirect_row(path) for path in wordlist]
        + [_redirect_row(f"/{entry}") for entry in controls]
    )

    assert _content_paths(manifest) == []
    reason = manifest["producers"]["web.content_discover"]["reason"]
    assert f"indistinguishable_from_absent:{len(wordlist)}" in reason
    # The control probes are the measurement; they are never surface themselves,
    # and they do not inflate the suspected-rewrite count.
    assert "unverified_redirect_observations" not in reason


def test_real_content_survives_the_calibration_that_drops_its_neighbours():
    from api.scan.negative_control import negative_control_entries

    controls = negative_control_entries(3, seed="surface-test")
    real = {
        "kind": "content_discovery",
        "url": "https://apex.example.test/robots.txt",
        "status": 200,
        "length": 843,
        "redirect_location": None,
    }
    moved = _redirect_row("/admin", to="apex.example.test/admin/login")
    moved["redirect_location"] = "https://apex.example.test/admin/login"
    manifest = _apex_surface(
        [_redirect_row(p) for p in ["/graphql", "/coupon", "/.env"]]
        + [_redirect_row(f"/{entry}") for entry in controls]
        + [real, moved]
    )

    assert _content_paths(manifest) == ["/admin", "/robots.txt"]


def test_without_a_control_probe_nothing_is_claimed_absent():
    """No measurement, no claim: observations are retained as uncertain."""
    wordlist = ["/admin", "/graphql", "/api-docs", "/coupon", "/login", "/.env"]
    manifest = _apex_surface([_redirect_row(path) for path in wordlist])

    assert _content_paths(manifest) == sorted(wordlist)
    reason = manifest["producers"]["web.content_discover"]["reason"]
    assert f"unverified_redirect_observations:{len(wordlist)}" in reason
    assert "indistinguishable_from_absent" not in reason
