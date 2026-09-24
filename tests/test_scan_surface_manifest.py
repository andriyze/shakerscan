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
            # The producer decides this on the raw pair before redaction.
            "redirect_preserves_request_target": True,
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


def _redirect_row(path, *, host="apex.example.test", to="www.apex.example.test",
                  status=301, preserves=True):
    return {
        "kind": "content_discovery",
        "url": f"https://{host}{path}",
        "status": status,
        "length": 0,
        "redirect_location": f"https://{to}{path}",
        "redirect_preserves_request_target": preserves,
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
    moved = _redirect_row("/admin", to="apex.example.test/admin/login", preserves=False)
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


def test_hint_files_declare_the_paths_a_crawl_cannot_reach():
    """robots.txt is the operator's own list of paths kept out of the link graph.

    A disallow rule is hand-written surface: OWASP Juice Shop publishes
    ``Disallow: /ftp`` and nothing links to it, so no crawl reaches it.
    """
    from api.capabilities.hint_files import ingest_hint_documents

    issues = []
    routes = ingest_hint_documents(
        [(
            "http://app.example.test/robots.txt",
            b"User-agent: *\nDisallow: /ftp\nDisallow: /admin/*\nAllow: /public\n"
            b"# a comment\nDisallow: /\nSitemap: http://app.example.test/sitemap.xml\n",
            "text/plain",
        )],
        origin="http://app.example.test",
        issues=issues,
    )

    assert [route["url"] for route in routes] == [
        "http://app.example.test/ftp",
        # A wildcard rule keeps the literal prefix it is anchored on.
        "http://app.example.test/admin/",
        "http://app.example.test/public",
        "http://app.example.test/sitemap.xml",
    ]
    # "Disallow: /" declares nothing about any particular route and is dropped.
    assert all(route["url"] != "http://app.example.test/" for route in routes)
    assert issues == []


def test_hint_routes_keep_query_names_and_never_their_values():
    """A declared query becomes a shape: names, order and multiplicity, no values.

    Ordinary values (`code`, `customer_id`) and percent-encoded names (`%74oken`) both
    slipped past the receipt scrubber, which only recognises secret-looking names.
    """
    from api.capabilities.hint_files import ingest_hint_documents

    routes = ingest_hint_documents(
        [(
            "http://app.example.test/llms.txt",
            b"Try http://app.example.test/callback?token=Ab9cD27e&code=Ab9cD27e"
            b" and /orders?customer_id=41&customer_id=42&%74oken=Ab9cD27e&flag\n",
            "text/plain",
        )],
        origin="http://app.example.test",
    )

    urls = [route["url"] for route in routes]
    assert "http://app.example.test/callback?token=&code=" in urls
    assert "http://app.example.test/orders?customer_id=&customer_id=&token=&flag=" in urls
    assert not any("Ab9cD27e" in url or "=41" in url or "=42" in url for url in urls)


def test_a_single_page_shell_is_not_a_published_hint_document():
    """A 200 for /llms.txt is usually the SPA catch-all, not a description.

    Juice Shop answers /llms.txt and /sitemap.xml with its own shell at an
    identical byte length. Mining that markup would invent declared routes.
    """
    from api.capabilities.hint_files import ingest_hint_documents

    issues = []
    routes = ingest_hint_documents(
        [(
            "http://app.example.test/llms.txt",
            b"<!DOCTYPE html><html><head><title>Shop</title></head>"
            b"<body><a href=\"/invented\">x</a></body></html>",
            "text/html",
        )],
        origin="http://app.example.test",
        issues=issues,
    )

    assert routes == []
    assert issues == ["hint_document_is_markup:llms.txt"]


def test_hint_documents_never_declare_another_origin():
    from api.capabilities.hint_files import ingest_hint_documents

    routes = ingest_hint_documents(
        [(
            "https://app.example.test/llms.txt",
            b"# Docs\n- [Tools](https://app.example.test/tools/)\n"
            b"- [Source](https://github.example/other)\n"
            b"Also /api/v1/tax?country=US and https://evil.example/x\n",
            "text/markdown",
        )],
        origin="https://app.example.test",
        issues=[],
    )

    urls = {route["url"] for route in routes}
    assert "https://app.example.test/tools/" in urls
    assert "https://app.example.test/api/v1/tax?country=" in urls
    assert not any("github.example" in url or "evil.example" in url for url in urls)


def test_a_route_that_moved_somewhere_of_its_own_is_not_absent():
    """A destination specific to one path says something about that path.

    The first version of this filter reduced every non-path-preserving redirect
    to "some redirect", so a control forwarding to /login and a real
    /admin -> /admin/login collided and the real route was deleted from the
    surface before anything could test it.
    """
    from api.scan.negative_control import negative_control_entries

    controls = negative_control_entries(3, seed="surface-test")
    observations = [
        {
            "kind": "content_discovery",
            "url": f"https://apex.example.test/{entry}",
            "status": 302,
            "length": 0,
            "redirect_location": "https://apex.example.test/login",
        }
        for entry in controls
    ] + [{
        "kind": "content_discovery",
        "url": "https://apex.example.test/admin",
        "status": 302,
        "length": 0,
        "redirect_location": "https://apex.example.test/admin/login",
    }]

    assert _content_paths(_apex_surface(observations)) == ["/admin"]


def test_equal_status_and_length_is_not_proof_of_the_same_page():
    """Content discovery reports a length, not the body it measured."""
    from api.scan.negative_control import negative_control_entries

    controls = negative_control_entries(3, seed="surface-test")
    observations = [
        {"kind": "content_discovery", "url": f"https://apex.example.test/{entry}",
         "status": 200, "length": 10, "redirect_location": None}
        for entry in controls
    ] + [{
        "kind": "content_discovery", "url": "https://apex.example.test/report",
        "status": 200, "length": 10, "redirect_location": None,
    }]

    assert _content_paths(_apex_surface(observations)) == ["/report"]


def test_one_disagreeing_control_does_not_establish_a_rule():
    """Two absent paths must answer alike before it is a server-wide rewrite."""
    from api.scan.negative_control import negative_control_entries

    controls = negative_control_entries(3, seed="surface-test")
    observations = [
        # Only one control shows the rewrite; the others answer differently.
        _redirect_row(f"/{controls[0]}"),
        {"kind": "content_discovery", "url": f"https://apex.example.test/{controls[1]}",
         "status": 404, "length": 12, "redirect_location": None},
        _redirect_row("/admin"),
    ]

    assert _content_paths(_apex_surface(observations)) == ["/admin"]


def test_another_origins_controls_never_classify_this_origin():
    from api.scan.negative_control import indistinguishable_from_absent, negative_control_entries

    controls = negative_control_entries(3, seed="surface-test")
    observations = [
        {"kind": "content_discovery", "url": f"https://other.test/{entry}", "status": 301,
         "length": 0, "redirect_location": f"https://www.other.test/{entry}"}
        for entry in controls
    ] + [_redirect_row("/admin")]

    assert indistinguishable_from_absent(observations) == frozenset()


def test_a_path_that_merely_looks_like_a_control_is_not_one():
    """Only the exact generated shape counts as our own measurement."""
    from api.scan.negative_control import is_negative_control_url

    assert not is_negative_control_url(
        "https://apex.example.test/.shakerscan-absent-not-a-digest"
    )
    assert is_negative_control_url(
        "https://apex.example.test/.shakerscan-absent-0123456789abcdef"
    )


def test_one_malformed_hint_reference_does_not_end_the_ingestion():
    """A reference is written by the target, so it can be anything at all.

    A single unparsable link raised out of the whole ingester, which shares its
    action with OpenAPI specification parsing, so one bad line in llms.txt could
    lose every declaration the action had already collected.
    """
    from api.capabilities.hint_files import ingest_hint_documents

    issues: list[str] = []
    routes = ingest_hint_documents(
        [(
            "https://app.example.test/llms.txt",
            b"# Documentation\n- [Good](/api/orders?id=123)\n"
            b"- [Broken](https://[broken/path)\n- [Worse](http://[::1x)\n",
            "text/markdown",
        )],
        origin="https://app.example.test",
        issues=issues,
    )

    assert [route["url"] for route in routes] == [
        "https://app.example.test/api/orders?id=",
    ]
    assert issues == ["hint_reference_unparsable:llms.txt:2"]
    # The diagnostic is a bounded class and a count; it never quotes the document.
    assert all("broken" not in issue and "::1" not in issue for issue in issues)


def _parsed_content_row(raw_request, raw_location, *, status=301, length=0):
    """Build the observation exactly as the ffuf projection emits it."""
    import agent_tools
    from scanner_tools.url_redaction import redact_url

    return {
        "kind": "content_discovery",
        "url": redact_url(raw_request, max_length=2_000),
        "status": status,
        "length": length,
        "redirect_location": redact_url(raw_location, max_length=2_000),
        "redirect_preserves_request_target": agent_tools._redirect_preserves_request_target(
            raw_request, raw_location,
        ),
    }


def test_redaction_cannot_make_a_route_specific_redirect_look_like_a_rewrite():
    """Redaction is not injective, so the comparison cannot be made after it.

    The projection strips the fragment outright and collapses every query value
    and secret-shaped path segment to a single marker. Judged on those strings,
    /report?mode=summary -> /report?mode=restricted and /admin ->
    /admin#/admin/users both look like the controls' origin-only rewrite, and
    both real routes were deleted from the endpoint manifest.
    """
    from api.scan.negative_control import (
        indistinguishable_from_absent,
        negative_control_entries,
    )

    controls = negative_control_entries(3, seed="surface-test")
    observations = [
        _parsed_content_row(
            f"https://apex.example.test/{entry}",
            f"https://www.apex.example.test/{entry}",
        )
        for entry in controls
    ] + [
        # A: origin AND query value change.
        _parsed_content_row(
            "https://apex.example.test/report?mode=summary",
            "https://www.apex.example.test/report?mode=restricted",
        ),
        # B: the destination adds a client-routing fragment.
        _parsed_content_row(
            "https://apex.example.test/admin",
            "https://www.apex.example.test/admin#/admin/users",
        ),
        # C: a secret-shaped path segment changes.
        _parsed_content_row(
            f"https://apex.example.test/reset/{'A' * 32}",
            f"https://www.apex.example.test/reset/{'B' * 32}",
        ),
        # D: a genuine origin-only move, which must still be recognised.
        _parsed_content_row(
            "https://apex.example.test/graphql",
            "https://www.apex.example.test/graphql",
        ),
    ]

    suppressed = indistinguishable_from_absent(observations)

    assert not any("/report" in url for url in suppressed)
    assert not any("/admin" in url for url in suppressed)
    assert not any("/reset/" in url for url in suppressed)
    assert suppressed == frozenset({"https://apex.example.test/graphql"})


def test_an_observation_without_the_producer_fact_claims_nothing():
    """The fact is decided before redaction; absent it, make no claim."""
    from api.scan.negative_control import (
        indistinguishable_from_absent,
        negative_control_entries,
    )

    controls = negative_control_entries(3, seed="surface-test")
    rows = [_redirect_row(f"/{entry}") for entry in controls] + [_redirect_row("/admin")]
    for row in rows:
        row.pop("redirect_preserves_request_target")

    assert indistinguishable_from_absent(rows) == frozenset()
