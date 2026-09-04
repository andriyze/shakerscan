from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from api.scan.manifest_store import (
    MIGRATION_NAME,
    PostgresScanManifestStore,
    SCAN_WORK_MANIFEST_SCHEMA_SQL,
    ScanManifestStoreError,
)
from api.scan.work_manifests import (
    execution_request_for_manifest_candidate,
    CANONICAL_NUCLEI_TEMPLATE_BUNDLE_COMMIT,
    CANONICAL_NUCLEI_TEMPLATE_BUNDLE_SHA256,
    CANONICAL_PASSIVE_NUCLEI_TEMPLATES,
    ScanWorkManifest,
    ScanWorkManifestError,
    ScanWorkManifestKind,
    ScanWorkManifestReference,
    build_candidate_manifest,
    build_canonical_passive_nuclei_template_manifest,
    build_canonical_scan_nuclei_template_manifest,
    build_canonical_nuclei_template_manifest,
    build_endpoint_manifest,
    build_request_candidate_manifest,
    build_request_manifest,
    build_template_manifest,
    canonical_nuclei_options_for_manifest,
    canonical_passive_nuclei_request_upper_bound,
    execution_url_for_endpoint,
    execution_url_for_manifest_candidate,
    execution_url_for_manifest_endpoint,
    unique_work_manifest_reference_dicts,
    work_manifest_references_in,
)


SCAN_ID = "40000000-0000-4000-8000-000000000001"
TARGET_DIGEST = "a" * 64


def _surface(*, query_keys=("page", "owner")):
    return {
        "schema_version": "endpoint-manifest/v1",
        "status": "complete",
        "reason": None,
        "endpoint_count": 1,
        "endpoints": [{
            "method": "GET",
            "scheme": "https",
            "host": "app.example.test",
            "port": 443,
            "normalized_path": "/api/orders/{int}",
            "concrete_path": "/api/orders/1",
            "query_keys": list(query_keys),
            "content_fingerprint": None,
            "source": "web.crawl",
            "sensitive_path_redacted": False,
        }],
        "producers": {},
        "persistence_errors": [],
    }


def _endpoint_manifest(**kwargs):
    return build_endpoint_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        surface_manifest=_surface(**kwargs),
        source_action_ids=("discover.web_crawl",),
        auth_lane="primary",
        selected_shard=2,
    )


def test_endpoint_manifest_freezes_complete_value_free_route_contract():
    manifest = _endpoint_manifest()
    entry = manifest.entries[0]

    assert manifest.kind is ScanWorkManifestKind.ENDPOINT
    assert manifest.content_schema == "endpoint-manifest/v2"
    assert entry["canonical_path"] == "/api/orders/{int}"
    assert entry["query_parameter_names"] == ("owner", "page")
    assert entry["source_tool"] == "web.crawl"
    assert entry["discovery_depth"] == 1
    assert entry["auth_lane"] == "primary"
    assert entry["selected_shard"] == 2
    assert len(entry["route_id"]) == 64
    assert execution_url_for_endpoint(entry) == (
        "https://app.example.test/api/orders/1?owner=1&page=1"
    )

    encoded = json.dumps(manifest.canonical_dict(), sort_keys=True)
    assert "concrete_path" not in encoded
    assert "query_value" not in encoded
    assert ScanWorkManifest.from_dict(manifest.canonical_dict()) == manifest
    assert ScanWorkManifestReference.from_dict(
        manifest.reference().canonical_dict()
    ) == manifest.reference()


def test_endpoint_manifest_preserves_route_specific_auth_lane():
    anonymous = _endpoint_manifest()
    route = anonymous.entries[0]["route_id"]

    manifest = build_endpoint_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        surface_manifest=_surface(),
        source_action_ids=("admission.surface",),
        auth_lane="anonymous",
        auth_lane_by_route={route: "secondary"},
        request_ref_ids_by_route={route: ("request-secondary-1",)},
    )

    assert manifest.entries[0]["auth_lane"] == "secondary"
    assert manifest.entries[0]["request_ref_ids"] == (
        "request-secondary-1",
    )


def test_endpoint_manifest_never_executes_a_public_redacted_path():
    surface = _surface()
    surface["endpoints"][0].update({
        "normalized_path": "/reset/<redacted>",
        "concrete_path": "/reset/<redacted>",
        "sensitive_path_redacted": True,
    })

    manifest = build_endpoint_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        surface_manifest=surface,
        source_action_ids=("admission.surface",),
    )

    assert manifest.entries == ()
    assert manifest.status == "partial"
    assert manifest.reason_code == "sensitive_paths_excluded:1"


def test_manifest_reference_extraction_accepts_only_canonical_nested_references():
    reference = _endpoint_manifest().reference()

    extracted = work_manifest_references_in({
        "target_manifest_ref": reference.canonical_dict(),
        "duplicate": [reference.canonical_dict()],
        "lookalike": {**reference.canonical_dict(), "entry_count": 99},
        "invalid": {"manifest_id": reference.manifest_id},
    })

    assert extracted == (
        reference,
        ScanWorkManifestReference.from_dict({
            **reference.canonical_dict(), "entry_count": 99,
        }),
    )
    assert unique_work_manifest_reference_dicts((
        {"first": reference.canonical_dict()},
        {"duplicate": reference.canonical_dict()},
    )) == (reference.canonical_dict(),)


def test_candidate_manifest_covers_every_parameter_and_marks_bounded_truncation():
    endpoint = _endpoint_manifest(query_keys=("a", "b", "c"))
    complete = build_candidate_manifest(
        endpoint,
        source_action_ids=("discover.candidates",),
        maximum=10,
    )
    partial = build_candidate_manifest(
        endpoint,
        source_action_ids=("discover.candidates",),
        maximum=2,
    )

    # Three query parameters plus one path-segment candidate from the fixture's /api/orders/{int}.
    assert {item["parameter_name"] for item in complete.entries} == {"a", "b", "c", "path_3"}
    assert list(complete.entries) == sorted(
        complete.entries,
        key=lambda item: (-item["score"], item["candidate_id"]),
    )
    assert len({item["candidate_id"] for item in complete.entries}) == 4
    query_entries = [e for e in complete.entries if e.get("parameter_location") != "path"]
    path_entries = [e for e in complete.entries if e.get("parameter_location") == "path"]
    assert all(item["family_hints"] == ("xss", "sqli") for item in query_entries)
    assert path_entries and all(item["family_hints"] == ("sqli",) for item in path_entries)
    assert all(item["ranking_rationale"] for item in complete.entries)
    assert partial.status == "partial"
    assert partial.reason_code == "candidate_limit_reached"
    assert len(partial.entries) == 2
    assert partial.entries == complete.entries[:2]


def test_candidate_ranking_is_semantic_recorded_and_observation_order_independent():
    surface = _surface(query_keys=("zzz", "search"))
    second = dict(surface["endpoints"][0])
    second.update({
        "normalized_path": "/api/users/{int}",
        "concrete_path": "/api/users/1",
        "query_keys": ["user_id"],
    })
    surface["endpoints"].append(second)
    first = build_endpoint_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        surface_manifest=surface,
        source_action_ids=("discover.web_crawl",),
    )
    surface["endpoints"].reverse()
    reversed_endpoint = build_endpoint_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        surface_manifest=surface,
        source_action_ids=("discover.web_crawl",),
    )

    ranked = build_candidate_manifest(
        first,
        source_action_ids=("discover.candidates",),
        maximum=3,
    )
    reranked = build_candidate_manifest(
        reversed_endpoint,
        source_action_ids=("discover.candidates",),
        maximum=3,
    )

    assert ranked.manifest_digest == reranked.manifest_digest
    assert ranked.entries[0]["parameter_name"] == "search"
    assert ranked.entries[0]["score"] > ranked.entries[-1]["score"]
    assert ranked.entries[0]["ranking_rationale"][-2:] == (
        "xss_semantic_parameter",
        "sqli_semantic_parameter",
    )



def test_candidate_ranking_puts_transport_plumbing_and_cache_busters_last():
    """A websocket handshake's timestamp nonce is not application input.

    A thorough scan spent its SQL injection verifier on ``/socket.io/?t=1`` ahead of the
    search query because both were observed GET parameters. Plumbing stays in the manifest
    (nothing is silently excluded) but ranks below every real parameter.
    """
    surface = _surface(query_keys=("q",))
    handshake = dict(surface["endpoints"][0])
    handshake.update({
        "normalized_path": "/socket.io/",
        "concrete_path": "/socket.io/",
        "query_keys": ["t", "EIO", "transport"],
    })
    busted = dict(surface["endpoints"][0])
    busted.update({
        "normalized_path": "/api/products",
        "concrete_path": "/api/products",
        "query_keys": ["ts", "category"],
    })
    surface["endpoints"].extend([handshake, busted])
    endpoints = build_endpoint_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        surface_manifest=surface,
        source_action_ids=("discover.web_crawl",),
    )

    ranked = build_candidate_manifest(
        endpoints, source_action_ids=("discover.candidates",), maximum=20,
    )

    order = [(entry["canonical_path"], entry["parameter_name"]) for entry in ranked.entries]
    # /api/orders/{int} now also yields a path-segment candidate, so seven candidates remain.
    assert len(order) == 7, "plumbing candidates remain in the manifest"
    orders_path = surface["endpoints"][0]["normalized_path"]
    real = {(orders_path, "q"), ("/api/products", "category"), (orders_path, "path_3")}
    assert set(order[:3]) == real, order
    plumbing = [entry for entry in ranked.entries if entry["canonical_path"] == "/socket.io/"]
    assert plumbing and all(
        "transport_plumbing_route" in entry["ranking_rationale"] for entry in plumbing
    )
    nonce = next(entry for entry in ranked.entries if entry["parameter_name"] == "ts")
    assert "cache_buster_parameter" in nonce["ranking_rationale"]
    assert nonce["score"] < min(
        entry["score"] for entry in ranked.entries if (entry["canonical_path"], entry["parameter_name"]) in real
    )

def test_manifest_execution_selects_exact_endpoint_and_candidate_index():
    endpoint = _endpoint_manifest(query_keys=("a", "b"))
    candidates = build_candidate_manifest(
        endpoint,
        source_action_ids=("discover.candidates",),
        maximum=10,
    )

    assert execution_url_for_manifest_endpoint(endpoint, 0) == (
        "https://app.example.test/api/orders/1?a=1&b=1"
    )
    query_index = next(
        i for i, c in enumerate(candidates.entries)
        if c.get("parameter_location") != "path"
    )
    selected_parameter = candidates.entries[query_index]["parameter_name"]
    assert execution_url_for_manifest_candidate(endpoint, candidates, query_index) == (
        f"https://app.example.test/api/orders/1?{selected_parameter}=1"
    )
    # The path-segment candidate resolves to the sqlmap marker at its segment.
    path_index = next(
        i for i, c in enumerate(candidates.entries)
        if c.get("parameter_location") == "path"
    )
    assert execution_url_for_manifest_candidate(endpoint, candidates, path_index) == (
        "https://app.example.test/api/orders/1*"
    )
    with pytest.raises(ScanWorkManifestError, match="outside immutable content"):
        execution_url_for_manifest_candidate(endpoint, candidates, len(candidates.entries))


def test_request_and_template_manifests_are_complete_bounded_and_deterministic():
    route = _endpoint_manifest().entries[0]["route_id"]
    request = build_request_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        source_action_ids=("inputs.collection_00",),
        requests=({
            "request_ref_id": "request-1",
            "route_id": route,
            "method": "GET",
            "auth_lane": "primary",
            "selected_shard": None,
            "safe_method": True,
            "body_schema_digest": None,
        },),
    )
    templates = build_template_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        source_action_ids=("active.templates",),
        templates=({
            "template_id": f"template-{index}",
            "template_digest": f"{index:064x}",
            "risk": "safe_active",
            "tags": ["cve"],
        } for index in range(5)),
        batch_size=2,
    )

    assert request.entries[0]["request_ref_id"] == "request-1"
    assert [item["batch_index"] for item in templates.entries] == [0, 0, 1, 1, 2]
    assert len(templates.entries) == 5


def test_request_candidate_manifest_authorizes_only_private_state_changing_refs():
    route = _endpoint_manifest().entries[0]["route_id"]
    requests = build_request_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        source_action_ids=("inputs.collection_00",),
        requests=(
            {
                "request_ref_id": "safe-read",
                "route_id": route,
                "method": "GET",
                "auth_lane": "primary",
                "selected_shard": None,
                "safe_method": True,
                "body_schema_digest": None,
            },
            {
                "request_ref_id": "create-order",
                "route_id": "b" * 64,
                "method": "POST",
                "auth_lane": "primary",
                "selected_shard": 3,
                "safe_method": False,
                "body_schema_digest": "c" * 64,
                "content_type": "application/json",
                "body_field_names": ["productId", "quantity"],
                "selection_digest": "d" * 64,
            },
        ),
    )

    candidates = build_request_candidate_manifest(
        (requests,),
        source_action_ids=("inputs.collection_00",),
        maximum=10,
    )

    assert candidates.content_schema == "request-candidate-manifest/v2"
    assert len(candidates.entries) == 2
    entry = candidates.entries[0]
    assert entry["request_ref_id"] == "create-order"
    assert entry["method"] == "POST"
    assert entry["request_class"] == "confirmed_mutation"
    assert entry["field_path"] in {"productId", "quantity"}
    assert entry["family_hints"] == ("xss", "sqli")
    encoded = json.dumps(candidates.canonical_dict(), sort_keys=True)
    assert "safe-read" not in encoded
    assert "https://" not in encoded
    assert "body_value" not in encoded
    assert ScanWorkManifest.from_dict(candidates.canonical_dict()) == candidates


def test_canonical_nuclei_pack_freezes_pinned_bundle_filters_and_action_authority():
    manifest = build_canonical_nuclei_template_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
    )

    assert manifest.kind.value == "template"
    assert manifest.status == "complete"
    assert len(manifest.entries) == 1
    assert canonical_nuclei_options_for_manifest(
        manifest, action_id="active.templates.00042",
    ) == {
        "severity": "high,critical",
        "tags": "exposure,misconfig,auth-bypass,default-login",
        "template_pack_digest": manifest.entries[0]["template_digest"],
    }
    with pytest.raises(ScanWorkManifestError, match="does not authorize"):
        canonical_nuclei_options_for_manifest(
            manifest, action_id="verify.xss",
        )


def test_passive_nuclei_pack_freezes_exact_get_only_template_allowlist():
    manifest = build_canonical_passive_nuclei_template_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
    )

    assert manifest.status == "complete"
    assert {entry["template_id"] for entry in manifest.entries} == {
        row[0] for row in CANONICAL_PASSIVE_NUCLEI_TEMPLATES
    }
    assert all(entry["risk"] == "passive" for entry in manifest.entries)
    assert all("method-get" in entry["tags"] for entry in manifest.entries)
    options = canonical_nuclei_options_for_manifest(
        manifest, action_id="passive.templates",
    )
    assert set(options["template_ids"].split(",")) == {
        row[0] for row in CANONICAL_PASSIVE_NUCLEI_TEMPLATES
    }
    assert options["template_request_cost_upper_bound"] == 7
    assert options["template_request_cost_upper_bound"] == (
        canonical_passive_nuclei_request_upper_bound()
    )
    assert "tags" not in options


def test_combined_nuclei_manifest_authorizes_passive_and_active_packs_separately():
    manifest = build_canonical_scan_nuclei_template_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        include_active=True,
    )

    passive = canonical_nuclei_options_for_manifest(
        manifest, action_id="passive.templates.00001",
    )
    active = canonical_nuclei_options_for_manifest(
        manifest, action_id="active.templates.00001",
    )
    assert passive["template_request_cost_upper_bound"] == 7
    assert active["severity"] == "high,critical"
    assert active["tags"] == "exposure,misconfig,auth-bypass,default-login"


def test_canonical_nuclei_pack_matches_the_image_pinned_template_bundle():
    dockerfile = (Path(__file__).parents[1] / "scanner" / "Dockerfile").read_text()

    assert (
        f"ARG NUCLEI_TEMPLATES_COMMIT={CANONICAL_NUCLEI_TEMPLATE_BUNDLE_COMMIT}"
        in dockerfile
    )
    assert (
        f"ARG NUCLEI_TEMPLATES_SHA256={CANONICAL_NUCLEI_TEMPLATE_BUNDLE_SHA256}"
        in dockerfile
    )
    for _template_id, digest, _requests, _severity, _tags in (
        CANONICAL_PASSIVE_NUCLEI_TEMPLATES
    ):
        assert digest in dockerfile


def test_manifests_reject_secret_fields_and_sensitive_concrete_paths():
    route = _endpoint_manifest().entries[0]["route_id"]
    with pytest.raises(ScanWorkManifestError, match="secret values"):
        build_request_manifest(
            scan_id=SCAN_ID,
            target_binding_digest=TARGET_DIGEST,
            source_action_ids=("inputs.collection_00",),
            requests=({
                "request_ref_id": "request-1",
                "route_id": route,
                "method": "GET",
                "auth_lane": "primary",
                "selected_shard": None,
                "safe_method": True,
                "body_schema_digest": None,
                "authorization": "Bearer should-never-persist",
            },),
        )

    surface = _surface()
    surface["endpoints"][0]["normalized_path"] = "/reset/secret_abcdefghijklmnopqrstuvwxyz"
    with pytest.raises(ScanWorkManifestError, match="sensitive path"):
        build_endpoint_manifest(
            scan_id=SCAN_ID,
            target_binding_digest=TARGET_DIGEST,
            surface_manifest=surface,
            source_action_ids=("discover.web_crawl",),
        )


class FakeConn:
    def __init__(self):
        self.rows = {}
        self.executed = []

    async def execute(self, query, *args):
        self.executed.append((query, args))

    async def fetchrow(self, query, *args):
        if query.lstrip().startswith("INSERT INTO scan_work_manifests"):
            manifest_id = args[0]
            content = args[11]
            existing = self.rows.get(manifest_id)
            if existing is not None and existing != content:
                return None
            self.rows[manifest_id] = content
            return {"content_json": content}
        if "FROM scan_work_manifests" in query:
            return (
                {"content_json": self.rows[args[0]]}
                if args[0] in self.rows else None
            )
        raise AssertionError(query)

    async def fetch(self, query, *args):
        assert "FROM scan_work_manifests" in query
        return [{"content_json": value} for value in self.rows.values()]


def test_postgres_manifest_store_round_trips_content_and_rejects_conflicts():
    manifest = _endpoint_manifest()
    conn = FakeConn()
    store = PostgresScanManifestStore()
    first = asyncio.run(store.persist(conn, manifest=manifest))
    second = asyncio.run(store.persist(conn, manifest=manifest))
    loaded = asyncio.run(store.load(
        conn,
        manifest_id=manifest.manifest_id,
        scan_id=SCAN_ID,
        expected_kind="endpoint",
        expected_digest=manifest.manifest_digest,
        expected_target_binding_digest=TARGET_DIGEST,
    ))

    assert first == second == manifest.reference()
    assert loaded == manifest
    assert asyncio.run(store.list_references(conn, scan_id=SCAN_ID)) == (
        manifest.reference(),
    )

    conn.rows[next(iter(conn.rows))] = json.dumps({"tampered": True})
    with pytest.raises(ScanManifestStoreError, match="invalid"):
        asyncio.run(store.load(
            conn, manifest_id=manifest.manifest_id, scan_id=SCAN_ID,
        ))


def test_work_manifest_schema_is_available_to_fresh_and_upgraded_databases():
    conn = FakeConn()
    asyncio.run(PostgresScanManifestStore().ensure_schema(conn))
    assert conn.executed == [(SCAN_WORK_MANIFEST_SCHEMA_SQL, ())]
    assert MIGRATION_NAME in SCAN_WORK_MANIFEST_SCHEMA_SQL
    for path in (
        Path("db/init.sql"),
        Path("db/repairs/2026-08-23_v2_scan_work_manifests.sql"),
    ):
        source = path.read_text(encoding="utf-8")
        assert "scan_work_manifests" in source
        assert "target_binding_digest" in source
        assert "manifest_digest" in source
        assert "content_json" in source


def test_mutating_work_is_counted_from_the_entry_class_not_the_input_field():
    """A manifest entry has request_class; safe_method belongs to the raw row.

    build_request_manifest pops safe_method and translates it into
    request_class, and _request_entry rejects any entry carrying an unexpected
    field. api/worker.py counted mutating child work with entry["safe_method"]
    and raised KeyError on every parallel child that had request entries.
    """
    from api.scan.work_manifests import (
        MUTATING_REQUEST_CLASSES, REQUEST_CLASSES, entry_is_mutating,
    )

    assert MUTATING_REQUEST_CLASSES <= REQUEST_CLASSES
    assert entry_is_mutating({"request_class": "confirmed_mutation"})
    assert not entry_is_mutating({"request_class": "safe_read"})
    assert not entry_is_mutating({"request_class": "safe_authentication"})
    # An entry never carries safe_method, so a counter reading it is a bug.
    assert not entry_is_mutating({"safe_method": False})


def test_request_manifest_entries_never_carry_safe_method():
    """Guards the schema the counter depends on."""
    import api.scan.work_manifests as wm

    route = _endpoint_manifest().entries[0]["route_id"]
    manifest = wm.build_request_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=TARGET_DIGEST,
        source_action_ids=("inputs.collection_00",),
        requests=[
            {
                "request_ref_id": "create-order",
                "route_id": route,
                "method": "POST",
                "auth_lane": "primary",
                "selected_shard": None,
                "body_schema_digest": None,
                "safe_method": False,
            },
            {
                "request_ref_id": "get-health",
                "route_id": route,
                "method": "GET",
                "auth_lane": "primary",
                "selected_shard": None,
                "body_schema_digest": None,
                "safe_method": True,
            },
        ],
        maximum=10,
    )
    for entry in manifest.entries:
        assert "safe_method" not in entry
        assert entry["request_class"] in wm.REQUEST_CLASSES
    assert sum(wm.entry_is_mutating(entry) for entry in manifest.entries) == 1


def test_templated_path_segments_become_sqli_only_candidates():
    """A path parameter is a value the query never names; it is a first-class SQLi site.

    Path-templated endpoints (/api/orders/{int}) declare no query or body input, so before this
    they produced no candidate at all. They are read with a GET, so a path candidate needs no
    state-changing authority and never reflects into HTML — SQLi only.
    """
    surface = {
        "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
        "endpoints": [{
            "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
            "normalized_path": "/api/orders/{int}", "concrete_path": "/api/orders/1",
            "query_keys": [], "source": "web.spec_ingest",
        }, {
            "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
            "normalized_path": "/rest/products/{int}/reviews",
            "concrete_path": "/rest/products/1/reviews", "query_keys": [], "source": "web.crawl",
        }],
    }
    endpoints = build_endpoint_manifest(
        scan_id=SCAN_ID, target_binding_digest=TARGET_DIGEST,
        surface_manifest=surface, source_action_ids=("discover.spec",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.candidates",), maximum=20,
    )
    path_candidates = [c for c in candidates.entries if c.get("parameter_location") == "path"]
    assert {c["canonical_path"] for c in path_candidates} == {
        "/api/orders/{int}", "/rest/products/{int}/reviews",
    }
    for candidate in path_candidates:
        assert candidate["family_hints"] == ("sqli",)
        assert "path_id_injection_point" in candidate["ranking_rationale"]
        index = candidates.entries.index(candidate)
        resolved = execution_request_for_manifest_candidate(endpoints, candidates, index)
        assert resolved["path_injection"] is True
        assert resolved["method"] == "GET"
        assert "1*" in resolved["url"]
    # The marker sits on the exact templated segment, not the tail.
    reviews = next(c for c in path_candidates if "reviews" in c["canonical_path"])
    reviews_url = execution_request_for_manifest_candidate(
        endpoints, candidates, candidates.entries.index(reviews),
    )["url"]
    assert reviews_url == "https://app.example.test/rest/products/1*/reviews"


def test_path_candidate_identity_and_field_tampering_are_rejected():
    surface = {
        "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
        "endpoints": [{
            "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
            "normalized_path": "/api/orders/{int}", "concrete_path": "/api/orders/1",
            "query_keys": [], "source": "web.crawl",
        }],
    }
    endpoints = build_endpoint_manifest(
        scan_id=SCAN_ID, target_binding_digest=TARGET_DIGEST,
        surface_manifest=surface, source_action_ids=("discover.spec",),
    )
    candidates = build_candidate_manifest(
        endpoints, source_action_ids=("discover.candidates",), maximum=20,
    )
    path = next(c for c in candidates.entries if c.get("parameter_location") == "path")
    # Pointing the candidate at a literal (non-templated) segment is rejected.
    tampered = {**path, "path_segment_index": 1}
    with pytest.raises(ScanWorkManifestError):
        ScanWorkManifest(
            scan_id=SCAN_ID, kind=ScanWorkManifestKind.CANDIDATE,
            target_binding_digest=TARGET_DIGEST, source_action_ids=("x",),
            entries=(tampered,), status="complete", reason_code=None,
        )


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD"])
def test_path_injection_never_invents_get_for_other_methods(method):
    surface = _surface(query_keys=())
    surface["endpoints"][0]["method"] = method
    endpoint = build_endpoint_manifest(scan_id=SCAN_ID, target_binding_digest=TARGET_DIGEST,
                                       surface_manifest=surface, source_action_ids=("discover.spec",))
    candidates = build_candidate_manifest(endpoint, source_action_ids=("discover.spec",), maximum=100,
                                           allow_state_changing_http=True)
    assert not candidates.entries
    assert candidates.status == "partial"
    assert candidates.reason_code == "path_operation_not_supported"


def test_legacy_non_get_path_candidate_is_rejected_at_execution():
    from dataclasses import replace
    surface = _surface(query_keys=())
    endpoint = build_endpoint_manifest(scan_id=SCAN_ID, target_binding_digest=TARGET_DIGEST,
                                       surface_manifest=surface, source_action_ids=("discover.spec",))
    candidates = build_candidate_manifest(endpoint, source_action_ids=("discover.spec",), maximum=100)
    # An old persisted candidate's method cannot silently become GET at either resolver.
    candidate = {**dict(candidates.entries[0]), "method": "POST"}
    legacy = object.__new__(ScanWorkManifest)
    for name, value in candidates.__dict__.items():
        object.__setattr__(legacy, name, value)
    object.__setattr__(legacy, "entries", (candidate,))
    with pytest.raises(ScanWorkManifestError, match="GET"):
        execution_request_for_manifest_candidate(endpoint, legacy, 0)
    with pytest.raises(ScanWorkManifestError, match="identity"):
        execution_url_for_manifest_candidate(endpoint, legacy, 0)
