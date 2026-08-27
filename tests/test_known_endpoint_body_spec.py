"""A seeded endpoint's body spec must not end up inside its URL.

`AGENTS.md` documents the seed format as `POST /api/v1/search json:{"query":"test"}`.
`_known_endpoint_url` split only on the first whitespace, so everything after the path -- including
the JSON body -- stayed glued to the URL. Every seeded non-GET endpoint therefore carried a
canonical path like `/rest/user/login json:{"email":...}`, which matches no real route: it breaks
route dedupe, coverage attribution and any later comparison against an observed endpoint. On the
live database 192 of the seeded non-GET endpoints were stored that way.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scanner"))

from scan.surface_manifest import _known_endpoint_url  # noqa: E402

ORIGIN = "https://target.test"


def test_a_json_body_spec_is_parsed_off_the_path():
    parsed = _known_endpoint_url('POST /rest/user/login json:{"email":"a","password":"b"}', origin=ORIGIN)
    assert parsed is not None
    method, url = parsed[0], parsed[1]
    assert method == "POST"
    assert url == "https://target.test/rest/user/login", "the body must not remain in the URL"


def test_the_body_fields_and_content_type_are_recovered():
    parsed = _known_endpoint_url('POST /api/search json:{"query":"test","page":1}', origin=ORIGIN)
    assert parsed is not None and len(parsed) == 4
    _, _, content_type, body_schema = parsed
    assert content_type == "application/json"
    assert sorted(body_schema) == ["page", "query"]


def test_a_plain_endpoint_is_unchanged():
    parsed = _known_endpoint_url("GET /api/v1/users?id=1&name=test", origin=ORIGIN)
    assert parsed[:2] == ("GET", "https://target.test/api/v1/users?id=1&name=test")
    assert parsed[2] is None and parsed[3] is None


def test_a_method_less_seed_still_defaults_to_get():
    assert _known_endpoint_url("/api/health", origin=ORIGIN)[:2] == (
        "GET", "https://target.test/api/health")


def test_malformed_body_json_does_not_poison_the_path():
    # A body we cannot parse is dropped; keeping it in the URL is what produced an unroutable path.
    parsed = _known_endpoint_url('POST /api/thing json:{not valid', origin=ORIGIN)
    assert parsed[1] == "https://target.test/api/thing"
    assert parsed[3] is None


def test_a_non_object_body_yields_no_field_names():
    parsed = _known_endpoint_url('POST /api/thing json:[1,2,3]', origin=ORIGIN)
    assert parsed[1] == "https://target.test/api/thing"
    assert parsed[2] == "application/json"
    assert parsed[3] is None, "only an object body has named fields"


def test_query_and_body_can_coexist():
    parsed = _known_endpoint_url('POST /api/search?page=2 json:{"query":"x"}', origin=ORIGIN)
    assert parsed[1] == "https://target.test/api/search?page=2"
    assert parsed[3] == ["query"]


# --- The parsed shape must survive into the durable manifest entry ----------------------------
# Parsing the body off the path is only half the fix: `EndpointRecord` kept a content fingerprint
# and nothing else, so the field names were discarded one layer later and `body_field_names` was
# empty for every endpoint ever recorded (0 of 9,229 on the live database). The fingerprint makes
# two body shapes distinguishable but tells a later stage nothing about what to test.

def test_the_endpoint_record_keeps_the_body_field_names():
    from manifests import normalize_endpoint

    record = normalize_endpoint(
        method="POST", url="https://target.test/rest/user/login", source="known_endpoints",
        content_type="application/json", body_schema=["email", "password"],
    )
    assert record.content_type == "application/json"
    assert record.body_field_names == ("email", "password")
    public = record.public_dict()
    assert public["body_field_names"] == ["email", "password"]
    assert public["content_type"] == "application/json"


def test_the_manifest_entry_carries_the_body_shape():
    from manifests import normalize_endpoint
    from scan.work_manifests import endpoint_entry_from_public_record

    record = normalize_endpoint(
        method="POST", url="https://target.test/api/search", source="known_endpoints",
        content_type="application/json", body_schema={"query": "x", "page": 1},
    )
    entry = endpoint_entry_from_public_record(
        record.public_dict(), target_binding_digest="d" * 64, source_tool="known_endpoints")
    assert entry["body_field_names"] == ["page", "query"]
    assert entry["content_type"] == "application/json"


def test_an_endpoint_with_no_body_is_unchanged():
    from manifests import normalize_endpoint
    from scan.work_manifests import endpoint_entry_from_public_record

    record = normalize_endpoint(
        method="GET", url="https://target.test/api/users?id=1", source="web.crawl")
    entry = endpoint_entry_from_public_record(
        record.public_dict(), target_binding_digest="d" * 64, source_tool="web.crawl")
    assert entry["body_field_names"] == []
    assert entry["content_type"] is None


def test_a_manifest_written_before_body_fields_existed_still_validates():
    # The keys are optional on read so durable manifests stored by an earlier build are not
    # rejected; only newly built entries carry the shape.
    from scan.work_manifests import _endpoint_entry, route_id

    digest = "d" * 64
    legacy = {
        "route_id": route_id(target_binding_digest=digest, method="GET", scheme="https",
                             host="target.test", port=443, canonical_path="/api/users",
                             query_parameter_names=[]),
        "method": "GET", "scheme": "https", "host": "target.test", "port": 443,
        "canonical_path": "/api/users", "query_parameter_names": [],
        "source_tool": "web.crawl", "discovery_depth": 1, "auth_lane": "anonymous",
        "selected_shard": None, "request_ref_ids": [],
    }
    normalized = _endpoint_entry(legacy, target_digest=digest)
    assert normalized["body_field_names"] == []
    assert normalized["content_type"] is None
