"""Exercise routing helpers and the actual producer/consumer adapter functions.

The adapter definitions are extracted from the production module to avoid loading
unrelated subprocess/scanner integrations. No network request or proof validator
runs here: these are isolated routing tests, not end-to-end verification acceptance.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import re
import sys
from typing import Any
import urllib.parse
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanner"))

from scanner_tools.authz_replay_routing import (
    prioritize_replay_candidates,
    select_replay_identifier,
)

FUNCTIONS = {
    "_replace_discovered_consumer_id", "_resource_replay_candidates",
    "_safe_scalar_id", "_resource_identifier_name", "_is_resource_identifier_name",
    "_is_resource_placeholder_segment", "_is_probable_id_param",
    "_path_with_resource_id", "_collection_item_base_path",
}
CONSTANTS = {"BOLA_RESOURCE_ID_KEYS", "QUERY_ID_PARAM_EXCLUSIONS"}


@pytest.fixture(scope="module")
def adapters():
    path = ROOT / "scanner/scanner_tools/access_control_checks.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    selected = []
    found = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in FUNCTIONS:
            selected.append(node)
            found.add(node.name)
        elif isinstance(node, ast.Assign):
            names = {target.id for target in node.targets if isinstance(target, ast.Name)}
            if names & CONSTANTS:
                selected.append(node)
                found.update(names & CONSTANTS)
    assert found == FUNCTIONS | CONSTANTS, "Production routing definitions changed; update this test."
    namespace = {
        "__name__": "scanner_tools._authz_routing_test",
        "__package__": "scanner_tools",
        "Any": Any, "re": re, "urllib": urllib,
        "parse_qsl": parse_qsl, "urlencode": urlencode,
        "urlsplit": urlsplit, "urlunsplit": urlunsplit,
    }
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


@pytest.mark.parametrize("path,key,expected", [
    ("/api/tenants/7/invoices/8", "id", "/api/tenants/7/invoices/101"),
    ("/api/tenants/7/invoices/8", "invoice_id", "/api/tenants/7/invoices/101"),
    ("/api/tenants/7/invoices/8", "tenantId", "/api/tenants/101/invoices/8"),
    ("/api/tenants/7/invoices/8", "object_id", "/api/tenants/7/invoices/101"),
    ("/api/tenants/7/invoices/8", "uuid", "/api/tenants/7/invoices/101"),
    ("/api/tenants/7/invoices/8", "uid", "/api/tenants/7/invoices/101"),
    ("/api/tenants/{tenantId}/invoices/{invoiceId}", "invoiceId",
     "/api/tenants/{tenantId}/invoices/101"),
    ("/api/tenants/{tenantId}/invoices/{invoiceId}", "tenantId",
     "/api/tenants/101/invoices/{invoiceId}"),
    ("/api/tenants/7/invoices?id=8&expand=lines", "id",
     "/api/tenants/7/invoices?id=101&expand=lines"),
    ("/api/tenants/7/invoices?invoiceId=8&expand=lines", "invoiceId",
     "/api/tenants/7/invoices?invoiceId=101&expand=lines"),
    ("/api/invoices/8?owner_id=7", "id", "/api/invoices/101?owner_id=7"),
    ("/api/invoices/8?owner_id=7", "owner_id", "/api/invoices/8?owner_id=101"),
    ("/api/invoices?tenantId=7&id=8", "id", "/api/invoices?tenantId=7&id=101"),
    ("/api/invoices?owner_id=7&invoiceId=8", "invoice_id",
     "/api/invoices?owner_id=7&invoiceId=101"),
    ("/api/invoices/8?invoiceId=7", "invoice_id", "/api/invoices/8?invoiceId=101"),
    ("/api/companies/7/invoices/8", "companyId", "/api/companies/101/invoices/8"),
    ("/api/addresses/7/invoices/8", "address_id", "/api/addresses/101/invoices/8"),
    ("/api/tenants/7/invoices/8/", "id", "/api/tenants/7/invoices/101/"),
])
def test_only_intended_identifier_changes(adapters, path, key, expected):
    result = adapters["_replace_discovered_consumer_id"](
        "https://app.test" + path, "101", object_id_key=key,
    )
    assert result["url"] == "https://app.test" + expected
    assert result["custom_endpoint"] == "GET " + expected
    assert result["method"] == "GET"


@pytest.mark.parametrize("value", ["8", "507f1f77bcf86cd799439011", "550e8400-e29b-41d4-a716-446655440000", "object_123456"])
def test_supported_child_identifier_shapes_preserve_parent(adapters, value):
    result = adapters["_replace_discovered_consumer_id"](
        "https://app.test/api/tenants/7/invoices/" + value, "101",
    )
    assert result["url"] == "https://app.test/api/tenants/7/invoices/101"


@pytest.mark.parametrize("segment", ["{id}", ":id", "<id>", "$id", "%7Bid%7D", "{invoiceId}"])
def test_child_placeholders_preserve_parent(adapters, segment):
    result = adapters["_replace_discovered_consumer_id"](
        "https://app.test/api/tenants/7/invoices/" + segment, "101",
    )
    assert result["url"] == "https://app.test/api/tenants/7/invoices/101"


@pytest.mark.parametrize("url", [
    "https://app.test/api/invoices",
    "https://app.test/api/invoices?sessionId=8",
    "https://app.test/api/invoices?csrf_id=8",
    "https://app.test/api/invoices?tokenId=8",
    "https://app.test/api/invoices/8#fragment",
    "https://[broken/api/invoices/8",
])
def test_previous_ineligible_shapes_stay_ineligible(adapters, url):
    assert adapters["_replace_discovered_consumer_id"](url, "101") is None


def test_empty_reference_does_not_create_candidate(adapters):
    assert adapters["_replace_discovered_consumer_id"]("https://app.test/api/invoices/8", "") is None
    assert adapters["_resource_replay_candidates"]("https://app.test/api/invoices", {}) == []


def _candidates(adapters, producer="https://app.test/api/invoices", templates=(), key="id"):
    return adapters["_resource_replay_candidates"](
        producer, {"object_id": "101", "object_id_key": key},
        consumer_templates=list(templates),
    )


def test_related_consumer_wins_single_replay_budget(adapters):
    candidates = _candidates(adapters, templates=[
        "https://app.test/api/users/7", "https://app.test/api/invoices/8",
    ])
    assert candidates[0]["url"] == "https://app.test/api/invoices/101"
    assert candidates[0]["source"] == "discovered_consumer_template"
    assert any(row["url"] == "https://app.test/api/users/101" for row in candidates)


def test_related_route_beyond_old_five_template_cutoff_is_not_starved(adapters):
    distractions = [f"https://app.test/api/{name}/7" for name in
                    ("users", "projects", "cards", "vehicles", "reports", "baskets", "orders")]
    candidates = _candidates(adapters, templates=distractions + ["https://app.test/api/invoices/8"])
    assert candidates[0]["url"] == "https://app.test/api/invoices/101"
    assert candidates[0]["source"] == "discovered_consumer_template"
    assert len(candidates) == 6


def test_synthesized_related_path_beats_unrelated_observed_path(adapters):
    candidates = _candidates(adapters, templates=["https://app.test/api/users/7"])
    assert candidates[0]["url"] == "https://app.test/api/invoices/101"
    assert any(row["source"] == "discovered_consumer_template" for row in candidates if "source" in row)


@pytest.mark.parametrize("suffix", ["all", "list", "mine", "owned", "history"])
def test_listing_action_does_not_become_item_parent(adapters, suffix):
    candidates = _candidates(adapters, producer=f"https://app.test/api/invoices/{suffix}")
    assert candidates[0]["url"] == "https://app.test/api/invoices/101"


def test_observed_query_consumer_is_not_replaced_by_a_guessed_path(adapters):
    candidates = _candidates(adapters, templates=[
        "https://app.test/api/users/7", "https://app.test/api/invoices?id=8&expand=lines",
    ])
    assert candidates[0]["url"] == "https://app.test/api/invoices?id=101&expand=lines"


def test_typed_foreign_key_can_prefer_its_observed_resource(adapters):
    candidates = _candidates(adapters, templates=[
        "https://app.test/api/invoices/8", "https://app.test/api/users/7",
    ], key="user_id")
    assert candidates[0]["url"] == "https://app.test/api/users/101"


def test_same_parent_resource_is_preferred_over_same_noun_elsewhere(adapters):
    candidates = _candidates(adapters, producer="https://app.test/api/tenants/7/invoices", templates=[
        "https://app.test/other/invoices/8", "https://app.test/api/tenants/7/invoices/8",
    ])
    assert candidates[0]["url"] == "https://app.test/api/tenants/7/invoices/101"


@pytest.mark.parametrize("origin", ["http://192.0.2.10:8080", "https://device.test:8443", "http://[2001:db8::1]:8080"])
def test_http_nonstandard_ports_and_ipv6_are_not_new_restrictions(adapters, origin):
    candidates = _candidates(adapters, producer=origin + "/api/invoices", templates=[
        origin + "/api/users/7", origin + "/api/invoices/8",
    ])
    assert candidates[0]["url"] == origin + "/api/invoices/101"


def test_different_origin_is_fallback_not_a_scope_grant(adapters):
    candidates = _candidates(adapters, templates=[
        "https://other.test/api/invoices/8", "https://app.test/api/invoices/8",
    ])
    assert candidates[0]["url"] == "https://app.test/api/invoices/101"
    assert any(row["url"].startswith("https://other.test/") for row in candidates)
    assert all("verified" not in row and "proof_state" not in row for row in candidates)


def test_default_port_origin_equivalence(adapters):
    candidates = _candidates(adapters, templates=["https://app.test:443/api/invoices/8"])
    assert candidates[0]["url"] == "https://app.test:443/api/invoices/101"


def test_templates_and_reference_are_not_mutated(adapters):
    templates = ["https://app.test/api/users/7", "https://app.test/api/invoices/8"]
    ref = {"object_id": "101", "object_id_key": "id", "sensitive_fields": ["amount"]}
    original = copy.deepcopy((templates, ref))
    adapters["_resource_replay_candidates"]("https://app.test/api/invoices", ref, consumer_templates=templates)
    assert (templates, ref) == original


def test_duplicate_candidates_are_removed_before_final_cap(adapters):
    candidates = _candidates(adapters, templates=["https://app.test/api/invoices/8"] * 12)
    assert len({row["url"] for row in candidates}) == len(candidates)
    assert len(candidates) <= 6


def test_ordering_retains_every_candidate_and_does_not_mutate_evidence():
    candidates = [
        {"url": "https://app.test/api/users/101", "object_id_location": "path", "source": "discovered_consumer_template"},
        {"url": "https://app.test/api/invoices/101", "object_id_location": "path"},
        {"url": "https://other.test/api/invoices/101", "object_id_location": "path"},
    ]
    original = copy.deepcopy(candidates)
    result = prioritize_replay_candidates("https://app.test/api/invoices", candidates, object_id="101")
    assert result[0] == candidates[1]
    assert len(result) == len(candidates)
    assert all(row in result for row in candidates)
    assert candidates == original


def test_unknown_relationship_retains_stable_order():
    candidates = [
        {"url": "https://app.test/a/101", "object_id_location": "path"},
        {"url": "https://app.test/b/101", "object_id_location": "path"},
    ]
    assert prioritize_replay_candidates("https://app.test/c", candidates, object_id="101") == candidates


def test_invalid_producer_never_claims_a_better_route():
    candidates = [{"url": "https://app.test/api/invoices/101", "object_id_location": "path"}]
    assert prioritize_replay_candidates("https://[bad", candidates, object_id="101") == candidates


def test_no_eligible_identifier_is_not_invented():
    assert select_replay_identifier(["", "api", "invoices"], [], [], []) is None
