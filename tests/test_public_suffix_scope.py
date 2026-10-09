"""Public Suffix List boundary for authorization and scope patterns (unit tests, no network).

A wildcard or apex that authorizes or scopes work must sit at or below a registrable domain
(eTLD+1) under the bundled, pinned Public Suffix List, including its private section.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from action_scope import evaluate_scope, receipt_to_dict, scope_roots  # noqa: E402
from api_utils import extract_root_domain  # noqa: E402
from hunt.permission_bounds import (  # noqa: E402
    BoundError, Bounds, bounds_from_public, parse_bounds, refused_bounds,
)
from hunt.permission_store import public_preauthorization  # noqa: E402
from runtime.models import TargetBinding  # noqa: E402
from scope.psl import public_suffix_refusal  # noqa: E402


@pytest.mark.parametrize("bound", [
    "target.authorize:*.co.uk", "target.authorize:*.github.io", "target.authorize:*.com",
    "target.authorize:co.uk", "target.authorize:*.herokuapp.com", "target.authorize:*.co.uk:443",
    "target.authorize:*.xn--55qx5d.cn", "target.authorize:*.公司.cn", "target.authorize:*.lab",
    "credential.use:co.uk", "credential.use:github.io",
])
def test_bounds_naming_a_public_suffix_are_refused(bound):
    with pytest.raises(BoundError, match="is a public suffix; name a domain you control"):
        parse_bounds([bound])


def test_refusal_names_the_pattern_and_an_example_under_it():
    with pytest.raises(BoundError) as refused:
        parse_bounds(["target.authorize:*.co.uk"])
    assert str(refused.value) == (
        "*.co.uk is a public suffix; name a domain you control, e.g. *.example.co.uk "
        "(a pattern must name a registrable domain or a name below one)"
    )
    assert public_suffix_refusal("example.co.uk", wildcard=True) is None


@pytest.mark.parametrize(("bound", "host"), [
    ("target.authorize:*.example.co.uk", "example.co.uk"),
    ("target.authorize:*.user.github.io", "user.github.io"),
    ("target.authorize:user.github.io", "user.github.io"),
    ("target.authorize:*.example.com:8443", "example.com"),
    ("target.authorize:*.xn--85x722f.xn--55qx5d.cn", "xn--85x722f.xn--55qx5d.cn"),
    ("target.authorize:*.食狮.公司.cn", "xn--85x722f.xn--55qx5d.cn"),
])
def test_bounds_at_or_below_a_registrable_domain_are_accepted(bound, host):
    (pattern,) = parse_bounds([bound]).target_patterns
    assert pattern.host == host and not pattern.refused
    assert pattern.covers(("api." if pattern.wildcard else "") + host, pattern.port)


def test_a_persisted_public_suffix_bound_fails_closed_without_reinterpretation():
    # Stored before the Public Suffix List check: the row is kept as written.
    stored = {
        "budget_multiplier": 2.0, "budget_totals": {}, "capability_flags": ["active-testing"],
        "credential_targets": ["co.uk", "app.example.com"], "ssh_host_trust_first_contact": False,
        "target_patterns": ["*.co.uk", "*.github.io:443", "*.example.co.uk"],
    }
    bounds = bounds_from_public(stored)
    # Every bound still reads as stored, and only the public-suffix ones match nothing.
    assert [pattern.text() for pattern in bounds.target_patterns] == stored["target_patterns"]
    assert not bounds.covers_target(host="shop.victim.co.uk", port=443)
    assert not bounds.covers_target(host="someone.github.io", port=443)
    assert bounds.covers_target(host="api.example.co.uk", port=443)
    assert not bounds.covers_credential(home_target_id="x", home_host="co.uk")
    assert bounds.covers_credential(home_target_id="x", home_host="app.example.com")
    assert bounds.budget_multiplier == 2.0 and bounds.covers_capability("active-testing")
    refused = refused_bounds(stored)
    assert [item["bound"] for item in refused] == [
        "target.authorize:*.co.uk", "target.authorize:*.github.io:443", "credential.use:co.uk",
    ]
    assert "*.co.uk is a public suffix" in refused[0]["message"]
    assert "no longer covers any host" in refused[0]["message"]
    shown = public_preauthorization({
        "id": "1", "bounds_json": stored, "bounds_digest": "d", "created_by": "p", "proof": "start",
        "created_at": None,
    })
    assert shown["bounds"] == stored and len(shown["refused_bounds"]) == 3
    clean = public_preauthorization({
        "id": "2", "bounds_json": Bounds().public(), "bounds_digest": "d", "created_by": "p",
        "proof": "start", "created_at": None,
    })
    assert "refused_bounds" not in clean


def test_scope_receipt_never_widens_through_a_public_suffix_root():
    receipt = evaluate_scope(
        "https://shop.victim.co.uk/", allowed_hosts=["app.example.co.uk"],
        allowed_root_domains=["co.uk"], environment="production",
    )
    assert receipt.verdict == "blocked"
    assert {"host_out_of_allowed_scope", "allowed_root_public_suffix"} <= set(receipt.blocked_by)
    assert receipt.allowed_root_domains == ()
    payload = receipt_to_dict(receipt)
    (check,) = [item for item in payload["checks"] if item["name"] == "allowed_root_public_suffix"]
    assert check["message"].startswith("*.co.uk is a public suffix")

    # A root with no other scope still refuses rather than asking for approval.
    only_suffix = evaluate_scope("https://x.github.io/", allowed_root_domains=["github.io"])
    assert only_suffix.verdict == "blocked"

    # The target's own host stays in scope, and a registrable root still works.
    own = evaluate_scope(
        "https://app.example.co.uk/", allowed_hosts=["app.example.co.uk"],
        allowed_root_domains=["co.uk"], redirect_urls=["https://evil.co.uk/"],
    )
    assert own.blocked_by == ("redirect_out_of_scope",)
    fine = evaluate_scope(
        "https://api.example.co.uk/", allowed_root_domains=["example.co.uk"],
        redirect_urls=["https://www.example.co.uk/"],
    )
    assert fine.verdict == "allowed"


def test_persisted_bindings_and_receipts_drop_public_suffix_roots():
    assert scope_roots(["co.uk", "example.co.uk", "github.io", "com", ""]) == ("example.co.uk",)
    binding = TargetBinding(
        target_id="t", target_kind="web", canonical_host="app.example.co.uk",
        allowed_origins=("https://app.example.co.uk",), allowed_root_domains=("co.uk", "example.co.uk"),
    )
    assert binding.allowed_root_domains == ("example.co.uk",)


def test_api_scope_matchers_ignore_public_suffix_roots():
    import importlib

    authorization = importlib.import_module("scan.authorization")
    receipt = {"allowed_hosts": [], "allowed_root_domains": ["co.uk", "example.co.uk"]}
    assert not authorization._host_in_scope("victim.co.uk", receipt)
    assert authorization._host_in_scope("api.example.co.uk", receipt)


@pytest.mark.parametrize(("url", "root"), [
    ("https://shop.example.co.uk/a", "example.co.uk"),
    ("https://user.github.io", "user.github.io"),
    ("https://api.example.com:8443", "example.com"),
    ("https://localhost", "localhost"),
    ("https://192.0.2.1", "192.0.2.1"),
])
def test_target_root_domain_is_the_registrable_domain(url, root):
    assert extract_root_domain(url) == root
