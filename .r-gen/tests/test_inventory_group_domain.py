"""The Targets list's domain groups come from the Public Suffix List, so a group (and the
"Delete domain" selection built on it) never spans registrants, and Discover is offered only for
groups POST /discovery accepts (unit tests; the SQL path runs in test_target_asset_psl_postgres)."""
from __future__ import annotations

import pytest

from targets.asset_inventory import discoverable, group_domain


@pytest.mark.parametrize(("locator", "group"), [
    ("victim.github.io", "victim.github.io"), ("api.victim.github.io", "victim.github.io"),
    ("attacker.github.io", "attacker.github.io"), ("github.io", "github.io"),
    ("shop.example.co.uk", "example.co.uk"), ("api.example.test", "example.test"),
    ("192.0.2.1", "192.0.2.1"), ("2001:db8::1", "2001:db8::1"), ("router.local", "router.local"),
    ("localhost", "localhost"), ("printer", "printer"), ("db.example.com#2", "example.com"),
    ("bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com"),
])
def test_group_domain(locator, group):
    assert group_domain(locator) == group


@pytest.mark.parametrize(("group", "expected"), [
    ("example.co.uk", True), ("victim.github.io", True), ("github.io", False), ("192.0.2.1", False),
    ("2001:db8::1", False), ("localhost", False), ("amazonaws.com", False),
])
def test_discover_is_offered_only_where_discovery_accepts_the_domain(group, expected):
    assert discoverable(group) is expected
