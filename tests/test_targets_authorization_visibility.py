"""The targets page must be able to see that a target is authorized.

Found by clicking through a clean 2.3.6 install: pressing "Authorize for active testing (once)"
recorded a real standing authorization -- approval receipt, scope receipt, `approved_by` -- and
said so in a toast. The row then looked exactly as before, on that render and on every later
page load, so the operator had no way to tell it had worked and would press it again.

The page reads the grouped shape, `GET /targets/grouped`. The flat `GET /targets` computed
`authorized_for_active_testing`; the grouped query did not select it, so the field was absent,
the UI's conditional saw `undefined`, and the "Authorized / Revoke" state was unreachable.
"""
from __future__ import annotations

import re
from pathlib import Path

ROUTER = Path(__file__).resolve().parents[1] / "api" / "targets" / "router.py"
SOURCE = ROUTER.read_text(encoding="utf-8")

def _query_after(marker: str) -> str:
    """The SQL string that follows a route definition."""
    start = SOURCE.index(marker)
    return SOURCE[start:start + 4000]


def test_both_target_listings_expose_the_authorization_state():
    """Whichever listing a client reads, it can tell an authorized target from an unauthorized
    one. The page uses the grouped one, which originally omitted the field entirely."""
    for marker in ('@router.get("/targets")', '@router.get("/targets/grouped")'):
        query = _query_after(marker)
        assert "_authorized_for_active_testing_sql()" in query, (
            f"{marker} does not project the authorization state, so a client cannot tell an "
            f"authorized target from an unauthorized one"
        )


def test_the_ui_renders_the_authorized_state_from_that_field():
    """The page's conditional must read the field the API sends, not a different name."""
    page = (Path(__file__).resolve().parents[1] / "ui" / "src" / "app" / "targets" / "page.tsx").read_text()
    assert "root_target.authorized_for_active_testing" in page
    assert "Authorize for active testing (once)" in page
    assert "Revoke" in page


def _render_predicate():
    """The predicate as the router builds it, without importing the router's dependencies."""
    import ast

    src = (Path(__file__).resolve().parents[1] / "api" / "targets" / "router.py").read_text()
    tree = ast.parse(src)
    wanted = {"_TARGET_HOST_SQL", "_authorized_for_active_testing_sql"}
    chunks = [
        ast.get_source_segment(src, node) for node in tree.body
        if (isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") in wanted)
        or (isinstance(node, ast.FunctionDef) and node.name in wanted)
    ]
    namespace: dict = {}
    exec("\n\n".join(chunks), namespace)
    return namespace["_authorized_for_active_testing_sql"]()


def test_the_listing_predicate_applies_the_canonical_reader_conditions():
    """Review finding R3: a listing said "Authorized" for receipts the canonical reader rejects.

    current_target_authorization() filters on the standing risk tiers and then discards a receipt
    whose scope is blocked or whose scope no longer names the target's current host. The listing
    checked only status, approver, action name and expiry, so a renamed target or a blocked scope
    still showed an Authorized badge while every later check found no authority.
    """
    root = Path(__file__).resolve().parents[1]
    predicate = _render_predicate()
    canonical = (root / "api" / "target_authorization.py").read_text()
    # The tier list moved to the shared approval policy when standing authorization began
    # covering credential use. Both halves are asserted, so neither the definition nor the
    # reader's use of it can drift away from the listing predicate.
    tiers = (root / "api" / "runtime" / "approval_policy.py").read_text()

    # the conditions the canonical reader applies, each now present in the listing predicate
    assert "risk_tier = ANY(ARRAY['active', 'intrusive'])" in predicate, "standing tiers"
    assert "STANDING_RISK_TIERS = (\"active\", \"intrusive\")" in tiers, (
        "the canonical tier list changed; the listing predicate must follow it"
    )
    assert "STANDING_RISK_TIERS" in canonical, (
        "the canonical reader must still apply the shared tier list"
    )
    assert "COALESCE(s.verdict, '') <> 'blocked'" in predicate, "blocked scope must not count"
    assert 'scope_verdict") or "") == "blocked"' in canonical
    assert "normalized_scope->>'host'" in predicate and "allowed_hosts" in predicate, (
        "the listing must require the scope to still name the target's current host"
    )
    assert "if host and host not in hosts:" in canonical


def test_both_listings_use_the_one_predicate_builder():
    """Two copies drift. The flat and grouped listings are built from the same function."""
    router = (Path(__file__).resolve().parents[1] / "api" / "targets" / "router.py").read_text()
    assert router.count("_authorized_for_active_testing_sql()") == 2
    assert router.count("AS authorized_for_active_testing") == 1, (
        "a second hand-written predicate has appeared; build it from the shared function"
    )
