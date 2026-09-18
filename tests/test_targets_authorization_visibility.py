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

AUTHORIZATION_EXISTS = re.compile(
    r"EXISTS\s*\(\s*SELECT 1 FROM approval_receipts a.*?"
    r"a\.action_name = 'target\.authorization'.*?"
    r"\)\s*AS authorized_for_active_testing",
    re.DOTALL,
)


def _query_after(marker: str) -> str:
    """The SQL string that follows a route definition."""
    start = SOURCE.index(marker)
    return SOURCE[start:start + 4000]


def test_both_target_listings_expose_the_authorization_state():
    """Whichever listing a client reads, it can tell an authorized target from an unauthorized
    one. The page uses the grouped one."""
    flat = _query_after('@router.get("/targets")')
    grouped = _query_after('@router.get("/targets/grouped")')
    assert AUTHORIZATION_EXISTS.search(flat), "the flat listing lost its authorization flag"
    assert AUTHORIZATION_EXISTS.search(grouped), (
        "GET /targets/grouped does not select authorized_for_active_testing, so the targets page "
        "cannot show that a target is authorized and offers 'Authorize' forever"
    )


def test_the_authorization_predicate_is_the_same_in_both():
    """Two different predicates would let the two listings disagree about the same target."""
    flat = AUTHORIZATION_EXISTS.search(_query_after('@router.get("/targets")'))
    grouped = AUTHORIZATION_EXISTS.search(_query_after('@router.get("/targets/grouped")'))
    normalize = lambda text: re.sub(r"\s+|--[^\n]*", " ", text).strip()
    assert normalize(flat.group(0)) == normalize(grouped.group(0))


def test_the_ui_renders_the_authorized_state_from_that_field():
    """The page's conditional must read the field the API sends, not a different name."""
    page = (Path(__file__).resolve().parents[1] / "ui" / "src" / "app" / "targets" / "page.tsx").read_text()
    assert "root_target.authorized_for_active_testing" in page
    assert "Authorize for active testing (once)" in page
    assert "Revoke" in page
