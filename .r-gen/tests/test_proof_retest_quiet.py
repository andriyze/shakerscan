"""A browser XSS retest waits a quiet spell after the page's own requests finish.

A page whose sink runs a moment after its last request finished (a ``setTimeout`` after the data
call answered, a render on the next frame) only shows the proof's marker after that request is
done. The retest waits, after the settle, while the page still has requests open, and then for a
quiet spell with none open; it reads the marker after every poll. Without the quiet spell such a
page read "likely fixed" for a flaw that is still there.

The page here is a stand-in Playwright page (a unit fixture) driven by the retest's own polls, so
the order of events is exact: no real browser, no timing.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from worker_handlers import proof_replay  # noqa: E402

PAGE = "http://shop.fixture.invalid/search?q=payload"
MARKER = "marker-fixture"


class _Frame:
    parent_frame = None


class _Request:
    def __init__(self, url: str, resource_type: str) -> None:
        self.url, self.resource_type, self.method = url, resource_type, "GET"
        self.frame, self.failure = type("Child", (), {"parent_frame": _Frame()})(), None

    def is_navigation_request(self) -> bool:
        return False


class _Response:
    def __init__(self, request: Any = None, status: int = 200) -> None:
        self.request, self.status, self.headers = request, status, {}


class _Page:
    """A page whose data call is open at the settle, finishes on the retest's ``finish_at``-th
    marker read, and whose sink writes the marker ``marker_after`` reads after that (None:
    never). Reads are what the retest's polls do, so the count is exact."""

    def __init__(self, *, finish_at: int | None, marker_after: int | None, open_call: bool = True) -> None:
        self.handlers: dict[str, Any] = {}
        self.url = PAGE
        self.reads = 0
        self.finish_at, self.marker_after, self.open_call = finish_at, marker_after, open_call
        self.call = _Request("http://shop.fixture.invalid/api/search?q=payload", "fetch")
        self.finished_at_read: int | None = None

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler

    async def goto(self, url: str, **_options: Any) -> _Response:
        if self.open_call:
            self.handlers["request"](self.call)
        else:
            self.finished_at_read = 0
        return _Response()

    async def get_attribute(self, _selector: str, _name: str) -> str | None:
        self.reads += 1
        if self.open_call and self.finished_at_read is None and self.finish_at is not None \
                and self.reads >= self.finish_at:
            self.handlers["response"](_Response(self.call, 200))
            self.handlers["requestfinished"](self.call)
            self.finished_at_read = self.reads
        if (self.marker_after is not None and self.finished_at_read is not None
                and self.reads >= self.finished_at_read + self.marker_after):
            return MARKER
        return None


class _Context:
    def __init__(self, page: _Page) -> None:
        self.page = page

    async def close(self) -> None:
        return None


class _Poe:
    def __init__(self, page: _Page) -> None:
        self.page = page

    async def proof_browser_context(self, url: str, **_options: Any) -> _Context:
        return _Context(self.page)

    async def proof_browser_page(self, context: _Context, **_options: Any) -> _Page:
        return context.page

    def baseline_refusal(self, *_args: Any) -> None:
        return None


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    # The settle and the poll are the browser proof's; here only their order matters.
    monkeypatch.setattr(proof_replay, "XSS_PROOF_SETTLE_SECONDS", 0)
    monkeypatch.setattr(proof_replay, "_PENDING_POLL_SECONDS", 0.01)
    monkeypatch.setattr(proof_replay, "_PENDING_QUIET_SECONDS", 0.2)


def _check(page: _Page) -> tuple[str, dict]:
    return asyncio.run(proof_replay._marker_check(
        PAGE, MARKER, poe=_Poe(page), headers=None, cancelled=lambda: False))


def test_a_marker_written_after_the_last_request_finished_is_read():
    """The sink runs two polls after its data call answered: the quiet spell is still on."""
    outcome, proof = _check(_Page(finish_at=3, marker_after=2))
    assert outcome == "reproduced", proof
    assert proof["technique"] == "headless_xss_dom"


def test_a_marker_written_after_a_page_with_nothing_open_settled_is_read():
    """Nothing open at the settle: the quiet spell still runs, and the marker it shows counts."""
    outcome, proof = _check(_Page(finish_at=None, marker_after=3, open_call=False))
    assert outcome == "reproduced", proof


def test_a_fixed_page_ends_after_the_quiet_spell():
    page = _Page(finish_at=3, marker_after=None)
    outcome, proof = _check(page)
    assert outcome == "not_reproduced", proof
    # It polled past the finish for the quiet spell (0.2 s at 0.01 s a poll), then stopped.
    assert page.reads - page.finished_at_read >= 5
    assert page.reads < 200
