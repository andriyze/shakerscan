"""Hosts a running replay may send traffic to.

A finding retest replays its proof against one destination its scope admitted. The worker
installs a guard for the duration of the replay (``destination_guard``); ``fetch_with_capture``
then refuses a request, and every redirect hop, to a host the guard does not allow, and follows
redirects itself so each hop is checked. ``guard_browser_context`` applies the same rule to a
headless browser. Without a guard nothing changes.

Refused URLs are recorded on the guard so the caller can tell a replay that was cut short from
one that ran: a cut-short replay proves neither a fix nor that the finding is still there.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator


@dataclass
class DestinationGuard:
    allowed: Callable[[str], bool]
    refused: list[str] = field(default_factory=list)

    def check(self, url: str) -> bool:
        if str(url).startswith(("data:", "blob:", "about:")):
            return True
        try:
            ok = bool(self.allowed(url))
        except Exception:
            ok = False
        if not ok and len(self.refused) < 20:
            self.refused.append(_host_only(url))
        return ok


def _host_only(url: str) -> str:
    """Only the host is kept: a refused URL may carry a payload or a token."""
    from urllib.parse import urlsplit

    try:
        return urlsplit(str(url)).hostname or "?"
    except ValueError:
        return "?"


_current: ContextVar[DestinationGuard | None] = ContextVar("replay_destination_guard", default=None)


def current_guard() -> DestinationGuard | None:
    return _current.get()


@contextmanager
def destination_guard(allowed: Callable[[str], bool] | None) -> Iterator[DestinationGuard | None]:
    if allowed is None:
        yield None
        return
    guard = DestinationGuard(allowed)
    token = _current.set(guard)
    try:
        yield guard
    finally:
        _current.reset(token)


REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


async def guard_browser_context(context: Any) -> None:
    """Abort browser requests (and redirect hops) to hosts the current guard does not allow.

    Redirects the browser follows itself are not routed, so each routed request is fetched
    without following redirects and its response fulfilled: a redirect then reaches the browser
    as a response, and the hop it starts is routed and checked again.
    """
    guard = current_guard()
    if guard is None:
        return

    async def handler(route: Any) -> None:
        request = route.request
        if not guard.check(request.url):
            await route.abort("blockedbyclient")
            return
        try:
            response = await route.fetch(max_redirects=0)
        except Exception:
            await route.abort("failed")
            return
        await route.fulfill(response=response)

    await context.route("**/*", handler)
