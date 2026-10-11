"""Hosts a running replay may send traffic to.

A finding retest replays its proof against one destination its scope admitted. The worker
installs a guard for the duration of the replay (``destination_guard``):

* ``fetch_with_capture`` refuses a request, and every redirect hop, to a host the guard does not
  allow, and follows redirects itself so each hop is checked;
* a headless browser context opened under the guard (``guarded_context_options``) sends all of its
  traffic -- navigations, every redirect hop, subresources, fetch/XHR, beacons, WebSockets --
  through a local egress proxy (``GuardProxy``) that refuses a host the guard does not allow, and
  blocks service workers. A route handler cannot do this: Chromium follows a redirect without
  routing the next hop, and WebSockets are not routed at all.

The rule is by host name (or IP literal), as the scope receipt names hosts: a name that resolves
to an unexpected address is not caught here, and ports are not constrained.

Refused hosts are recorded on the guard so the caller can tell a replay that was cut short from
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
    proxy: Any = None

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
        if guard.proxy is not None:
            guard.proxy.close()


REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class GuardProxy:
    """A local HTTP proxy that forwards only to hosts the guard allows.

    ``CONNECT host:port`` (HTTPS and secure WebSockets) and absolute-form requests (plain HTTP
    and ``ws://``) are checked before any upstream connection is made; a refused one is answered
    403 and recorded on the guard. An allowed connection is relayed as bytes. A client that reuses
    a plain-HTTP connection only ever reaches the upstream host already checked.
    """

    def __init__(self, guard: DestinationGuard) -> None:
        self.guard = guard
        self.server: Any = None
        self.port = 0

    async def start(self) -> str:
        import asyncio

        if self.server is None:
            self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
            self.port = self.server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        if self.server is not None:
            self.server.close()
            self.server = None

    async def _handle(self, reader: Any, writer: Any) -> None:
        import asyncio
        from urllib.parse import urlsplit

        upstream_writer = None
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
            line, _, rest = head.partition(b"\r\n")
            method, target, version = line.decode("latin-1").split(" ", 2)
            if method.upper() == "CONNECT":
                host, _, port = target.rpartition(":")
                url, port_number = f"https://{host}:{port}/", int(port)
            else:
                url = target
                parts = urlsplit(target)
                host = parts.hostname or ""
                port_number = parts.port or (443 if parts.scheme in {"https", "wss"} else 80)
            if not host or not self.guard.check(url):
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                return
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host.strip("[]"), port_number), timeout=30)
            if method.upper() == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
            else:
                parts = urlsplit(target)
                origin_form = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
                headers = [h for h in rest.split(b"\r\n")
                           if h and not h.lower().startswith(b"proxy-connection:")]
                upstream_writer.write(f"{method} {origin_form} {version}\r\n".encode("latin-1")
                                      + b"\r\n".join(headers) + b"\r\n\r\n")
                await upstream_writer.drain()

            async def pump(src: Any, dst: Any) -> None:
                try:
                    while chunk := await src.read(65536):
                        dst.write(chunk)
                        await dst.drain()
                except Exception:
                    pass
                finally:
                    try:
                        dst.close()
                    except Exception:
                        pass
            await asyncio.gather(pump(reader, upstream_writer), pump(upstream_reader, writer))
        except Exception:
            pass
        finally:
            for stream in (writer, upstream_writer):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass


async def guarded_context_options() -> dict[str, Any]:
    """Options for ``browser.new_context`` under the current guard (none without one): every
    request through the guard's egress proxy, loopback included, and no service workers."""
    guard = current_guard()
    if guard is None:
        return {}
    if guard.proxy is None:
        guard.proxy = GuardProxy(guard)
    server = await guard.proxy.start()
    return {"proxy": {"server": server, "bypass": "<-loopback>"}, "service_workers": "block"}
