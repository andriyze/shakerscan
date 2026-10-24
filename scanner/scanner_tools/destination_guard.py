"""Hosts a running replay may send traffic to.

A finding retest replays its proof against one destination its scope admitted. The worker
installs a guard for the duration of the replay (``destination_guard``):

* ``fetch_with_capture`` refuses a request, and every redirect hop, to a host the guard does not
  allow, and follows redirects itself so each hop is checked;
* every headless browser context opened under the guard (``guarded_context_options``, applied to
  any Playwright context by ``enforce_on_playwright``) sends all of its traffic -- navigations,
  every redirect hop, subresources, fetch/XHR, beacons, WebSockets -- through a local egress
  proxy (``GuardProxy``) that refuses a host the guard does not allow; service workers are
  blocked and WebRTC (UDP, outside any proxy) is disabled. A route handler cannot do this:
  Chromium follows a redirect without routing the next hop, and WebSockets are not routed.

The rule is by host name (or IP literal), as the scope receipt names hosts: a name that resolves
to an unexpected address (DNS rebinding) is not caught here, and ports are not constrained.

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
    # Proxy failures (host and error class only), kept apart from refusals.
    incidents: list[str] = field(default_factory=list)
    proxy: Any = None

    def incident(self, host: str, error: BaseException) -> None:
        if len(self.incidents) < 20:
            self.incidents.append(f"{host or '?'}:{type(error).__name__}")

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
    enforce_on_playwright()
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

    ``CONNECT host:port`` (HTTPS and WebSockets) and absolute-form requests (plain HTTP) are
    checked before any upstream connection is made; a refused one is answered 403 and recorded on
    the guard. A CONNECT tunnel is relayed as bytes to the one host checked. A plain-HTTP request
    is forwarded with exactly its own body and ``Connection: close``, and the client connection
    is closed after the response, so every request on it is checked: a client that would reuse
    the connection opens a new one. Failures are recorded as incidents, never swallowed.
    """

    def __init__(self, guard: DestinationGuard, *, close_on_refusal: bool = False) -> None:
        self.guard = guard
        self.server: Any = None
        self.port = 0
        # Refuse by closing the connection unanswered: the page sees a network error, as for a
        # refused CONNECT, instead of a 403 that would read as the refused origin's answer.
        self.close_on_refusal = close_on_refusal
        self._tasks: set[Any] = set()

    async def start(self) -> str:
        import asyncio

        if self.server is None:
            self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
            self.port = self.server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        """Stop accepting, and end every connection still open (its tunnel included)."""
        if self.server is not None:
            self.server.close()
            self.server = None
        for task in list(self._tasks):
            task.cancel()

    async def _handle(self, reader: Any, writer: Any) -> None:
        import asyncio
        from urllib.parse import urlsplit

        upstream_writer = None
        host = ""
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
            line, _, rest = head.partition(b"\r\n")
            method, target, version = line.decode("latin-1").split(" ", 2)
            connect = method.upper() == "CONNECT"
            if connect:
                host, _, port = target.rpartition(":")
                url, port_number = f"https://{host}:{port}/", int(port)
            else:
                url = target
                parts = urlsplit(target)
                host = parts.hostname or ""
                port_number = parts.port or 80
            if not host or not self.guard.check(url):
                if not self.close_on_refusal:
                    writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                return
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host.strip("[]"), port_number), timeout=30)
            if connect:
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                await asyncio.gather(_pump(reader, upstream_writer), _pump(upstream_reader, writer))
                return
            await self._forward_one(method, target, version, rest, reader, upstream_reader, upstream_writer, writer)
        except asyncio.CancelledError:
            pass  # the proxy was closed with this connection open
        except Exception as exc:  # recorded, not swallowed; the client sees the connection end
            self.guard.incident(host, exc)
        finally:
            if task is not None:
                self._tasks.discard(task)
            for stream in (writer, upstream_writer):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass

    async def _forward_one(self, method: str, target: str, version: str, rest: bytes, reader: Any,
                           upstream_reader: Any, upstream_writer: Any, writer: Any) -> None:
        import asyncio
        from urllib.parse import urlsplit

        parts = urlsplit(target)
        origin_form = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        headers = [h for h in rest.split(b"\r\n") if h]
        names = {h.split(b":", 1)[0].strip().lower() for h in headers}
        upgrade = b"upgrade" in names
        kept = [h for h in headers if h.split(b":", 1)[0].strip().lower()
                not in {b"proxy-connection", b"connection", b"keep-alive"}]
        kept.append(b"Connection: Upgrade" if upgrade else b"Connection: close")
        upstream_writer.write(f"{method} {origin_form} {version}\r\n".encode("latin-1")
                              + b"\r\n".join(kept) + b"\r\n\r\n")
        if upgrade:  # an upgraded connection stays with the host already checked
            await upstream_writer.drain()
            await asyncio.gather(_pump(reader, upstream_writer), _pump(upstream_reader, writer))
            return
        length = next((int(h.split(b":", 1)[1].strip()) for h in headers
                       if h.split(b":", 1)[0].strip().lower() == b"content-length"), 0)
        chunked = any(h.split(b":", 1)[0].strip().lower() == b"transfer-encoding"
                      and b"chunked" in h.lower() for h in headers)
        if chunked:
            body = b""
            while not body.endswith(b"0\r\n\r\n"):
                chunk = await reader.read(65536)
                if not chunk:
                    break
                body += chunk
            upstream_writer.write(body)
        elif length:
            upstream_writer.write(await reader.readexactly(length))
        await upstream_writer.drain()
        # Only the response goes back; nothing more is read from this client connection.
        await _pump(upstream_reader, writer)


async def _pump(src: Any, dst: Any) -> None:
    try:
        while chunk := await src.read(65536):
            dst.write(chunk)
            await dst.drain()
    finally:
        try:
            dst.close()
        except Exception:
            pass


# Chromium sends WebRTC (STUN/ICE) over UDP, outside any HTTP proxy. Browsers that may run a
# guarded replay are launched with this (``guarded_launch_args``); guarded contexts also remove the
# WebRTC constructors (``DISABLE_WEBRTC``).
WEBRTC_LAUNCH_ARG = "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
DISABLE_WEBRTC = """(() => {
  for (const name of ["RTCPeerConnection", "webkitRTCPeerConnection", "RTCDataChannel",
                      "RTCSessionDescription", "RTCIceCandidate"]) {
    try { Object.defineProperty(globalThis, name, {value: undefined, configurable: false}); } catch (e) {}
  }
})();"""


def guarded_launch_args(args: list[str] | tuple[str, ...] = ()) -> list[str]:
    """Launch arguments with WebRTC limited to proxied (no) UDP; harmless without a guard."""
    return [*args, *([] if WEBRTC_LAUNCH_ARG in args else [WEBRTC_LAUNCH_ARG])]


async def guarded_context_options() -> dict[str, Any]:
    """Options for ``browser.new_context`` under the current guard (none without one): every
    request through the guard's egress proxy, loopback included, and no service workers.

    Every context created while a guard is set gets them anyway (``enforce_on_playwright``); the
    explicit call keeps the contract visible at the call sites.
    """
    guard = current_guard()
    if guard is None:
        return {}
    if guard.proxy is None:
        guard.proxy = GuardProxy(guard)
    server = await guard.proxy.start()
    return {"proxy": {"server": server, "bypass": "<-loopback>"}, "service_workers": "block"}


_ENFORCED = False


def enforce_on_playwright() -> None:
    """Make every Playwright context or browser created while a guard is set a guarded one.

    Wraps ``Browser.new_context`` and ``BrowserType.launch_persistent_context`` (guarded proxy
    and service workers, WebRTC constructors removed) and ``BrowserType.launch`` (WebRTC launch
    argument), so a code path that opens its own browser during a replay cannot step around the
    guard. Without a guard they behave as before. Idempotent.
    """
    global _ENFORCED
    if _ENFORCED:
        return
    try:
        from playwright.async_api import Browser, BrowserType
    except ImportError:
        return
    _ENFORCED = True
    new_context, persistent, launch = Browser.new_context, BrowserType.launch_persistent_context, BrowserType.launch

    async def guarded_new_context(self: Any, *args: Any, **kwargs: Any) -> Any:
        if current_guard() is None:
            return await new_context(self, *args, **kwargs)
        context = await new_context(self, *args, **{**kwargs, **await guarded_context_options()})
        await context.add_init_script(DISABLE_WEBRTC)
        return context

    async def guarded_persistent(self: Any, *args: Any, **kwargs: Any) -> Any:
        if current_guard() is None:
            return await persistent(self, *args, **kwargs)
        kwargs = {**kwargs, **await guarded_context_options(),
                  "args": guarded_launch_args(kwargs.get("args") or [])}
        context = await persistent(self, *args, **kwargs)
        await context.add_init_script(DISABLE_WEBRTC)
        return context

    async def guarded_launch(self: Any, *args: Any, **kwargs: Any) -> Any:
        if current_guard() is not None:
            kwargs = {**kwargs, "args": guarded_launch_args(kwargs.get("args") or [])}
        return await launch(self, *args, **kwargs)

    Browser.new_context = guarded_new_context  # type: ignore[method-assign]
    BrowserType.launch_persistent_context = guarded_persistent  # type: ignore[method-assign]
    BrowserType.launch = guarded_launch  # type: ignore[method-assign]
