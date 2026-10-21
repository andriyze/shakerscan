"""Requests that carry session credentials follow redirects only on their own origin.

httpx, aiohttp, urllib and curl drop ``Authorization`` and ``Cookie`` when a redirect
changes host, but they copy every other request header to the next hop. A scan
authenticated with an API key header (``X-API-Key``, ``X-Auth-Token`` ...) or a bound
browser-session header would hand that value to whatever origin the target names in a
``Location`` header.

A request carrying session material follows a redirect only while the next hop has the same
scheme, host and port, or is the same host upgraded from http on port 80 to https on 443. Any
other redirect is not followed; the caller receives the redirect response itself. Requests
without session material keep the client's normal behaviour, and for curl, material that curl
7.83 and later strip themselves on a cross-host redirect (``Authorization``, ``Cookie``, ``-u``,
``--oauth2-bearer``) is left to curl.
"""

from __future__ import annotations

import contextlib
import re
import time
import urllib.parse
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from typing import Any

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
DEFAULT_MAX_REDIRECTS = 10

# Request headers that identify nothing about the scan's session. Every other header a
# caller adds is treated as session material, so an unrecognised credential header is
# protected by default.
_NEUTRAL_HEADERS = frozenset({
    "accept", "accept-charset", "accept-encoding", "accept-language", "cache-control",
    "connection", "content-length", "content-type", "dnt", "expect", "host",
    "if-modified-since", "if-none-match", "origin", "pragma", "range", "referer", "te",
    "upgrade-insecure-requests", "user-agent", "x-requested-with",
})

_CURL_DATA_OPTIONS = frozenset({
    "-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode",
    "-F", "--form", "--form-string", "--json", "-T", "--upload-file",
})
_CURL_PROBE_MARK = "__shakerscan_redirect_probe__"


def origin_key(url: Any) -> tuple[str, str, int] | None:
    """Return ``(scheme, host, effective port)`` for an http(s) URL, else ``None``."""
    try:
        parsed = urllib.parse.urlsplit(str(url or "").strip())
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return scheme, parsed.hostname.lower().rstrip("."), port or (443 if scheme == "https" else 80)


def same_credential_origin(current_url: Any, next_url: Any) -> bool:
    """Whether session credentials may accompany a redirect from ``current_url``: the same
    scheme, host and port, or the same host upgraded from http on port 80 to https on 443."""
    current = origin_key(current_url)
    target = origin_key(urllib.parse.urljoin(str(current_url), str(next_url)))
    if current is None or target is None:
        return False
    return current == target or (current == ("http", current[1], 80) and target == ("https", current[1], 443))


def redirect_method(method: str, status: int) -> str:
    """The method a client uses for the next hop (RFC 9110 and common client practice)."""
    method = method.upper()
    if status == 303 and method != "HEAD":
        return "GET"
    if status in (301, 302) and method == "POST":
        return "GET"
    return method


def is_session_header(name: Any) -> bool:
    return str(name or "").strip().lower() not in _NEUTRAL_HEADERS


def carries_session_headers(headers: Any) -> bool:
    try:
        return any(is_session_header(name) for name in dict(headers or {}))
    except (TypeError, ValueError):
        return bool(headers)


async def httpx_request(client: Any, method: str, url: str, *, max_redirects: int = DEFAULT_MAX_REDIRECTS,
                        **kwargs: Any) -> Any:
    """Send through an ``httpx.AsyncClient``, following only same-origin redirects when the
    request carries session headers or cookies; otherwise the client follows as configured."""
    if not (carries_session_headers(kwargs.get("headers")) or kwargs.get("cookies")
            or carries_session_headers(getattr(client, "headers", None))):
        return await client.request(method, url, **kwargs)
    kwargs.pop("follow_redirects", None)
    current_url, current_method = url, method.upper()
    history: list[Any] = []
    for hop in range(max_redirects + 1):
        response = await client.request(current_method, current_url, follow_redirects=False, **kwargs)
        response.history = list(history)
        location = response.headers.get("location")
        if response.status_code not in REDIRECT_STATUSES or not location or hop == max_redirects:
            return response
        response_url = str(response.url)
        next_url = urllib.parse.urljoin(response_url, location.strip())
        if not same_credential_origin(response_url, next_url):
            return response
        next_method = redirect_method(current_method, response.status_code)
        if next_method != current_method:
            for key in ("content", "data", "files", "json"):
                kwargs.pop(key, None)
        await response.aclose()
        history.append(response)
        current_url, current_method = next_url, next_method
    return response  # pragma: no cover - the loop always returns


@contextlib.asynccontextmanager
async def aiohttp_request(session: Any, method: str, url: str, *, max_redirects: int = DEFAULT_MAX_REDIRECTS,
                          credentials: bool = True, **kwargs: Any) -> AsyncIterator[Any]:
    """``async with`` an aiohttp request that follows only same-origin redirects.

    ``credentials=False`` (the request carries no session material) keeps aiohttp's own
    redirect handling.
    """
    if not credentials:
        async with session.request(method, url, **kwargs) as plain_response:
            yield plain_response
        return
    kwargs["allow_redirects"] = False
    current_url, current_method = url, method.upper()
    response = None
    for hop in range(max_redirects + 1):
        response = await session.request(current_method, current_url, **kwargs)
        location = response.headers.get("Location")
        if response.status in REDIRECT_STATUSES and location and hop < max_redirects:
            response_url = str(response.url)
            next_url = urllib.parse.urljoin(response_url, location.strip())
            if same_credential_origin(response_url, next_url):
                next_method = redirect_method(current_method, response.status)
                if next_method != current_method:
                    kwargs.pop("data", None)
                    kwargs.pop("json", None)
                response.release()
                current_url, current_method = next_url, next_method
                continue
        break
    try:
        yield response
    finally:
        if response is not None:
            response.release()


def _curl_header_name(value: str) -> str:
    return value.split(":", 1)[0].split(";", 1)[0].strip()


# curl 7.83.0 and later drop a custom ``Authorization`` or ``Cookie`` header, ``-u`` and
# ``--oauth2-bearer`` on a redirect to another host, port or scheme (CVE-2022-27774/27776).
# They are not session material for curl that new; every other header and an inline ``-b``
# cookie string are, because curl sends those to any host a redirect names.
_CURL_SELF_PROTECTED_HEADERS = frozenset({"authorization", "cookie"})
_CURL_SELF_PROTECTED_OPTIONS = frozenset({"-u", "--user", "--oauth2-bearer"})
_CURL_ALWAYS_CREDENTIAL_OPTIONS = frozenset({"-E", "--cert", "--aws-sigv4"})
_CURL_STRIPS_SINCE = (7, 83, 0)
_curl_versions: dict[str, tuple[int, ...] | None] = {}


def curl_version(binary: str = "curl") -> tuple[int, ...] | None:
    """The ``curl --version`` release of ``binary`` (cached), or None when it cannot be read."""
    if binary not in _curl_versions:
        import re
        import subprocess

        version = None
        try:
            done = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5, check=False)
            match = re.match(r"curl (\d+)\.(\d+)\.(\d+)", done.stdout or "")
            version = tuple(int(part) for part in match.groups()) if match else None
        except (OSError, subprocess.SubprocessError):
            version = None
        _curl_versions[binary] = version
    return _curl_versions[binary]


def curl_strips_credentials(binary: str = "curl") -> bool:
    version = curl_version(binary)
    return version is not None and version >= _CURL_STRIPS_SINCE


def curl_carries_credentials(cmd: list[str]) -> bool:
    """Whether a curl argv sends session material that curl itself would copy to another host."""
    self_protected = curl_strips_credentials(str(cmd[0])) if cmd else False
    args = list(cmd[1:])

    def header_is_material(value: str) -> bool:
        name = _curl_header_name(value)
        if not is_session_header(name):
            return False
        return not (self_protected and name.lower() in _CURL_SELF_PROTECTED_HEADERS)

    for index, value in enumerate(args):
        if not isinstance(value, str):
            continue
        following = str(args[index + 1]) if index + 1 < len(args) else ""
        if value in {"-H", "--header"} and following:
            if header_is_material(following):
                return True
        elif value.startswith("-H") and len(value) > 2 and not value.startswith("--"):
            if header_is_material(value[2:]):
                return True
        elif value in {"-b", "--cookie"} and "=" in following:
            return True  # an inline cookie string goes to every host; a cookie file is domain-scoped
        elif value in _CURL_ALWAYS_CREDENTIAL_OPTIONS:
            return True
        elif value in _CURL_SELF_PROTECTED_OPTIONS and not self_protected:
            return True
    return False


def curl_follows_with_credentials(cmd: list[str]) -> bool:
    return (
        bool(cmd)
        and str(cmd[0]).rsplit("/", 1)[-1] == "curl"
        and any(value in {"-L", "--location"} for value in cmd)
        and curl_carries_credentials(cmd)
    )


# curl's own limit when --max-redirs is not given; a larger or unlimited (-1) value is held to it.
CURL_MAX_REDIRECTS = 50
# Marks where the caller's own write-out starts on stdout (the last occurrence: the response
# before it is the target's, and may contain anything).
_CURL_PROBE_SPLIT = "~~shakerscan-write-out-" + __import__("secrets").token_hex(8) + "~~"
_CURL_OPTIONS_WITH_VALUE = frozenset({"-c", "--cookie-jar", "--max-redirs"})


def _strip_location(cmd: list[str]) -> tuple[list[str], int, str | None]:
    """``cmd`` without ``-L``, ``--max-redirs`` and ``-c`` (the limit and the jar are returned)."""
    stripped: list[str] = []
    max_redirects = CURL_MAX_REDIRECTS
    jar = None
    skip_next = False
    for index, value in enumerate(cmd):
        if skip_next:
            skip_next = False
            continue
        if value in {"-L", "--location"}:
            continue
        if value in _CURL_OPTIONS_WITH_VALUE and index + 1 < len(cmd):
            skip_next = True
            if value == "--max-redirs":
                try:
                    limit = int(cmd[index + 1])
                except ValueError:
                    limit = CURL_MAX_REDIRECTS
                max_redirects = CURL_MAX_REDIRECTS if limit < 0 else min(limit, CURL_MAX_REDIRECTS)
            else:
                jar = str(cmd[index + 1])
            continue
        stripped.append(value)
    return stripped, max_redirects, jar


def _with_probe(cmd: list[str], url_index: int, url: str, extra: list[str]) -> list[str] | None:
    """Swap in ``url``, add ``extra`` options, and a write-out that marks where the caller's own
    write-out starts on stdout and reports the response code and redirect on stderr."""
    argv = list(cmd)
    argv[url_index] = url
    argv[url_index:url_index] = extra
    url_index += len(extra)
    probe = "%{stderr}\n" + _CURL_PROBE_MARK + "%{response_code} %{redirect_url}\n"
    for index in range(len(argv) - 1, 0, -1):
        if argv[index] in {"-w", "--write-out"} and index + 1 < len(argv):
            if str(argv[index + 1]).startswith("@"):
                return None
            argv[index + 1] = _CURL_PROBE_SPLIT + str(argv[index + 1]) + probe
            return argv
    return argv[:url_index] + ["-w", _CURL_PROBE_SPLIT + probe] + argv[url_index:]


def _split_probe(stderr: str) -> tuple[str, int, str]:
    status, location, kept = 0, "", []
    for line in str(stderr or "").splitlines():
        if line.startswith(_CURL_PROBE_MARK):
            code, _, redirect_url = line[len(_CURL_PROBE_MARK):].partition(" ")
            try:
                status = int(code)
            except ValueError:
                status = 0
            location = redirect_url.strip()
            continue
        kept.append(line)
    return "\n".join(kept).strip(), status, location


def _includes_headers(cmd: list[str]) -> bool:
    for index, value in enumerate(cmd):
        if value in {"-i", "--include", "-I", "--head"}:
            return True
        if value in {"-D", "--dump-header"} and index + 1 < len(cmd) and cmd[index + 1] == "-":
            return True
    return False


def _header_block(output: str) -> str:
    """The response's header block as curl prints it, ending in its blank line."""
    if not output:
        return ""
    for separator in ("\r\n\r\n", "\n\n"):
        position = output.find(separator)
        if position >= 0:
            return output[:position + len(separator)]
    # A headers-only response (-I, or an empty body) lost its blank line to the runner's strip.
    return output.rstrip("\r\n") + "\r\n\r\n"


def _without_request_body(cmd: list[str]) -> list[str]:
    kept: list[str] = []
    skip_next = False
    for value in cmd:
        if skip_next:
            skip_next = False
            continue
        if value in _CURL_DATA_OPTIONS:
            skip_next = True
            continue
        kept.append(value)
    return kept


def _last_url_index(cmd: list[str]) -> int:
    return max(
        (index for index, value in enumerate(cmd)
         if index > 0 and isinstance(value, str) and value.startswith(("http://", "https://"))),
        default=-1,
    )


def _shows_errors(cmd: list[str]) -> bool:
    silent = show = False
    for value in cmd[1:]:
        if value in {"--silent"}:
            silent = True
        elif value in {"--show-error"}:
            show = True
        elif value.startswith("-") and not value.startswith("--"):
            silent = silent or "s" in value[1:]
            show = show or "S" in value[1:]
    return show or not silent


RunHop = Callable[..., Awaitable[tuple[str, str, int]]]


async def run_curl_same_origin(cmd: list[str], run_hop: RunHop, *, timeout: int, **run_kwargs: Any) -> tuple[str, str, int]:
    """Run a session-carrying ``curl -L`` hop by hop, following only same-origin redirects.

    Each hop is an ordinary ``curl`` run without ``-L`` (metered and archived like any other
    request). On the request's origin the result is what ``curl -L`` gives: the header blocks of
    the followed hops when headers are printed, then the final response and the caller's
    write-out; a request body dropped after 301/302/303 (the ``-X`` method kept, ``--post30x``
    honoured) and kept after 307/308; cookies set along the way sent on the next hop and written
    to the ``-c`` jar; exit 47 past ``--max-redirs``. A redirect to another origin is returned
    as the response, not followed.
    """
    import os
    import shutil
    import tempfile

    base, max_redirects, user_jar = _strip_location(cmd)
    url_index = _last_url_index(base)
    if url_index < 0:
        return await run_hop(cmd, timeout=timeout, **run_kwargs)
    include_headers = _includes_headers(base)
    # curl's cookie engine (cookies received on one hop sent on the next) runs with a jar (-c)
    # or a cookie file (-b <file>); an inline -b string alone does not start it.
    cookie_engine = user_jar is not None or any(
        value in {"-b", "--cookie"} and index + 1 < len(base) and "=" not in str(base[index + 1])
        for index, value in enumerate(base)
    )
    jar = None
    if cookie_engine:
        handle, jar = tempfile.mkstemp(prefix="shakerscan-curl-", suffix=".jar")
        os.close(handle)
        os.unlink(jar)  # curl creates it the way it would create the caller's jar
    deadline = time.monotonic() + max(1, int(timeout))
    current_url = str(base[url_index])
    prefix: list[str] = []
    errors: list[str] = []

    def finish(text: str, rc: int, error: str = "") -> tuple[str, str, int]:
        if error:
            errors.append(error)
        if jar is not None:
            if user_jar is not None and os.path.exists(jar):
                if user_jar == "-":
                    with open(jar, encoding="utf-8", errors="ignore") as handle:
                        text = (text + handle.read()).strip()
                else:
                    shutil.copyfile(jar, user_jar)
            with contextlib.suppress(OSError):
                os.unlink(jar)
        return text, "\n".join(errors), rc

    try:
        for hop in range(max_redirects + 1):
            extra: list[str] = []
            if jar is not None:
                extra = (["-b", jar] if hop else []) + ["-c", jar]
            argv = _with_probe(base, url_index, current_url, extra)
            if argv is None:
                restored = list(cmd)
                restored[_last_url_index(restored)] = current_url
                out, err, rc = await run_hop(restored, timeout=timeout, **run_kwargs)
                return finish(out, rc, err)
            remaining = max(1, int(deadline - time.monotonic()))
            out, err, rc = await run_hop(argv, timeout=remaining, **run_kwargs)
            err, status, location = _split_probe(err)
            if err:
                errors.append(err)
            response, _, write_out = out.rpartition(_CURL_PROBE_SPLIT)
            if not _:
                response, write_out = out, ""
            follows = 300 <= status < 400 and bool(location)
            if rc != 0 or not follows:
                return finish(("".join(prefix) + response + write_out).strip(), rc)
            if hop == max_redirects:
                shown = _header_block(response) if include_headers else ""
                message = f"curl: (47) Maximum ({max_redirects}) redirects followed" if _shows_errors(cmd) else ""
                return finish(("".join(prefix) + shown + write_out).strip(), 47, message)
            if not same_credential_origin(current_url, location):
                return finish(("".join(prefix) + response + write_out).strip(), rc)
            if include_headers:
                prefix.append(_header_block(response))
            if status in (301, 302, 303) and f"--post{status}" not in base or "-G" in base or "--get" in base:
                base = _without_request_body(base)
                url_index = _last_url_index(base)
            current_url = urllib.parse.urljoin(current_url, location)
        return finish("".join(prefix).strip(), 1)  # pragma: no cover - the loop always returns
    except BaseException:
        if jar is not None:
            with contextlib.suppress(OSError):
                os.unlink(jar)
        raise


# --- browser contexts ------------------------------------------------------------------------
#
# Playwright's ``extra_http_headers`` add the headers to every request a page makes, other
# origins and redirect hops included, and a route that continues a request with extra headers
# carries them into its redirects too (redirect hops never reach a route handler). A context
# that carries session headers therefore fetches each request to the target's origin itself
# (``route.fetch`` with the context's cookies, proxy and TLS settings, redirects not followed),
# with the headers added, and hands the response to the page:
#
# - a non-redirect response is the response;
# - a redirect of a fetch, script or other subresource is followed here while it stays on the
#   origin, with the headers; a redirect elsewhere is returned for the browser to follow, and a
#   hop the browser follows carries no session header;
# - a redirect of a navigation is returned for the browser to follow (the page's URL must be
#   the URL that answered). Its next hop has the context's cookies but not the session header.
#
# Requests to any other origin are passed on untouched. Cookies keep their own domain scoping.

_BROWSER_DROPPED_ON_REWRITE = frozenset({"content-type", "content-length"})

# What keeping the headers on the origin costs, recorded so a result never hides it:
SESSION_HEADER_DROPPED_ON_NAVIGATION_REDIRECT = "session_header_dropped_on_navigation_redirect"
PRIVATE_NETWORK_SUBRESOURCE_BLOCKED = "private_network_subresource_blocked"
# Chromium's Local Network Access refusal, as its console reports it.
_LOCAL_NETWORK_REFUSAL = re.compile(r"Permission was denied for this request to access the `\w+` address space")


class SessionHeaderEvents:
    """Counts of the two things a session-header route cannot do, for coverage and receipts:

    - ``session_header_dropped_on_navigation_redirect``: a page on the origin redirected a
      navigation within the origin; the next page was loaded with cookies but without the
      session header;
    - ``private_network_subresource_blocked``: a target page delivered by the route asked for a
      resource from another origin on a private or loopback address, and Chromium's Local
      Network Access check refused it.
    """

    def __init__(self) -> None:
        self.counts: dict[str, int] = {
            SESSION_HEADER_DROPPED_ON_NAVIGATION_REDIRECT: 0, PRIVATE_NETWORK_SUBRESOURCE_BLOCKED: 0,
        }

    def record(self, reason: str) -> None:
        self.counts[reason] = self.counts.get(reason, 0) + 1

    def reasons(self) -> list[str]:
        return sorted(reason for reason, count in self.counts.items() if count)

    def as_dict(self) -> dict[str, Any]:
        return {"reasons": self.reasons(), "counts": {k: v for k, v in self.counts.items() if v}}

    def observe_console(self, message: Any) -> None:
        try:
            text = str(message.text)
        except Exception:  # a console message that cannot be read records nothing
            return
        if _LOCAL_NETWORK_REFUSAL.search(text):
            self.record(PRIVATE_NETWORK_SUBRESOURCE_BLOCKED)


def add_session_header_reasons(coverage: dict[str, Any], recorded: Any) -> None:
    """List recorded session-header reasons (and their counts) on a coverage block. They
    describe what the authenticated browser could not do; they change no status."""
    if not isinstance(coverage, dict) or not isinstance(recorded, dict):
        return
    reasons = [str(item) for item in recorded.get("reasons") or [] if str(item)]
    if not reasons:
        return
    coverage["reasons"] = sorted(set(coverage.get("reasons") or []) | set(reasons))
    counts = coverage.setdefault("browser_session_headers", {})
    for reason, count in dict(recorded.get("counts") or {}).items():
        counts[str(reason)] = int(counts.get(str(reason), 0)) + int(count or 0)


async def _browser_fetch(route: Any, request: Any, headers: dict[str, str], origin: tuple[str, str, int] | None,
                         origins: frozenset, events: SessionHeaderEvents, *,
                         overrides: dict[str, Any] | None = None, on_hop: Callable[[], bool] | None = None) -> Any:
    overrides = dict(overrides or {})
    response = await route.fetch(headers=headers, max_redirects=0, **overrides)
    if request.is_navigation_request():
        location = response.headers.get("location")
        if 300 <= response.status < 400 and location:
            if origin_key(urllib.parse.urljoin(request.url, location.strip())) in origins:
                events.record(SESSION_HEADER_DROPPED_ON_NAVIGATION_REDIRECT)
        return response
    url, method = request.url, str(overrides.get("method") or request.method).upper()
    for _hop in range(DEFAULT_MAX_REDIRECTS):
        location = response.headers.get("location")
        if response.status not in REDIRECT_STATUSES or not location:
            return response
        next_url = urllib.parse.urljoin(url, location.strip())
        if origin_key(next_url) not in origins or (on_hop is not None and not on_hop()):
            return response
        next_method = redirect_method(method, response.status)
        options: dict[str, Any] = {"url": next_url, "method": next_method, "max_redirects": 0}
        if next_method != method:
            headers = {k: v for k, v in headers.items() if k.lower() not in _BROWSER_DROPPED_ON_REWRITE}
            options["post_data"] = b""
        elif "post_data" in overrides:
            options["post_data"] = overrides["post_data"]
        await response.dispose()
        response = await route.fetch(headers=headers, **options)
        url, method = next_url, next_method
    return response


async def fulfill_with_session_headers(route: Any, request: Any, headers: Mapping[str, str], origins: Any,
                                       events: SessionHeaderEvents, *, on_hop: Callable[[], bool] | None = None,
                                       **overrides: Any) -> None:
    """Answer a routed request to the bound origin with session ``headers`` (see above):
    fetched without following redirects, redirects within ``origins`` followed here for a
    subresource (``on_hop`` may refuse another hop), and the response handed to the page.
    ``overrides`` (method, post_data) apply to the first request only."""
    try:
        response = await _browser_fetch(
            route, request, dict(headers), origin_key(request.url), frozenset(origins), events,
            overrides=overrides, on_hop=on_hop,
        )
    except Exception:  # the request failed as it would have in the browser
        await route.abort("failed")
        return
    await route.fulfill(response=response)


def bound_origins(origin_urls: Any) -> set[tuple[str, str, int]]:
    """The origins of ``origin_urls``, each http origin on port 80 with its https upgrade."""
    origins: set[tuple[str, str, int]] = set()
    for url in origin_urls:
        key = origin_key(url)
        if key is None:
            continue
        origins.add(key)
        if key[0] == "http" and key[2] == 80:
            origins.add(("https", key[1], 443))
    return origins


async def bind_session_headers(context: Any, origin_urls: Any, headers: Any) -> SessionHeaderEvents:
    """Send ``headers`` (a mapping, or a callable returning the current one) with a context's
    requests to the origins of ``origin_urls`` only (see above). Register it before any other
    route of the context: those hand a request on with ``route.fallback()``. The returned
    events count what the route could not do, for the caller's coverage."""
    origins = frozenset(bound_origins(origin_urls))
    events = SessionHeaderEvents()
    with contextlib.suppress(Exception):
        context.on("console", events.observe_console)

    async def handler(route: Any, request: Any) -> None:
        current = headers() if callable(headers) else headers
        origin = origin_key(request.url)
        if not current or origin is None or origin not in origins:
            await route.fallback()
            return
        merged = dict(await request.all_headers())
        lowered = {str(name).lower() for name in current}
        merged = {name: value for name, value in merged.items() if name.lower() not in lowered}
        merged.update({str(name): str(value) for name, value in dict(current).items()})
        await fulfill_with_session_headers(route, request, merged, origins, events)

    await context.route("**/*", handler)
    return events
