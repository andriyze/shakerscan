"""Requests that carry session credentials follow redirects only on their own origin.

httpx, aiohttp, urllib and curl drop ``Authorization`` and ``Cookie`` when a redirect
changes host, but they copy every other request header to the next hop. A scan
authenticated with an API key header (``X-API-Key``, ``X-Auth-Token`` ...) or a bound
browser-session header would hand that value to whatever origin the target names in a
``Location`` header.

The rule here matches the capability layer's ``credential_destination`` stop: a request
carrying session material follows a redirect only while the next hop has the same scheme,
host and port. Any other redirect is not followed; the caller receives the redirect
response itself. Requests without session material keep the client's normal behaviour.
"""

from __future__ import annotations

import contextlib
import time
import urllib.parse
from collections.abc import AsyncIterator, Awaitable, Callable
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

_CURL_CREDENTIAL_OPTIONS = frozenset({
    "-b", "--cookie", "-u", "--user", "--oauth2-bearer", "-E", "--cert", "--aws-sigv4",
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
    """Whether session credentials may accompany a redirect from ``current_url``."""
    current = origin_key(current_url)
    return current is not None and current == origin_key(urllib.parse.urljoin(str(current_url), str(next_url)))


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
    """Send through an ``httpx.AsyncClient``, following only same-origin redirects."""
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


def curl_carries_credentials(cmd: list[str]) -> bool:
    """Whether a curl argv sends session material (credential headers, cookies, user)."""
    args = list(cmd[1:])
    for index, value in enumerate(args):
        if not isinstance(value, str):
            continue
        if value in {"-H", "--header"} and index + 1 < len(args):
            if is_session_header(_curl_header_name(str(args[index + 1]))):
                return True
        elif value.startswith("-H") and len(value) > 2 and not value.startswith("--"):
            if is_session_header(_curl_header_name(value[2:])):
                return True
        elif value in _CURL_CREDENTIAL_OPTIONS:
            return True
    return False


def curl_follows_with_credentials(cmd: list[str]) -> bool:
    return (
        bool(cmd)
        and str(cmd[0]).rsplit("/", 1)[-1] == "curl"
        and any(value in {"-L", "--location"} for value in cmd)
        and curl_carries_credentials(cmd)
    )


def _strip_location(cmd: list[str]) -> tuple[list[str], int]:
    stripped: list[str] = []
    max_redirects = DEFAULT_MAX_REDIRECTS
    skip_next = False
    for index, value in enumerate(cmd):
        if skip_next:
            skip_next = False
            continue
        if value in {"-L", "--location"}:
            continue
        if value == "--max-redirs":
            skip_next = True
            try:
                max_redirects = max(0, min(int(cmd[index + 1]), 50))
            except (IndexError, ValueError):
                pass
            continue
        stripped.append(value)
    return stripped, max_redirects


def _with_probe(cmd: list[str], url_index: int, url: str) -> list[str] | None:
    """Swap in ``url`` and add a write-out that reports the redirect on stderr."""
    argv = list(cmd)
    argv[url_index] = url
    probe = "%{stderr}\n" + _CURL_PROBE_MARK + "%{response_code} %{redirect_url}\n"
    for index in range(len(argv) - 1, 0, -1):
        if argv[index] in {"-w", "--write-out"} and index + 1 < len(argv):
            if str(argv[index + 1]).startswith("@"):
                return None
            argv[index + 1] = str(argv[index + 1]) + probe
            return argv
    return argv[:url_index] + ["-w", probe] + argv[url_index:]


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
    for separator in ("\r\n\r\n", "\n\n"):
        position = output.find(separator)
        if position >= 0:
            return output[:position + len(separator)]
    return output


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


RunHop = Callable[..., Awaitable[tuple[str, str, int]]]


async def run_curl_same_origin(cmd: list[str], run_hop: RunHop, *, timeout: int, **run_kwargs: Any) -> tuple[str, str, int]:
    """Run a credential-carrying ``curl -L`` hop by hop, following only same-origin redirects.

    Each hop is an ordinary ``curl`` run without ``-L`` (so it is metered and archived like
    any other request). The output matches what ``curl -L`` prints: the header blocks of
    the followed hops when headers are included, then the final hop's output.
    """
    base, max_redirects = _strip_location(cmd)
    url_index = _last_url_index(base)
    if url_index < 0:
        return await run_hop(base, timeout=timeout, **run_kwargs)
    include_headers = _includes_headers(base)
    method_forced = any(value in {"-X", "--request"} for value in base)
    deadline = time.monotonic() + max(1, int(timeout))
    current_url = str(base[url_index])
    prefix: list[str] = []
    errors: list[str] = []
    for hop in range(max_redirects + 1):
        argv = _with_probe(base, url_index, current_url)
        if argv is None:
            base[url_index] = current_url
            return await run_hop(base, timeout=timeout, **run_kwargs)
        remaining = max(1, int(deadline - time.monotonic()))
        out, err, rc = await run_hop(argv, timeout=remaining, **run_kwargs)
        err, status, location = _split_probe(err)
        if err:
            errors.append(err)
        if (
            rc != 0
            or status not in REDIRECT_STATUSES
            or not location
            or hop == max_redirects
            or not same_credential_origin(current_url, location)
        ):
            return "".join(prefix) + out, "\n".join(errors), rc
        if include_headers:
            prefix.append(_header_block(out))
        if not method_forced and status in (301, 302, 303):
            base = _without_request_body(base)
            url_index = _last_url_index(base)
        current_url = urllib.parse.urljoin(current_url, location)
    return "".join(prefix), "\n".join(errors), 1  # pragma: no cover - the loop always returns
