#!/usr/bin/env python3
"""One way to call the ShakerScan API from an agent session: `shakerscan api METHOD PATH [JSON]`.

The agent kit (AGENTS.md, .claude/commands, skills) uses this instead of raw curl so the same
instructions work against a local engine and against a remote, authenticating instance such
as ShakerScan Enterprise: the helper knows the base URL and the credential, sends a bearer token
only over HTTPS, prints the JSON answer, and on an error prints the instance's own message (a
gateway refusal names what is missing) and exits 1.

Base URL: --api-url, else SHAKERSCAN_API_BASE, else SHAKERSCAN_API_URL, else http://127.0.0.1:8080.
Token:    SHAKERSCAN_API_TOKEN_FILE (a file, preferred) or SHAKERSCAN_API_TOKEN; never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_API_URL = "http://127.0.0.1:8080"
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class ApiCliError(RuntimeError):
    pass


def base_url(explicit: str | None, environ: dict[str, str] | None = None) -> str:
    environ = os.environ if environ is None else environ
    raw = (
        explicit
        or environ.get("SHAKERSCAN_API_BASE")
        or environ.get("SHAKERSCAN_API_URL")
        or DEFAULT_API_URL
    ).strip().rstrip("/")
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ApiCliError("the API URL must be an http(s) origin")
    return raw


def bearer_token(environ: dict[str, str] | None = None) -> str | None:
    """The credential, from a file by preference so it never has to sit in the environment."""
    environ = os.environ if environ is None else environ
    path = environ.get("SHAKERSCAN_API_TOKEN_FILE", "").strip()
    if path:
        try:
            with open(path, encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as exc:
            raise ApiCliError(f"cannot read SHAKERSCAN_API_TOKEN_FILE: {exc.strerror or exc}") from exc
    else:
        token = environ.get("SHAKERSCAN_API_TOKEN", "").strip()
    if not token:
        return None
    if len(token) > 4096 or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in token):
        raise ApiCliError("the API token must be printable ASCII without spaces")
    return token


def build_request(
    method: str, path: str, body: str | None, *, api_url: str, token: str | None
) -> urllib.request.Request:
    method = method.upper()
    if method not in METHODS:
        raise ApiCliError(f"method must be one of {', '.join(METHODS)}")
    if not path.startswith("/"):
        path = "/" + path
    if "://" in path:
        raise ApiCliError("give a path such as /findings?limit=20, not a full URL")
    if token and not api_url.startswith("https://"):
        raise ApiCliError("a token is only ever sent over https://; the API URL is plain http")
    headers = {"Accept": "application/json", "User-Agent": "shakerscan-api-cli"}
    data = None
    if body is not None:
        try:
            parsed = json.loads(body)
        except ValueError as exc:
            raise ApiCliError(f"the request body must be JSON: {exc}") from exc
        data = json.dumps(parsed, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    return urllib.request.Request(api_url + path, data=data, headers=headers, method=method)


def call(request: urllib.request.Request, *, opener=None, timeout: float = 60.0) -> tuple[int, str]:
    opener = opener or urllib.request.build_opener()
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(MAX_RESPONSE_BYTES).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_RESPONSE_BYTES).decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ApiCliError(f"cannot reach {request.full_url}: {getattr(exc, 'reason', exc)}") from exc


def render(status: int, text: str) -> tuple[str, int]:
    """Pretty JSON on success; on an error the instance's own detail, exit 1."""
    try:
        parsed = json.loads(text) if text.strip() else None
    except ValueError:
        parsed = None
    if status < 400:
        return (json.dumps(parsed, indent=2, sort_keys=False) if parsed is not None else text), 0
    detail = parsed.get("detail") if isinstance(parsed, dict) else None
    if isinstance(detail, dict):
        detail = detail.get("message") or detail.get("error") or json.dumps(detail)
    if isinstance(detail, list):
        detail = "; ".join(str(item.get("msg") or item) if isinstance(item, dict) else str(item) for item in detail)
    return f"HTTP {status}: {detail or text.strip() or 'no detail'}", 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shakerscan api",
        description="Call the ShakerScan API: METHOD PATH [JSON body]. Prints the JSON answer.",
    )
    parser.add_argument("--api-url", help=argparse.SUPPRESS)
    parser.add_argument("--timeout", type=float, default=60.0, help="seconds (default 60)")
    parser.add_argument("method", help="GET, POST, PUT, PATCH or DELETE")
    parser.add_argument("path", help="the API path, with query string if any, e.g. /findings?limit=20")
    parser.add_argument("body", nargs="?", help="a JSON object for POST, PUT or PATCH")
    args = parser.parse_args(argv)
    try:
        api_url = base_url(args.api_url)
        request = build_request(args.method, args.path, args.body, api_url=api_url, token=bearer_token())
        status, text = call(request, timeout=args.timeout)
    except ApiCliError as exc:
        print(f"shakerscan api: {exc}", file=sys.stderr)
        return 2
    output, code = render(status, text)
    print(output, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main())
