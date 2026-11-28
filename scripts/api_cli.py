#!/usr/bin/env python3
"""One way to call the ShakerScan API from an agent session: `shakerscan api METHOD PATH [JSON]`.

The agent kit (AGENTS.md, .claude/commands, skills) uses this instead of raw curl so the same
instructions work against a local engine and against a remote, authenticating instance such
as ShakerScan Enterprise: the helper knows the base URL and the credential, sends a bearer token
only over HTTPS, prints the JSON answer, and on an error prints the instance's own message (a
gateway refusal names what is missing) and exits 1.

Base URL: --api-url, else SHAKERSCAN_API_BASE, else SHAKERSCAN_API_URL, else http://127.0.0.1:8080.
Token:    SHAKERSCAN_API_TOKEN_FILE (a file, preferred) or SHAKERSCAN_API_TOKEN; never printed.

A person's decision (person_decision_routes.py: allowing a Hunt permission request, authorizing a
target, dismissing a finding, recording an approval, revealing a secret, approving an access-control
contract, ...) is never sent from inside an agent that `shakerscan agent` launched
(SHAKERSCAN_AGENT_NAME), nor from anywhere that is not a person's terminal (stdin and stdout both
terminals: an agent started without the launcher runs this from its shell tool, which has none):
the helper prints the command the person runs in their own terminal and exits 3 with nothing sent.
A person's own script, which has no terminal either, says so with SHAKERSCAN_PERSON_SCRIPT=1
(docs/agent-mcp-setup.md); inside a launched agent that changes nothing. On an open-source engine
without authentication all of this is a guard rail for an agent following its kit, not a security
boundary (any process on the host can call the API directly); ShakerScan Enterprise enforces
person decisions on the server.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_API_URL = "http://127.0.0.1:8080"
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
# An error body is only shown as the instance's message, so a short read of it is enough.
MAX_ERROR_BYTES = 64 * 1024
# The longest request body read from a file (`@FILE`).
MAX_BODY_FILE_BYTES = 8 * 1024 * 1024


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


#: The public API's retry key (api/public_api_contract.py): 8-200 safe characters.
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,199}$")


def build_request(
    method: str, path: str, body: str | None, *, api_url: str, token: str | None,
    idempotency_key: str | None = None,
) -> urllib.request.Request:
    method = method.upper()
    if method not in METHODS:
        raise ApiCliError(f"method must be one of {', '.join(METHODS)}")
    if not path.startswith("/"):
        path = "/" + path
    # Only the path part can name another origin; a query may carry a URL as a value
    # (GET /targets/lookup?url=https://app.example). The request always goes to api_url + path.
    if "://" in path.split("?", 1)[0]:
        raise ApiCliError("give a path such as /findings?limit=20, not a full URL")
    if token and not api_url.startswith("https://"):
        raise ApiCliError("a token is only ever sent over https://; the API URL is plain http")
    headers = {"Accept": "application/json", "User-Agent": "shakerscan-api-cli"}
    data = None
    if body is not None and body.startswith("@"):
        # `@FILE`: the body is read from a file (a JSON text never starts with "@"), as the
        # command a person is given for a request too long to name inline. Only from the
        # directory the client saves those in: any other file a person could be talked into
        # naming (a registry login, a cloud key) would become the request's body.
        where = _decision_body_file(body[1:])
        try:
            with open(where, "rb") as handle:
                raw = handle.read(MAX_BODY_FILE_BYTES + 1)
        except OSError as exc:
            raise ApiCliError(f"cannot read the request body from {body[1:]}: {exc.strerror or exc}") from exc
        if len(raw) > MAX_BODY_FILE_BYTES:
            raise ApiCliError("the request body file is larger than 8 MiB")
        body = raw.decode("utf-8", "replace")
    if body is not None:
        try:
            parsed = json.loads(body)
        except ValueError as exc:
            raise ApiCliError(f"the request body must be JSON: {exc}") from exc
        data = json.dumps(parsed, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if idempotency_key is not None:
        # A write that timed out on the client side may still have run (a 50-target Scan batch
        # outlived a 120 s client timeout): the same key replays its stored answer, with every
        # per-target error, instead of running it again.
        if method in {"GET", "HEAD", "OPTIONS"}:
            raise ApiCliError("--idempotency-key applies to POST, PUT, PATCH and DELETE")
        if not IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key):
            raise ApiCliError("--idempotency-key must be 8 to 200 characters (letters, digits, _ . : -), "
                              "starting with a letter or digit")
        headers["Idempotency-Key"] = idempotency_key
    if token:
        headers["Authorization"] = "Bearer " + token
    return urllib.request.Request(api_url + path, data=data, headers=headers, method=method)


def _decision_body_file(name: str) -> str:
    """The real path of an ``@FILE`` body inside the client's decisions directory
    (person_decision.decisions_directory), links and ``..`` resolved; ApiCliError otherwise."""
    directory = os.path.realpath(_person_decision().decisions_directory())
    where = os.path.realpath(os.path.expanduser(name))
    if os.path.dirname(where) != directory:
        raise ApiCliError(
            f"shakerscan api reads a request body only from {directory} (@FILE), where the client "
            "saves a decision's body too long to show; give any other JSON body inline"
        )
    return where


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never replay an authenticated request against another origin.

    The https:// guard above only covers the URL the operator supplied. Following a
    redirect with urllib's default handler re-sends the Authorization header to
    whatever Location names -- another host, or plain HTTP. Refuse instead, and let
    the caller surface the 3xx.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect())


def call(request: urllib.request.Request, *, opener=None, timeout: float = 60.0,
         headers_out: dict | None = None) -> tuple[int, str]:
    """``(status, text)``; ``headers_out``, when given, receives an error answer's headers."""
    opener = opener or _opener()
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                # A JSON answer cut at the cap is not JSON, and printing its first part as the
                # answer read as "this is all there is". Refuse it and say how to ask for less.
                raise ApiCliError(
                    f"the answer is larger than {MAX_RESPONSE_BYTES // (1024 * 1024)} MiB and was not printed; "
                    "ask for less: a list takes limit= and the next_cursor of the previous page "
                    "(cursor=), and fields= or a narrower filter where the endpoint has one"
                )
            return response.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            # D17: name where the instance is and the client option that points there (the
            # internal --api-url is not a flag anyone types).
            try:
                from redirect_hint import redirect_explanation
            except ModuleNotFoundError:
                from scripts.redirect_hint import redirect_explanation
            location = exc.headers.get("Location") if exc.headers is not None else None
            raise ApiCliError(redirect_explanation(exc.code, location, request.full_url)) from exc
        if headers_out is not None and exc.headers is not None:
            headers_out.update({key.lower(): value for key, value in exc.headers.items()})
        return exc.code, exc.read(MAX_ERROR_BYTES).decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        try:
            from redirect_hint import with_certificate_hint
        except ModuleNotFoundError:
            from scripts.redirect_hint import with_certificate_hint
        reason = getattr(exc, "reason", exc)
        raise ApiCliError(with_certificate_hint(f"cannot reach {request.full_url}: {reason}", reason)) from exc


def detail_text(detail: dict) -> str:
    """One error object as a reader acts on it: its message, or its code with the violation it
    names (``{"error": "invalid_workflow", "violation": ...}`` printed only the code), and its
    next step (a credential refusal's ``attach``)."""
    def text(key: str) -> str:
        value = detail.get(key)
        return value.strip() if isinstance(value, str) else ""
    said = text("message")
    if not said:
        error, violation = text("error"), text("violation")
        said = f"{error}: {violation}" if error and violation and error not in violation else violation or error
    attach = text("attach")
    if attach and attach not in said:
        said = f"{said} {attach}".strip()
    return said or json.dumps(detail)


def render(status: int, text: str) -> tuple[str, int]:
    """Pretty JSON on success; on an error the instance's own detail, exit 1."""
    try:
        parsed = json.loads(text) if text.strip() else None
    except ValueError:
        parsed = None
    if status < 300:
        return (json.dumps(parsed, indent=2, sort_keys=False) if parsed is not None else text), 0
    detail = parsed.get("detail") if isinstance(parsed, dict) else None
    if isinstance(detail, dict):
        detail = detail_text(detail)
    if isinstance(detail, list):
        detail = "; ".join(validation_error_text(item) for item in detail)
    return f"HTTP {status}: {detail or text.strip() or 'no detail'}", 1


def validation_error_text(item: object) -> str:
    """One validation error as ``field: message`` (D48: "Field required" named no field). The
    rejected input the error echoes is never printed."""
    if not isinstance(item, dict):
        return str(item)
    where = ".".join(str(part) for part in item.get("loc") or () if part != "body")
    said = str(item.get("msg") or "invalid value")
    return f"{where}: {said}" if where else said


def _person_decision():
    try:
        import person_decision
    except ModuleNotFoundError:
        from scripts import person_decision
    return person_decision


def _person_decision_routes():
    try:
        import person_decision_routes
    except ModuleNotFoundError:
        from scripts import person_decision_routes
    return person_decision_routes


def agent_session(environ: dict[str, str] | None = None) -> bool:
    """Inside an agent that ``shakerscan agent`` launched: the signal every command that asks the
    person reads (hunt_approve.person_at_terminal)."""
    environ = os.environ if environ is None else environ
    return bool((environ.get("SHAKERSCAN_AGENT_NAME") or "").strip())


#: Set to 1 by a person for their own script (cron, CI, a pipe): the script, which has no terminal,
#: sends the person's decisions it was written to send. Named for what it asserts. It never applies
#: inside an agent that ``shakerscan agent`` launched.
PERSON_SCRIPT_ENV = "SHAKERSCAN_PERSON_SCRIPT"


def person_terminal(stdin: object = None, stdout: object = None) -> bool:
    """A person's terminal: stdin and stdout are both terminals (hunt_approve.person_at_terminal
    asks the same of the commands that prompt). An agent's shell tool has neither."""
    def is_tty(stream: object) -> bool:
        try:
            return bool(stream is not None and stream.isatty())
        except (AttributeError, ValueError):
            return False
    return is_tty(sys.stdin if stdin is None else stdin) and is_tty(sys.stdout if stdout is None else stdout)


def person_script(environ: dict[str, str] | None = None) -> bool:
    """The person stated that this call without a terminal is their own script."""
    environ = os.environ if environ is None else environ
    return (environ.get(PERSON_SCRIPT_ENV) or "").strip().lower() in {"1", "true", "yes"}


def agent_refusal(request: urllib.request.Request, path: str, api_url: str,
                  environ: dict[str, str] | None = None, *, terminal: bool | None = None) -> str | None:
    """The line an agent gets instead of sending a person's decision, or None to send the
    request. The body read is the one that would be sent (parsed and serialized once, so a
    repeated key cannot hide the decision).

    A person's decision is sent only from a person: never inside an agent ``shakerscan agent``
    launched, and otherwise only from a terminal (``terminal``; read from stdin and stdout when
    None) or from a script the person marked as theirs (PERSON_SCRIPT_ENV). An agent started
    without the launcher carries no signal, but its shell tool has no terminal."""
    routes = _person_decision_routes()
    if agent_session(environ):
        return routes.refusal(request.get_method(), path, request.data, api_url=api_url)
    if routes.match(request.get_method(), path, request.data) is None:
        return None
    if (person_terminal() if terminal is None else terminal) or person_script(environ):
        return None
    return routes.refusal(request.get_method(), path, request.data, api_url=api_url, no_terminal=True)


def with_person_decision(request: urllib.request.Request, api_url: str, token: str | None, *,
                         timeout: float, sender=None) -> tuple[int, str]:
    """Send ``request``; when an Enterprise gateway refuses it for a person's security-key touch,
    complete the touch in the person's own terminal and send it again once (person_decision.py).
    Without a terminal, PersonDecisionRefused (exit 3). ``sender`` defaults to this module's
    ``call`` as it is when the request is sent."""
    call = sender or globals()["call"]
    seen: dict = {}
    status, text = call(request, timeout=timeout, headers_out=seen)
    decision = _person_decision()
    detail = decision.detail_of(text)
    if not decision.required(status, seen, detail):
        return status, text
    parts = urllib.parse.urlsplit(api_url)

    def resend(grant: str) -> tuple[int, str]:
        again = urllib.request.Request(request.full_url, data=request.data, method=request.get_method(),
                                       headers={**dict(request.header_items()), decision.PROOF_HEADER: grant})
        return call(again, timeout=timeout)

    return decision.handle(
        decision.json_poster(api_url, token), origin=f"{parts.scheme}://{parts.netloc}",
        method=request.get_method(), path=request.selector, body=request.data or b"", detail=detail, resend=resend,
        gateway=api_url,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shakerscan api",
        description="Call the ShakerScan API: METHOD PATH [JSON body]. Prints the JSON answer.",
    )
    parser.add_argument("--api-url", help=argparse.SUPPRESS)
    parser.add_argument("--timeout", type=float, default=60.0, help="seconds (default 60)")
    parser.add_argument("--stream", action="store_true", help="print SSE events as they arrive; never retry")
    parser.add_argument("--idempotency-key", metavar="KEY",
                        help="retry key for a write: sending it again with the same key and body returns the "
                             "first answer instead of running the request twice (e.g. POST /scans/batch)")
    parser.add_argument("method", help="GET, POST, PUT, PATCH or DELETE")
    parser.add_argument("path", help="the API path, with query string if any, e.g. /findings?limit=20")
    parser.add_argument("body", nargs="?", help="a JSON object for POST, PUT or PATCH, or @FILE to read it from a file")
    args = parser.parse_args(argv)
    try:
        api_url = base_url(args.api_url)
        request = build_request(args.method, args.path, args.body, api_url=api_url, token=bearer_token(),
                                idempotency_key=args.idempotency_key)
        refused = agent_refusal(request, args.path, api_url)
        if refused is not None:
            print(f"shakerscan api: {refused}", file=sys.stderr)
            return _person_decision().EXIT_REFUSED
        if args.stream:
            from api_stream import stream_response
            try:
                return stream_response(request, opener=_opener(), timeout=args.timeout)
            except urllib.error.HTTPError as exc:
                output, code = render(exc.code, exc.read(MAX_ERROR_BYTES).decode('utf-8', 'replace'))
                print(output, file=sys.stderr)
                return code
            except (ValueError, OSError, urllib.error.URLError) as exc:
                raise ApiCliError(str(exc)) from exc
        token = bearer_token()
        status, text = with_person_decision(request, api_url, token, timeout=args.timeout)
    except ApiCliError as exc:
        print(f"shakerscan api: {exc}", file=sys.stderr)
        return 2
    except _person_decision().PersonDecisionRefused as exc:
        # An agent's tool call: never a prompt, never a key; the person runs the command.
        print(f"shakerscan api: {exc.line}", file=sys.stderr)
        return _person_decision().EXIT_REFUSED
    except _person_decision().PersonDecisionCancelled as exc:
        print(f"shakerscan api: {exc}", file=sys.stderr)
        return _person_decision().EXIT_CANCELLED
    except _person_decision().PersonDecisionError as exc:
        print(f"shakerscan api: {exc}", file=sys.stderr)
        return 1
    output, code = render(status, text)
    print(output, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main())
