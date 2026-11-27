"""One grammar for operator-declared known endpoints.

A known endpoint is one line: an optional HTTP method, a path (or an absolute http(s) URL) and an
optional body or parameter spec::

    GET /api/users
    GET /api/users id,name              -> GET /api/users?id=&name=
    POST /api/login username,password   -> POST /api/login json:{"username":"","password":""}
    POST /api/login username=alice      -> POST /api/login json:{"username":"alice"}
    POST /api/search json:{"query":"test"}
    POST /api/login form:user=a&pass=b
    POST /hub/login form:username,password  -> POST /hub/login form:username=&password=
    POST /hub/login form:username=,password= -> POST /hub/login form:username=&password=

A bare field list on a body method is a JSON body (kept for compatibility with every stored
seed). An HTML form posts ``application/x-www-form-urlencoded``, so a form login is declared with
``form:``, which takes either a query string or the same field list. Before, ``form:`` read only a
query string: ``form:username,password`` was refused and ``form:username=,password=`` became the
single field ``username`` with the value ``,password=`` (soak N54, where the documented field list
probed honey's HTML sign-in form as a JSON API).

The New Scan form documented the field-list form while the Scan surface manifest understood only
``json:`` and ``form:``; everything after the path was kept as path text, so
``POST /api/v1/agent/run task`` was stored as the route ``/api/v1/agent/run task`` and never
produced a candidate. Every consumer now reads the canonical form this module emits, and a line it
cannot read is refused at submission instead of being stored as a path.
"""

from __future__ import annotations

import json
import re
import urllib.parse

KNOWN_ENDPOINT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})
BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})
MAX_KNOWN_ENDPOINT_LENGTH = 8_192
KNOWN_ENDPOINT_SYNTAX = (
    "METHOD /path, optionally followed by field names (a,b) or name=value pairs (a JSON body "
    "on POST/PUT/PATCH, a query on GET), json:{...}, or form:a,b / form:a=1&b=2 for an HTML form"
)

_FIELD_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-\[\]]{0,199}$")
# ``form:a=1,b=2``: a comma (or space) followed by another ``name=`` separates fields. A comma
# inside one value (``form:q=a,b``) still reads as part of the query string, as before.
_FORM_FIELD_LIST_SEPARATOR = re.compile(r"[,\s]\s*[A-Za-z_][A-Za-z0-9_.\-\[\]]{0,199}=")


class KnownEndpointSyntaxError(ValueError):
    """A declared endpoint line that cannot be read as method, path and body spec.

    The message never repeats the line: a declared query may carry a secret.
    """


def _field_pairs(spec: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for token in re.split(r"[,\s]+", spec):
        if not token:
            continue
        name, separator, value = token.partition("=")
        if not _FIELD_NAME.fullmatch(name):
            raise KnownEndpointSyntaxError(
                f"unreadable field name after the path; expected {KNOWN_ENDPOINT_SYNTAX}"
            )
        pairs.append((name, value if separator else ""))
    if not pairs:
        raise KnownEndpointSyntaxError(f"empty field list; expected {KNOWN_ENDPOINT_SYNTAX}")
    return pairs


def normalize_known_endpoint(value: object) -> str:
    """Return the canonical ``METHOD path [json:{...}|form:...]`` line for one declaration."""
    if not isinstance(value, str):
        raise KnownEndpointSyntaxError("a known endpoint must be a string")
    text = value.strip()
    if not text:
        raise KnownEndpointSyntaxError("a known endpoint must not be empty")
    if len(text) > MAX_KNOWN_ENDPOINT_LENGTH:
        raise KnownEndpointSyntaxError(
            f"a known endpoint must not exceed {MAX_KNOWN_ENDPOINT_LENGTH} characters"
        )
    pieces = text.split(None, 1)
    method = "GET"
    if pieces[0].upper() in KNOWN_ENDPOINT_METHODS:
        method = pieces[0].upper()
        if len(pieces) == 1:
            raise KnownEndpointSyntaxError(f"a method needs a path; expected {KNOWN_ENDPOINT_SYNTAX}")
        text = pieces[1].strip()
    path, _, spec = text.partition(" ")
    path = path.strip()
    spec = spec.strip()
    lowered = path.lower()
    if not (
        (path.startswith("/") and not path.startswith("//"))
        or lowered.startswith(("http://", "https://"))
    ):
        raise KnownEndpointSyntaxError(
            f"a known endpoint path must start with / or http(s)://; expected {KNOWN_ENDPOINT_SYNTAX}"
        )
    if not spec:
        return f"{method} {path}"
    marker = spec[:5].lower()
    if marker == "json:":
        try:
            body = json.loads(spec[5:].strip())
        except (TypeError, ValueError):
            raise KnownEndpointSyntaxError("the json: body is not valid JSON") from None
        if not isinstance(body, (dict, list)):
            raise KnownEndpointSyntaxError("the json: body must be a JSON object or array")
        return f"{method} {path} json:{json.dumps(body, separators=(',', ':'), ensure_ascii=False)}"
    if marker == "form:":
        body_text = spec[5:].strip()
        if body_text and "&" not in body_text and (
            "=" not in body_text or _FORM_FIELD_LIST_SEPARATOR.search(body_text)
        ):
            # The field-list spelling of a form body: canonicalize it to the query string.
            body_text = urllib.parse.urlencode(_field_pairs(body_text))
        try:
            pairs = urllib.parse.parse_qsl(
                body_text, keep_blank_values=True, strict_parsing=True, max_num_fields=128,
            )
        except ValueError:
            raise KnownEndpointSyntaxError("the form: body is not a name=value&... list") from None
        if not pairs:
            raise KnownEndpointSyntaxError("the form: body is empty")
        return f"{method} {path} form:{body_text}"
    pairs = _field_pairs(spec)
    if method in BODY_METHODS:
        body = dict(pairs)
        return f"{method} {path} json:{json.dumps(body, separators=(',', ':'), ensure_ascii=False)}"
    split = urllib.parse.urlsplit(path)
    present = {name for name, _ in urllib.parse.parse_qsl(split.query, keep_blank_values=True)}
    added = [(name, field_value) for name, field_value in pairs if name not in present]
    query = "&".join(item for item in (split.query, urllib.parse.urlencode(added)) if item)
    return f"{method} {urllib.parse.urlunsplit(split._replace(query=query))}"


def normalize_known_endpoints(values: list[object] | tuple[object, ...]) -> list[str]:
    """Normalize every declared line, naming the first unreadable one by its position only."""
    normalized: list[str] = []
    for index, value in enumerate(values):
        if isinstance(value, str) and not value.strip():
            continue
        try:
            normalized.append(normalize_known_endpoint(value))
        except KnownEndpointSyntaxError as exc:
            raise KnownEndpointSyntaxError(f"known endpoint {index + 1}: {exc}") from None
    return normalized
