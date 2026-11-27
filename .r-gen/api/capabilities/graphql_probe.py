"""GraphQL endpoint discovery and bounded, read-only GraphQL checks.

Pure request builders and response proofs; the batches that send them live in
``scan/action_adapter.py``. Every request is a GET of a fixed, reviewed GraphQL document in the
``query`` parameter (GraphQL over HTTP: a GET may only carry a query operation, never a
mutation), so no resolver of the application's own fields ever runs:

* ``query{__typename}`` -- the root type's name, which every GraphQL server answers -- and a
  control document no schema defines, which every GraphQL server rejects. Together they prove
  an endpoint is a validating GraphQL server rather than a page that answers everything.
* the introspection document below -- only the ``__schema`` meta field.
* a misspelt root field name, or with introspection off names reserved for introspection
  (``__user``; no schema may define one) (active family only) -- the server's validation rejects
  it before execution; a server with field suggestions names the real field in its error.
* ``__typename`` under 100 aliases, or repeated 100 times (active family only) -- meta fields
  only; whether the server bounds aliases or duplicate fields at all.

Each proof parses hostile JSON or HTML defensively: a value is used only after its type and
grammar are checked, and a reflected or echoed request never satisfies a proof.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
import json
import re
import urllib.parse
from typing import Any

try:
    from capabilities.secret_material import keyed_response_digest
except ModuleNotFoundError:
    from api.capabilities.secret_material import keyed_response_digest


# Where GraphQL endpoints conventionally live. Each is probed with a fixed document; a path
# that is not GraphQL answers with its own page or an error and proves nothing.
GRAPHQL_ENDPOINT_PATHS: tuple[str, ...] = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/v1",
    "/gql",
)
# Where in-browser GraphQL IDEs are served. They render only for a browser (Accept: text/html).
GRAPHQL_IDE_PATHS: tuple[str, ...] = ("/graphiql", "/graphql/console", "/playground")
GRAPHQL_IDE_HEADERS: tuple[tuple[str, str], ...] = (("Accept", "text/html"),)
# Asks for JSON, and satisfies the CSRF guard of servers that refuse a "simple" GET
# (Apollo Server's csrfPrevention) without changing what the request can do.
GRAPHQL_REQUEST_HEADERS: tuple[tuple[str, str], ...] = (
    ("Accept", "application/graphql-response+json, application/json"),
    ("Apollo-Require-Preflight", "true"),
)

TYPENAME_QUERY = "query{__typename}"
# A document every GraphQL server must reject at validation (no type defines this meta-like
# field). A responder that answers it as it answers ``__typename`` is not validating
# documents, so nothing it returns proves anything about GraphQL limits.
CONTROL_QUERY = "query{__typenamezq}"
# Root type names and type names only: the smallest document that proves introspection is
# enabled. Field names of the query root feed the suggestion check.
INTROSPECTION_QUERY = (
    "query{__schema{queryType{name fields(includeDeprecated:true){name}}types{name}}}"
)
ALIAS_COUNT = 100
DUPLICATE_FIELD_COUNT = 100

# GraphQL Name grammar (spec 2.1.9), bounded.
_NAME_RE = re.compile(r"[_A-Za-z][_0-9A-Za-z]{0,127}")
# The last path segment of a discovered route that names a GraphQL transport.
_ENDPOINT_SEGMENTS = frozenset({"graphql", "gql"})
_MAX_TYPES = 10_000
_MAX_FIELDS = 2_000
_MAX_ERRORS = 50
_MAX_MESSAGE_CHARS = 2_000
_SUGGESTION_RE = re.compile(r"Did you mean\b[^?\n]{0,500}")
_QUOTED_NAME_RE = re.compile(r"[\"'`“”]([_A-Za-z][_0-9A-Za-z]{0,127})[\"'`“”]")
# In-browser IDEs, each by its own bundle and its render call; prose that merely mentions
# GraphiQL, or a page that links to one, has neither pair.
_GRAPHIQL_BUNDLE_RE = re.compile(r"(?i)graphiql(?:@[\w.\-]{1,40})?/(?:dist/|umd/)?graphiql(?:\.min)?\.(?:js|css)")
_GRAPHIQL_RENDER_RE = re.compile(
    r"createElement\(\s*GraphiQL\b|<GraphiQL[\s>/]|GraphiQL\.createFetcher\s*\(|new\s+GraphiQL\b"
)
_PLAYGROUND_BUNDLE_RE = re.compile(r"(?i)graphql-playground-react(?:@[\w.\-]{1,40})?/build/")
_PLAYGROUND_RENDER_RE = re.compile(r"GraphQLPlayground\.init\s*\(")


def is_graphql_name(value: Any) -> bool:
    return isinstance(value, str) and _NAME_RE.fullmatch(value) is not None


def graphql_request_url(endpoint_url: str, document: str) -> str:
    """``endpoint_url`` with ``document`` as its only query parameter (fragment dropped)."""
    parts = urllib.parse.urlsplit(str(endpoint_url))
    query = urllib.parse.urlencode({"query": document}, quote_via=urllib.parse.quote)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))


def endpoint_of(request_url: str) -> str:
    """The endpoint a GraphQL request URL addresses: the URL without query or fragment."""
    parts = urllib.parse.urlsplit(str(request_url))
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def is_graphql_endpoint_url(url: str) -> bool:
    """A discovered route whose last path segment names a GraphQL transport."""
    try:
        path = urllib.parse.urlsplit(str(url or "")).path
    except ValueError:
        return False
    return path.rstrip("/").rsplit("/", 1)[-1].lower() in _ENDPOINT_SEGMENTS


def seed_endpoint_urls(base_origin: str) -> tuple[str, ...]:
    return tuple(f"{base_origin}{path}" for path in GRAPHQL_ENDPOINT_PATHS)


def _errors(document: Mapping[str, Any]) -> list[str]:
    raw = document.get("errors")
    if not isinstance(raw, list):
        return []
    messages = []
    for item in raw[:_MAX_ERRORS]:
        message = item.get("message") if isinstance(item, Mapping) else None
        if isinstance(message, str):
            messages.append(message[:_MAX_MESSAGE_CHARS])
    return messages


def _data(document: Any) -> Mapping[str, Any] | None:
    if not isinstance(document, Mapping):
        return None
    data = document.get("data")
    return data if isinstance(data, Mapping) else None


_RESPONSE_KEYS = frozenset({"data", "errors", "extensions"})


def typename_root(document: Any) -> str | None:
    """The root type name a ``query{__typename}`` answer proves, or None.

    A GraphQL response, not a reflection: only the response keys GraphQL defines, and
    ``data.__typename`` is a GraphQL Name and nothing else was selected. An HTML page, an echo
    of the query string or an error is not one.
    """
    data = _data(document)
    if (
        data is None or set(data) != {"__typename"} or _errors(document)
        or not set(document) <= _RESPONSE_KEYS
    ):
        return None
    name = data.get("__typename")
    return name if is_graphql_name(name) else None


def introspection_summary(document: Any) -> dict[str, Any] | None:
    """The schema facts an introspection answer proves, or None when it is not one.

    Proof: ``data.__schema.queryType.name`` is a GraphQL Name that also appears in the
    returned ``types`` list. A server with introspection off answers with an error and no
    ``__schema``; nothing that merely echoes the request has both.
    """
    data = _data(document)
    schema = data.get("__schema") if data is not None else None
    if not isinstance(schema, Mapping):
        return None
    query_type = schema.get("queryType")
    if not isinstance(query_type, Mapping) or not is_graphql_name(query_type.get("name")):
        return None
    raw_types = schema.get("types")
    if not isinstance(raw_types, list) or not raw_types:
        return None
    type_names = [
        item.get("name") for item in raw_types[:_MAX_TYPES]
        if isinstance(item, Mapping) and is_graphql_name(item.get("name"))
    ]
    root = str(query_type["name"])
    if root not in type_names:
        return None
    raw_fields = query_type.get("fields")
    raw_fields = raw_fields if isinstance(raw_fields, list) else []
    fields = [
        item.get("name") for item in raw_fields[:_MAX_FIELDS]
        if isinstance(item, Mapping) and is_graphql_name(item.get("name"))
    ]
    return {
        "query_type": root,
        "type_count": len(type_names),
        "query_field_count": len(fields),
        "query_fields": tuple(dict.fromkeys(fields)),
        # Every root field was read and named validly: only then can a misspelling be proven
        # not to be one of them.
        "query_fields_complete": len(raw_fields) <= _MAX_FIELDS and len(fields) == len(raw_fields),
    }


def is_introspection_request(url: str) -> bool:
    """A request URL whose ``query`` parameter is a document selecting ``__schema``."""
    try:
        values = urllib.parse.parse_qs(urllib.parse.urlsplit(str(url or "")).query).get("query")
    except ValueError:
        return False
    return bool(values) and "__schema" in values[0]


def is_ide_location(url: str) -> bool:
    """A path where an in-browser GraphQL IDE is conventionally served."""
    try:
        path = urllib.parse.urlsplit(str(url or "")).path.rstrip("/").lower()
    except ValueError:
        return False
    return path in GRAPHQL_IDE_PATHS or path.rsplit("/", 1)[-1] in {"graphiql", "playground"}


def ide_page(text: str) -> str | None:
    """The in-browser GraphQL IDE an HTML page renders (``graphiql``/``playground``), or None."""
    sample = text[:262_144]
    if _GRAPHIQL_BUNDLE_RE.search(sample) and _GRAPHIQL_RENDER_RE.search(sample):
        return "graphiql"
    if _PLAYGROUND_BUNDLE_RE.search(sample) and _PLAYGROUND_RENDER_RE.search(sample):
        return "playground"
    return None


# --- active checks -----------------------------------------------------------------------------


def rejected(document: Any) -> bool:
    """A validation rejection: an error list and no data (the control document's answer)."""
    return (
        isinstance(document, Mapping) and bool(_errors(document)) and not _data(document)
        and set(document) <= _RESPONSE_KEYS
    )


def misspelt_field(query_fields: Sequence[str]) -> tuple[str, str] | None:
    """A (real field, misspelling) pair whose misspelling is not itself a root field.

    The misspelling must fail validation, so it is never a name the root type has: a
    request for a real field would execute that field's resolver.
    """
    names = [name for name in query_fields if is_graphql_name(name)]
    existing = set(names)
    for name in names:
        if len(name) < 4 or name.startswith("__"):
            continue
        for suffix in ("zq", "qz", "xq"):
            candidate = name[:-1] + suffix
            if candidate not in existing and is_graphql_name(candidate):
                return name, candidate
    return None


def suggestion_query(misspelling: str) -> str:
    if not is_graphql_name(misspelling):
        raise ValueError("misspelling is not a GraphQL name")
    return "query{" + misspelling + "}"


# Names reserved by GraphQL for introspection (spec 3.4: a schema may not define a field whose
# name begins with "__"), each one edit-close to a common root field. Querying them is always a
# validation error, so no resolver can run, and a server with suggestions names its real field.
RESERVED_PROBE_FIELDS: tuple[str, ...] = (
    "__user", "__users", "__me", "__viewer", "__node", "__search", "__account", "__products",
)


def reserved_probe_query() -> str:
    return "query{" + " ".join(RESERVED_PROBE_FIELDS) + "}"


def suggested_fields(
    document: Any, *, misspelling: str | Sequence[str], known_fields: Sequence[str] | None,
) -> tuple[str, ...]:
    """Root fields a validation error suggested for a misspelling (empty when none).

    Only an error that rejects one of the misspellings and names, as a suggestion, another field
    counts: a generic error, or one that only repeats the request, does not. With
    ``known_fields`` the suggestion must be a field the schema really has; without (introspection
    off) it must be an ordinary field name, which only the server's schema can have supplied.
    """
    if not isinstance(document, Mapping) or _data(document):
        return ()
    misspellings = (misspelling,) if isinstance(misspelling, str) else tuple(misspelling)
    known = set(known_fields) if known_fields is not None else None
    found: list[str] = []
    for message in _errors(document):
        if not any(item in message for item in misspellings):
            continue
        match = _SUGGESTION_RE.search(message)
        if match is None:
            continue
        for name in _QUOTED_NAME_RE.findall(match.group(0)):
            acceptable = (
                name in known if known is not None
                else not name.startswith("__")
            )
            if acceptable and name not in misspellings and name not in found:
                found.append(name)
    return tuple(found)


def alias_query(count: int = ALIAS_COUNT) -> str:
    return "query{" + " ".join(f"a{index}:__typename" for index in range(count)) + "}"


def aliases_answered(document: Any, *, count: int = ALIAS_COUNT) -> bool:
    """Every alias of ``__typename`` answered in one response, with no error."""
    data = _data(document)
    if data is None or _errors(document) or len(data) != count:
        return False
    return all(is_graphql_name(data.get(f"a{index}")) for index in range(count))


def duplicate_field_query(count: int = DUPLICATE_FIELD_COUNT) -> str:
    return "query{" + " ".join(["__typename"] * count) + "}"


def duplicates_answered(document: Any) -> bool:
    """A document repeating ``__typename`` answered, with no error (no duplicate-field limit)."""
    return typename_root(document) is not None


# --- the active batch ---------------------------------------------------------------------------

GRAPHQL_PROBE_PARSER_VERSION = "graphql-probe-batch/v1"
# One contract per check; registered in ``proof_contracts.CANONICAL_PROOF_CONTRACTS``.
GRAPHQL_PROOF_CONTRACTS: Mapping[str, str] = {
    "field_suggestions": "graphql_field_suggestions/v1",
    "alias_limit_absent": "graphql_alias_limit_absent/v1",
    "duplicate_field_limit_absent": "graphql_duplicate_field_limit_absent/v1",
}
# At most this many requests per endpoint: typename, the control, introspection, suggestion,
# aliases, duplicates. A route that does not answer the first as GraphQL costs one request.
GRAPHQL_REQUESTS_PER_ENDPOINT = 6
_MAX_JSON_BYTES = 2_000_000

Send = Callable[[str], Awaitable[tuple[int | None, bytes]]]


def graphql_first_slice_hold(slice_count: int) -> dict[str, int]:
    """The reservation the first slice needs beyond its endpoint share: every check on
    every conventional GraphQL location."""
    seeds = len(GRAPHQL_ENDPOINT_PATHS) * GRAPHQL_REQUESTS_PER_ENDPOINT
    endpoints = max(0, int(slice_count))
    return {"http_requests": seeds + endpoints, "tool_wall_seconds": 2 * seeds + endpoints}


def json_body(body: bytes) -> Any:
    """A bounded JSON document from a response body, or None."""
    if not body or len(body) > _MAX_JSON_BYTES:
        return None
    text = body.decode("utf-8", errors="replace").lstrip()
    if not text.startswith(("{", "[")):
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):  # a hostile, deeply nested body
        return None


def _proof(check: str, endpoint: str, root: str, status: int | None, body: bytes,
           **details: Any) -> dict[str, Any]:
    return {
        "kind": "graphql_proof",
        "check": check,
        "proof_state": "verified",
        "finding_verdict": "verified",
        "proof_contract": GRAPHQL_PROOF_CONTRACTS[check],
        "endpoint": endpoint,
        "root_type": root,
        "response_status": status,
        "response_body_sha256": keyed_response_digest(body),
        "proof_producer": "shakerscan",
        **details,
    }


async def check_endpoint(
    endpoint: str, send: Send, *, can_send: Callable[[], bool],
) -> dict[str, Any]:
    """Run the bounded read-only checks against one candidate endpoint.

    ``send(url)`` performs one GET and returns ``(status, body)``; ``can_send()`` says
    whether the batch may still spend a request. Returns what was proved, how many requests
    were sent, and whether every check that applied could run.
    """
    outcome: dict[str, Any] = {
        "endpoint": endpoint, "graphql": False, "root_type": None, "requests": 0,
        "complete": True, "introspection": False, "proofs": [],
    }

    async def get(document: str) -> tuple[int | None, bytes] | None:
        if not can_send():
            outcome["complete"] = False
            return None
        outcome["requests"] += 1
        return await send(graphql_request_url(endpoint, document))

    answer = await get(TYPENAME_QUERY)
    if answer is None:
        return outcome
    status, body = answer
    root = typename_root(json_body(body)) if status == 200 else None
    if root is None:
        return outcome
    # The server must reject an invalid document; a responder that answers everything the
    # same way is not a GraphQL server whose limits can be measured.
    answer = await get(CONTROL_QUERY)
    if answer is None:
        return outcome
    if not rejected(json_body(answer[1])):
        return outcome
    outcome.update(graphql=True, root_type=root)

    answer = await get(INTROSPECTION_QUERY)
    summary = None
    if answer is not None and answer[0] == 200:
        summary = introspection_summary(json_body(answer[1]))
    outcome["introspection"] = summary is not None
    pair = (
        misspelt_field(summary["query_fields"])
        if summary and summary["query_fields_complete"] else None
    )
    # With the root fields known, one of them is misspelt; without them (introspection off,
    # where suggestions matter most), reserved names close to common fields are asked for.
    if pair is not None:
        misspelling: str | tuple[str, ...] = pair[1]
        document, known = suggestion_query(pair[1]), summary["query_fields"]
    else:
        misspelling, document, known = RESERVED_PROBE_FIELDS, reserved_probe_query(), None
    answer = await get(document)
    if answer is not None:
        # Validation errors may come back as 200 or, under the GraphQL over HTTP response
        # media type, as 400; either carries the error list.
        suggested = suggested_fields(
            json_body(answer[1]) if answer[0] in {200, 400} else None,
            misspelling=misspelling, known_fields=known,
        )
        if suggested:
            outcome["proofs"].append(_proof(
                "field_suggestions", endpoint, root, answer[0], answer[1],
                misspelling=misspelling if isinstance(misspelling, str) else ",".join(misspelling),
                suggested_fields=list(suggested[:10]),
            ))

    answer = await get(alias_query())
    if answer is not None and answer[0] == 200 and aliases_answered(json_body(answer[1])):
        outcome["proofs"].append(_proof(
            "alias_limit_absent", endpoint, root, answer[0], answer[1], alias_count=ALIAS_COUNT,
        ))
    answer = await get(duplicate_field_query())
    if answer is not None and answer[0] == 200 and duplicates_answered(json_body(answer[1])):
        outcome["proofs"].append(_proof(
            "duplicate_field_limit_absent", endpoint, root, answer[0], answer[1],
            duplicate_count=DUPLICATE_FIELD_COUNT,
        ))
    return outcome


__all__ = [
    "ALIAS_COUNT",
    "DUPLICATE_FIELD_COUNT",
    "GRAPHQL_PROBE_PARSER_VERSION",
    "GRAPHQL_PROOF_CONTRACTS",
    "GRAPHQL_REQUESTS_PER_ENDPOINT",
    "GRAPHQL_ENDPOINT_PATHS",
    "GRAPHQL_IDE_HEADERS",
    "GRAPHQL_IDE_PATHS",
    "GRAPHQL_REQUEST_HEADERS",
    "INTROSPECTION_QUERY",
    "CONTROL_QUERY",
    "RESERVED_PROBE_FIELDS",
    "TYPENAME_QUERY",
    "alias_query",
    "aliases_answered",
    "check_endpoint",
    "graphql_first_slice_hold",
    "duplicate_field_query",
    "duplicates_answered",
    "endpoint_of",
    "graphql_request_url",
    "ide_page",
    "introspection_summary",
    "is_graphql_endpoint_url",
    "is_ide_location",
    "is_introspection_request",
    "is_graphql_name",
    "json_body",
    "misspelt_field",
    "rejected",
    "reserved_probe_query",
    "seed_endpoint_urls",
    "suggested_fields",
    "suggestion_query",
    "typename_root",
]
