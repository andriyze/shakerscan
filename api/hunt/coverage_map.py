"""Open coverage of a web Hunt: the endpoints it knows and the test classes not yet run on them.

A Hunt planner (an agent in a terminal) loses its working memory on every context compaction and
tends to finish right after one, with most of its time and budget unused and most of the mapped
surface never requested. The coverage ledger (``coverage_ledger``) records what a planner says it
examined; nothing told the planner what it had *not* examined. This module computes that, on
read, from records the server already keeps:

* endpoints: the target's endpoint inventory (crawl, content discovery, specification and probe
  hits, earlier Scans) plus every route this Hunt's own actions answered on;
* test classes per endpoint, from the route and its parameters (``classify``): a login takes
  default credentials, a route with an object id takes object-level authorization, a parameter
  takes SQL injection and XSS, a file-like or sensitive path takes exposure review, a
  command/URL/file parameter takes the injection checks no verifier proves, and so on;
* what this Hunt ran: verifier calls on the route, requests to it (with or without parameters),
  candidates on it, and coverage angles recorded on it with a settled status.

The result is a worklist, never a finding and never authority. ``open`` pairs are endpoint x class
combinations nothing in this Hunt has touched; a pair closes when the Hunt runs the suggested
check, records a candidate on the route, or records a coverage angle (status negative, partial,
blocked or candidate) for it. Discovery steps that have not run are listed first.

The compact form (``compact_open_coverage``) is small enough to ride on every capability answer
and survives a context compaction because the agent can re-query it (query kind ``coverage``,
``GET /hunts/{id}/coverage``). ``finish_guard`` turns it into the finish refusal: finishing while
coverage is open and time and budget remain is refused with what is open, unless the planner
finishes with ``force`` and a stated reason, which the debrief records.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
import json
import re
from typing import Any
import urllib.parse

from .auto_discovery import COVERAGE_TARGET_KINDS, discovery_state, key_digest, probe_key_digests

SCHEMA = "hunt-open-coverage/v1"
# Bounds: the inventory read, the routes taken from this Hunt's actions, one listed page.
MAX_INVENTORY_ENDPOINTS = 600
MAX_ACTION_ROWS = 5_000
MAX_ENDPOINTS = 800
MAX_PAGE = 200
COMPACT_ITEMS = 5
FINISH_ITEMS = 8
# Finishing is not held when less than this much of the Hunt's wall remains.
FINISH_MIN_WALL_SECONDS = 120
MIN_FORCE_REASON_CHARS = 10
# Test classes: the check, and what this engine offers to run it.
CLASS_GUIDE: Mapping[str, str] = {
    "review": "request it (http.request GET, or artifact.inspect for a file) and read what it returns",
    "exposure": "request it and read it; a secret, credential, key or private document is a "
                "data_exposure candidate (candidate.verify proves it); nothing sensitive: record a "
                "coverage angle with status negative citing the request",
    "default_credentials": "try the built-in default pairs on this login (http.request with a "
                           "request_bindings default_credential entry in form_body or json_body), "
                           "then candidate.verify family default_credentials",
    "object_authz": "read/write another principal's object (authz.verify mode object, or a bola "
                    "candidate and candidate.verify)",
    "function_authz": "call it as a lower-role principal and anonymously (authz.verify mode "
                      "function, or an access_control/auth_bypass candidate)",
    "sqli": "sqli.verify on this route and parameter (it proves and records SQL injection itself)",
    "xss": "xss.verify on this route and parameter (it proves and records XSS itself)",
    "injection": "send crafted values in the named parameters (command, template, URL/SSRF, "
                 "path traversal, redirect, XML) with http.request and record what the answer shows",
    "graphql": "introspection and batching queries with http.request POST; record what the schema "
               "or answers expose",
    "upload": "upload a harmless file of a disallowed type and see whether it is stored and served",
    "unauthenticated_api": "call it anonymously; data or actions without sign-in are an auth_bypass "
                           "or data_exposure candidate; a refusal (401/403) closes it, otherwise "
                           "record a candidate or a negative coverage angle",
}
CLASSES = tuple(CLASS_GUIDE)
# Classes a deterministic verifier can prove: listed first.
_VERIFIER_CLASSES = ("default_credentials", "sqli", "xss", "object_authz", "function_authz", "exposure")
_CLASS_RANK = {name: index for index, name in enumerate((*_VERIFIER_CLASSES, *[
    name for name in CLASSES if name not in _VERIFIER_CLASSES]))}

DISCOVERY_STEPS: Mapping[str, str] = {
    "crawl": "web.crawl",
    "content_discovery": "web.content_discover",
}

_ID_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[0-9a-fA-F]{24,})$"
)
_TEMPLATE_SEGMENT = re.compile(r"^(?:\{[^/{}]{1,64}\}|:[A-Za-z_][A-Za-z0-9_]{0,63}|<[^/<>]{1,64}>)$")
_LOGIN = re.compile(r"(?:^|/)(?:log-?in|sign-?in|auth(?:enticate)?|session|token|oauth/token|"
                    r"j_security_check|wp-login\.php|user/login|account/login)(?:/|$|\.)", re.I)
_LOGIN_EXCLUDE = re.compile(r"(?:logout|signout|refresh|verify|callback|register|reset|forgot)", re.I)
_ADMIN = re.compile(r"(?:^|/)(?:admin|administrator|internal|manage(?:r|ment)?|console|debug|"
                    r"actuator|export|config(?:uration)?|settings|impersonate|approve|reindex|"
                    r"script|telescope|horizon|_ignition|jolokia|metrics|system|ops|staff|"
                    r"superuser|root|audit|payroll|billing)(?:/|$|\.)", re.I)
_SENSITIVE_FILE = re.compile(
    r"(?:^|/)(?:\.[A-Za-z0-9_-]+(?:/|$)|[^/]*\.(?:env|bak|old|orig|swp|sql|dump|db|sqlite3?|"
    r"ya?ml|ini|conf|cfg|config|properties|json|xml|log|txt|tar|gz|tgz|zip|7z|key|pem|p12|pfx|"
    r"crt|kdbx|docx?|xlsx?|csv|ipynb|tfvars|tfstate|php~|php\.bak|toml|lock)$|"
    r"(?:backup|backups|dump|dumps|logs?|secrets?|credentials?|private|keys?|id_rsa|id_ed25519|"
    r"kubeconfig|wp-config[^/]*|phpinfo[^/]*|info\.php|server-status|"
    r"heapdump|env|swagger|openapi|api-docs|sbom|_catalog|\.git|\.svn)(?:/|$))", re.I)
_UPLOAD = re.compile(r"(?:^|/)(?:upload[s]?|avatar|attachments?|import|files?/new|media)(?:/|$)", re.I)
_GRAPHQL = re.compile(r"(?:^|/)graph(?:i)?ql(?:/|$)", re.I)
_SEARCHY = re.compile(r"(?:^|/)(?:search|query|find|lookup|filter|products?|items?|users?|orders?|"
                      r"reports?|catalog|list)/?$", re.I)
_API = re.compile(r"(?:^|/)(?:api|rest|v[0-9]+|graphql|rpc|ajax-api|odata|scim|mcp|a2a)(?:/|$)", re.I)
# Parameter names that point at injection classes no verifier proves.
_INJECTION_PARAMS = re.compile(
    r"^(?:cmd|command|exec|run|shell|host|hostname|ip|addr|address|ping|domain|target|"
    r"url|uri|link|href|src|source|dest|destination|redirect|redirect_uri|return|return_to|"
    r"returnurl|next|continue|callback|webhook|feed|fetch|proxy|image_url|file|filename|"
    r"path|filepath|dir|folder|doc|document|download|template|tpl|view|page|include|lang|"
    r"locale|xml|data|payload|expr|expression|code|eval|query_xml|format)$", re.I)
_PATH_INJECTION = re.compile(
    r"(?:^|/)(?:ping|exec|run|shell|cmd|command|dns-lookup|traceroute|convert|render|template|"
    r"preview|fetch|proxy|webhook|import|download|files?/view|static-preview|redirect|xml|soap|"
    r"parse|merge|pickle|deserialize|log/append|validate/code|custom_component)(?:/|$)", re.I)


def _json(value: Any, default: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return default
    return value if isinstance(value, type(default)) else default


def normalize_path(path: Any) -> str | None:
    """A route path: no scheme/host, query or fragment; id-shaped segments templated as ``{id}``."""
    text = str(path or "").strip()
    if not text:
        return None
    if text.startswith(("http://", "https://")):
        text = urllib.parse.urlsplit(text).path or "/"
    text = text.split("?", 1)[0].split("#", 1)[0]
    if not text.startswith("/") or len(text) > 2048 or any(ch.isspace() for ch in text):
        return None
    segments = []
    for segment in text.split("/"):
        if segment and (_ID_SEGMENT.match(segment) or _TEMPLATE_SEGMENT.match(segment)):
            segments.append("{id}")
        else:
            segments.append(segment)
    return "/".join(segments) or "/"


def _query_names(path: Any) -> set[str]:
    text = str(path or "")
    if "?" not in text:
        return set()
    query = text.split("?", 1)[1].split("#", 1)[0]
    return {name for name, _ in urllib.parse.parse_qsl(query, keep_blank_values=True) if name}


_INPUT_NAME = re.compile(r"[A-Za-z0-9_.\[\]-]{1,64}")
MAX_REQUEST_INPUTS = 20


def _request_inputs(values: Mapping[str, Any]) -> set[str]:
    """The input names one request of this Hunt carried besides its path's query: the keys of
    its ``query``/``params`` and of a JSON or form body object. A default-credential attempt
    names a sign-in's own fields, which the sign-in checks already cover."""
    if _uses_default_credential(values):
        return set()
    names: list[str] = []
    for key in ("query", "params", "json_body", "form_body"):
        value = values.get(key)
        if isinstance(value, Mapping):
            names += [str(name) for name in value if isinstance(name, str) and _INPUT_NAME.fullmatch(name)]
    return set(names[:MAX_REQUEST_INPUTS])


_CAPTURE_BINDING_KEYS = frozenset({"source_action_id", "capture_name", "header", "prefix"})


def _capture_identity(values: Mapping[str, Any]) -> list[dict[str, str]] | None:
    """The identity one request of this Hunt was sent as, when it is made only of values the
    Hunt's own login captured (a session cookie, a bearer token): the bindings, by reference."""
    bindings = values.get("request_bindings")
    if not isinstance(bindings, list) or not 1 <= len(bindings) <= 4:
        return None
    found: list[dict[str, str]] = []
    for item in bindings:
        if not isinstance(item, Mapping) or not set(item) <= _CAPTURE_BINDING_KEYS or not all(
                isinstance(item.get(key), str) and item.get(key) for key in ("source_action_id", "capture_name", "header")):
            return None
        found.append({key: str(item[key]) for key in ("source_action_id", "capture_name", "header", "prefix")
                      if key in item})
    return found


def _params(value: Any) -> set[str]:
    if isinstance(value, str):
        return {item.strip() for item in re.split(r"[,&;\s]+", value) if item.strip()}
    if isinstance(value, Mapping):
        return {str(key) for key in value}
    if isinstance(value, (list, tuple, set)):
        return {str(item) for item in value if isinstance(item, (str, int))}
    return set()


def classify(method: str, path: str, params: Iterable[str] = (), *, content_type: str = "") -> set[str]:
    """The test classes that apply to one endpoint (``CLASSES``); ``review`` always does."""
    method = str(method or "GET").upper()
    names = {str(name).lower() for name in params if name}
    classes = {"review"}
    lowered = path.lower()
    if _LOGIN.search(path) and not _LOGIN_EXCLUDE.search(path):
        classes.add("default_credentials")
    if "{id}" in path:
        classes.add("object_authz")
    if _ADMIN.search(path):
        classes.add("function_authz")
    if _SENSITIVE_FILE.search(path):
        classes.add("exposure")
    if _GRAPHQL.search(path):
        classes.add("graphql")
    if _UPLOAD.search(path) and method in {"POST", "PUT", "PATCH", "GET"}:
        classes.add("upload")
    if names or (_SEARCHY.search(path) and method in {"GET", "POST"}):
        if "graphql" not in classes:
            classes.update({"sqli", "xss"})
    if any(_INJECTION_PARAMS.match(name) for name in names) or _PATH_INJECTION.search(path):
        classes.add("injection")
    if _API.search(path) and "default_credentials" not in classes:
        classes.add("unauthenticated_api")
    if "json" in str(content_type).lower() and method == "GET" and "{id}" not in path:
        classes.add("unauthenticated_api")
    if lowered.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
                         ".woff2", ".ttf", ".map")) and "exposure" not in classes:
        return {"review"}
    return classes


# --- what this Hunt ran -------------------------------------------------------------------------

_VERIFIER_CLASS = {
    "sqli.verify": ("sqli",),
    "xss.verify": ("xss",),
    "authz.verify": ("object_authz", "function_authz", "unauthenticated_api"),
}
# What one request.verify check settles on its route: the class its deterministic proof covers.
_REQUEST_CHECK_CLASS: Mapping[str, tuple[str, ...]] = {
    "sql_injection": ("sqli",), "exposure": ("exposure",), "directory_listing": ("exposure",),
    "unauthenticated_api": ("unauthenticated_api",), "graphql": ("graphql",),
    **{check: ("injection",) for check in (
        "command_injection", "path_traversal", "template_injection", "ssrf", "xxe", "open_redirect",
        "crlf_injection", "nosql_injection", "ldap_injection")},
}
_FAMILY_CLASSES: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = (
    (re.compile(r"sql", re.I), ("sqli",)),
    (re.compile(r"xss|cross.?site.?script", re.I), ("xss",)),
    (re.compile(r"bola|idor|object", re.I), ("object_authz",)),
    (re.compile(r"bfla|access.?control|auth.?bypass|authz|authori[sz]|privilege|function", re.I),
     ("function_authz", "unauthenticated_api")),
    (re.compile(r"default.?cred|weak.?(?:cred|pass)|default.?pass|brute|login", re.I), ("default_credentials",)),
    (re.compile(r"exposure|disclosure|secret|leak|sensitive|information", re.I), ("exposure", "unauthenticated_api")),
    (re.compile(r"graphql", re.I), ("graphql",)),
    (re.compile(r"upload", re.I), ("upload",)),
    (re.compile(r"inject|cmdi|command|ssti|template|ssrf|traversal|lfi|rfi|redirect|xxe|"
                r"deserial|nosql|ldap|crlf|prototype", re.I), ("injection",)),
    (re.compile(r"mass.?assign|field|workflow|business", re.I), ("object_authz", "function_authz")),
)
SETTLED_ANGLE_STATUSES = frozenset({"negative", "partial", "blocked", "candidate"})
# A candidate or settled angle on a route means the Hunt looked at it.
_LOOKED_AT = frozenset({"review", "exposure", "unauthenticated_api"})
# Answers that serve nothing: a route that only ever answered these exposed nothing to judge.
_NOTHING_SERVED = frozenset({401, 403, 404, 405, 407, 410})
# Process-state keys of the discovery runner that are not step outcomes.
_STATE_KEYS = frozenset({"running", "products", "notes", "probe_hits", "sweep_counts", "deferred_finish",
                         "sweep_stats"})


def family_classes(family: Any) -> set[str]:
    """The classes a candidate or coverage angle of ``family`` closes on its route."""
    text = str(family or "")
    if text in CLASS_GUIDE:
        return {text}
    found: set[str] = set()
    for pattern, classes in _FAMILY_CLASSES:
        if pattern.search(text):
            found.update(classes)
    return found


def _input_path(capability: str, values: Mapping[str, Any]) -> str | None:
    for key in ("path", "url", "route", "target_path", "endpoint"):
        if values.get(key):
            return str(values[key])
    if capability in {"web.crawl", "web.content_discover", "templates.scan"}:
        return None
    return None


def _has_parameters(values: Mapping[str, Any]) -> bool:
    raw_path = str(values.get("path") or values.get("url") or "")
    return bool(
        "?" in raw_path or values.get("query") or values.get("params") or values.get("json_body")
        or values.get("form_body") or values.get("body") or values.get("parameter")
        or values.get("parameters") or values.get("injection_field") or values.get("body_field_names")
    )


def _uses_default_credential(values: Mapping[str, Any]) -> bool:
    bindings = values.get("request_bindings")
    return isinstance(bindings, list) and any(
        isinstance(item, Mapping) and item.get("default_credential") for item in bindings
    )


def _locus_path(locus: Mapping[str, Any]) -> str | None:
    for key in ("route", "path", "url", "endpoint"):
        if locus.get(key):
            return str(locus[key])
    return None


class _Ledger:
    """Which classes this Hunt touched per normalized route (method-insensitive)."""

    def __init__(self) -> None:
        self.requested: set[str] = set()
        self.with_params: set[str] = set()
        # HTTP statuses the Hunt's own requests got per route: a route that only ever refused or
        # was absent exposed nothing, so its exposure needs no judgement.
        self.statuses: dict[str, set[int]] = {}
        self.written: set[str] = set()
        self.closed: dict[str, set[str]] = {}

    def close(self, route: str | None, classes: Iterable[str]) -> None:
        if route:
            self.closed.setdefault(route, set()).update(classes)

    def closed_for(self, route: str) -> set[str]:
        return self.closed.get(route, set())


def _discovered_from_action(row: Mapping[str, Any]) -> tuple[str, str, int | None, str] | None:
    """(method, raw path, status, content type) of a completed request action, else None."""
    values = _json(row.get("input"), {})
    path = _input_path(str(row.get("capability_name") or ""), values)
    if not path:
        return None
    status = row.get("http_status")
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    return (str(values.get("method") or "GET").upper(), path, status, str(row.get("content_type") or ""))


def build_coverage(
    *,
    actions: Sequence[Mapping[str, Any]],
    endpoints: Sequence[Mapping[str, Any]],
    candidates: Sequence[Mapping[str, Any]] = (),
    angles: Sequence[Mapping[str, Any]] = (),
    discovery: Mapping[str, Any] | None = None,
    probe_key_digests: Iterable[str] = (),
    allowed: Iterable[str] | None = None,
) -> dict[str, Any]:
    """The coverage map from this Hunt's records (pure; ``load_coverage`` reads them).

    ``actions``: this Hunt's actions with ``capability_name``, ``status``, ``input`` (the redacted
    planner input), and for requests ``http_status`` / ``content_type``. ``endpoints``: inventory
    rows (``method``, ``path``, ``param_shape``, ``content_type``, ``source``). ``candidates``:
    this Hunt's candidates (``family``, ``canonical_locus``). ``angles``: the latest coverage
    angle per fingerprint (``family``, ``locus``, ``status``). ``probe_key_digests``: sha256 of the
    engine's own probe idempotency keys, whose answers are discovery, not testing. ``allowed``:
    the Hunt's capability manifest; a discovery step it cannot run is ``not_allowed``, not pending.
    """
    probe_digests = set(probe_key_digests)
    ledger = _Ledger()
    known: dict[tuple[str, str], dict[str, Any]] = {}
    ran: dict[str, str] = {}
    # The signed-in identity this Hunt's own request last reached each route with (2xx answer).
    identities: dict[str, list[dict[str, str]]] = {}

    def add(method: str, raw_path: str, params: Iterable[str], content_type: str, source: str) -> None:
        route = normalize_path(raw_path)
        if route is None:
            return
        method = method if method in {"GET", "POST", "PUT", "PATCH", "DELETE"} else "GET"
        key = (method, route)
        entry = known.get(key)
        names = set(params) | _query_names(raw_path)
        if entry is None:
            if len(known) >= MAX_ENDPOINTS:
                return
            known[key] = {"method": method, "route": route, "params": names,
                          "content_type": content_type, "sources": {source}}
        else:
            entry["params"].update(names)
            entry["sources"].add(source)
            entry["content_type"] = entry["content_type"] or content_type

    for row in endpoints[:MAX_INVENTORY_ENDPOINTS]:
        add(str(row.get("method") or "GET").upper(), str(row.get("path") or ""),
            _params(row.get("param_shape")), str(row.get("content_type") or ""),
            str(row.get("source") or "inventory"))

    for row in actions[:MAX_ACTION_ROWS]:
        name = str(row.get("capability_name") or "")
        status = str(row.get("status") or "")
        for step, capability in DISCOVERY_STEPS.items():
            if name == capability and status in {"completed", "partial"}:
                ran[step] = "done"
            elif name == capability and status in {"reserved", "running"}:
                ran.setdefault(step, "running")
        if name == "templates.scan" and status in {"completed", "partial"}:
            ran["templates"] = "done"
        if status not in {"completed", "partial"}:
            continue
        values = _json(row.get("input"), {})
        if name == "authz.verify" and isinstance(values.get("routes"), list):
            for item in values["routes"][:50]:
                text = str(item or "").strip()
                route = normalize_path(text.split(" ", 1)[-1])
                if route:
                    ledger.requested.add(route)
                    ledger.close(route, _VERIFIER_CLASS[name])
            continue
        raw_path = _input_path(name, values)
        route = normalize_path(raw_path) if raw_path else None
        if route is None:
            continue
        is_probe = str(row.get("idempotency_key_sha256") or "") in probe_digests
        if not is_probe:
            ledger.requested.add(route)
            if _has_parameters(values):
                ledger.with_params.add(route)
            if str(values.get("method") or "GET").upper() in {"POST", "PUT", "PATCH"}:
                ledger.written.add(route)
            if name in _VERIFIER_CLASS:
                ledger.close(route, _VERIFIER_CLASS[name])
            if name == "request.verify":
                ledger.close(route, _REQUEST_CHECK_CLASS.get(str(values.get("check") or ""), ()))
            if name == "http.request" and _uses_default_credential(values):
                ledger.close(route, ("default_credentials",))
        found = _discovered_from_action(row)
        if found is not None and name in {"http.request", "artifact.inspect"}:
            method, path, http_status, content_type = found
            if not is_probe and http_status is not None:
                ledger.statuses.setdefault(route, set()).add(http_status)
            # An answer that is not "absent" names a route that exists. The engine's own probes
            # enter the inventory through the runner's negative control, never from here.
            if not is_probe and http_status is not None and 200 <= http_status < 300 and name == "http.request":
                identity = _capture_identity(values)
                if identity:
                    identities[route] = identity
            if not is_probe and http_status is not None and http_status != 404 and http_status < 500:
                # The inputs the request itself carried are the route's inputs: the sweep tests them.
                add(method, path, _request_inputs(values), content_type, "hunt_request")

    for row in candidates:
        locus = _json(row.get("canonical_locus"), {})
        ledger.close(normalize_path(_locus_path(locus)), family_classes(row.get("family")) | _LOOKED_AT)
    for row in angles:
        if str(row.get("status") or "") not in SETTLED_ANGLE_STATUSES:
            continue
        locus = _json(row.get("locus"), {})
        ledger.close(normalize_path(_locus_path(locus)), family_classes(row.get("family")) | _LOOKED_AT)

    items: list[dict[str, Any]] = []
    pairs_total = 0
    for (method, route), entry in known.items():
        classes = classify(method, route, entry["params"], content_type=entry["content_type"])
        closed = set(ledger.closed_for(route))
        if route in ledger.requested:
            closed.add("review")
            statuses = ledger.statuses.get(route)
            if statuses and statuses <= _NOTHING_SERVED:
                closed.update({"exposure", "unauthenticated_api"})
        if route in ledger.with_params:
            closed.add("injection")
        if route in ledger.written:
            closed.update({"graphql", "upload"})
        pairs_total += len(classes)
        open_classes = sorted(classes - closed, key=lambda name: _CLASS_RANK.get(name, 99))
        if open_classes:
            items.append({
                "endpoint": f"{method} {route}",
                "untested": open_classes,
                "params": sorted(entry["params"])[:8],
                "requested": route in ledger.requested,
                "sources": sorted(entry["sources"])[:4],
                # By reference only: the sweep sends its checks on this route as the same login.
                **({"identity": identities[route]} if route in identities else {}),
            })
    items.sort(key=_item_rank)
    pairs_open = sum(len(item["untested"]) for item in items)
    state = dict(discovery or {})
    allowed_names = None if allowed is None else {str(name) for name in allowed}
    steps = {
        step: ran.get(step) or state.get(step) or (
            "not_allowed" if allowed_names is not None and capability not in allowed_names else "not_run")
        for step, capability in DISCOVERY_STEPS.items()
    }
    for step, value in state.items():
        if step not in steps and step not in _STATE_KEYS and isinstance(value, str):
            steps[step] = value
    if "templates" in ran:
        steps["templates"] = ran["templates"]
    # Running discovery holds a finish (what it maps is about to be listed); a step that never ran
    # is named, with the call that runs it, but holds nothing on its own.
    pending = sorted(step for step, value in steps.items()
                     if value in {"running", "queued"} and step in DISCOVERY_STEPS)
    not_run = sorted(step for step, value in steps.items() if value == "not_run" and step in DISCOVERY_STEPS)
    # A sweep that follows the Hunt has tested what was mapped and waits for the planner's own
    # requests: nothing of the engine's is pending then.
    if state.get("running") and state.get("sweep") != "following":
        pending = sorted(set(pending) | {"auto_discovery"})
    by_class: dict[str, int] = {}
    for item in items:
        for name in item["untested"]:
            by_class[name] = by_class.get(name, 0) + 1
    return {
        "schema_version": SCHEMA,
        "endpoints": len(known),
        "endpoints_requested": sum(1 for (_m, route) in known if route in ledger.requested),
        "pairs_total": pairs_total,
        "pairs_open": pairs_open,
        "endpoints_open": len(items),
        "open_by_class": dict(sorted(by_class.items(), key=lambda pair: (-pair[1], pair[0]))),
        "discovery": {"steps": steps, "pending": pending,
                      **({"not_run": not_run, "run_with": {step: DISCOVERY_STEPS[step] for step in not_run}}
                         if not_run else {}),
                      **({"products": state["products"]} if state.get("products") else {}),
                      **({"sweep_checks": dict(state["sweep_counts"])}
                         if isinstance(state.get("sweep_counts"), Mapping) else {}),
                      **({"planner_finished": True} if state.get("deferred_finish") else {}),
                      **({"sweep_stats": dict(state["sweep_stats"])}
                         if isinstance(state.get("sweep_stats"), Mapping) else {}),
                      **({"notes": state["notes"]} if state.get("notes") else {})},
        "open": items,
        "class_guide": {name: CLASS_GUIDE[name] for name in by_class},
    }


def _item_rank(item: Mapping[str, Any]) -> tuple:
    best = min((_CLASS_RANK.get(name, 99) for name in item["untested"]), default=99)
    return (item["requested"], best, -len(item["untested"]), item["endpoint"])


def coverage_page(report: Mapping[str, Any], *, limit: int = 50, offset: int = 0,
                  class_filter: str | None = None) -> dict[str, Any]:
    """One page of the open list, with the totals."""
    items = [item for item in report.get("open") or ()
             if not class_filter or class_filter in item.get("untested", ())]
    limit = max(1, min(int(limit or 50), MAX_PAGE))
    offset = max(0, int(offset or 0))
    page = items[offset:offset + limit]
    rest = {key: value for key, value in report.items() if key != "open"}
    return {**rest, "open": page, "returned": len(page), "offset": offset,
            "has_more": offset + len(page) < len(items),
            "next_offset": offset + len(page) if offset + len(page) < len(items) else None}


def _item_line(item: Mapping[str, Any]) -> str:
    params = item.get("params") or []
    return (f"{item['endpoint']}"
            + (f" ({', '.join(params[:4])})" if params else "")
            + f": {', '.join(item['untested'])}")


def compact_open_coverage(report: Mapping[str, Any], hunt_id: str) -> dict[str, Any]:
    """What rides on a capability answer: totals, pending discovery, the next few open items."""
    discovery = report.get("discovery") or {}
    return {
        "pairs_open": int(report.get("pairs_open") or 0),
        "endpoints_open": int(report.get("endpoints_open") or 0),
        "endpoints_known": int(report.get("endpoints") or 0),
        "discovery_pending": list(discovery.get("pending") or []),
        **({"sweep": discovery["steps"]["sweep"]} if (discovery.get("steps") or {}).get("sweep") else {}),
        **({"sweep_checks": discovery["sweep_checks"]} if discovery.get("sweep_checks") else {}),
        **({"discovery_not_run": list(discovery["not_run"])} if discovery.get("not_run") else {}),
        "next": [_item_line(item) for item in (report.get("open") or [])[:COMPACT_ITEMS]],
        "list": f"POST /hunts/{hunt_id}/query kind=coverage (or GET /hunts/{hunt_id}/coverage)",
    }


def debrief_coverage(report: Mapping[str, Any], *, forced: bool, reason: str | None) -> dict[str, Any]:
    """What the debrief keeps about coverage at finish."""
    discovery = report.get("discovery") or {}
    return {
        "schema_version": SCHEMA,
        "endpoints": int(report.get("endpoints") or 0),
        "endpoints_requested": int(report.get("endpoints_requested") or 0),
        "pairs_total": int(report.get("pairs_total") or 0),
        "pairs_open": int(report.get("pairs_open") or 0),
        "open_by_class": dict(report.get("open_by_class") or {}),
        "discovery": {"steps": dict(discovery.get("steps") or {}),
                      **({"sweep_stats": dict(discovery["sweep_stats"])} if discovery.get("sweep_stats") else {}),
                      **({"sweep_checks": dict(discovery["sweep_checks"])} if discovery.get("sweep_checks") else {}),
                      **({"products": list(discovery.get("products") or [])} if discovery.get("products") else {})},
        "open_sample": [_item_line(item) for item in (report.get("open") or [])[:20]],
        "forced": bool(forced),
        **({"force_reason": str(reason)[:2000]} if forced and reason else {}),
    }


def wall_remaining_seconds(run: Mapping[str, Any], *, now: datetime | None = None) -> float | None:
    """Seconds of the Hunt's wall still left, or None when it has no wall limit."""
    budget = _json(run.get("budget_json"), {})
    limit = budget.get("max_duration_seconds")
    created = run.get("created_at")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0 or not isinstance(created, datetime):
        return None
    moment = now or datetime.now(timezone.utc)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return limit - (moment - created).total_seconds()


def http_budget_left(run: Mapping[str, Any]) -> bool:
    budget = _json(run.get("budget_json"), {})
    used = _json(run.get("budget_used_json"), {})
    limit = budget.get("max_http_requests")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        return True
    return int(used.get("http_requests") or 0) < limit


def finish_guard(run: Mapping[str, Any], report: Mapping[str, Any] | None, *, force: bool,
                 force_reason: str | None, now: datetime | None = None,
                 can_test: bool = True) -> str | None:
    """Why this finish is refused, or None.

    Never refuses a Hunt that cannot test (``can_test`` false: passive, or its approval revoked
    or expired; it has no checks to close the open pairs with), a Hunt whose wall or HTTP budget
    is spent, a budget-exhausted Hunt, one with nothing open, or a forced finish with a reason
    (the engine's own sweep, not the planner, does the remaining work; a finish while it runs is
    deferred until it ends, see ``run_service``)."""
    if str(run.get("target_kind") or "") not in COVERAGE_TARGET_KINDS or report is None:
        return None
    if not can_test:
        return None
    if force:
        if len(str(force_reason or "").strip()) < MIN_FORCE_REASON_CHARS:
            return ("force=true needs force_reason: say in a sentence why the open coverage is left "
                    "untested; it is recorded in the debrief")
        return None
    if str(run.get("status") or "") == "budget_exhausted":
        return None
    remaining = wall_remaining_seconds(run, now=now)
    if remaining is not None and remaining < FINISH_MIN_WALL_SECONDS:
        return None
    if not http_budget_left(run):
        return None
    pending = list((report.get("discovery") or {}).get("pending") or [])
    pairs = int(report.get("pairs_open") or 0)
    if not pairs and not pending:
        return None
    hunt_id = str(run.get("id") or "")
    lines = [_item_line(item) for item in (report.get("open") or [])[:FINISH_ITEMS]]
    left = (f"{int(remaining // 60)} min of wall" if remaining is not None else "wall time")
    parts = [
        f"coverage is open: {pairs} endpoint/test-class pairs untested on "
        f"{int(report.get('endpoints_open') or 0)} of {int(report.get('endpoints') or 0)} known endpoints"
        + (f"; discovery not finished: {', '.join(pending)}" if pending else "")
        + f", with {left} and HTTP budget left. Every listed endpoint answered on this target "
        "differently from a path that cannot exist, so it is part of this target's surface.",
    ]
    if lines:
        parts.append("Untested first: " + "; ".join(lines) + ".")
    parts.append(
        f"Continue: POST /hunts/{hunt_id}/query kind=coverage lists every open pair with the check "
        "to run (class_guide). Or finish with force=true and force_reason; the reason and the open "
        "coverage go into the debrief.")
    return " ".join(parts)


# --- loading ------------------------------------------------------------------------------------

async def load_coverage(conn: Any, run: Mapping[str, Any]) -> dict[str, Any] | None:
    """The coverage map of one web Hunt, or None for another target kind."""
    if str(run.get("target_kind") or "") not in COVERAGE_TARGET_KINDS or not run.get("target_id"):
        return None
    hunt_uuid = run["id"]
    # The answer's status is in the Hunt's HTTP archive (one row per request an action sent), not
    # in the action's settled summary.
    actions = await conn.fetch(
        """SELECT a.capability_name, a.status, a.input_summary->'input' AS input,
                  a.input_summary->>'idempotency_key_sha256' AS idempotency_key_sha256,
                  t.status_code::text AS http_status, NULL::text AS content_type
           FROM hunt_actions a
           LEFT JOIN (SELECT DISTINCT ON (hunt_action_id) hunt_action_id, status_code
                      FROM http_transactions
                      WHERE hunt_run_id=$1 AND hunt_action_id IS NOT NULL
                      ORDER BY hunt_action_id, sequence DESC) t ON t.hunt_action_id = a.id
           WHERE a.hunt_run_id=$1
           ORDER BY a.started_at LIMIT $2""",
        hunt_uuid, MAX_ACTION_ROWS,
    )
    endpoints = await conn.fetch(
        """SELECT method, path, param_shape, content_type, source
           FROM target_endpoints WHERE target_id=$1 AND test_status <> 'gone'
           ORDER BY priority_score DESC, last_seen_at DESC LIMIT $2""",
        run["target_id"], MAX_INVENTORY_ENDPOINTS,
    )
    candidates = await conn.fetch(
        """SELECT c.family, c.canonical_locus FROM investigation_candidates c
           WHERE c.status <> 'expired' AND EXISTS (
               SELECT 1 FROM investigation_candidate_observations o
               WHERE o.candidate_id=c.id AND o.hunt_run_id=$1)
           LIMIT 2000""",
        hunt_uuid,
    )
    angles = await conn.fetch(
        """SELECT DISTINCT ON (fingerprint) family, locus_json AS locus, status
           FROM hunt_coverage_angle_events WHERE hunt_run_id=$1
           ORDER BY fingerprint, event_seq DESC""",
        hunt_uuid,
    )
    return build_coverage(
        actions=[dict(row) for row in actions], endpoints=[dict(row) for row in endpoints],
        candidates=[dict(row) for row in candidates], angles=[dict(row) for row in angles],
        discovery=discovery_state(str(hunt_uuid)), probe_key_digests=probe_key_digests(),
        allowed=list(_json(run.get("policy_json"), {}).get("allowed_capabilities") or []),
    )


__all__ = [
    "CLASSES", "CLASS_GUIDE", "COVERAGE_TARGET_KINDS", "MIN_FORCE_REASON_CHARS", "SCHEMA",
    "build_coverage", "classify",
    "compact_open_coverage", "coverage_page", "debrief_coverage", "family_classes", "finish_guard",
    "key_digest", "load_coverage", "normalize_path", "wall_remaining_seconds",
]
