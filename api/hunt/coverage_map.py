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
# Bounds: the inventory read, the routes kept (inventory first, then this Hunt's own), one listed page.
MAX_INVENTORY_ENDPOINTS = 600
# This Hunt's actions are read whole, a page at a time (``load_coverage``).
ACTION_PAGE_ROWS = 1_000
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


_CAPTURE_BINDING_KEYS = frozenset({"source_action_id", "capture_name", "withheld_ref", "header", "prefix"})


def _capture_identity(values: Mapping[str, Any]) -> list[dict[str, str]] | None:
    """The identity one request of this Hunt was sent as, when it is made only of values the
    Hunt's own login captured (a session cookie, a bearer token): the bindings, by reference."""
    bindings = values.get("request_bindings")
    if not isinstance(bindings, list) or not 1 <= len(bindings) <= 4:
        return None
    found: list[dict[str, str]] = []
    for item in bindings:
        if not isinstance(item, Mapping) or not set(item) <= _CAPTURE_BINDING_KEYS:
            return None
        source = (("withheld_ref",) if item.get("withheld_ref") else ("source_action_id", "capture_name"))
        if ("withheld_ref" in item) == ("source_action_id" in item) or not all(
                isinstance(item.get(key), str) and item.get(key) for key in (*source, "header")):
            return None
        found.append({key: str(item[key]) for key in (*source, "header", "prefix") if key in item})
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
}
# "injection" bundles the classes no single check proves: it closes on a route once both checks
# every input of it gets (command and template injection) have run there.
_INJECTION_CHECKS = frozenset({"command_injection", "template_injection"})
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
                         "engine_accounts", "engine_writes", "deferred_finish_failed", "stopping",
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
    """Examination per method and route; input checks cover only the named inputs."""

    def __init__(self) -> None:
        self.requested: set[tuple[str, str]] = set()
        # HTTP statuses the Hunt's own requests got per route: a route that only ever refused or
        # was absent exposed nothing, so its exposure needs no judgement.
        self.statuses: dict[tuple[str, str], set[int]] = {}
        self.closed: dict[tuple[str, str], set[str]] = {}
        self.inputs: dict[tuple[str, str, str], set[str]] = {}

    def close(self, route: str | None, classes: Iterable[str], method: str = "GET", *,
              inputs: set[str] | None = None) -> None:
        if route:
            for klass in classes:
                if inputs is None:
                    self.closed.setdefault((method, route), set()).add(klass)
                elif inputs:
                    self.inputs.setdefault((method, route, klass), set()).update(inputs)

    def closed_for(self, route: str, method: str, params: set[str]) -> set[str]:
        closed = set(self.closed.get((method, route), set()))
        if params:
            for klass in ("sqli", "xss", "injection"):
                if params <= self.inputs.get((method, route, klass), set()):
                    closed.add(klass)
        return closed

    def close_locus(self, route: str | None, method: str, classes: Iterable[str],
                    locus: Mapping[str, Any]) -> None:
        field = locus.get("parameter") or locus.get("input") or locus.get("injection_field")
        for klass in classes:
            self.close(route, (klass,), method,
                       inputs={str(field)} if field and klass in {"sqli", "xss", "injection"} else None)


def _checked_inputs(values: Mapping[str, Any]) -> set[str]:
    field = values.get("parameter") or values.get("injection_field")
    if field:
        return {str(field)}
    return (_query_names(values.get("path")) | _request_inputs(values)
            | _params(values.get("body_field_names")))


def _locus_methods(locus: Mapping[str, Any], route: str | None, known: Mapping) -> set[str]:
    if locus.get("method"):
        return {str(locus["method"]).upper()}
    # A historical note without a method is usable only when the inventory is unambiguous.
    methods = {method for method, path in known if path == route}
    return methods if len(methods) == 1 else set()


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


class CoverageFold:
    """This Hunt's records folded into what its coverage needs, one action row at a time.

    What it keeps grows with the routes the Hunt knows, never with the actions it ran, so a Hunt's
    whole action record is read in pages (``load_coverage``) however long it is: one engine sweep
    runs more than five thousand actions, and a read that kept only the first five thousand never
    saw a later request close a class or map a route."""

    def __init__(self, *, endpoints: Sequence[Mapping[str, Any]], probe_key_digests: Iterable[str] = ()) -> None:
        self.probe_digests = set(probe_key_digests)
        self.ledger = _Ledger()
        self.known: dict[tuple[str, str], dict[str, Any]] = {}
        self.ran: dict[str, str] = {}
        self.ran_checks: dict[tuple[str, str, str], set[str]] = {}
        # The signed-in identity this Hunt's own request last reached each route with (2xx answer).
        self.identities: dict[tuple[str, str], list[dict[str, str]]] = {}
        self.actions = 0
        for row in endpoints[:MAX_INVENTORY_ENDPOINTS]:
            self._add(str(row.get("method") or "GET").upper(), str(row.get("path") or ""),
                      _params(row.get("param_shape")), str(row.get("content_type") or ""),
                      str(row.get("source") or "inventory"))

    def _add(self, method: str, raw_path: str, params: Iterable[str], content_type: str, source: str) -> None:
        known = self.known
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

    def add_action(self, row: Mapping[str, Any]) -> None:
        """Fold one action of this Hunt (rows in the order they started)."""
        ledger, ran, ran_checks, probe_digests = self.ledger, self.ran, self.ran_checks, self.probe_digests
        self.actions += 1
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
            return
        values = _json(row.get("input"), {})
        if name == "authz.verify" and isinstance(values.get("routes"), list):
            if status != "completed":
                return  # an incomplete comparison does not examine every submitted route
            classes = (("function_authz", "unauthenticated_api") if values.get("mode") == "function"
                       else ("object_authz", "unauthenticated_api"))
            for item in values["routes"][:50]:
                text = str(item or "").strip()
                route = normalize_path(text.split(" ", 1)[-1])
                if route:
                    ledger.requested.add(("GET", route))
                    ledger.close(route, classes)
            return
        raw_path = _input_path(name, values)
        route = normalize_path(raw_path) if raw_path else None
        if route is None:
            return
        method = str(values.get("method") or "GET").upper()
        endpoint = (method, route)
        is_probe = str(row.get("idempotency_key_sha256") or "") in probe_digests
        if not is_probe:
            ledger.requested.add(endpoint)
            if name in _VERIFIER_CLASS and status == "completed":
                ledger.close(route, _VERIFIER_CLASS[name], method, inputs=_checked_inputs(values))
            if name == "request.verify" and status == "completed":
                check = str(values.get("check") or "")
                inputs = _checked_inputs(values)
                ledger.close(route, _REQUEST_CHECK_CLASS.get(check, ()), method,
                             inputs=inputs if check == "sql_injection" else None)
                for field in inputs:
                    checked = ran_checks.setdefault((method, route, field), set())
                    checked.add(check)
                    if _INJECTION_CHECKS <= checked:
                        ledger.close(route, ("injection",), method, inputs={field})
            if name == "http.request" and _uses_default_credential(values):
                ledger.close(route, ("default_credentials",), method)
        found = _discovered_from_action(row)
        if found is not None and name in {"http.request", "artifact.inspect"}:
            method, path, http_status, content_type = found
            if not is_probe and http_status is not None:
                ledger.statuses.setdefault(endpoint, set()).add(http_status)
            # An answer that is not "absent" names a route that exists. The engine's own probes
            # enter the inventory through the runner's negative control, never from here.
            if not is_probe and http_status is not None and 200 <= http_status < 300 and name == "http.request":
                identity = _capture_identity(values)
                if identity:
                    self.identities[endpoint] = identity
            if not is_probe and http_status is not None and http_status != 404 and http_status < 500:
                # The inputs the request itself carried are the route's inputs: the sweep tests them.
                self._add(method, path, _request_inputs(values), content_type, "hunt_request")

    def report(self, *, candidates: Sequence[Mapping[str, Any]] = (), angles: Sequence[Mapping[str, Any]] = (),
               discovery: Mapping[str, Any] | None = None, allowed: Iterable[str] | None = None) -> dict[str, Any]:
        """The coverage map of what was folded."""
        ledger, known, ran, identities = self.ledger, self.known, self.ran, self.identities
        for row in candidates:
            locus = _json(row.get("canonical_locus"), {})
            route = normalize_path(_locus_path(locus))
            for method in _locus_methods(locus, route, known):
                ledger.close_locus(route, method, family_classes(row.get("family")) | _LOOKED_AT, locus)
        for row in angles:
            if str(row.get("status") or "") not in SETTLED_ANGLE_STATUSES:
                continue
            locus = _json(row.get("locus"), {})
            route = normalize_path(_locus_path(locus))
            for method in _locus_methods(locus, route, known):
                ledger.close_locus(route, method, family_classes(row.get("family")) | _LOOKED_AT, locus)

        items: list[dict[str, Any]] = []
        pairs_total = 0
        for (method, route), entry in known.items():
            classes = classify(method, route, entry["params"], content_type=entry["content_type"])
            endpoint = (method, route)
            closed = ledger.closed_for(route, method, entry["params"])
            if endpoint in ledger.requested:
                closed.add("review")
                statuses = ledger.statuses.get(endpoint)
                if statuses and statuses <= _NOTHING_SERVED:
                    closed.update({"exposure", "unauthenticated_api"})
            pairs_total += len(classes)
            open_classes = sorted(classes - closed, key=lambda name: _CLASS_RANK.get(name, 99))
            if open_classes:
                untested_params = {
                    klass: sorted(entry["params"] - ledger.inputs.get((method, route, klass), set()))[:8]
                    for klass in open_classes if klass in {"sqli", "xss", "injection"} and entry["params"]
                }
                injection_checks = {
                    field: sorted(_INJECTION_CHECKS - self.ran_checks.get((method, route, field), set()))
                    for field in untested_params.get("injection", ())
                }
                items.append({
                    "endpoint": f"{method} {route}",
                    "untested": open_classes,
                    "params": sorted(entry["params"])[:8],
                    **({"untested_params": untested_params} if untested_params else {}),
                    **({"untested_injection_checks": injection_checks} if injection_checks else {}),
                    "requested": endpoint in ledger.requested,
                    "sources": sorted(entry["sources"])[:4],
                    # By reference only: the sweep sends its checks on this route as the same login.
                    **({"identity": identities[endpoint]} if endpoint in identities else {}),
                })
        items.sort(key=_item_rank)
        # Routes reached with the Hunt's own login whose classes are all settled anonymously: the sweep
        # still tests their inputs as that login. Not open coverage (nothing here holds a finish).
        listed = {item["endpoint"] for item in items}
        signed_in = [{"endpoint": f"{method} {route}", "untested": [], "params": sorted(entry["params"])[:8],
                      "identity": identities[(method, route)]}
                     for (method, route), entry in known.items()
                     if (method, route) in identities and f"{method} {route}" not in listed][:MAX_PAGE]
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
            "endpoints_requested": sum(1 for endpoint in known if endpoint in ledger.requested),
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
                      # The engine could not complete the planner's recorded finish: the Hunt is
                      # still open and somebody has to finish it.
                      **({"deferred_finish_failed": str(state["deferred_finish_failed"])[:300]}
                         if state.get("deferred_finish_failed") else {}),
                          **({"sweep_stats": dict(state["sweep_stats"])}
                             if isinstance(state.get("sweep_stats"), Mapping) else {}),
                          **({"notes": state["notes"]} if state.get("notes") else {}),
                          # What the engine made on the target (allow_account_creation), for clean-up.
                          **({"engine_accounts": list(state["engine_accounts"])} if state.get("engine_accounts") else {}),
                          **({"engine_writes": list(state["engine_writes"])} if state.get("engine_writes") else {})},
            "open": items,
            **({"signed_in": signed_in} if signed_in else {}),
            **({"allowed": sorted(allowed_names)} if allowed_names is not None else {}),
            "class_guide": {name: CLASS_GUIDE[name] for name in by_class},
        }


def build_coverage(
    *,
    actions: Iterable[Mapping[str, Any]],
    endpoints: Sequence[Mapping[str, Any]],
    candidates: Sequence[Mapping[str, Any]] = (),
    angles: Sequence[Mapping[str, Any]] = (),
    discovery: Mapping[str, Any] | None = None,
    probe_key_digests: Iterable[str] = (),
    allowed: Iterable[str] | None = None,
) -> dict[str, Any]:
    """The coverage map from this Hunt's records (pure; ``load_coverage`` reads them).

    ``actions``: this Hunt's actions, every one, in the order they started, with
    ``capability_name``, ``status``, ``input`` (the redacted
    planner input), and for requests ``http_status`` / ``content_type``. ``endpoints``: inventory
    rows (``method``, ``path``, ``param_shape``, ``content_type``, ``source``). ``candidates``:
    this Hunt's candidates (``family``, ``canonical_locus``). ``angles``: the latest coverage
    angle per fingerprint (``family``, ``locus``, ``status``). ``probe_key_digests``: sha256 of the
    engine's own probe idempotency keys, whose answers are discovery, not testing. ``allowed``:
    the Hunt's capability manifest; a discovery step it cannot run is ``not_allowed``, not pending.
    """
    fold = CoverageFold(endpoints=endpoints, probe_key_digests=probe_key_digests)
    for row in actions:
        fold.add_action(row)
    return fold.report(candidates=candidates, angles=angles, discovery=discovery, allowed=allowed)


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
    calls = next_calls(report)
    return {**rest, **({"next_calls": calls} if calls else {}), "open": page, "returned": len(page), "offset": offset,
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
        **({"next_calls": calls} if (calls := next_calls(report)) else {}),
        "list": f"POST /hunts/{hunt_id}/query kind=coverage (or GET /hunts/{hunt_id}/coverage)",
    }


def debrief_coverage(report: Mapping[str, Any], *, forced: bool, reason: str | None,
                     engine_deferred: bool = False) -> dict[str, Any]:
    """What the debrief keeps about coverage at finish. ``forced`` and ``reason`` are the
    planner's own (never the engine's); ``engine_deferred`` marks a finish the planner recorded
    while the engine's sweep ran and the engine completed when its work ended."""
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
                      **({"products": list(discovery.get("products") or [])} if discovery.get("products") else {}),
                      **({key: list(discovery[key]) for key in ("engine_accounts", "engine_writes") if discovery.get(key)})},
        "open_sample": [_item_line(item) for item in (report.get("open") or [])[:20]],
        "forced": bool(forced),
        **({"force_reason": str(reason)[:2000]} if forced and reason else {}),
        **({"engine_deferred": True} if engine_deferred else {}),
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


# The planner loop: every capability answer and every finish refusal names the next concrete calls,
# ready to send, so a planner always has a next step instead of deciding it is done.
NEXT_CALLS = 3


def _concrete(route: str) -> str:
    return re.sub(r"\{[^/{}]*\}", "1", route)


def next_call(item: Mapping[str, Any], allowed: Iterable[str] | None = None) -> dict[str, Any] | None:
    """One ready-to-send call that closes the first open class of an endpoint, or None. With
    ``allowed`` (the Hunt's capability manifest), only a call the Hunt may make."""
    permitted = None if allowed is None else {str(name) for name in allowed}
    for call in _next_call_options(item):
        if permitted is not None and call["capability"] not in permitted:
            continue
        if call.get("default_credential") and not _default_credentials_on():
            continue
        call.pop("default_credential", None)
        return call
    return None


def _default_credentials_on() -> bool:
    try:
        from .default_credentials import enabled
    except ImportError:  # pragma: no cover - the module is part of the package
        return False
    return enabled()


def _next_call_options(item: Mapping[str, Any]):
    """Every ready call that would close an open class of the endpoint, best first."""
    method, _, route = str(item.get("endpoint") or "").partition(" ")
    if not route.startswith("/"):
        return None
    path = _concrete(route)
    params = [str(name) for name in item.get("params") or () if str(name)]
    identity = {"request_bindings": list(item["identity"])} if item.get("identity") else {}
    for klass in item.get("untested") or ():
        remaining = (item.get("untested_params") or {}).get(klass) or params
        request_params = list(dict.fromkeys([*remaining, *params]))
        if klass in {"sqli", "injection"} and params:
            pending = (item.get("untested_injection_checks") or {}).get(remaining[0])
            check = "sql_injection" if klass == "sqli" else (pending or ["command_injection"])[0]
            base = ({"query": {name: "1" for name in request_params[:10]}} if method == "GET"
                    else {"json_body": {name: "1" for name in request_params[:20]}})
            yield {"capability": "request.verify", "why": f"{klass} on {method} {route} ({remaining[0]})",
                    "input": {"check": check, "method": method, "path": path, "parameter": remaining[0], **base, **identity}}
        if klass == "xss" and params and method == "GET":
            yield {"capability": "xss.verify", "why": f"xss on GET {route}",
                    "input": {"path": f"{path}?" + urllib.parse.urlencode({name: "1" for name in request_params[:10]})}}
        if klass in {"exposure", "unauthenticated_api"} and method == "GET" and not identity:
            yield {"capability": "request.verify", "why": f"{klass} on GET {route}",
                    "input": {"check": "exposure" if klass == "exposure" else "unauthenticated_api",
                              "method": "GET", "path": path}}
        if klass == "default_credentials" and method == "POST":
            yield {"capability": "http.request", "why": f"default credentials on POST {route}", "default_credential": True, "input": {
                "method": "POST", "path": path, "json_body": {"username": "", "password": ""},
                "request_bindings": [
                    {"default_credential": "dc-01", "credential_field": "username", "body_pointer": "/username"},
                    {"default_credential": "dc-01", "credential_field": "secret", "body_pointer": "/password"}]}}
        if klass in {"review", "object_authz", "function_authz"} and method == "GET":
            yield {"capability": "http.request", "why": f"{klass}: read GET {route}" + (
                " as the login that reached it" if identity else ""),
                "input": {"method": "GET", "path": path, **identity}}


def next_calls(report: Mapping[str, Any] | None, *, limit: int = NEXT_CALLS) -> list[dict[str, Any]]:
    """The first few ready calls of the open list, only of capabilities the Hunt may run (the
    report's ``allowed``, when it was built with the manifest)."""
    calls: list[dict[str, Any]] = []
    allowed = (report or {}).get("allowed")
    for item in (report or {}).get("open") or ():
        call = next_call(item, allowed) if isinstance(item, Mapping) else None
        if call is not None:
            calls.append(call)
        if len(calls) >= limit:
            break
    return calls


def http_budget_left(run: Mapping[str, Any]) -> bool:
    budget = _json(run.get("budget_json"), {})
    used = _json(run.get("budget_used_json"), {})
    limit = budget.get("max_http_requests")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        return True
    return int(used.get("http_requests") or 0) < limit


def finish_guard(run: Mapping[str, Any], report: Mapping[str, Any] | None, *, force: bool,
                 force_reason: str | None, now: datetime | None = None,
                 can_test: bool = True, engine_deferred: bool = False) -> str | None:
    """Why this finish is refused, or None.

    ``engine_deferred`` is the engine completing a finish the planner already recorded
    (``auto_discovery``): the planner's guards were applied when it was recorded, the engine's
    own work has ended, and no planner is left to send a next call, so nothing here holds it.
    Only server code sets it; no request carries it.

    Never refuses a Hunt that cannot test (``can_test`` false: passive, or its approval revoked
    or expired; it has no checks to close the open pairs with), a Hunt whose wall or HTTP budget
    is spent, a budget-exhausted Hunt, one with nothing open, or a forced finish with a reason
    (the engine's own sweep, not the planner, does the remaining work; a finish while it runs is
    deferred until it ends, see ``run_service``). Profile duration is a ceiling, not a minimum
    amount of time the planner must spend after it answers the operator's objective."""
    if str(run.get("target_kind") or "") not in COVERAGE_TARGET_KINDS or report is None:
        return None
    if not can_test or engine_deferred:
        return None
    if force:
        if len(str(force_reason or "").strip()) < MIN_FORCE_REASON_CHARS:
            return ("force=true needs force_reason: say in a sentence why the open coverage is left "
                    "untested; it is recorded in the debrief")
        # A resource profile is a ceiling, never a minimum investigation length. The caller
        # records why the objective is complete and the remaining coverage in the debrief.
        return None
    if str(run.get("status") or "") == "budget_exhausted":
        return None
    remaining = wall_remaining_seconds(run, now=now)
    if remaining is not None and remaining < FINISH_MIN_WALL_SECONDS:
        return None
    if not http_budget_left(run):
        return None
    return _open_refusal(run, report, remaining)


def _open_refusal(run: Mapping[str, Any], report: Mapping[str, Any], remaining: float | None) -> str | None:
    """The unforced finish refusal: what is open, and the next calls to send."""
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
        + f", with {left} and HTTP budget left. The listed endpoints are this target's mapped "
        "surface: routes its pages, scripts, robots and sitemap files or API description name, "
        "paths a probe saw answer unlike a path that cannot exist, and routes this Hunt's own "
        "requests reached (each entry's sources say which). A route that turns out not to exist "
        "closes with the request that shows it.",
    ]
    if lines:
        parts.append("Untested first: " + "; ".join(lines) + ".")
    calls = next_calls(report)
    if calls:
        parts.append("Send next (ready to send): " + "; ".join(
            f"{call['capability']} {json.dumps(call['input'], separators=(',', ':'))[:300]}" for call in calls) + ".")
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
    endpoints = await conn.fetch(
        """SELECT method, path, param_shape, content_type, source
           FROM target_endpoints WHERE target_id=$1 AND test_status <> 'gone'
           ORDER BY priority_score DESC, last_seen_at DESC LIMIT $2""",
        run["target_id"], MAX_INVENTORY_ENDPOINTS,
    )
    fold = CoverageFold(endpoints=[dict(row) for row in endpoints], probe_key_digests=probe_key_digests())
    # Every action of the Hunt, in the order they started, a page at a time through a cursor: the
    # fold keeps routes, not rows, so the read is whole however many actions there are (it was
    # the first 5,000, which one sweep exceeds). The answer's status is in the Hunt's HTTP archive
    # (one row per request an action sent), not in the action's settled summary.
    async with conn.transaction():
        async for row in conn.cursor(
            """SELECT a.capability_name, a.status, a.input_summary->'input' AS input,
                      a.input_summary->>'idempotency_key_sha256' AS idempotency_key_sha256,
                      t.status_code::text AS http_status, NULL::text AS content_type
               FROM hunt_actions a
               LEFT JOIN (SELECT DISTINCT ON (hunt_action_id) hunt_action_id, status_code
                          FROM http_transactions
                          WHERE hunt_run_id=$1 AND hunt_action_id IS NOT NULL
                          ORDER BY hunt_action_id, sequence DESC) t ON t.hunt_action_id = a.id
               WHERE a.hunt_run_id=$1
               ORDER BY a.started_at, a.id""",
            hunt_uuid, prefetch=ACTION_PAGE_ROWS,
        ):
            fold.add_action(row)
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
    return fold.report(
        candidates=[dict(row) for row in candidates], angles=[dict(row) for row in angles],
        discovery=discovery_state(str(hunt_uuid)),
        allowed=list(_json(run.get("policy_json"), {}).get("allowed_capabilities") or []),
    )


__all__ = [
    "CLASSES", "CLASS_GUIDE", "COVERAGE_TARGET_KINDS", "CoverageFold", "MIN_FORCE_REASON_CHARS", "SCHEMA",
    "build_coverage", "classify",
    "compact_open_coverage", "coverage_page", "debrief_coverage", "family_classes", "finish_guard",
    "key_digest", "load_coverage", "normalize_path", "wall_remaining_seconds",
]
