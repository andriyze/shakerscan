"""Authorization-aware selection of active Nuclei templates by HTTP method.

The active Scan Nuclei family selects templates by severity and tag (``-tags`` as
an OR filter). The pinned ``nuclei-templates`` bundle contains, inside that
selection, hundreds of templates whose requests are *not* GET/HEAD -- default
logins that POST credentials, raw ``PUT``/``DELETE`` requests, and a handful
tagged ``intrusive`` that write or delete server state. Feeding the tag filter
straight to Nuclei therefore sends state-changing traffic that the Scan never
reserved, counted, or was authorized for.

This module parses the bundle once and classifies every template in the
selection by the methods it actually issues, so the executor can:

* run only GET/HEAD templates when ``allow_state_changing_http`` is not granted;
* additionally run non-GET templates when it is granted;
* treat a credential-level template -- a login attempt, which can lock the account it
  tries -- as needing that permission whatever its method: one tagged ``default-login``; one
  that sends a value named like a username or password (a payload, a variable or an extracted
  value) in a header, the body or the query string (``tomcat-default-login`` sends its password
  list by GET in an ``Authorization`` header); or one whose Basic ``Authorization`` header holds
  a literal ``user:password`` pair;
* treat the GET templates reviewed as changing state (``STATE_CHANGING_GET_TEMPLATE_IDS``) the
  same way;
* always exclude ``intrusive`` (destructive) templates -- Scan policy has no
  dangerous/destructive tier that could authorize them (the ``intrusive`` risk
  tier in ``scan.authorization`` is a per-action dangerous-approval concept that
  the deterministic Scan does not plumb), so they are excluded unconditionally;
* always exclude templates that request a path the exposure probe never requests
  (``capabilities.exposure_probe.is_never_requested``: a ``/heapdump`` route makes
  the JVM write a full heap dump), whatever their method and the authorization;
* fail closed: when the index cannot be built, or no permitted template remains,
  the executor skips the active Nuclei run and records a coverage gap instead of
  running an unbounded selection.

The classification mirrors ``scratchpad/nuclei/analyze.py`` (the reviewed
analyzer): the ``method`` field of each ``http``/``requests`` entry plus the
first token of every ``raw:`` request, a bare entry defaulting to GET. Templates
Nuclei would itself skip by default (``.nuclei-ignore`` tags/files, ``fuzzing``
requests) are excluded too, because the executor feeds an explicit ``-id``
allowlist and ``-id`` would otherwise resurrect them.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import os
import re
from typing import Any, Iterable, Mapping

try:  # PyYAML ships in the scanner/worker image where this runs.
    import yaml
except ModuleNotFoundError:  # pragma: no cover - index then fails closed
    yaml = None  # type: ignore[assignment]

try:
    from capabilities.exposure_probe import is_never_requested
except ModuleNotFoundError:  # package import layout
    from ..capabilities.exposure_probe import is_never_requested


# Methods that do not change server state. Every other verb (POST, PUT, DELETE,
# PATCH, OPTIONS, PROPFIND, ...) is treated as state-changing, matching the
# unauthorized rule "run only templates whose every request is GET/HEAD".
_SAFE_METHODS = frozenset({"GET", "HEAD"})
_RAW_METHOD_RE = re.compile(r"\s*(?:@[^\n]*\n\s*)*([A-Z]+)\s")
# A template id Nuclei will accept on ``-id``. The ids come from the pinned,
# checksum-verified bundle, so this only bounds pathological values defensively.
_TEMPLATE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")
# Default ignore list, used only when the bundle ships no ``.nuclei-ignore``.
_DEFAULT_IGNORE_TAGS = frozenset({"dos", "local", "fuzz", "bruteforce", "txt-service"})
_UNKNOWN_METHOD = "UNKNOWN"
_DEFAULT_SEVERITIES = ("high", "critical")
_DEFAULT_TAGS = ("exposure", "misconfig", "auth-bypass", "default-login")
# Reviewed templates of the pinned bundle that request a never-requested path. They stay
# excluded even if a bundle update hides the path from the request expansion below; a test
# pins this set to what that expansion finds in the pinned bundle.
NEVER_REQUESTED_TEMPLATE_IDS = frozenset({"springboot-heapdump"})
# Reviewed templates of the pinned bundle whose GET requests change server state. They need the
# state-changing permission like a non-GET template; a test pins each to a GET-only template of
# the pinned bundle's selection that is not already credential-level.
STATE_CHANGING_GET_TEMPLATE_IDS = frozenset({
    "cve-2025-0674",  # GET /json_data/set_pwd?lev=2&pass=admin1234 sets the admin password
})
# The request target of a raw request: the token after the method, past any ``@`` annotations.
_RAW_TARGET_RE = re.compile(r"\s*(?:@[^\n]*\n\s*)*\S+[ \t]+(\S+)")
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([^{}]*?)\s*\}\}")
# A raw request's ``@`` annotations and request line; what follows is its headers and body.
_RAW_REQUEST_LINE_RE = re.compile(r"\s*(?:@[^\n]*\n\s*)*[^\n]*")
# A payload, variable or extracted value is named like a username or password when one word of
# its name is one of these (``username``, ``pass``, ``aem_user``, ``os_password``, ``adminPassword``).
_CREDENTIAL_NAME_WORDS = frozenset({
    "user", "users", "username", "usernames", "login", "logins",
    "pass", "passwd", "password", "passwords", "pwd", "pw",
})
_NAME_WORD_RE = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A Basic ``Authorization`` header line of a raw request, and the quoted literals of an expression.
_BASIC_AUTH_RE = re.compile(r"(?im)^[ \t]*authorization[ \t]*:[ \t]*basic[ \t]+(\S.*?)[ \t]*$")
_QUOTED_RE = re.compile(r"'([^']*)'|\"([^\"]*)\"")
CREDENTIAL_LEVEL_TAG = "default-login"


@dataclass(frozen=True)
class _TemplateRecord:
    template_id: str
    severity: str
    tags: frozenset[str]
    methods: frozenset[str]
    intrusive: bool
    # Needs an out-of-band interaction (``{{interactsh-url}}``). Scan runs Nuclei with
    # ``-no-interactsh``, so such a template can never match: a verify Scan must not read its
    # silence as "not affected".
    oob: bool = False
    # Follows redirects (``redirects``/``host-redirects``). Scan runs ``-disable-redirects``, so its
    # silence is not a reliable "not matched".
    redirects: bool = False
    # Exploit-class check (rce, lfi, sqli, deserialization, ssti, xxe, code/command injection,
    # ssrf, or a code/javascript/flow step): a verify Scan runs it only with the exploit tier.
    exploit_class: bool = False
    # Requests a path ``is_never_requested`` refuses, in a path, a raw request line, or once a
    # payload or variable value is put into one.
    never_requested: bool = False
    # Tries logins (``_tries_login``). A login attempt can lock the account it tries, so it
    # needs the state-changing permission even when every request is a GET.
    credential_level: bool = False

    @property
    def state_changing(self) -> bool:
        """Needs ``allow_state_changing_http``: a non-GET/HEAD method, credential-level, or a
        GET reviewed as changing state."""
        return (
            bool(self.methods - _SAFE_METHODS) or self.credential_level
            or self.template_id in STATE_CHANGING_GET_TEMPLATE_IDS
        )


@dataclass(frozen=True)
class NucleiMethodIndex:
    """Classified HTTP templates from one pinned bundle directory."""

    templates: tuple[_TemplateRecord, ...]
    ignore_tags: frozenset[str]
    ignore_files: frozenset[str]
    parse_errors: int


@dataclass(frozen=True)
class ActiveNucleiSelection:
    """The server-resolved active Nuclei template allowlist, or a fail-closed skip."""

    template_ids: tuple[str, ...]
    includes_state_changing: bool
    skip: bool
    skip_reason: str | None
    total_matched: int
    get_only_count: int
    state_changing_count: int
    intrusive_excluded: int
    oob_excluded: int = 0
    never_requested_excluded: int = 0
    # Credential-level templates (default logins) among the eligible ones, whether or not the
    # permission they need was granted; they are counted in ``state_changing_count`` as well.
    credential_level_count: int = 0
    # Verify Scans only: which requested checks ran, which did not and why, and which ran but
    # cannot give a reliable "not matched". Recorded on the step's receipt.
    verify_selection: Mapping[str, Any] | None = None

    def telemetry(self) -> dict[str, Any]:
        """The counts a step's receipt records: what matched, what ran and what was held back.

        Credential-level templates are counted as ``default_login``: a receipt masks every
        key named like credential material, and this is a count, not a secret."""
        return {
            "matched": self.total_matched,
            "selected": len(self.template_ids),
            "get_only": self.get_only_count,
            "state_changing": self.state_changing_count,
            "default_login": self.credential_level_count,
            "includes_state_changing": self.includes_state_changing,
            "intrusive_excluded": self.intrusive_excluded,
            "never_requested_excluded": self.never_requested_excluded,
            **({"oob_excluded": self.oob_excluded} if self.oob_excluded else {}),
        }


_INDEX_CACHE: dict[tuple[str, int], NucleiMethodIndex] = {}


def clear_index_cache() -> None:
    """Drop the per-directory index cache (used by tests)."""
    _INDEX_CACHE.clear()


def nuclei_templates_directory() -> str:
    """The pinned Nuclei template bundle directory on the worker image."""
    return os.environ.get("NUCLEI_TEMPLATES", "/opt/nuclei-templates")


def _as_tag_set(value: Any) -> frozenset[str]:
    if isinstance(value, str):
        items: Iterable[str] = value.split(",")
    elif isinstance(value, (list, tuple)):
        items = (str(item) for item in value)
    else:
        items = ()
    return frozenset(item.strip().lower() for item in items if str(item).strip())


def _template_methods(document: Mapping[str, Any]) -> frozenset[str]:
    methods: set[str] = set()
    requests = document.get("http") or document.get("requests") or []
    if not isinstance(requests, list):
        return frozenset()
    for request in requests:
        if not isinstance(request, Mapping):
            continue
        method = request.get("method")
        if method:
            methods.add(str(method).upper())
        raw_requests = request.get("raw") or []
        if isinstance(raw_requests, list):
            for raw in raw_requests:
                match = _RAW_METHOD_RE.match(str(raw))
                # A request line we cannot read (e.g. a templated {{method}}) could send
                # anything, so it counts as a mutation rather than as a GET.
                methods.add(match.group(1).upper() if match else _UNKNOWN_METHOD)
        if not method and not request.get("raw"):
            # A bare request with neither an explicit method nor a raw block is a GET.
            methods.add("GET")
    return frozenset(methods)


EXPLOIT_CLASS_TAGS = frozenset({
    "rce", "lfi", "sqli", "deserialization", "ssti", "xxe", "code-injection", "cmdi", "ssrf",
})


def _follows_redirects(document: Mapping[str, Any]) -> bool:
    requests = document.get("http") or document.get("requests") or []
    return isinstance(requests, list) and any(
        isinstance(request, Mapping) and (request.get("redirects") or request.get("host-redirects"))
        for request in requests
    )


def _is_fuzzing(document: Mapping[str, Any]) -> bool:
    requests = document.get("http") or document.get("requests") or []
    if not isinstance(requests, list):
        return False
    return any(
        isinstance(request, Mapping) and request.get("fuzzing")
        for request in requests
    )


def _payload_values(
    values: Any, bundle: str, template_dir: str, files: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    """A payload's values: an inline list, or the lines of a file inside the bundle, read
    from the bundle root (``helpers/...``) or beside the template."""
    if isinstance(values, (list, tuple)):
        return tuple(str(item) for item in values)
    for base in (bundle, template_dir):
        path = os.path.realpath(os.path.join(base, str(values)))
        if not path.startswith(os.path.realpath(bundle) + os.sep):
            continue
        if path not in files:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    files[path] = tuple(line.strip() for line in handle)
            except OSError:
                continue
        return files[path]
    return (str(values),)


def _requests_never_requested_path(
    document: Mapping[str, Any], bundle: str, template_dir: str, files: dict[str, tuple[str, ...]],
) -> bool:
    """Whether a path, a raw request line, or either with one payload or variable value put
    into it, is a path the exposure probe never requests. Other placeholders read as empty."""
    requests = document.get("http") or document.get("requests") or []
    if not isinstance(requests, list):
        return False
    template_variables = document.get("variables")
    for request in requests:
        if not isinstance(request, Mapping):
            continue
        values: dict[str, Any] = {}
        for source in (template_variables, request.get("variables")):
            if isinstance(source, Mapping):
                values.update({str(name): [value] for name, value in source.items()})
        if isinstance(request.get("payloads"), Mapping):
            values.update({str(name): value for name, value in request["payloads"].items()})
        paths = request.get("path") if isinstance(request.get("path"), list) else []
        raws = request.get("raw") if isinstance(request.get("raw"), list) else []
        targets = [str(path) for path in paths]
        targets.extend(match.group(1) for match in map(_RAW_TARGET_RE.match, map(str, raws)) if match)
        for target in targets:
            fills: list[dict[str, str]] = [{}]
            for name in {match.group(1) for match in _PLACEHOLDER_RE.finditer(target)} & set(values):
                fills.extend(
                    {name: value}
                    for value in _payload_values(values[name], bundle, template_dir, files)
                )
            if any(is_never_requested(_filled(target, fill)) for fill in fills):
                return True
    return False


def _filled(target: str, fill: Mapping[str, str]) -> str:
    return _PLACEHOLDER_RE.sub(lambda match: fill.get(match.group(1), ""), target)


def _credential_named(name: Any) -> bool:
    return any(
        word.lower() in _CREDENTIAL_NAME_WORDS
        for part in re.split(r"[^A-Za-z0-9]+", str(name))
        for word in _NAME_WORD_RE.findall(part)
    )


def _references(text: Any, names: frozenset[str]) -> bool:
    """Whether a ``{{...}}`` expression in ``text`` uses one of ``names`` (``{{password}}``,
    ``{{base64(username + ':' + password)}}``)."""
    return any(
        names.intersection(_IDENTIFIER_RE.findall(match.group(1)))
        for match in _PLACEHOLDER_RE.finditer(str(text))
    )


def _credential_names(document: Mapping[str, Any]) -> frozenset[str]:
    """The template's payloads, variables and extracted values named like a username or password."""
    requests = document.get("http") or document.get("requests") or []
    requests = [request for request in requests if isinstance(request, Mapping)] if isinstance(requests, list) else []
    names: list[Any] = []
    for source in (document.get("variables"), *(request.get(key) for request in requests
                                                 for key in ("payloads", "variables"))):
        names.extend(source if isinstance(source, Mapping) else ())
    for request in requests:
        extractors = request.get("extractors") if isinstance(request.get("extractors"), list) else []
        names.extend(extractor.get("name") for extractor in extractors if isinstance(extractor, Mapping))
    return frozenset(str(name) for name in names if name and _credential_named(name))


def _query(target: str) -> str:
    return target.split("?", 1)[1] if "?" in target else ""


def _literal_pair(value: str) -> bool:
    """Whether a Basic header value holds a literal ``user:password`` pair: base64 text that
    decodes to one, or a quoted literal holding one inside a ``{{...}}`` expression."""
    if "{{" in value:
        return any(
            ":" in literal.strip(":") for match in _QUOTED_RE.finditer(value)
            for literal in (match.group(1) or match.group(2) or "",)
        )
    token = value.split()[0]
    try:
        decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    return ":" in decoded.strip(":")


def _tries_login(document: Mapping[str, Any]) -> bool:
    """Whether a request sends a value named like a username or password -- a payload, a
    variable or an extracted value -- in a header, the body or the query string, or a literal
    ``user:password`` pair in a Basic ``Authorization`` header. A name used only in a path
    enumerates, it does not sign in; a token alone in a Basic header names no account."""
    requests = document.get("http") or document.get("requests") or []
    if not isinstance(requests, list):
        return False
    names = _credential_names(document)
    for request in requests:
        if not isinstance(request, Mapping):
            continue
        raws = [str(raw) for raw in request.get("raw") or ()] if isinstance(request.get("raw"), list) else []
        headers = request.get("headers") if isinstance(request.get("headers"), Mapping) else {}
        paths = [str(path) for path in request.get("path") or ()] if isinstance(request.get("path"), list) else []
        after_line = [raw[_RAW_REQUEST_LINE_RE.match(raw).end():] for raw in raws]
        sent = [*after_line, *(str(value) for value in headers.values()), str(request.get("body") or "")]
        sent.extend(_query(path) for path in paths)
        sent.extend(
            _query(match.group(1)) for match in map(_RAW_TARGET_RE.match, raws) if match
        )
        if names and any(_references(text, names) for text in sent):
            return True
        basic = [match.group(1) for text in after_line for match in _BASIC_AUTH_RE.finditer(text)]
        basic.extend(
            str(value).strip()[len("basic"):].strip() for name, value in headers.items()
            if str(name).strip().lower() == "authorization"
            and str(value).strip().lower().startswith("basic ")
        )
        if any(_literal_pair(value) for value in basic):
            return True
    return False


def _parse_ignore(templates_dir: str) -> tuple[frozenset[str], frozenset[str]]:
    path = os.path.join(templates_dir, ".nuclei-ignore")
    if yaml is None:
        return frozenset(_DEFAULT_IGNORE_TAGS), frozenset()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            parsed = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError):
        return frozenset(_DEFAULT_IGNORE_TAGS), frozenset()
    if not isinstance(parsed, Mapping):
        return frozenset(_DEFAULT_IGNORE_TAGS), frozenset()
    tags = frozenset(
        str(tag).strip().lower() for tag in (parsed.get("tags") or ()) if str(tag).strip()
    )
    files = frozenset(
        str(name).strip() for name in (parsed.get("files") or ()) if str(name).strip()
    )
    return (tags or frozenset(_DEFAULT_IGNORE_TAGS)), files


def build_nuclei_method_index(templates_dir: str) -> NucleiMethodIndex:
    """Parse and classify every HTTP template under ``templates_dir/http``.

    Raises ``FileNotFoundError`` when the bundle's ``http`` directory is absent so
    callers fail closed rather than running an unknown selection.
    """
    if yaml is None:
        raise RuntimeError("PyYAML is required to classify Nuclei templates")
    root = os.path.join(templates_dir, "http")
    if not os.path.isdir(root):
        raise FileNotFoundError(f"nuclei http template directory is absent: {root}")
    ignore_tags, ignore_files = _parse_ignore(templates_dir)
    records: dict[str, _TemplateRecord] = {}
    parse_errors = 0
    payload_files: dict[str, tuple[str, ...]] = {}
    for dirpath, _dirs, files in os.walk(root):
        for filename in files:
            if not filename.endswith(".yaml"):
                continue
            full = os.path.join(dirpath, filename)
            relpath = os.path.relpath(full, templates_dir)
            if relpath in ignore_files:
                continue
            try:
                with open(full, "r", encoding="utf-8") as handle:
                    source = handle.read()
                document = yaml.safe_load(source)
            except (OSError, UnicodeError, yaml.YAMLError):
                parse_errors += 1
                continue
            if not isinstance(document, Mapping) or "info" not in document:
                continue
            info = document.get("info") or {}
            if not isinstance(info, Mapping):
                continue
            template_id = str(document.get("id") or "").strip().lower()
            if not template_id:
                continue
            tags = _as_tag_set(info.get("tags"))
            if tags & ignore_tags:
                continue
            if _is_fuzzing(document):
                continue
            methods = _template_methods(document)
            if not methods:
                # No HTTP request block we can classify -- not an executable http template.
                continue
            record = _TemplateRecord(
                template_id=template_id,
                severity=str(info.get("severity") or "").strip().lower(),
                tags=tags,
                methods=methods,
                intrusive="intrusive" in tags,
                oob="interactsh" in source,
                redirects=_follows_redirects(document),
                exploit_class=bool(tags & EXPLOIT_CLASS_TAGS) or any(
                    key in document for key in ("code", "javascript", "flow")),
                never_requested=_requests_never_requested_path(
                    document, templates_dir, dirpath, payload_files),
                credential_level=(
                    CREDENTIAL_LEVEL_TAG in tags or _tries_login(document)),
            )
            prior = records.get(template_id)
            if prior is not None:
                # `-id` runs every template carrying the id, so a shared id is classified
                # by the union of what its templates send and whether any is intrusive.
                record = _TemplateRecord(
                    template_id=template_id,
                    severity=prior.severity,
                    tags=prior.tags | record.tags,
                    methods=prior.methods | record.methods,
                    intrusive=prior.intrusive or record.intrusive,
                    oob=prior.oob or record.oob,
                    redirects=prior.redirects or record.redirects,
                    exploit_class=prior.exploit_class or record.exploit_class,
                    never_requested=prior.never_requested or record.never_requested,
                    credential_level=prior.credential_level or record.credential_level,
                )
            records[template_id] = record
    return NucleiMethodIndex(
        templates=tuple(records.values()),
        ignore_tags=ignore_tags,
        ignore_files=ignore_files,
        parse_errors=parse_errors,
    )


def _cached_index(templates_dir: str) -> NucleiMethodIndex:
    realpath = os.path.realpath(templates_dir)
    try:
        signature = os.stat(os.path.join(realpath, "http")).st_mtime_ns
    except OSError:
        signature = 0
    key = (realpath, signature)
    index = _INDEX_CACHE.get(key)
    if index is None:
        index = build_nuclei_method_index(templates_dir)
        _INDEX_CACHE[key] = index
    return index


def _normalize_filter(values: Any, default: tuple[str, ...]) -> frozenset[str]:
    parsed = _as_tag_set(values)
    return parsed or frozenset(default)


def resolve_active_nuclei_selection(
    templates_dir: str,
    *,
    severities: Any = None,
    tags: Any = None,
    allow_state_changing_http: bool,
    only_template_ids: Any = None,
    allow_exploit_classes: bool = False,
) -> ActiveNucleiSelection:
    """Resolve the authorization-aware active Nuclei template allowlist.

    ``skip`` is set (fail closed) when the index cannot be built or no permitted
    template remains; the caller then records a coverage gap, not a clean result.
    ``only_template_ids`` (a verify Scan) selects exactly those templates instead of the
    severity/tag filter; intrusive, never-requested-path and unauthorized non-GET templates
    are still dropped.
    """
    exact_ids = _as_tag_set(only_template_ids)
    want_sev = _normalize_filter(severities, _DEFAULT_SEVERITIES)
    want_tags = _normalize_filter(tags, _DEFAULT_TAGS)
    try:
        index = _cached_index(templates_dir)
    except (FileNotFoundError, RuntimeError, OSError):
        return ActiveNucleiSelection(
            template_ids=(), includes_state_changing=False, skip=True,
            skip_reason="nuclei_template_index_unavailable",
            total_matched=0, get_only_count=0, state_changing_count=0,
            intrusive_excluded=0,
        )
    if not index.templates:
        return ActiveNucleiSelection(
            template_ids=(), includes_state_changing=False, skip=True,
            skip_reason="nuclei_template_index_unavailable",
            total_matched=0, get_only_count=0, state_changing_count=0,
            intrusive_excluded=0,
        )
    if exact_ids:
        return _exact_selection(
            index, exact_ids, allow_state_changing_http=allow_state_changing_http,
            allow_exploit_classes=allow_exploit_classes,
        )
    matched = [
        record for record in index.templates
        if record.severity in want_sev and (record.tags & want_tags)
    ]
    get_only: list[str] = []
    state_changing: list[str] = []
    intrusive_excluded = 0
    never_requested_excluded = 0
    credential_level = 0
    for record in matched:
        if record.intrusive:
            # Destructive templates need more than state-changing permission, and
            # Scan has no dangerous/destructive tier to grant it, so they are
            # excluded whether or not state-changing HTTP is authorized.
            intrusive_excluded += 1
            continue
        if _never_requested(record):
            never_requested_excluded += 1
            continue
        if not _TEMPLATE_ID_RE.match(record.template_id):
            continue
        credential_level += int(record.credential_level)
        if record.state_changing:
            state_changing.append(record.template_id)
        else:
            get_only.append(record.template_id)
    allow_ids = list(get_only)
    if allow_state_changing_http:
        allow_ids.extend(state_changing)
    allow_ids = sorted(set(allow_ids))
    if not allow_ids:
        return ActiveNucleiSelection(
            template_ids=(), includes_state_changing=False, skip=True,
            skip_reason="no_eligible_nuclei_templates",
            total_matched=len(matched), get_only_count=len(get_only),
            state_changing_count=len(state_changing),
            intrusive_excluded=intrusive_excluded,
            never_requested_excluded=never_requested_excluded,
            credential_level_count=credential_level,
        )
    includes_state_changing = allow_state_changing_http and bool(state_changing)
    return ActiveNucleiSelection(
        template_ids=tuple(allow_ids),
        includes_state_changing=includes_state_changing,
        skip=False, skip_reason=None,
        total_matched=len(matched), get_only_count=len(get_only),
        state_changing_count=len(state_changing),
        intrusive_excluded=intrusive_excluded,
        never_requested_excluded=never_requested_excluded,
        credential_level_count=credential_level,
    )


def _never_requested(record: _TemplateRecord) -> bool:
    """The template requests a path a Scan never requests, whatever its method or authority."""
    return record.never_requested or record.template_id in NEVER_REQUESTED_TEMPLATE_IDS


def _exact_selection(index: NucleiMethodIndex, exact_ids: frozenset[str], *,
                     allow_state_changing_http: bool, allow_exploit_classes: bool) -> ActiveNucleiSelection:
    """A verify Scan's selection: exactly the requested checks, each either run or excluded with a
    reason, so a non-match is reported as "not affected" only for checks that actually ran."""
    by_id = {record.template_id: record for record in index.templates if record.template_id in exact_ids}
    excluded: dict[str, str] = {}
    ran: list[str] = []
    unreliable: list[str] = []
    state_changing = 0
    credential_level = 0
    for template_id in sorted(exact_ids):
        record = by_id.get(template_id)
        if record is None or not _TEMPLATE_ID_RE.match(template_id):
            excluded[template_id] = "not_in_template_bundle"
        elif record.oob:
            # Scan runs -no-interactsh: such a check can never match.
            excluded[template_id] = "needs_oob_interaction"
        elif record.intrusive:
            excluded[template_id] = "intrusive"
        elif _never_requested(record):
            excluded[template_id] = "never_requested_path"
        elif record.exploit_class and not allow_exploit_classes:
            excluded[template_id] = "exploit_class_needs_exploit_tier"
        elif record.credential_level and not allow_state_changing_http:
            credential_level += 1
            excluded[template_id] = "credential_level_needs_state_changing_http"
        elif record.state_changing and not allow_state_changing_http:
            excluded[template_id] = "needs_state_changing_http"
        else:
            ran.append(template_id)
            state_changing += int(record.state_changing)
            credential_level += int(record.credential_level)
            if record.redirects:
                unreliable.append(template_id)
    selection = {"requested": sorted(exact_ids), "ran": ran, "excluded": excluded,
                 "negative_unreliable": {item: "needs_redirects" for item in unreliable}}
    reasons = sorted(set(excluded.values()))
    return ActiveNucleiSelection(
        template_ids=tuple(ran), includes_state_changing=bool(state_changing),
        skip=not ran,
        skip_reason=None if ran else (
            "verify_checks_need_oob_interaction" if reasons == ["needs_oob_interaction"]
            else "verify_checks_excluded"),
        total_matched=len(by_id), get_only_count=len(ran) - state_changing,
        state_changing_count=state_changing,
        intrusive_excluded=sum(1 for reason in excluded.values() if reason == "intrusive"),
        oob_excluded=sum(1 for reason in excluded.values() if reason == "needs_oob_interaction"),
        never_requested_excluded=sum(
            1 for reason in excluded.values() if reason == "never_requested_path"),
        credential_level_count=credential_level,
        verify_selection=selection,
    )
