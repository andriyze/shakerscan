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
* always exclude ``intrusive`` (destructive) templates -- Scan policy has no
  dangerous/destructive tier that could authorize them (the ``intrusive`` risk
  tier in ``scan.authorization`` is a per-action dangerous-approval concept that
  the deterministic Scan does not plumb), so they are excluded unconditionally;
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

from dataclasses import dataclass
import os
import re
from typing import Any, Iterable, Mapping

try:  # PyYAML ships in the scanner/worker image where this runs.
    import yaml
except ModuleNotFoundError:  # pragma: no cover - index then fails closed
    yaml = None  # type: ignore[assignment]


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
_DEFAULT_SEVERITIES = ("high", "critical")
_DEFAULT_TAGS = ("exposure", "misconfig", "auth-bypass", "default-login")


@dataclass(frozen=True)
class _TemplateRecord:
    template_id: str
    severity: str
    tags: frozenset[str]
    methods: frozenset[str]
    intrusive: bool

    @property
    def state_changing(self) -> bool:
        return bool(self.methods - _SAFE_METHODS)


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
                if match:
                    methods.add(match.group(1).upper())
        if not method and not request.get("raw"):
            # A bare request with neither an explicit method nor a raw block is a GET.
            methods.add("GET")
    return frozenset(methods)


def _is_fuzzing(document: Mapping[str, Any]) -> bool:
    requests = document.get("http") or document.get("requests") or []
    if not isinstance(requests, list):
        return False
    return any(
        isinstance(request, Mapping) and request.get("fuzzing")
        for request in requests
    )


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
    records: list[_TemplateRecord] = []
    seen: set[str] = set()
    parse_errors = 0
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
                    document = yaml.safe_load(handle)
            except (OSError, yaml.YAMLError):
                parse_errors += 1
                continue
            if not isinstance(document, Mapping) or "info" not in document:
                continue
            info = document.get("info") or {}
            if not isinstance(info, Mapping):
                continue
            template_id = str(document.get("id") or "").strip().lower()
            if not template_id or template_id in seen:
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
            seen.add(template_id)
            records.append(_TemplateRecord(
                template_id=template_id,
                severity=str(info.get("severity") or "").strip().lower(),
                tags=tags,
                methods=methods,
                intrusive="intrusive" in tags,
            ))
    return NucleiMethodIndex(
        templates=tuple(records),
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
) -> ActiveNucleiSelection:
    """Resolve the authorization-aware active Nuclei template allowlist.

    ``skip`` is set (fail closed) when the index cannot be built or no permitted
    template remains; the caller then records a coverage gap, not a clean result.
    """
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
    matched = [
        record for record in index.templates
        if record.severity in want_sev and (record.tags & want_tags)
    ]
    get_only: list[str] = []
    state_changing: list[str] = []
    intrusive_excluded = 0
    for record in matched:
        if record.intrusive:
            # Destructive templates need more than state-changing permission, and
            # Scan has no dangerous/destructive tier to grant it, so they are
            # excluded whether or not state-changing HTTP is authorized.
            intrusive_excluded += 1
            continue
        if not _TEMPLATE_ID_RE.match(record.template_id):
            continue
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
        )
    includes_state_changing = allow_state_changing_http and bool(state_changing)
    return ActiveNucleiSelection(
        template_ids=tuple(allow_ids),
        includes_state_changing=includes_state_changing,
        skip=False, skip_reason=None,
        total_matched=len(matched), get_only_count=len(get_only),
        state_changing_count=len(state_changing),
        intrusive_excluded=intrusive_excluded,
    )
