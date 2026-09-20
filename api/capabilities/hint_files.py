"""Ingest the machine-readable files an application publishes about itself.

A crawler sees the routes an application happens to link. ``robots.txt`` and
``llms.txt`` are the operator's own statement about routes that exist, including
the ones deliberately kept out of the link graph: a disallow rule is a hand-written
list of paths somebody wanted crawlers to stay away from, which is precisely the
surface a black-box crawl never reaches.

This module is pure parsing and normalization: it turns document bytes into
value-free ``discovered_route`` records. The bounded, pinned fetching lives in the
dispatcher, which owns target binding and budget. Nothing here performs I/O.

A declared path is a claim, never a confirmed route. These records enter the same
endpoint manifest as the crawl and are probed like any other candidate.
"""

from __future__ import annotations

import re
from typing import Any, Sequence
import urllib.parse

try:
    from scan.redirect_evidence import http_origin
except ModuleNotFoundError:  # package import in host-side tests
    from ..scan.redirect_evidence import http_origin

# The two conventional, standardized locations. robots.txt is RFC 9309; llms.txt is
# the published convention for describing a site to language-model clients. Both are
# fetched at the origin root and nowhere else, so the cost stays exactly two requests.
HINT_DISCOVERY_PATHS: tuple[str, ...] = ("/robots.txt", "/llms.txt")

_MAX_DOCUMENT_BYTES = 512 * 1024
_MAX_ROUTES = 500
# A single-page application commonly serves its shell for every unknown path, so the
# 200 that comes back for /llms.txt is often HTML, not a description of the site.
# Treating that shell as a hint document would mine the application's own markup for
# "declared" routes that were never declared.
_HTML_PREFIXES = ("<!doctype html", "<html", "<?xml")
_ROBOTS_DIRECTIVE = re.compile(r"^(disallow|allow|sitemap)\s*:\s*(.*)$", re.IGNORECASE)
_MARKDOWN_LINK = re.compile(r"\]\(\s*(<?)([^)\s>]+)")
_BARE_URL = re.compile(r"https?://[^\s<>()\[\]\"']+")
# A path written in prose keeps its query: the parameters are the reason a declared
# route is worth more than the bare path, because candidates are made from observed
# parameters. Trailing sentence punctuation is trimmed rather than captured.
_BARE_PATH = re.compile(
    r"(?<![\w./])(/[A-Za-z0-9._~\-/%]{1,200}(?:\?[A-Za-z0-9._~\-/%=&+]{1,200})?)"
)
_TRAILING_PUNCTUATION = ".,;:!"


def _decoded(body: Any) -> str | None:
    if isinstance(body, bytes):
        body = body[:_MAX_DOCUMENT_BYTES]
        text = body.decode("utf-8", errors="replace")
    elif isinstance(body, str):
        text = body[:_MAX_DOCUMENT_BYTES]
    else:
        return None
    return text


def _is_markup(text: str, content_type: str | None) -> bool:
    if content_type and "html" in str(content_type).lower():
        return True
    return text.lstrip()[:64].lower().startswith(_HTML_PREFIXES)


def _same_origin_path(value: str, *, origin: str) -> str | None:
    """Return the origin-relative path of a declared reference, or None.

    A reference is written by the target, so it can be anything at all. A single
    malformed one used to raise out of the whole ingestion and take the good
    declarations -- and the OpenAPI results this action collects alongside them --
    with it. Every reference is now judged on its own.
    """
    candidate = str(value or "").strip().strip("<>").rstrip(",;")
    if not candidate or candidate.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    # Parsing failures are not silently swallowed here: the caller counts them so
    # a partly unusable document is visible rather than quietly smaller.
    joined = urllib.parse.urljoin(f"{origin}/", candidate)
    parsed = urllib.parse.urlsplit(joined)
    # One definition of "same origin", shared with the report projections, so a
    # scheme or port change can never be judged differently in two places.
    if http_origin(joined) != http_origin(origin):
        return None
    path = parsed.path or "/"
    # A pattern is not a path. Keep the literal prefix a wildcard rule is anchored
    # on and drop the rule entirely when that prefix is the whole site, which
    # declares nothing about any particular route.
    for marker in ("*", "$", "?"):
        index = path.find(marker)
        if index >= 0:
            path = path[:index]
    path = path.rstrip()
    if not path.startswith("/") or path == "/":
        return None
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{path}{query}"


def _robots_references(text: str) -> list[str]:
    references: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        match = _ROBOTS_DIRECTIVE.match(line)
        if match and match.group(2).strip():
            references.append(match.group(2).strip())
    return references


def _llms_references(text: str) -> list[str]:
    references = [match.group(2) for match in _MARKDOWN_LINK.finditer(text)]
    references.extend(
        match.group(0).rstrip(_TRAILING_PUNCTUATION) for match in _BARE_URL.finditer(text)
    )
    references.extend(
        match.group(1).rstrip(_TRAILING_PUNCTUATION) for match in _BARE_PATH.finditer(text)
    )
    return references


def ingest_hint_documents(
    documents: Sequence[tuple[str, Any, str | None]],
    *,
    origin: str,
    issues: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Render robots.txt and llms.txt references as value-free discovered routes."""
    recorded: list[str] = issues if issues is not None else []
    routes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for document_url, body, content_type in documents:
        text = _decoded(body)
        if text is None:
            continue
        name = urllib.parse.urlsplit(str(document_url or "")).path.rsplit("/", 1)[-1]
        if _is_markup(text, content_type):
            # Report it: a site that answers every unknown path with its shell has
            # not published this file, and the coverage it implies is not real.
            recorded.append(f"hint_document_is_markup:{name}")
            continue
        references = (
            _robots_references(text) if name == "robots.txt" else _llms_references(text)
        )
        rejected = 0
        for reference in references:
            try:
                path = _same_origin_path(reference, origin=origin)
            except Exception:  # noqa: BLE001 - a target's text must not end ingestion
                rejected += 1
                continue
            if path is None or path in seen:
                continue
            if len(routes) >= _MAX_ROUTES:
                recorded.append(f"hint_route_limit_reached:{name}")
                break
            seen.add(path)
            routes.append({
                "kind": "discovered_route",
                "method": "GET",
                "url": f"{origin}{path}",
                "source": f"hint:{name}",
            })
        if rejected:
            # A count and the file it came from: enough to see that the document
            # was partly unusable, without quoting any of its content back.
            recorded.append(f"hint_reference_unparsable:{name}:{rejected}")
    return routes


__all__ = [
    "HINT_DISCOVERY_PATHS",
    "ingest_hint_documents",
]
