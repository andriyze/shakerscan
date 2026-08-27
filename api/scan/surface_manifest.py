"""Build the one canonical endpoint manifest owned by Scan surface discovery."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping
import urllib.parse

try:
    from runtime.models import TargetBinding
except ModuleNotFoundError:  # package imports in host-side tests
    from ..runtime.models import TargetBinding

try:
    from manifests import EndpointManifest, EndpointRecord, normalize_endpoint
except ModuleNotFoundError:  # package imports through scanner
    from scanner.manifests import EndpointManifest, EndpointRecord, normalize_endpoint


_HTTP_METHOD = re.compile(r"^[A-Z]{3,12}$")
_DEGRADED_STATUSES = frozenset({"partial", "failed", "blocked"})


def _record_origin(record: EndpointRecord) -> str:
    host = f"[{record.host}]" if ":" in record.host else record.host
    default_port = 443 if record.scheme == "https" else 80
    authority = host if record.port == default_port else f"{host}:{record.port}"
    return f"{record.scheme}://{authority}"


def _host_in_roots(host: str, roots: Iterable[str]) -> bool:
    normalized = str(host or "").lower().rstrip(".")
    return any(
        normalized == root or normalized.endswith("." + root)
        for raw_root in roots
        if (root := str(raw_root or "").lower().rstrip("."))
    )


def _summary_status(summary: Any) -> tuple[str, str | None, bool]:
    item = dict(summary) if isinstance(summary, Mapping) else {}
    status = str(item.get("status") or "skipped").strip().lower()
    reason = str(item.get("reason") or "").strip()[:200] or None
    if status == "cancelled":
        return "cancelled", reason or "capability_cancelled", True
    if status in _DEGRADED_STATUSES:
        return ("partial" if status == "partial" else "failed"), reason, False
    return "complete", reason, False


def _known_endpoint_url(
    value: Any, *, origin: str,
) -> tuple[str, str, str | None, list[str] | None] | None:
    """Parse one seeded endpoint into method, URL, and any declared body shape.

    The documented seed format is `POST /api/v1/search json:{"query":"test"}`. Splitting on the
    first whitespace alone left the body spec attached to the URL, so a seeded non-GET endpoint was
    stored with a canonical path like `/rest/user/login json:{...}` -- a path that matches no real
    route, and therefore never dedupes against the same endpoint seen by a crawler and never
    attributes coverage to it. The body is parsed off the path here, and its field names are
    returned so the endpoint record can carry the shape rather than only a fingerprint.
    """
    text = str(value or "").strip()
    if not text:
        return None
    pieces = text.split(None, 1)
    if len(pieces) == 2 and _HTTP_METHOD.fullmatch(pieces[0].upper()):
        method, text = pieces[0].upper(), pieces[1].strip()
    else:
        method = "GET"
    content_type: str | None = None
    body_fields: list[str] | None = None
    marker = text.find(" json:")
    if marker >= 0:
        body_text = text[marker + len(" json:"):].strip()
        text = text[:marker].strip()
        content_type = "application/json"
        try:
            decoded = json.loads(body_text)
        except (TypeError, ValueError):
            # An unparseable body is dropped rather than left in the URL: a path that cannot be
            # requested is worse than an endpoint with no declared body.
            decoded = None
        if isinstance(decoded, Mapping):
            body_fields = sorted(str(key)[:200] for key in decoded)
    if text.startswith("/") and not text.startswith("//"):
        text = urllib.parse.urljoin(origin + "/", text.lstrip("/"))
    return method, text, content_type, body_fields


def build_scan_surface_manifest(
    *,
    target_url: str,
    target: TargetBinding,
    options: Mapping[str, Any],
    collection_replay: Mapping[str, Any],
    subdomains: Mapping[str, Any],
    probe: Mapping[str, Any],
    crawl: Mapping[str, Any],
    content: Mapping[str, Any],
    max_endpoints: int,
    browser: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize every fixed-stage surface producer without retaining URL values.

    ``browser`` is optional: the headless crawl is a supporting producer that a
    target without a browser runtime simply does not run, and an absent summary
    is recorded as skipped rather than treated as a failure.
    """
    browser = browser if isinstance(browser, Mapping) else {"status": "skipped"}
    limit = max(1, min(100_000, int(max_endpoints)))
    manifest = EndpointManifest(auto_persist=False)
    allowed_origins = {
        str(item).strip().lower().rstrip("/")
        for item in target.allowed_origins
        if str(item).strip()
    }
    roots = target.allowed_root_domains or (target.canonical_host,)
    parsed_target = urllib.parse.urlsplit(str(target_url or ""))
    target_origin = urllib.parse.urlunsplit((
        parsed_target.scheme.lower(), parsed_target.netloc.lower(), "", "", "",
    ))

    cancelled = False
    endpoint_identities: set[str] = set()

    def collect(
        name: str,
        candidates: Iterable[tuple[Any, Any]],
        *,
        summary: Mapping[str, Any] | None = None,
        root_scoped: bool = False,
    ) -> None:
        nonlocal cancelled
        manifest.start_producer(name)
        invalid = 0
        out_of_scope = 0
        truncated = 0
        for raw in candidates:
            raw_method, raw_url = raw[0], raw[1]
            raw_content_type = raw[2] if len(raw) > 2 else None
            raw_body_schema = raw[3] if len(raw) > 3 else None
            try:
                record = normalize_endpoint(
                    method=str(raw_method or "GET"),
                    url=str(raw_url or ""),
                    source=name,
                    content_type=raw_content_type,
                    body_schema=raw_body_schema,
                )
            except ValueError:
                invalid += 1
                continue
            in_scope = (
                _host_in_roots(record.host, roots)
                if root_scoped
                else _record_origin(record).lower() in allowed_origins
                and record.host == target.canonical_host
            )
            if not in_scope:
                out_of_scope += 1
                continue
            if (
                record.identity not in endpoint_identities
                and len(endpoint_identities) >= limit
            ):
                truncated += 1
                continue
            if manifest.add(name, record):
                endpoint_identities.add(record.identity)
        status, summary_reason, producer_cancelled = _summary_status(summary)
        cancelled = cancelled or producer_cancelled
        reasons = [item for item in (
            summary_reason,
            f"invalid_observations:{invalid}" if invalid else None,
            f"out_of_scope_observations:{out_of_scope}" if out_of_scope else None,
            f"endpoint_limit_reached:{truncated}" if truncated else None,
        ) if item]
        if status == "complete" and (invalid or out_of_scope or truncated):
            status = "partial"
        manifest.finish_producer(
            name,
            status=status,
            reason=";".join(reasons)[:200] or None,
        )

    collect("seed", (("GET", target_url),), summary={"status": "success"})
    collect(
        "known_endpoints",
        (
            item
            for raw in options.get("custom_endpoints") or ()
            if (item := _known_endpoint_url(raw, origin=target_origin)) is not None
        ),
        summary={"status": "success"},
    )
    collect(
        "collections.replay",
        (
            (
                item.get("method") or "GET",
                item.get("final_url") or item.get("redacted_url"),
            )
            for item in collection_replay.get("observations") or ()
            if isinstance(item, Mapping) and item.get("kind") == "request_replay"
        ),
        summary=collection_replay,
    )
    collect(
        "web.probe",
        (
            ("GET", item.get("url"))
            for item in probe.get("observations") or ()
            if isinstance(item, Mapping) and item.get("kind") == "http_fingerprint"
        ),
        summary=probe,
    )
    collect(
        "web.crawl",
        (
            (item.get("method") or "GET", item.get("url"))
            for item in crawl.get("observations") or ()
            if isinstance(item, Mapping) and item.get("kind") == "discovered_route"
        ),
        summary=crawl,
    )
    collect(
        "web.browser_crawl",
        (
            (item.get("method") or "GET", item.get("url"))
            for item in browser.get("observations") or ()
            if isinstance(item, Mapping) and item.get("kind") == "discovered_route"
        ),
        summary=browser,
    )
    collect(
        "web.content_discover",
        (
            ("GET", item.get("url"))
            for item in content.get("observations") or ()
            if isinstance(item, Mapping) and item.get("kind") == "content_discovery"
        ),
        summary=content,
    )
    collect(
        "subdomains.discover",
        (
            (
                "GET",
                f"{parsed_target.scheme.lower()}://{str(item.get('host') or '').lower().rstrip('.')}/",
            )
            for item in subdomains.get("observations") or ()
            if isinstance(item, Mapping) and item.get("kind") == "subdomain"
        ),
        summary=subdomains,
        root_scoped=True,
    )
    manifest.finalize(cancelled=cancelled)
    payload = manifest.to_dict()
    # Defense in depth: the public manifest must remain JSON-safe and detached
    # from the mutable producer summaries passed by the worker.
    return json.loads(json.dumps(payload, sort_keys=True, separators=(",", ":")))
