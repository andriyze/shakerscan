"""The Exposure candidates a finding relates to, for the finding detail read path.

Service Intelligence lists advisory candidates for each service from the product and version it
observed (a ``Server`` header, a service fingerprint). A finding about that software on the same
origin -- a template match for one of those CVEs, or one naming the product -- links to them here.
The link is read-only and bounded: the newest few identity-bearing Scan actions of the finding's
own target, the same validated sources and matcher the Exposure view uses, and only labels and
identifiers in the result. A candidate is never proof and a link never changes the finding.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Callable, Mapping
from urllib.parse import quote, urlsplit
import uuid

from .service_intel import CVE_ID, PRODUCT_CPE_ALIASES, enrich_service, load_service_intelligence
from .service_inventory import build_inventory, object_value, origin, text
from .service_store import SCAN_SOURCES_SQL, validated_scan_source

logger = logging.getLogger(__name__)

# The newest identity-bearing actions read for one finding: one Scan's probe, baseline and
# fingerprint actions. The Exposure view reads up to twelve; a detail page needs the current one.
MAX_FINDING_SOURCES = 4
MAX_RELATED_EXPOSURES = 8
_CVE_TEXT = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,19}\b", re.IGNORECASE)
# "Apache 2.4.49", "nginx/1.18.0", "OpenSSH v8.2": a product named with a version.
_VERSIONED_NAME = re.compile(r"\b[A-Za-z][A-Za-z0-9_.+-]{1,40}[ /]v?[0-9]+\.[0-9]+")
_SOURCES = {"http_response": "Server header", "network_fingerprint": "Service fingerprint"}


def finding_cves(finding: Mapping[str, Any]) -> list[str]:
    """CVE ids the finding names in its evidence or title, upper-cased and bounded."""
    evidence = object_value(finding.get("evidence"))
    raw = evidence.get("cve_ids")
    values = [str(item) for item in raw[:10]] if isinstance(raw, list) else []
    values.extend(_CVE_TEXT.findall(text(finding.get("title"), 300)))
    found: list[str] = []
    for value in values:
        cve = value.strip().upper()
        if CVE_ID.fullmatch(cve) and cve not in found:
            found.append(cve)
    return found[:5]


def _finding_text(finding: Mapping[str, Any]) -> str:
    evidence = object_value(finding.get("evidence"))
    parts = [finding.get("title"), evidence.get("cpe"), evidence.get("template_id")]
    return " ".join(text(part, 300) for part in parts).lower()


_TOKEN = re.compile(r"[a-z0-9]+")


def _tokens(value: str) -> tuple[str, ...]:
    return tuple(_TOKEN.findall(value.lower()))


def _contains(haystack: tuple[str, ...], needle: tuple[str, ...]) -> bool:
    size = len(needle)
    return bool(size) and any(haystack[i:i + size] == needle for i in range(len(haystack) - size + 1))


def names_product(named: str, product: str) -> bool:
    """True when the finding's text names ``product`` as whole words, and not as part of a longer
    known product name: "go" is not in "going", "php" not in "phpmyadmin", and "Apache" (the HTTP
    server) is not "Apache Tomcat"."""
    words = _tokens(named)
    wanted = _tokens(product)
    if not _contains(words, wanted):
        return False
    aliases = PRODUCT_CPE_ALIASES.get(" ".join(wanted))
    for other, other_aliases in PRODUCT_CPE_ALIASES.items():
        other_words = _tokens(other)
        if (len(other_words) > len(wanted) and _contains(other_words, wanted)
                and other_aliases != aliases and _contains(words, other_words)):
            return False
    return True


def _finding_origin(finding: Mapping[str, Any]) -> str | None:
    evidence = object_value(finding.get("evidence"))
    return origin(finding.get("url")) or origin(evidence.get("matched_at")) or origin(evidence.get("request_url"))


def wants_exposure_link(finding: Mapping[str, Any]) -> bool:
    """Only a web finding about identified software is worth the read: it names a CVE, a CPE or a
    versioned product. Anything else on the origin is not about the advisories listed there."""
    if not finding.get("target_id") or finding.get("device_target_id") or not _finding_origin(finding):
        return False
    evidence = object_value(finding.get("evidence"))
    return bool(
        finding_cves(finding) or text(evidence.get("cpe"), 300)
        or _VERSIONED_NAME.search(text(finding.get("title"), 300))
    )


def _exposure_href(app_origin: str, service_id: str) -> str:
    host = urlsplit(app_origin).hostname or ""
    return f"/exposure?service_query={quote(host, safe='')}&service_id={quote(service_id, safe='')}"


def exposure_links(
    finding: Mapping[str, Any], services: list[dict[str, Any]], *,
    snapshot: Mapping[str, Any], matcher: Callable[..., Any], limit: int = MAX_RELATED_EXPOSURES,
) -> list[dict[str, Any]]:
    """Candidates of the services at the finding's origin that share its CVE or product.

    Pure: ``services`` are inventory records (``build_inventory``); each matching one is enriched
    with the same snapshot and matcher the Exposure view uses. CVE matches lead.
    """
    app_origin = _finding_origin(finding)
    if not app_origin:
        return []
    cves = set(finding_cves(finding))
    named = _finding_text(finding)
    links: list[tuple[int, int, dict[str, Any]]] = []
    seen: set[str] = set()
    for service in services:
        if (service.get("application_origin") != app_origin or service.get("binding_status") == "historical_locator"
                or service.get("identity_basis") == "port_hint" or not service.get("product")):
            continue
        enriched = dict(service)
        enrich_service(enriched, snapshot, matcher)
        product = text(enriched.get("product"), 80)
        same_product = bool(product) and names_product(named, product)
        for order, candidate in enumerate(enriched.get("cve_candidates") or []):
            cve = text(candidate.get("id"), 30)
            if not CVE_ID.fullmatch(cve) or cve in seen or not (cve in cves or same_product):
                continue
            seen.add(cve)
            links.append((0 if cve in cves else 1, order, {
                "cve": cve,
                "title": text(candidate.get("title"), 200),
                "severity": text(candidate.get("severity"), 20),
                "product": product,
                "version": text(enriched.get("version"), 60),
                "source": _SOURCES.get(str(enriched.get("identity_basis")), "Service observation"),
                "relation": "Same CVE" if cve in cves else "Same product on this origin",
                "match_type": text(candidate.get("match_type"), 60),
                "service_id": text(enriched.get("id"), 60),
                "exposure_href": _exposure_href(app_origin, str(enriched.get("id") or "")),
            }))
    links.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in links[:limit]]


async def related_exposures(
    conn: Any, finding: Mapping[str, Any], *,
    intelligence: Callable[[], tuple[dict[str, Any], Callable[..., Any]]] = load_service_intelligence,
) -> list[dict[str, Any]]:
    """The finding's linked Exposure candidates; empty when it has none or they cannot be read.

    One bounded query (the Exposure view's own source query, newest ``MAX_FINDING_SOURCES``
    actions of the finding's target) in a read-only transaction, then the same manifest
    validation. A failure here never fails the finding read.
    """
    if not wants_exposure_link(finding):
        return []
    try:
        target_id = uuid.UUID(str(finding["target_id"]))
        sources = []
        async with conn.transaction(isolation="repeatable_read", readonly=True):
            rows = await conn.fetch(SCAN_SOURCES_SQL, target_id, MAX_FINDING_SOURCES)
            for raw in rows[:MAX_FINDING_SOURCES]:
                try:
                    source = await validated_scan_source(conn, dict(raw))
                except ValueError:
                    continue
                if source:
                    sources.append(source)
        if not sources:
            return []
        services, _rejected = build_inventory({"kind": "web", "id": str(target_id)}, sources)
        app_origin = _finding_origin(finding)
        if not any(service.get("application_origin") == app_origin and service.get("product") for service in services):
            return []
        snapshot, matcher = await asyncio.to_thread(intelligence)
        return exposure_links(finding, services, snapshot=snapshot, matcher=matcher)
    except Exception as exc:  # the brief stands without the link
        logger.warning("finding exposure link unavailable: %s", type(exc).__name__)
        return []


__all__ = [
    "MAX_RELATED_EXPOSURES", "exposure_links", "finding_cves", "names_product", "related_exposures",
    "wants_exposure_link",
]
