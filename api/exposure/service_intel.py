"""Offline service intelligence. Advisory matches are candidates, never proof.

The existing pinned snapshot and matcher remain the source of applicability
logic. Loading this module neither accesses the network nor executes a tool.
"""
from __future__ import annotations

import os
from functools import lru_cache
import re
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .service_inventory import text, timestamp

CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
MAX_CANDIDATES = 30


def reference_url(value: Any) -> str | None:
    """References are links, not execution instructions or fetch destinations."""
    if not isinstance(value, str) or len(value) > 2000:
        return None
    if any(ord(c) < 33 for c in value) or "\\" in value:
        return None
    try:
        url = urlsplit(value)
        if url.scheme not in {"https", "http"} or not url.hostname or url.username is not None or url.password is not None:
            return None
        if url.port is not None and not 1 <= url.port <= 65535:
            return None
    except ValueError:
        return None
    return value


def load_service_intelligence() -> tuple[dict[str, Any], Callable[..., Any]]:
    """Reuse the device intelligence trust boundary; never fetch a live feed."""
    try:
        from scanner_tools import device_advisories
    except ModuleNotFoundError:
        from scanner.scanner_tools import device_advisories
    snapshot = device_advisories.load_verified_snapshot(
        os.environ.get("DEVICE_INTEL_DB_PATH"), os.environ.get("DEVICE_INTEL_DB_SHA256"),
    )
    # Build a request-local candidate index once. Matching the entire custom
    # snapshot for every visible listener would turn one page into O(S * CVEs).
    records = [row for row in snapshot.get("advisories", []) if isinstance(row, Mapping)]
    products: dict[str, list[int]] = {}
    identities: dict[tuple[str, ...], list[int]] = {}
    references: dict[str, list[Mapping[str, Any]]] = {}
    for index, row in enumerate(records):
        products.setdefault(str(row.get("product") or "").strip().lower(), []).append(index)
        identity = device_advisories._cpe_identity(row.get("cpe"))
        if identity and all(not part.wildcard and not part.not_applicable for part in identity[:3]):
            identities.setdefault(tuple(part.value for part in identity[:3]), []).append(index)
        aid = str(row.get("advisory_id") or row.get("cve") or "").upper()
        if CVE_ID.fullmatch(aid):
            references.setdefault(aid, []).append(row)
    snapshot["_advisories_by_id"] = references

    @lru_cache(maxsize=256)
    def lookup(cpe, product, version, limit):
        selected = set(products.get(str(product or "").strip().lower(), ())) if product else set()
        identity = device_advisories._cpe_identity(cpe)
        if identity:
            selected.update(identities.get(tuple(part.value for part in identity[:3]), ()))
        return device_advisories.match_advisories(
            [records[index] for index in sorted(selected)], cpe=cpe, product=product,
            version=version, identity_evidence_tier="network_service_fingerprint", limit=limit,
        )

    def indexed_matcher(_records, *, cpe, product, version, identity_evidence_tier=None, limit=50):
        return lookup(cpe, product, version, limit)

    return snapshot, indexed_matcher


def snapshot_summary(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    generated = timestamp(snapshot.get("generated_at"))
    return {
        "status": text(snapshot.get("status"), 60) or "unavailable",
        "generated_at": generated.isoformat() if generated else None,
        "snapshot_sha256": text(snapshot.get("snapshot_sha256"), 64) or None,
        "record_count": len(snapshot.get("advisories") or []),
        "coverage": "curated_offline_snapshot",
        "limitations": [
            "This is a curated offline snapshot, not complete or live CVE coverage.",
            "Version and CPE matches do not establish configuration or distribution backport applicability.",
            "Public exploit references are unexecuted research links, not ShakerScan capabilities.",
        ],
    }


def _number(value: Any, low: float, high: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if low <= value <= high else None


def _exploitation_context(records: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Exploitation context from the pinned snapshot: CVSS base score, CISA KEV membership, the
    EPSS likelihood, and the checks the image's own templates carry. Metadata, never executed."""
    context: dict[str, Any] = {"cvss_score": None, "known_exploited": None, "epss": None, "checks": []}
    for record in records:
        score = _number(record.get("cvss_score"), 0, 10)
        if score is not None and (context["cvss_score"] is None or score > context["cvss_score"]):
            context["cvss_score"] = score
        kev = record.get("known_exploited")
        if isinstance(kev, Mapping) and context["known_exploited"] is None:
            context["known_exploited"] = {"date_added": text(kev.get("date_added"), 10) or None,
                                          "ransomware": kev.get("ransomware") is True}
        epss = record.get("epss")
        if isinstance(epss, Mapping) and context["epss"] is None:
            probability, percentile = _number(epss.get("score"), 0, 1), _number(epss.get("percentile"), 0, 1)
            if probability is not None:
                context["epss"] = {"score": probability, "percentile": percentile}
        for check in list(record.get("checks") or [])[:5]:
            if isinstance(check, Mapping) and re.fullmatch(r"[A-Za-z0-9._-]{1,120}", str(check.get("id") or "")):
                item = {"kind": "nuclei_template", "id": str(check["id"])}
                if item not in context["checks"]:
                    context["checks"].append(item)
    return context


def candidate_priority(row: Mapping[str, Any]) -> tuple[Any, ...]:
    epss = row.get("epss") or {}
    return (0 if row.get("known_exploited") else 1, -(epss.get("score") or 0.0),
            -(row.get("cvss_score") or 0.0), str(row.get("id") or ""))


def enrich_service(service: dict[str, Any], snapshot: Mapping[str, Any], matcher: Callable[..., Any]) -> None:
    """Attach separate applicability, reference and local-validation dimensions."""
    service["cve_candidates"] = []
    service["intelligence_status"] = "identity_unknown"
    service["candidates_truncated"] = False
    if snapshot.get("status") != "available":
        service["intelligence_status"] = "snapshot_unavailable"
        return
    if service.get("identity_basis") == "port_hint" or not (service.get("cpes") or service.get("product")):
        return
    records = snapshot.get("advisories", [])
    by_id = snapshot.get("_advisories_by_id")
    if by_id is None:
        by_id = {}
        for row in records:
            if not isinstance(row, Mapping):
                continue
            aid = str(row.get("advisory_id") or row.get("cve") or "").upper()
            if CVE_ID.fullmatch(aid):
                by_id.setdefault(aid, []).append(row)
    found: dict[str, dict[str, Any]] = {}
    for cpe in service.get("cpes") or [None]:
        # Even authenticated identity is not proof of affected build/configuration
        # here. Findings and their verifier contract remain a separate source.
        matches = matcher(
            records, cpe=cpe, product=service.get("product"), version=service.get("version"),
            identity_evidence_tier="network_service_fingerprint", limit=MAX_CANDIDATES + 1,
        )
        for match in matches:
            aid = str(match.get("advisory_id") or "").upper()
            if not CVE_ID.fullmatch(aid):
                continue
            references: dict[str, dict[str, str]] = {}
            for record in by_id.get(aid, []):
                # Only explicitly typed references from the trusted snapshot.
                # A vendor advisory URL is not mislabeled as an exploit.
                for ref in list(record.get("exploit_references") or [])[:20]:
                    if not isinstance(ref, Mapping):
                        continue
                    url = reference_url(ref.get("url"))
                    if url:
                        references[url] = {
                            "url": url, "source": text(ref.get("source"), 120) or "pinned snapshot",
                            "kind": text(ref.get("kind"), 60) or "public_reference",
                            "review_status": "not_reviewed_for_execution",
                        }
            context = _exploitation_context(by_id.get(aid, []))
            candidate = {
                "id": aid, "title": text(match.get("title"), 500) or aid,
                "severity": text(match.get("severity"), 30) or "unknown",
                "advisory_url": reference_url(match.get("reference")) or f"https://nvd.nist.gov/vuln/detail/{aid}",
                "match_type": text(match.get("match_type"), 80) or "unknown",
                "confidence": text(match.get("confidence"), 30) or "unknown",
                "applicability": "candidate",
                "version_evaluation": text(match.get("version_evaluation"), 30) or "unknown",
                "local_validation": "no_linked_validation",
                "exploit_references": list(references.values())[:10],
                **context,
                "identity_stale": bool(service.get("identity_stale")),
                "prerequisites": ["Confirm exact product/build", "Check affected configuration and vendor backports"],
            }
            prior = found.get(aid)
            if prior is None or candidate["match_type"] == "exact_cpe_version_range":
                found[aid] = candidate
    service["candidates_truncated"] = len(found) > MAX_CANDIDATES
    # What to look at first: known exploited in the wild, then exploitation likelihood, then
    # severity; the cap keeps those, never an alphabetical slice.
    service["cve_candidates"] = sorted(found.values(), key=candidate_priority)[:MAX_CANDIDATES]
    service["intelligence_status"] = "candidates_found" if found else "no_match_in_snapshot"
