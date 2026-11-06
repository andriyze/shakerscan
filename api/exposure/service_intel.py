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

try:
    from scanner_tools.corporate_identity import derived_cpes as corporate_cpes, product_for_label
except ModuleNotFoundError:  # package import
    from scanner.scanner_tools.corporate_identity import derived_cpes as corporate_cpes, product_for_label

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


# The index built for the snapshot object last loaded. The loader returns the same verified object
# until the file changes, so an unchanged snapshot is indexed once per process, not per request.
_INDEXED: dict[str, tuple[dict[str, Any], Callable[..., Any]]] = {}


def load_service_intelligence() -> tuple[dict[str, Any], Callable[..., Any]]:
    """Reuse the device intelligence trust boundary; never fetch a live feed."""
    try:
        from scanner_tools import device_advisories
    except ModuleNotFoundError:
        from scanner.scanner_tools import device_advisories
    snapshot = device_advisories.load_verified_snapshot(
        os.environ.get("DEVICE_INTEL_DB_PATH"), os.environ.get("DEVICE_INTEL_DB_SHA256"),
    )
    cached = _INDEXED.get("current")
    if cached is not None and cached[0] is snapshot:
        return cached
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

    if snapshot.get("status") == "available":
        _INDEXED["current"] = (snapshot, indexed_matcher)
    return snapshot, indexed_matcher


def snapshot_summary(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    generated = timestamp(snapshot.get("generated_at"))
    return {
        "status": text(snapshot.get("status"), 60) or "unavailable",
        "generated_at": generated.isoformat() if generated else None,
        "snapshot_sha256": text(snapshot.get("snapshot_sha256"), 64) or None,
        "record_count": len(snapshot.get("advisories") or []),
        "coverage": "curated_offline_snapshot",
        # builtin | external_bundle | operator_pinned; bundle says why an installed bundle is not used.
        "source": text(snapshot.get("source"), 40) or "builtin",
        "bundle": _bundle_summary(snapshot.get("bundle")),
        "limitations": [
            "This is a curated offline snapshot, not complete or live CVE coverage.",
            "Version and CPE matches do not establish configuration or distribution backport applicability.",
            "Public exploit references are unexecuted research links, not ShakerScan capabilities.",
        ],
    }


def _bundle_summary(value: Any) -> dict[str, Any]:
    bundle = value if isinstance(value, Mapping) else {}
    version = bundle.get("bundle_version")
    return {
        "status": text(bundle.get("status"), 60) or "absent",
        "bundle_version": version if isinstance(version, int) and not isinstance(version, bool) else None,
        "generated_at": text(bundle.get("generated_at"), 40) or None,
        "key_id": text(bundle.get("key_id"), 16) or None,
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


# Product names fingerprints report without a CPE (httpx/tech detection, some nmap banners) ->
# the NVD CPE part:vendor:product the snapshot keys on. Only unambiguous names; a version is required.
PRODUCT_CPE_ALIASES: dict[str, tuple[str, ...]] = {
    "nginx": ("a:f5:nginx", "a:nginx:nginx"),
    "apache": ("a:apache:http_server",),
    "apache httpd": ("a:apache:http_server",),
    "apache http server": ("a:apache:http_server",),
    "microsoft-iis": ("a:microsoft:internet_information_services",),
    "microsoft iis httpd": ("a:microsoft:internet_information_services",),
    "iis": ("a:microsoft:internet_information_services",),
    "openssh": ("a:openbsd:openssh",),
    "apache tomcat": ("a:apache:tomcat",),
    "tomcat": ("a:apache:tomcat",),
    "jetty": ("a:eclipse:jetty",),
    "php": ("a:php:php",),
    "mysql": ("a:oracle:mysql",),
    "mariadb": ("a:mariadb:mariadb",),
    "postgresql": ("a:postgresql:postgresql",),
    "redis": ("a:redis:redis",),
    "elasticsearch": ("a:elastic:elasticsearch",),
    "jenkins": ("a:jenkins:jenkins",),
    "grafana": ("a:grafana:grafana",),
    "exim": ("a:exim:exim",),
    "exim smtpd": ("a:exim:exim",),
    "postfix": ("a:postfix:postfix",),
    "postfix smtpd": ("a:postfix:postfix",),
    "dovecot": ("a:dovecot:dovecot",),
    "samba": ("a:samba:samba",),
    "samba smbd": ("a:samba:samba",),
    "isc bind": ("a:isc:bind",),
    "squid": ("a:squid-cache:squid",),
    "squid http proxy": ("a:squid-cache:squid",),
    "haproxy": ("a:haproxy:haproxy",),
    "lighttpd": ("a:lighttpd:lighttpd",),
    "openssl": ("a:openssl:openssl",),
    "vsftpd": ("a:vsftpd:vsftpd",),
    "proftpd": ("a:proftpd:proftpd",),
    "dnsmasq": ("a:thekelleys:dnsmasq",),
    "fortios": ("o:fortinet:fortios",),
    "fortinet fortios": ("o:fortinet:fortios",),
    "pan-os": ("o:paloaltonetworks:pan-os",),
    "palo alto networks pan-os": ("o:paloaltonetworks:pan-os",),
    "ivanti connect secure": ("a:ivanti:connect_secure",),
    "citrix netscaler application delivery controller": ("a:citrix:netscaler_application_delivery_controller",),
    "atlassian confluence server": ("a:atlassian:confluence_server",),
    "atlassian confluence data center": ("a:atlassian:confluence_data_center",),
    "atlassian jira server": ("a:atlassian:jira_server",),
    "atlassian jira data center": ("a:atlassian:jira_data_center",),
    "dropbear sshd": ("a:dropbear_ssh_project:dropbear_ssh",),
}
_VERSION_TEXT = re.compile(r"^[0-9][0-9A-Za-z._+~-]{0,40}$")


def derived_cpes(product: Any, version: Any) -> list[str]:
    """CPEs for a fingerprint that names a known product and a version but carries no CPE."""
    corporate = product_for_label(product)
    if corporate is not None:
        # Catalogue products map an exact version onto their NVD names (or onto none).
        return corporate_cpes(corporate, version)
    name = str(product or "").strip().lower()
    version_text = str(version or "").strip().split()[0] if str(version or "").strip() else ""
    if name not in PRODUCT_CPE_ALIASES or not _VERSION_TEXT.fullmatch(version_text):
        return []
    return [f"cpe:2.3:{alias}:{version_text}:*:*:*:*:*:*:*" for alias in PRODUCT_CPE_ALIASES[name]]


APPLICABILITY_STATUSES = ("affected", "not_affected", "unresolved")
# What each unresolved reason still needs; the follow-up names only that missing evidence.
FOLLOW_UPS: dict[str, dict[str, str]] = {
    "product_probable": {"need": "confirm_product", "capability": "web.identify",
                         "detail": "A product recipe or a product-specific response confirms the product."},
    "version_not_reported": {"need": "reported_version", "capability": "web.identify",
                             "detail": "The product has not stated its version; a recipe that reads it, or authenticated inventory, resolves it."},
    "version_inferred": {"need": "reported_version", "capability": "web.identify",
                         "detail": "The version was inferred from a fingerprint or a readme, not stated by the product."},
    "distribution_package": {"need": "package_fix_status", "capability": "ssh.connect",
                             "detail": "A distribution may have backported the fix into this package revision; authenticated package inventory resolves it."},
    "advisory_range_unresolved": {"need": "exact_identity", "capability": None,
                                  "detail": "The advisory names the product, but not a range this identity can be compared with."},
}


def _component_queries(service: Mapping[str, Any]) -> list[dict[str, Any]]:
    """What to match: each named component, or the service's own identity (older records)."""
    components = [c for c in service.get("components") or () if isinstance(c, Mapping) and c.get("product")]
    if components:
        return [dict(c) for c in components]
    if not service.get("product") and not service.get("cpes"):
        return []
    version = service.get("version")
    return [{
        "id": None, "role": "service", "base_path": "/", "product": service.get("product"),
        "product_key": None, "product_status": "identified", "version": version,
        "version_status": "reported" if version else "unknown", "distribution": None,
        "cpes": list(service.get("cpes") or ()), "advisory_product": None, "claims": {},
    }]


def _versionless(cpe: Any) -> str | None:
    """The same CPE with its version wildcarded: every advisory naming the product."""
    if not isinstance(cpe, str):
        return None
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        return ":".join([*parts[:5], "*", *parts[6:]]) if len(parts) >= 6 else cpe
    parts = cpe.split(":")  # cpe:/a:vendor:product:version
    return ":".join(parts[:4]) if len(parts) > 4 else cpe


def applicability(component: Mapping[str, Any], match: Mapping[str, Any]) -> tuple[str, str | None]:
    """affected only for an identified product whose upstream version the product reported, with
    no distribution package that may carry a backport, inside an exact CPE range; else unresolved."""
    if component.get("product_status") != "identified":
        return "unresolved", "product_probable"
    if component.get("version_status") == "inferred_range":
        return "unresolved", "version_inferred"
    if component.get("version_status") != "reported" or not component.get("version"):
        return "unresolved", "version_not_reported"
    if component.get("distribution"):
        return "unresolved", "distribution_package"
    if match.get("match_type") == "exact_cpe_version_range" and match.get("version_evaluation") == "affected":
        return "affected", None
    return "unresolved", "advisory_range_unresolved"


def _published_after(records: list[Mapping[str, Any]], observed: Any) -> bool:
    """Whether the advisory entered the snapshot after this identity was last observed."""
    seen = timestamp(observed)
    if seen is None:
        return False
    for record in records:
        published = timestamp(record.get("published"))
        if published is not None and published > seen:
            return True
    return False


def enrich_service(service: dict[str, Any], snapshot: Mapping[str, Any], matcher: Callable[..., Any]) -> None:
    """Attach separate applicability, reference and local-validation dimensions.

    The retained inventory is matched against the snapshot loaded now, so a changed advisory
    bundle is applied to every listener already observed without new traffic. Each candidate
    names the component it was matched for and an applicability of its own; a component whose
    version the product reported also lists the advisories its version is outside of.
    """
    service["cve_candidates"] = []
    service["intelligence_status"] = "identity_unknown"
    service["candidates_truncated"] = False
    service["advisory_follow_up"] = []
    service["advisory_changes"] = []
    if snapshot.get("status") != "available":
        service["intelligence_status"] = "snapshot_unavailable"
        return
    if service.get("identity_basis") == "port_hint":
        return
    queries = _component_queries(service)
    if not queries:
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
    follow: dict[tuple[Any, ...], dict[str, Any]] = {}
    by_component = {item["id"]: item for item in service.get("components") or () if isinstance(item, dict) and item.get("id")}
    for component in queries:
        product = component.get("advisory_product") or component.get("product")
        version = component.get("version")
        cpes = list(component.get("cpes") or []) or derived_cpes(component.get("product"), version)
        component_matches: dict[str, dict[str, Any]] = {}
        for cpe in cpes or [None]:
            # Even authenticated identity is not proof of affected build/configuration
            # here. Findings and their verifier contract remain a separate source.
            for match in matcher(
                records, cpe=cpe, product=product, version=version,
                identity_evidence_tier="network_service_fingerprint", limit=MAX_CANDIDATES + 1,
            ):
                aid = str(match.get("advisory_id") or "").upper()
                if CVE_ID.fullmatch(aid) and (aid not in component_matches or match.get("match_type") == "exact_cpe_version_range"):
                    component_matches[aid] = match
        not_affected: set[str] = set()
        if component.get("version_status") == "reported" and version and component.get("product_status") == "identified":
            for cpe in cpes or [None]:
                for match in matcher(records, cpe=_versionless(cpe), product=product, version=None,
                                     identity_evidence_tier="network_service_fingerprint", limit=200):
                    aid = str(match.get("advisory_id") or "").upper()
                    if CVE_ID.fullmatch(aid) and aid not in component_matches:
                        not_affected.add(aid)
        target = by_component.get(component.get("id"))
        if target is not None:
            target["advisories_not_affected"] = {"count": len(not_affected), "ids": sorted(not_affected)[:20]}
        version_observed = ((component.get("claims") or {}).get("version") or {}).get("observed_at") \
            or ((component.get("claims") or {}).get("product") or {}).get("observed_at")
        for aid, match in component_matches.items():
            status, reason = applicability(component, match)
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
            newly = _published_after(by_id.get(aid, []), version_observed)
            candidate = {
                "id": aid, "title": text(match.get("title"), 500) or aid,
                "severity": text(match.get("severity"), 30) or "unknown",
                "advisory_url": reference_url(match.get("reference")) or f"https://nvd.nist.gov/vuln/detail/{aid}",
                "match_type": text(match.get("match_type"), 80) or "unknown",
                "confidence": text(match.get("confidence"), 30) or "unknown",
                "applicability": "candidate",
                "applicability_status": status, "unresolved_reason": reason,
                "component_id": component.get("id"),
                "component": {"role": component.get("role"), "product": text(component.get("product"), 120),
                              "base_path": component.get("base_path"), "version": component.get("version"),
                              "package_version": component.get("package_version")},
                "new_since_observation": newly,
                "version_evaluation": text(match.get("version_evaluation"), 30) or "unknown",
                "local_validation": "no_linked_validation",
                "exploit_references": list(references.values())[:10],
                **context,
                "identity_stale": bool(service.get("identity_stale")),
                "prerequisites": ["Confirm exact product/build", "Check affected configuration and vendor backports"],
            }
            prior = found.get(aid)
            if prior is None or (status == "affected" and prior["applicability_status"] != "affected") or (
                    prior["applicability_status"] == status and candidate["match_type"] == "exact_cpe_version_range"):
                found[aid] = candidate
            if reason:
                need = FOLLOW_UPS[reason]
                key = (component.get("id"), need["need"])
                entry = follow.setdefault(key, {
                    "component_id": component.get("id"), "role": component.get("role"),
                    "product": text(component.get("product"), 120), "base_path": component.get("base_path"),
                    **need, "advisories": 0,
                })
                entry["advisories"] += 1
            if newly and status == "affected":
                service["advisory_changes"].append({"kind": "newly_applicable", "advisory_id": aid,
                                                    "component_id": component.get("id")})
    service["candidates_truncated"] = len(found) > MAX_CANDIDATES
    # What to look at first: known exploited in the wild, then exploitation likelihood, then
    # severity; the cap keeps those, never an alphabetical slice.
    service["cve_candidates"] = sorted(found.values(), key=candidate_priority)[:MAX_CANDIDATES]
    # Re-evaluation queues only what is missing: one item per component and missing evidence.
    service["advisory_follow_up"] = sorted(follow.values(), key=lambda item: (-item["advisories"], str(item["product"])))[:10]
    service["advisory_changes"] = service["advisory_changes"][:20]
    service["intelligence_status"] = "candidates_found" if found else "no_match_in_snapshot"
