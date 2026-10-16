"""Corporate applications and edge appliances recognised from evidence a Scan already holds.

Mail portals, identity providers, VPN gateways, CI servers and admin consoles are the surface a
corporate estate usually exposes first. This module names them from three kinds of passive
evidence that capabilities already record, and never sends traffic itself:

* ``technology`` -- an exact technology name the HTTP probe reported (httpx ``-tech-detect``,
  i.e. the pinned Wappalyzer fingerprints), optionally with the version that fingerprint read
  from a header or the page (``"Jenkins:2.401.1"``);
* ``page_title`` -- the probed page's title matching an anchored product title;
* ``path_marker`` -- a content-discovery hit on a product-specific path (``/remote/login``,
  ``/dana-na/...``) whose response is distinguishable from the host's measured absent-path
  answer (the negative control).

Every result is a *lead*: an unconfirmed identity with its basis. A version is reported only
when the fingerprint read one and it is a plain dotted number; nothing is inferred. CPE names are
derived only from such a version and only for products whose public versioning maps one-to-one
onto the NVD product (Exchange build numbers and SharePoint builds do not, so they get none).
Advisory matches built on these CPEs stay candidates (``api/exposure/service_intel.py``); a
known-exploited (KEV) match is a prioritisation lead until a deterministic check proves it.

Standard library only, so the scanner package and the API share it.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable, Mapping
import urllib.parse

CATALOGUE_VERSION = "corporate-identity/v1"
MAX_LEADS = 60
MAX_EVIDENCE_PER_LEAD = 5
_VERSION = re.compile(r"^[0-9]{1,6}(?:\.[0-9]{1,9}){0,5}$")
# Statuses that say a path exists (or is protected); a 404/5xx says nothing about a product.
_PATH_HIT_STATUSES = frozenset({200, 204, 301, 302, 303, 307, 308, 401, 403, 405})


@dataclass(frozen=True)
class CorporateProduct:
    key: str
    label: str
    vendor: str
    category: str
    technologies: tuple[str, ...] = ()
    titles: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    # NVD ``part:vendor:product`` names a reported version maps onto exactly.
    cpe_products: tuple[str, ...] = ()


CATALOGUE: tuple[CorporateProduct, ...] = (
    # Mail, identity and remote access
    CorporateProduct("outlook_web_app", "Microsoft Outlook Web App", "Microsoft", "mail_portal",
                     ("Outlook Web App",), (r"Outlook(?: Web App)?",), ("/owa/auth/logon.aspx",)),
    CorporateProduct("exchange_control_panel", "Microsoft Exchange Control Panel", "Microsoft",
                     "mail_administration", paths=("/ecp/",)),
    CorporateProduct("exchange_autodiscover", "Microsoft Exchange Autodiscover", "Microsoft",
                     "mail_portal", paths=("/autodiscover/autodiscover.xml",)),
    CorporateProduct("adfs", "Microsoft AD FS", "Microsoft", "identity_provider",
                     paths=("/adfs/ls/", "/adfs/ls/idpinitiatedsignon.aspx")),
    CorporateProduct("rd_web_access", "Microsoft Remote Desktop Web Access", "Microsoft",
                     "remote_access", paths=("/RDWeb/Pages/en-US/login.aspx",)),
    CorporateProduct("sharepoint", "Microsoft SharePoint", "Microsoft", "collaboration",
                     ("Microsoft SharePoint",)),
    CorporateProduct("okta", "Okta", "Okta", "identity_provider", ("Okta",)),
    CorporateProduct("roundcube", "Roundcube Webmail", "Roundcube", "mail_portal",
                     ("RoundCube",), (r"Roundcube Webmail.*",), cpe_products=("a:roundcube:webmail",)),
    CorporateProduct("zimbra", "Zimbra Collaboration", "Zimbra", "mail_portal", ("Zimbra",)),
    # Edge appliances: VPN gateways and application delivery controllers
    CorporateProduct("fortigate_ssl_vpn", "Fortinet FortiGate SSL VPN", "Fortinet", "edge_vpn",
                     ("Fortinet FortiGate",), paths=("/remote/login",)),
    CorporateProduct("globalprotect", "Palo Alto Networks GlobalProtect", "Palo Alto Networks",
                     "edge_vpn", ("Palo Alto Networks - GlobalProtect",), (r"GlobalProtect Portal",),
                     ("/global-protect/login.esp",)),
    CorporateProduct("ivanti_connect_secure", "Ivanti Connect Secure (Pulse Secure)", "Ivanti",
                     "edge_vpn", ("Pulse Secure",), (r"(?:Ivanti|Pulse) Connect Secure",),
                     ("/dana-na/auth/url_default/welcome.cgi",)),
    CorporateProduct("citrix_gateway", "Citrix Gateway (NetScaler)", "Citrix", "edge_vpn",
                     ("Citrix",), (r"(?:Citrix|NetScaler) Gateway",),
                     ("/vpn/index.html", "/logon/LogonPoint/index.html")),
    CorporateProduct("citrix_storefront", "Citrix StoreFront", "Citrix", "remote_access",
                     paths=("/Citrix/StoreWeb/",)),
    CorporateProduct("cisco_asa_webvpn", "Cisco ASA WebVPN (AnyConnect)", "Cisco", "edge_vpn",
                     paths=("/+CSCOE+/logon.html",)),
    CorporateProduct("f5_big_ip", "F5 BIG-IP", "F5", "edge_appliance", ("F5 BigIP",),
                     paths=("/tmui/login.jsp", "/my.policy")),
    CorporateProduct("vmware_vcenter", "VMware vCenter Server", "VMware", "virtualization_admin",
                     titles=(r"ID_VC_Welcome",)),
    CorporateProduct("vmware_horizon", "VMware Horizon", "VMware", "remote_access",
                     paths=("/portal/webclient/index.html",)),
    # Developer, CI/CD and collaboration servers
    CorporateProduct("jenkins", "Jenkins", "Jenkins", "ci_cd", ("Jenkins",),
                     cpe_products=("a:jenkins:jenkins",)),
    CorporateProduct("gitlab", "GitLab", "GitLab", "source_control", ("GitLab",),
                     cpe_products=("a:gitlab:gitlab",)),
    CorporateProduct("atlassian_jira", "Atlassian Jira", "Atlassian", "collaboration",
                     ("Atlassian Jira",),
                     cpe_products=("a:atlassian:jira", "a:atlassian:jira_server",
                                   "a:atlassian:jira_data_center")),
    CorporateProduct("atlassian_confluence", "Atlassian Confluence", "Atlassian", "collaboration",
                     ("Atlassian Confluence",),
                     cpe_products=("a:atlassian:confluence_server",
                                   "a:atlassian:confluence_data_center")),
    CorporateProduct("atlassian_bitbucket", "Atlassian Bitbucket", "Atlassian", "source_control",
                     ("Atlassian Bitbucket",), cpe_products=("a:atlassian:bitbucket",)),
    CorporateProduct("teamcity", "JetBrains TeamCity", "JetBrains", "ci_cd", ("TeamCity",),
                     cpe_products=("a:jetbrains:teamcity",)),
    CorporateProduct("sonarqube", "SonarQube", "SonarSource", "ci_cd", ("SonarQube",),
                     cpe_products=("a:sonarsource:sonarqube",)),
    CorporateProduct("artifactory", "JFrog Artifactory", "JFrog", "ci_cd", ("Artifactory",),
                     cpe_products=("a:jfrog:artifactory",)),
    CorporateProduct("mattermost", "Mattermost", "Mattermost", "collaboration", ("Mattermost",),
                     cpe_products=("a:mattermost:mattermost_server",)),
    CorporateProduct("nextcloud", "Nextcloud", "Nextcloud", "file_sharing", ("Nextcloud",),
                     cpe_products=("a:nextcloud:nextcloud_server",)),
    CorporateProduct("moveit_transfer", "Progress MOVEit Transfer", "Progress", "file_sharing",
                     ("Progress MOVEit",), paths=("/human.aspx",),
                     cpe_products=("a:progress:moveit_transfer",)),
    # Monitoring and administration consoles
    CorporateProduct("grafana", "Grafana", "Grafana Labs", "monitoring", ("Grafana",),
                     (r"Grafana",), cpe_products=("a:grafana:grafana",)),
    CorporateProduct("kibana", "Kibana", "Elastic", "monitoring", ("Kibana",), (r"Kibana",),
                     cpe_products=("a:elastic:kibana",)),
    CorporateProduct("zabbix", "Zabbix", "Zabbix", "monitoring", ("Zabbix",),
                     cpe_products=("a:zabbix:zabbix",)),
    CorporateProduct("splunk", "Splunk", "Splunk", "monitoring", ("Splunkd",),
                     cpe_products=("a:splunk:splunk",)),
    CorporateProduct("tomcat_manager", "Apache Tomcat", "Apache", "admin_console",
                     ("Apache Tomcat",), paths=("/manager/html", "/host-manager/html"),
                     cpe_products=("a:apache:tomcat",)),
    CorporateProduct("weblogic", "Oracle WebLogic Server", "Oracle", "admin_console",
                     ("Oracle WebLogic Server", "Weblogic Server"),
                     paths=("/console/login/LoginForm.jsp",),
                     cpe_products=("a:oracle:weblogic_server",)),
    CorporateProduct("websphere", "IBM WebSphere Application Server", "IBM", "admin_console",
                     ("WebSphere",)),
    CorporateProduct("coldfusion", "Adobe ColdFusion", "Adobe", "admin_console",
                     ("Adobe ColdFusion",), paths=("/CFIDE/administrator/index.cfm",),
                     cpe_products=("a:adobe:coldfusion",)),
    CorporateProduct("cpanel", "cPanel", "cPanel", "hosting_panel", ("cPanel",),
                     cpe_products=("a:cpanel:cpanel",)),
    CorporateProduct("plesk", "Plesk", "WebPros", "hosting_panel", ("Plesk",)),
    CorporateProduct("webmin", "Webmin", "Webmin", "admin_console", ("Webmin",),
                     cpe_products=("a:webmin:webmin",)),
    CorporateProduct("sap_netweaver", "SAP NetWeaver Application Server", "SAP", "erp",
                     ("SAP",), cpe_products=("a:sap:netweaver_application_server",)),
)

_BY_TECHNOLOGY: dict[str, CorporateProduct] = {
    name.lower(): product for product in CATALOGUE for name in product.technologies
}
_BY_LABEL: dict[str, CorporateProduct] = {product.label.lower(): product for product in CATALOGUE}
_TITLES: tuple[tuple[re.Pattern[str], CorporateProduct], ...] = tuple(
    (re.compile(rf"\A\s*(?:{pattern})\s*\Z", re.IGNORECASE), product)
    for product in CATALOGUE for pattern in product.titles
)
_BY_PATH: dict[str, CorporateProduct] = {
    path.lower(): product for product in CATALOGUE for path in product.paths
}


def catalogue_paths() -> tuple[str, ...]:
    """Every product-specific path, in catalogue order (the corporate wordlist carries them)."""
    return tuple(path for product in CATALOGUE for path in product.paths)


def version_text(value: Any) -> str | None:
    """A plain dotted version, or None; a fingerprint's free text is never a version."""
    text = str(value or "").strip()
    return text if _VERSION.fullmatch(text) else None


def split_technology(value: Any) -> tuple[str, str | None]:
    """``"Jenkins:2.401.1"`` -> ``("Jenkins", "2.401.1")``; a non-version suffix is kept."""
    text = str(value or "").strip()[:200]
    name, separator, tail = text.rpartition(":")
    if separator and name and version_text(tail):
        return name.strip(), tail
    return text, None


def product_for_label(label: Any) -> CorporateProduct | None:
    return _BY_LABEL.get(str(label or "").strip().lower())


def derived_cpes(product: CorporateProduct, version: Any) -> list[str]:
    """CPE names for an exactly reported version; empty without one or without a 1:1 mapping."""
    text = version_text(version)
    if not text:
        return []
    return [f"cpe:2.3:{name}:{text}:*:*:*:*:*:*:*" for name in product.cpe_products]


def _path_of(url: Any) -> str:
    try:
        return urllib.parse.urlsplit(str(url or "")).path or "/"
    except ValueError:
        return ""


def _origin_of(url: Any) -> str | None:
    try:
        parts = urllib.parse.urlsplit(str(url or ""))
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    return f"{parts.scheme}://{parts.netloc.lower()}"


class _Leads:
    def __init__(self) -> None:
        self._items: dict[tuple[str, str | None], dict[str, Any]] = {}

    def add(self, product: CorporateProduct, *, origin: str | None, basis: str,
            evidence: str, version: str | None = None) -> None:
        key = (product.key, origin)
        lead = self._items.get(key)
        if lead is None:
            if len(self._items) >= MAX_LEADS:
                return
            lead = self._items[key] = {
                "product": product.label, "catalogue_id": product.key, "vendor": product.vendor,
                "category": product.category, "origin": origin, "version": None,
                "basis": [], "evidence": [], "status": "lead",
                "applicability": "unconfirmed",
            }
        if version and not lead["version"]:
            lead["version"] = version
        if basis not in lead["basis"]:
            lead["basis"].append(basis)
        if evidence not in lead["evidence"] and len(lead["evidence"]) < MAX_EVIDENCE_PER_LEAD:
            lead["evidence"].append(evidence[:200])

    def result(self) -> list[dict[str, Any]]:
        out = []
        for lead in self._items.values():
            product = _BY_LABEL[lead["product"].lower()]
            out.append({**lead, "cpes": derived_cpes(product, lead["version"])})
        return sorted(out, key=lambda item: (item["category"], item["product"], item["origin"] or ""))


def identities_from_fingerprint(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Leads from one ``http_fingerprint`` observation (technologies and title)."""
    leads = _Leads()
    _add_fingerprint(leads, row)
    return leads.result()


def _add_fingerprint(leads: _Leads, row: Mapping[str, Any]) -> None:
    origin = _origin_of(row.get("url"))
    for item in list(row.get("technologies") or ())[:50]:
        raw = item.get("name") if isinstance(item, Mapping) else item
        name, version = split_technology(raw)
        if isinstance(item, Mapping) and not version:
            version = version_text(item.get("version"))
        product = _BY_TECHNOLOGY.get(name.lower())
        if product is not None:
            leads.add(product, origin=origin, basis="technology",
                      evidence=f"technology {name}" + (f" {version}" if version else ""),
                      version=version)
    title = str(row.get("title") or "")[:300]
    if title:
        for pattern, product in _TITLES:
            if pattern.fullmatch(title):
                leads.add(product, origin=origin, basis="page_title", evidence=f"title {title[:80]}")


def _absent_answers(rows: Iterable[Mapping[str, Any]]) -> dict[str, set[tuple[int, Any]]]:
    """Per origin, the (status, length) the measured absent paths received."""
    answers: dict[str, set[tuple[int, Any]]] = {}
    for row in rows:
        if not row.get("negative_control"):
            continue
        origin = _origin_of(row.get("url"))
        status = row.get("status")
        if origin and type(status) is int:
            answers.setdefault(origin, set()).add((status, row.get("length")))
    return answers


def identities_from_content_discovery(
    rows: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Path-marker leads from content-discovery hits, and how many hits the control removed.

    Content discovery sends a few paths that cannot exist with every calibrated run and reports
    only answers with a hit status. A hit is distinguishable when its status and length differ
    from every absent-path answer the run reported on that origin, or when no absent path was
    reported there at all (the server answered them with a non-hit status such as 404). A
    soft-404 host answers ``/remote/login`` exactly as it answers a path that cannot exist, and
    that hit is removed.
    """
    items = [dict(row) for row in rows if isinstance(row, Mapping)
             and str(row.get("kind") or "content_discovery") == "content_discovery"]
    absent = _absent_answers(items)
    leads = _Leads()
    controlled = 0
    for row in items:
        if row.get("negative_control"):
            continue
        product = _BY_PATH.get(_path_of(row.get("url")).lower())
        status = row.get("status")
        if product is None or type(status) is not int or status not in _PATH_HIT_STATUSES:
            continue
        origin = _origin_of(row.get("url"))
        measured = absent.get(origin or "") or set()
        if (status, row.get("length")) in measured:
            controlled += 1
            continue
        leads.add(product, origin=origin, basis="path_marker",
                  evidence=f"{_path_of(row.get('url'))} answered {status}")
    return leads.result(), controlled


def corporate_surface(
    fingerprints: Iterable[Mapping[str, Any]],
    content_discovery: Iterable[Mapping[str, Any]],
) -> dict[str, Any] | None:
    """The report's bounded ``discovery.corporate_surface`` section, or None when empty."""
    leads = _Leads()
    for row in fingerprints:
        if isinstance(row, Mapping):
            _add_fingerprint(leads, row)
    path_leads, controlled = identities_from_content_discovery(content_discovery)
    for lead in path_leads:
        product = _BY_LABEL[lead["product"].lower()]
        for evidence in lead["evidence"]:
            leads.add(product, origin=lead["origin"], basis="path_marker", evidence=evidence)
    items = leads.result()
    if not items and not controlled:
        return None
    return {
        "catalogue": CATALOGUE_VERSION,
        "items": items,
        "count": len(items),
        "path_hits_without_distinct_control": controlled,
        "scope": "unconfirmed_leads",
        "note": ("Identities named from passive fingerprints, page titles and product paths. "
                 "Leads, not findings: confirm the product and build before acting; advisory "
                 "and known-exploited matches are prioritisation candidates."),
    }


__all__ = [
    "CATALOGUE", "CATALOGUE_VERSION", "CorporateProduct", "catalogue_paths", "corporate_surface",
    "derived_cpes", "identities_from_content_discovery", "identities_from_fingerprint",
    "product_for_label", "split_technology", "version_text",
]
