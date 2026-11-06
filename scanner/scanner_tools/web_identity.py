"""Web components behind one listener, and product recipes that identify them.

One HTTP listener usually carries several pieces of software: an edge or proxy in front, a web
server, the application under a base path, and that application's plugins. Each is a separate
*component* with its own identity evidence. This module names components from two sources:

* the passive HTTP fingerprint a Scan already records (``Server`` header, the probe's
  technology names, the page title) -- :func:`components_from_fingerprint`;
* product *recipes* -- a few fixed read-only GET requests per product, each with identity
  signals, a version parser, a negative control and a request ceiling -- :func:`identify`.

Three fields stay separate on every component:

* ``product_status``: ``identified`` (a product-specific signal: a product header, a JSON
  document only that product serves, an authentication realm, or a product error page) or
  ``probable`` (a technology fingerprint, a page title, a product path). A listener with no
  component has an unknown product.
* ``version_status``: ``reported`` (the product states its version in a field meant for it: a
  version header, a health document, a ``Server`` token, its own error page), ``inferred_range``
  (a fingerprint pattern or a plugin readme suggests it) or ``unknown``. An exact version is never
  derived from a favicon, a title or a generic asset.
* advisory applicability is decided later from these two (``api/exposure/service_intel.py``).

Negative controls: every base path gets one request for a path that cannot exist. A probe whose
answer is indistinguishable from that control (the site's generic 404, login redirect, WAF page,
or a catch-all 200) counts for nothing, and body text the control also carries counts for
nothing; so a site that answers every path alike produces no recipe match. A product header the
product sends on every response (``X-Jenkins``) counts on its own.

Response headers and bodies are target-controlled. Product names come from this catalogue only;
versions must be plain dotted numbers; a plugin name must be a plain slug. No response text is
copied into an observation.

Standard library only, so the scanner package and the API share it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
import hashlib
import re
import secrets
import time
from typing import Any
import urllib.parse

RECIPE_CATALOGUE_VERSION = "web-identity/v1"
ROLES = ("edge", "web_server", "framework", "application", "plugin", "service")
PRODUCT_STATUSES = ("identified", "probable")
VERSION_STATUSES = ("reported", "inferred_range", "unknown")
# Bases one action examines: "/", the target's own path, the root's same-origin redirect, and
# the recipe mounts that answered as their product.
MAX_BASES = 3
MAX_MOUNT_BASES = 4
MAX_PLUGIN_SLUGS = 8
MAX_PLUGIN_READMES = 4
BODY_LIMIT = 256 * 1024
CONTROL_PREFIX = ".shakerscan-absent-"

_PLAIN_VERSION = re.compile(r"[0-9]{1,6}(?:\.[0-9]{1,9}){0,5}")
_SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_BASE_SEGMENT = re.compile(r"[A-Za-z0-9._~+-]{1,64}")
_SERVER_TOKEN = re.compile(
    r"([A-Za-z][A-Za-z0-9_.-]{0,79})(?:/([0-9][0-9A-Za-z._+~:-]{0,60}))?(?:[ \t]+\(([^()]{1,80})\))?"
)
# Distribution package markers: a vendor may backport a fix without changing the upstream number.
_DISTRIBUTION = re.compile(
    r"(ubuntu|debian|deb[0-9]+u[0-9]+|\+deb|raspbian|\bel[5-9]\b|\.el[5-9]|centos|red ?hat|rhel|"
    r"fedora|\bfc[0-9]{2}\b|amzn|amazon linux|suse|sles|alpine|-r[0-9]+$)",
    re.IGNORECASE,
)
_DISTRIBUTION_NAMES = (
    ("ubuntu", "ubuntu"), ("raspbian", "raspbian"), ("deb", "debian"), ("el", "rhel"),
    ("centos", "centos"), ("red", "rhel"), ("rhel", "rhel"), ("fedora", "fedora"),
    ("fc", "fedora"), ("amzn", "amazon"), ("amazon", "amazon"), ("suse", "suse"),
    ("sles", "suse"), ("alpine", "alpine"), ("-r", "alpine"),
)


@dataclass(frozen=True)
class Product:
    key: str
    label: str
    vendor: str
    category: str
    role: str
    # NVD ``part:vendor:product`` names a reported upstream version maps onto exactly.
    cpe_products: tuple[str, ...] = ()
    # The advisory snapshot's plain product name, for products without a one-to-one CPE.
    advisory_product: str | None = None


PRODUCTS: tuple[Product, ...] = (
    # Edges and proxies
    Product("cloudflare", "Cloudflare", "Cloudflare", "cdn", "edge"),
    Product("cloudfront", "Amazon CloudFront", "Amazon", "cdn", "edge"),
    Product("akamai", "Akamai", "Akamai", "cdn", "edge"),
    Product("fastly", "Fastly", "Fastly", "cdn", "edge"),
    Product("sucuri", "Sucuri WAF", "Sucuri", "waf", "edge"),
    Product("imperva", "Imperva", "Imperva", "waf", "edge"),
    Product("aws_elb", "AWS Elastic Load Balancing", "Amazon", "load_balancer", "edge"),
    Product("varnish", "Varnish", "Varnish", "cache", "edge", ("a:varnish-software:varnish_cache",)),
    Product("envoy", "Envoy", "Envoy", "proxy", "edge", ("a:envoyproxy:envoy",)),
    Product("traffic_server", "Apache Traffic Server", "Apache", "proxy", "edge",
            ("a:apache:traffic_server",)),
    Product("squid", "Squid", "Squid", "proxy", "edge", ("a:squid-cache:squid",)),
    # Web and application servers
    Product("nginx", "nginx", "F5", "web_server", "web_server", ("a:f5:nginx", "a:nginx:nginx")),
    Product("openresty", "OpenResty", "OpenResty", "web_server", "web_server",
            ("a:openresty:openresty",)),
    Product("apache_httpd", "Apache HTTP Server", "Apache", "web_server", "web_server",
            ("a:apache:http_server",)),
    Product("iis", "Microsoft IIS", "Microsoft", "web_server", "web_server",
            ("a:microsoft:internet_information_services",)),
    Product("litespeed", "LiteSpeed Web Server", "LiteSpeed", "web_server", "web_server",
            ("a:litespeedtech:litespeed_web_server",)),
    Product("caddy", "Caddy", "Caddy", "web_server", "web_server", ("a:caddyserver:caddy",)),
    Product("tomcat", "Apache Tomcat", "Apache", "application_server", "web_server",
            ("a:apache:tomcat",)),
    Product("jetty", "Eclipse Jetty", "Eclipse", "application_server", "web_server",
            ("a:eclipse:jetty",)),
    Product("webmin", "Webmin", "Webmin", "admin_console", "application", ("a:webmin:webmin",)),
    # Frameworks named by their own error pages
    Product("spring_boot", "Spring Boot", "VMware", "framework", "framework"),
    Product("express", "Express", "OpenJS Foundation", "framework", "framework"),
    Product("django", "Django", "Django", "framework", "framework"),
    Product("php", "PHP", "PHP", "language_runtime", "framework", ("a:php:php",)),
    Product("aspnet", "ASP.NET", "Microsoft", "framework", "framework"),
    # Applications with recipes
    Product("jenkins", "Jenkins", "Jenkins", "ci_cd", "application", ("a:jenkins:jenkins",)),
    Product("grafana", "Grafana", "Grafana Labs", "monitoring", "application", ("a:grafana:grafana",)),
    Product("gitlab", "GitLab", "GitLab", "source_control", "application", ("a:gitlab:gitlab",)),
    Product("nexus", "Sonatype Nexus Repository", "Sonatype", "ci_cd", "application",
            ("a:sonatype:nexus_repository_manager",)),
    Product("keycloak", "Keycloak", "Red Hat", "identity_provider", "application",
            ("a:redhat:keycloak",)),
    Product("wordpress", "WordPress", "WordPress", "cms", "application", ("a:wordpress:wordpress",)),
    Product("kibana", "Kibana", "Elastic", "monitoring", "application", ("a:elastic:kibana",)),
    Product("phpmyadmin", "phpMyAdmin", "phpMyAdmin", "admin_console", "application",
            ("a:phpmyadmin:phpmyadmin",)),
    Product("tomcat_manager", "Apache Tomcat Manager", "Apache", "admin_console", "application"),
    Product("fortigate_ssl_vpn", "Fortinet FortiGate SSL VPN", "Fortinet", "edge_vpn", "application"),
    Product("globalprotect", "Palo Alto Networks GlobalProtect", "Palo Alto Networks", "edge_vpn",
            "application"),
    Product("ivanti_connect_secure", "Ivanti Connect Secure (Pulse Secure)", "Ivanti", "edge_vpn",
            "application"),
    Product("citrix_gateway", "Citrix Gateway (NetScaler)", "Citrix", "edge_vpn", "application"),
    Product("cisco_asa_webvpn", "Cisco ASA WebVPN (AnyConnect)", "Cisco", "edge_vpn", "application"),
)
_BY_KEY: dict[str, Product] = {product.key: product for product in PRODUCTS}
_BY_LABEL: dict[str, Product] = {product.label.lower(): product for product in PRODUCTS}

# ``Server`` tokens -> product keys. Anything else stays a bounded label with no catalogue key.
_SERVER_PRODUCTS: dict[str, str] = {
    "cloudflare": "cloudflare", "cloudfront": "cloudfront", "akamaighost": "akamai",
    "akamainetstorage": "akamai", "awselb": "aws_elb", "varnish": "varnish", "envoy": "envoy",
    "ats": "traffic_server", "squid": "squid", "sucuri": "sucuri",
    "nginx": "nginx", "openresty": "openresty", "apache": "apache_httpd",
    "microsoft-iis": "iis", "litespeed": "litespeed", "caddy": "caddy",
    "apache-coyote": "tomcat", "jetty": "jetty", "miniserv": "webmin",
}
# httpx/Wappalyzer technology names -> product keys (exact names only).
_TECHNOLOGY_PRODUCTS: dict[str, str] = {
    "nginx": "nginx", "openresty": "openresty", "apache http server": "apache_httpd",
    "apache": "apache_httpd", "iis": "iis", "microsoft iis": "iis", "litespeed": "litespeed",
    "caddy": "caddy", "apache tomcat": "tomcat", "jetty": "jetty", "cloudflare": "cloudflare",
    "amazon cloudfront": "cloudfront", "akamai": "akamai", "fastly": "fastly", "varnish": "varnish",
    "envoy": "envoy", "php": "php", "microsoft asp.net": "aspnet", "express": "express",
    "django": "django", "jenkins": "jenkins", "grafana": "grafana", "gitlab": "gitlab",
    "keycloak": "keycloak", "wordpress": "wordpress", "kibana": "kibana", "phpmyadmin": "phpmyadmin",
    "webmin": "webmin", "sonatype nexus": "nexus", "fortinet fortigate": "fortigate_ssl_vpn",
    "palo alto networks - globalprotect": "globalprotect", "pulse secure": "ivanti_connect_secure",
    "citrix": "citrix_gateway",
}
_TITLE_PRODUCTS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(rf"\A\s*(?:{pattern})\s*\Z", re.IGNORECASE), key) for pattern, key in (
        (r"Grafana", "grafana"), (r"Kibana", "kibana"), (r"GlobalProtect Portal", "globalprotect"),
        (r"(?:Ivanti|Pulse) Connect Secure", "ivanti_connect_secure"),
        (r"(?:Citrix|NetScaler) Gateway", "citrix_gateway"),
        (r"Sign in \[Jenkins\]|Dashboard \[Jenkins\]", "jenkins"),
        (r"Sign in · GitLab", "gitlab"), (r"Nexus Repository Manager", "nexus"),
        (r"phpMyAdmin", "phpmyadmin"),
    )
)


def product(key: Any) -> Product | None:
    return _BY_KEY.get(str(key or ""))


def product_for_label(label: Any) -> Product | None:
    return _BY_LABEL.get(str(label or "").strip().lower())


def plain_version(value: Any) -> str | None:
    text = str(value or "").strip()
    return text if _PLAIN_VERSION.fullmatch(text) else None


def split_package_version(raw: Any, comment: Any = None) -> tuple[str | None, str | None, str | None]:
    """``"1.18.0-6ubuntu14.4"`` -> (upstream ``"1.18.0"``, the full package text, ``"ubuntu"``).

    The upstream part is what advisories name; the full text is kept because a distribution may
    have backported the fix into exactly that package revision. With no package suffix and no
    distribution comment the package text is None.
    """
    text = str(raw or "").strip()[:80]
    note = str(comment or "").strip()[:80]
    if not text:
        return None, None, _distribution(note)
    head = re.match(r"[0-9]{1,6}(?:\.[0-9]{1,9}){0,5}(?:[a-z][0-9]{0,4})?", text)
    # "8.2p1" keeps its letter-suffixed upstream release, which the matcher compares as such.
    upstream = head.group(0) if head else None
    distribution = _distribution(f"{text} {note}")
    full = f"{text} ({note})" if note else text
    package = full if (distribution or (upstream and text != upstream)) else None
    return upstream, package, distribution


def _distribution(value: str) -> str | None:
    match = _DISTRIBUTION.search(value or "")
    if not match:
        return None
    token = match.group(1).lower().lstrip("+.")
    for prefix, name in _DISTRIBUTION_NAMES:
        if token.startswith(prefix):
            return name
    return "distribution"


def component_cpes(key: Any, version: Any) -> list[str]:
    """CPE names for a catalogue product and an upstream version, else empty."""
    item = product(key)
    text = plain_version(version) or (str(version or "") if re.fullmatch(
        r"[0-9]{1,6}(?:\.[0-9]{1,9}){0,5}[a-z][0-9]{0,4}", str(version or "")) else None)
    if item is None or not text:
        return []
    return [f"cpe:2.3:{name}:{text}:*:*:*:*:*:*:*" for name in item.cpe_products]


def base_path(value: Any) -> str | None:
    """A normalized base path (``/``, ``/jenkins/``), or None when it is not a plain path."""
    text = str(value or "/")
    if not text.startswith("/") or len(text) > 260:
        return None
    segments = [segment for segment in text.split("/") if segment]
    if len(segments) > 4 or any(not _BASE_SEGMENT.fullmatch(s) or s in {".", ".."} for s in segments):
        return None
    return "/" + "".join(f"{segment}/" for segment in segments)


def base_of_url_path(path: Any) -> str:
    """The directory of a request path: ``/jenkins/login`` -> ``/jenkins/``; else ``/``."""
    text = str(path or "/")
    directory = text[: text.rfind("/") + 1] if "/" in text else "/"
    return base_path(directory) or "/"


def claim(key: str | None, *, role: str, basis: str, base: str, product_status: str,
          label: str | None = None, version: str | None = None, version_status: str = "unknown",
          version_source_field: str | None = None, product_source_field: str | None = None,
          package_version: str | None = None, distribution: str | None = None,
          recipe: str | None = None, signals: Iterable[str] = ()) -> dict[str, Any]:
    """One component claim as observations carry it."""
    item = product(key)
    if version_status not in VERSION_STATUSES or not version:
        version, version_status, package_version = None, "unknown", None
        version_source_field = None
    return {
        "role": item.role if item else role,
        "base_path": base,
        "product_key": item.key if item else None,
        "product": item.label if item else label,
        "vendor": item.vendor if item else None,
        "category": item.category if item else None,
        "product_status": product_status,
        "version": version, "version_status": version_status,
        "package_version": package_version, "distribution": distribution,
        "basis": basis, "product_source_field": product_source_field,
        "version_source_field": version_source_field,
        "recipe": recipe,
        "recipe_version": f"{RECIPE_CATALOGUE_VERSION}:{recipe}@{RECIPES_BY_KEY[recipe].revision}"
        if recipe in RECIPES_BY_KEY else None,
        "signals": sorted(set(signals))[:8],
    }


def server_claim(value: Any, *, base: str) -> dict[str, Any] | None:
    """The ``Server`` header as an edge or web-server component; never a guessed version."""
    if not isinstance(value, str) or len(value) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return None
    match = _SERVER_TOKEN.match(value.strip())
    if not match:
        return None
    name, raw_version, comment = match.group(1), match.group(2), match.group(3)
    key = _SERVER_PRODUCTS.get(name.lower())
    upstream, package, distribution = split_package_version(raw_version, comment)
    return claim(
        key, role="web_server", basis="server_header", base=base, product_status="identified",
        label=None if key else name, version=upstream,
        version_status="reported" if upstream else "unknown",
        version_source_field="response.header.server", product_source_field="response.header.server",
        package_version=package, distribution=distribution,
    )


def components_from_fingerprint(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Components a passive ``http_fingerprint`` observation names (Server, technologies, title)."""
    try:
        parts = urllib.parse.urlsplit(str(row.get("url") or ""))
    except ValueError:
        return []
    base = base_of_url_path(parts.path)
    found: dict[tuple[str, str], dict[str, Any]] = {}
    server = server_claim(row.get("webserver"), base=base) if row.get("webserver") else None
    if server is not None:
        found[(server["role"], server["product_key"] or str(server["product"]).lower())] = server
    for raw in list(row.get("technologies") or ())[:50]:
        name = raw.get("name") if isinstance(raw, Mapping) else raw
        text = str(name or "").strip()[:200]
        label, separator, tail = text.rpartition(":")
        version = plain_version(tail) if separator else None
        if not version:
            label = text
            version = plain_version(raw.get("version")) if isinstance(raw, Mapping) else None
        key = _TECHNOLOGY_PRODUCTS.get(label.strip().lower())
        item = product(key)
        if item is None:
            continue
        slot = (item.role, item.key)
        prior = found.get(slot)
        if prior is not None and prior["product_status"] == "identified":
            continue  # the Server header already names it, with its own version evidence
        found[slot] = claim(
            key, role=item.role, basis="technology_fingerprint", base=base,
            product_status="probable", version=version,
            # A fingerprint pattern may read the version from a generic asset; never exact.
            version_status="inferred_range" if version else "unknown",
            version_source_field="fingerprint.technology" if version else None,
            product_source_field="fingerprint.technology",
        )
    title = str(row.get("title") or "")[:300]
    for pattern, key in _TITLE_PRODUCTS:
        if title and pattern.fullmatch(title):
            item = product(key)
            if item and (item.role, item.key) not in found:
                found[(item.role, item.key)] = claim(
                    key, role=item.role, basis="page_title", base=base,
                    product_status="probable", product_source_field="response.title",
                )
    return list(found.values())


# ---------------------------------------------------------------------------------------------
# Recipes


@dataclass(frozen=True)
class Signal:
    """One identity signal read from one probe's response.

    ``kind``: ``header`` (named header value), ``body`` (bounded body text), ``json`` (a
    top-level key of a JSON object document), ``realm`` (the ``WWW-Authenticate`` challenge).
    ``everywhere`` marks a product header the product sends on every response, which counts even
    when the probe answered like the negative control.
    """

    name: str
    probe: str
    kind: str
    pattern: str
    field: str = ""
    strong: bool = True
    everywhere: bool = False
    statuses: tuple[int, ...] = ()


@dataclass(frozen=True)
class VersionSource:
    probe: str
    kind: str
    pattern: str
    field: str = ""
    status: str = "reported"
    source_field: str = ""


@dataclass(frozen=True)
class Recipe:
    key: str
    revision: int
    # Paths relative to a base path; "" is the base itself.
    probes: tuple[str, ...]
    signals: tuple[Signal, ...]
    versions: tuple[VersionSource, ...] = ()
    # Base paths a reverse proxy commonly mounts the product under (probed from "/").
    mounts: tuple[str, ...] = ()
    plugins: bool = False


_PLAIN = r"([0-9]{1,6}(?:\.[0-9]{1,9}){1,5})"

RECIPES: tuple[Recipe, ...] = (
    Recipe("jenkins", 1, ("login",), (
        Signal("header:x-jenkins", "*", "header", r"\A[0-9.]{1,40}\Z", "x-jenkins", everywhere=True),
        Signal("header:x-hudson", "*", "header", r"\A[0-9.]{1,40}\Z", "x-hudson", everywhere=True),
        Signal("body:jenkins-login-form", "login", "body", r'name="j_username"|action="j_spring_security_check"|action="j_acegi_security_check"', strong=False),
    ), (VersionSource("*", "header", r"\A" + _PLAIN + r"\Z", "x-jenkins", source_field="response.header.x-jenkins"),),
        mounts=("jenkins/",)),
    Recipe("grafana", 1, ("api/health", "login"), (
        Signal("json:grafana-health", "api/health", "json", r"\A(?:ok|failing)\Z", "database", statuses=(200, 503)),
        Signal("body:grafana-boot", "login", "body", r"grafanaBootData|window\.grafanaBootData", strong=False),
    ), (VersionSource("api/health", "json", r"\A" + _PLAIN + r"\Z", "version", source_field="api/health.version"),),
        mounts=("grafana/",)),
    Recipe("gitlab", 1, ("users/sign_in", "api/v4/version"), (
        Signal("header:x-gitlab-meta", "api/v4/version", "header", r'\A\{"correlation_id"', "x-gitlab-meta"),
        Signal("body:gitlab-site-name", "users/sign_in", "body", r'content="GitLab"\s+property="og:site_name"|property="og:site_name"\s+content="GitLab"'),
    ), mounts=("gitlab/",)),
    Recipe("nexus", 1, ("service/rest/v1/status",), (
        Signal("header:server-nexus", "*", "header", r"\ANexus/[0-9]", "server", everywhere=True),
        Signal("body:nexus-title", "", "body", r"<title>\s*(?:Sonatype )?Nexus Repository(?: Manager)?\s*</title>", strong=False),
    ), (VersionSource("*", "header", r"\ANexus/([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})(-[0-9]{1,4})?", "server", source_field="response.header.server"),),
        mounts=("nexus/",)),
    Recipe("keycloak", 1, ("realms/master/.well-known/openid-configuration",), (
        Signal("json:keycloak-issuer", "realms/master/.well-known/openid-configuration", "json", r"/realms/master\Z", "issuer", statuses=(200,)),
        Signal("json:keycloak-auth-endpoint", "realms/master/.well-known/openid-configuration", "json", r"/realms/master/protocol/openid-connect/auth\Z", "authorization_endpoint", statuses=(200,)),
    ), mounts=("auth/", "keycloak/")),
    Recipe("wordpress", 1, ("", "wp-login.php", "wp-json/"), (
        Signal("body:wp-login-form", "wp-login.php", "body", r'id="loginform"[^>]{0,200}action="[^"]{0,300}wp-login\.php|name="wp-submit"', statuses=(200,)),
        Signal("json:wp-rest-namespaces", "wp-json/", "json", r"wp/v2", "namespaces", statuses=(200,)),
        Signal("body:wp-content-paths", "", "body", r"/wp-content/(?:themes|plugins)/|/wp-includes/", strong=False),
    ), (VersionSource("", "body", r'<meta name="generator" content="WordPress ' + _PLAIN + r'"', source_field="html.meta.generator"),),
        mounts=("wordpress/", "blog/"), plugins=True),
    Recipe("kibana", 1, ("api/status",), (
        Signal("header:kbn-name", "*", "header", r"\A[A-Za-z0-9._-]{1,64}\Z", "kbn-name", everywhere=True),
    ), (VersionSource("*", "header", r"\A" + _PLAIN + r"\Z", "kbn-version", source_field="response.header.kbn-version"),),
        mounts=("kibana/",)),
    Recipe("phpmyadmin", 1, ("",), (
        Signal("body:pma-token", "", "body", r'name="pma_username"|class="pma_|phpMyAdmin\s+[0-9]|<title>phpMyAdmin', statuses=(200,)),
    ), mounts=("phpmyadmin/",)),
    Recipe("tomcat_manager", 1, ("manager/html",), (
        Signal("realm:tomcat-manager", "manager/html", "realm", r'realm="Tomcat Manager Application"', statuses=(401,)),
    )),
    Recipe("webmin", 1, (), (
        Signal("header:server-miniserv", "*", "header", r"\AMiniServ/[0-9]", "server", everywhere=True),
    ), (VersionSource("*", "header", r"\AMiniServ/" + _PLAIN + r"\Z", "server", source_field="response.header.server"),)),
    Recipe("fortigate_ssl_vpn", 1, ("remote/login",), (
        Signal("body:fortigate-login", "remote/login", "body", r"ftnt-fortinet-grid|/remote/logincheck|fgt_lang", statuses=(200,)),
    )),
    Recipe("globalprotect", 1, ("global-protect/login.esp", "ssl-vpn/prelogin.esp"), (
        Signal("body:globalprotect-portal", "global-protect/login.esp", "body", r"GlobalProtect Portal|global-protect/portal/", statuses=(200,)),
        Signal("body:globalprotect-prelogin", "ssl-vpn/prelogin.esp", "body", r"<prelogin-response>", statuses=(200,)),
    )),
    Recipe("ivanti_connect_secure", 1, ("dana-na/auth/url_default/welcome.cgi",), (
        Signal("body:ivanti-welcome", "dana-na/auth/url_default/welcome.cgi", "body", r"/dana-na/auth/url_default/login\.cgi|dana-na/css/ds\.css|Pulse Connect Secure|Ivanti Connect Secure", statuses=(200,)),
    )),
    Recipe("citrix_gateway", 1, ("vpn/index.html", "logon/LogonPoint/index.html"), (
        Signal("body:citrix-vpn", "vpn/index.html", "body", r"/vpn/resources/|NetScaler Gateway|Citrix Gateway", statuses=(200,)),
        Signal("body:citrix-logonpoint", "logon/LogonPoint/index.html", "body", r"LogonPoint|ctxs\.core|Citrix Gateway", statuses=(200,)),
    )),
    Recipe("cisco_asa_webvpn", 1, ("+CSCOE+/logon.html",), (
        Signal("body:cisco-webvpn", "+CSCOE+/logon.html", "body", r"webvpnlogin|/\+CSCOE\+/|SSL VPN Service", statuses=(200,)),
    )),
)
RECIPES_BY_KEY: dict[str, Recipe] = {recipe.key: recipe for recipe in RECIPES}
_COMPILED: dict[str, re.Pattern[str]] = {}

# The product's own error page, read from the negative control (an absent path) and only when it
# answered an error status. Server and framework components, never an application recipe.
_ERROR_PAGES: tuple[tuple[str, str, str], ...] = (
    ("tomcat", r"<h3>Apache Tomcat/" + _PLAIN + r"</h3>|Apache Tomcat/" + _PLAIN, "error_page.tomcat"),
    ("nginx", r"<center>nginx/" + _PLAIN + r"</center>|<center>nginx</center>", "error_page.nginx"),
    ("apache_httpd", r"<address>Apache/" + _PLAIN + r"(?: \(([A-Za-z ]{1,30})\))? Server at", "error_page.apache"),
    ("jetty", r"Powered by Jetty:// " + _PLAIN, "error_page.jetty"),
    ("iis", r"<title>IIS " + _PLAIN + r" Detailed Error", "error_page.iis"),
    ("spring_boot", r"<h1>Whitelabel Error Page</h1>", "error_page.spring_boot"),
    ("django", r"Using the URLconf defined in <code>", "error_page.django"),
    ("express", r"<pre>Cannot GET /[^<]{0,300}</pre>", "error_page.express"),
)
# Response headers that name an edge in front of the listener.
_EDGE_HEADERS: tuple[tuple[str, str, str], ...] = (
    ("cf-ray", r"\A[0-9a-f]{8,32}-[A-Z]{3}\Z", "cloudflare"),
    ("x-amz-cf-id", r"\A[A-Za-z0-9_=-]{20,80}\Z", "cloudfront"),
    ("x-akamai-request-id", r"\A[0-9a-f.]{4,40}\Z", "akamai"),
    ("akamai-grn", r"\A[0-9a-f.]{4,60}\Z", "akamai"),
    ("x-fastly-request-id", r"\A[0-9a-f]{20,64}\Z", "fastly"),
    ("x-sucuri-id", r"\A[0-9]{1,12}\Z", "sucuri"),
    ("x-iinfo", r"\A[0-9]{1,3}-[0-9]{3,12}-", "imperva"),
    ("via", r"varnish", "varnish"),
)


def _pattern(value: str) -> re.Pattern[str]:
    compiled = _COMPILED.get(value)
    if compiled is None:
        compiled = _COMPILED[value] = re.compile(value, re.IGNORECASE)
    return compiled


@dataclass(frozen=True)
class Response:
    """A bounded response: status, lower-cased headers, capped body, query-less Location path."""

    status: int
    headers: Mapping[str, str]
    body: bytes
    location: str | None = None
    connected_address: str | None = None
    requested_path: str = ""

    @property
    def digest(self) -> str:
        """The body's digest with the requested path removed: error pages echo it."""
        body = self.body
        if self.requested_path and len(self.requested_path) > 1:
            for variant in {self.requested_path, urllib.parse.quote(self.requested_path, safe="/")}:
                body = body.replace(variant.encode("utf-8", "replace"), b"")
        return hashlib.sha256(body).hexdigest()

    def text(self) -> str:
        return self.body[:BODY_LIMIT].decode("utf-8", "replace")

    def json_object(self) -> Mapping[str, Any] | None:
        content_type = str(self.headers.get("content-type") or "").lower()
        if "json" not in content_type and not self.body.lstrip()[:1] == b"{":
            return None
        try:
            import json
            value = json.loads(self.body[:BODY_LIMIT].decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None
        return value if isinstance(value, Mapping) else None


def response_from(status: Any, headers: Mapping[str, Any], body: bytes, *,
                  connected_address: str | None = None, requested_path: str = "") -> Response | None:
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        return None
    lowered = {str(k).lower(): str(v)[:2048] for k, v in list((headers or {}).items())[:200]}
    location = None
    if lowered.get("location"):
        try:
            location = urllib.parse.urlsplit(lowered["location"][:2048]).path or "/"
        except ValueError:
            location = "?"
    return Response(status, lowered, bytes(body or b"")[:BODY_LIMIT], location, connected_address,
                    str(requested_path or "")[:300])


def indistinguishable(probe: Response, control: Response | None) -> bool:
    """Whether a probe answered like the path that cannot exist (generic 404, redirect, WAF)."""
    if control is None or probe.status != control.status:
        return False
    if 300 <= probe.status < 400:
        # A login or canonical redirect: the same destination, whatever was requested.
        return (probe.location or "") == (control.location or "")
    if probe.digest == control.digest:
        return True
    # A generic page carrying a request id or a time: the same page at a near-equal length.
    # Short documents (a health JSON, a version string) must match exactly.
    size, other = len(probe.body), len(control.body)
    return min(size, other) >= 256 and abs(size - other) <= max(16, other // 100)


def _header_value(response: Response, name: str) -> str:
    return str(response.headers.get(name) or "")


def _signal_value(signal_kind: str, field: str, response: Response) -> str | None:
    if signal_kind == "header":
        return _header_value(response, field) or None
    if signal_kind == "realm":
        return _header_value(response, "www-authenticate") or None
    if signal_kind == "body":
        return response.text()
    if signal_kind == "json":
        document = response.json_object()
        if document is None or field not in document:
            return None
        value = document[field]
        if isinstance(value, list):
            return " ".join(str(item)[:200] for item in value[:100] if isinstance(item, (str, int, float)))
        return str(value)[:500] if isinstance(value, (str, int, float)) and not isinstance(value, bool) else None
    return None


@dataclass
class _Evidence:
    responses: dict[str, Response] = field(default_factory=dict)
    control: Response | None = None


def evaluate_recipe(recipe: Recipe, *, base: str, evidence: _Evidence) -> dict[str, Any] | None:
    """A component claim when the recipe's signals hold against the base's negative control."""
    control = evidence.control
    matched: list[str] = []
    strong = False
    status_of: int | None = None
    for signal in recipe.signals:
        probes = list(evidence.responses) if signal.probe == "*" else [signal.probe]
        for path in probes:
            response = evidence.responses.get(path)
            if response is None or (signal.statuses and response.status not in signal.statuses):
                continue
            if not signal.everywhere and indistinguishable(response, control):
                continue
            value = _signal_value(signal.kind, signal.field, response)
            if not value or not _pattern(signal.pattern).search(value):
                continue
            if signal.kind == "body" and control is not None and _pattern(signal.pattern).search(control.text()):
                continue  # the site's generic page carries the same text
            matched.append(signal.name)
            strong = strong or signal.strong
            status_of = status_of or response.status
            break
    if not matched:
        return None
    version = version_status = source_field = package = None
    for source in recipe.versions:
        probes = list(evidence.responses) if source.probe == "*" else [source.probe]
        for path in probes:
            response = evidence.responses.get(path)
            if response is None:
                continue
            if source.probe != "*" and indistinguishable(response, control):
                continue
            value = _signal_value(source.kind, source.field, response)
            match = _pattern(source.pattern).search(value or "")
            found = next((group for group in (match.groups() if match else ()) if group), None)
            if found and plain_version(found):
                version, version_status, source_field = found, source.status, source.source_field
                tail = match.group(0) if match else ""
                package = tail if source.kind == "header" and tail != found and len(tail) <= 80 else None
                break
        if version:
            break
    result = claim(
        recipe.key, role="application", basis="recipe", base=base,
        product_status="identified" if strong else "probable",
        version=version, version_status=version_status or "unknown",
        version_source_field=source_field, product_source_field=f"recipe.{matched[0]}",
        package_version=package, recipe=recipe.key, signals=matched,
    )
    result["status"] = status_of
    return result


def error_page_claims(control: Response | None, *, base: str) -> list[dict[str, Any]]:
    """Server and framework components named by the absent path's own error page."""
    if control is None or control.status < 400:
        return []
    page = control.text()
    found = []
    for key, pattern, source in _ERROR_PAGES:
        match = _pattern(pattern).search(page)
        if not match:
            continue
        groups = [group for group in match.groups() if group]
        version = plain_version(groups[0]) if groups else None
        comment = groups[1] if len(groups) > 1 else None
        upstream, package, distribution = split_package_version(version, comment)
        found.append(claim(
            key, role="web_server", basis="error_page", base=base, product_status="identified",
            version=upstream, version_status="reported" if upstream else "unknown",
            version_source_field=source if upstream else None, product_source_field=source,
            package_version=package, distribution=distribution,
        ))
    return found


def header_claims(response: Response | None, *, base: str) -> list[dict[str, Any]]:
    """Edge components named by response headers, and the ``Server`` component."""
    if response is None:
        return []
    found: dict[str, dict[str, Any]] = {}
    for name, pattern, key in _EDGE_HEADERS:
        value = _header_value(response, name)
        if value and _pattern(pattern).search(value) and key not in found:
            found[key] = claim(key, role="edge", basis="edge_header", base=base,
                               product_status="identified",
                               product_source_field=f"response.header.{name}")
    server = server_claim(response.headers.get("server"), base=base) if response.headers.get("server") else None
    if server is not None:
        found.setdefault(server["product_key"] or str(server["product"]).lower(), server)
    return list(found.values())


_PLUGIN_PATH = re.compile(r"/wp-content/plugins/([a-z0-9][a-z0-9_-]{0,63})/")
_README_TAG = re.compile(r"^\s*Stable tag:\s*" + _PLAIN + r"\s*$", re.IGNORECASE | re.MULTILINE)


def plugin_slugs(response: Response | None) -> list[str]:
    if response is None:
        return []
    slugs: list[str] = []
    for match in _PLUGIN_PATH.finditer(response.text()):
        slug = match.group(1)
        if _SLUG.fullmatch(slug) and slug not in slugs:
            slugs.append(slug)
        if len(slugs) >= MAX_PLUGIN_SLUGS:
            break
    return slugs


def plugin_claim(slug: str, *, base: str, readme: Response | None, control: Response | None) -> dict[str, Any]:
    """A WordPress plugin the page references; its readme's stable tag is inferred, not reported."""
    version = None
    identified = False
    if readme is not None and readme.status == 200 and not indistinguishable(readme, control):
        text = readme.text()
        if text.lstrip().startswith("===") and "Stable tag" in text:
            identified = True
            match = _README_TAG.search(text)
            version = plain_version(match.group(1)) if match else None
    result = claim(
        None, role="plugin", basis="wordpress_plugin", base=base,
        product_status="identified" if identified else "probable",
        label=f"WordPress plugin {slug}",
        version=version, version_status="inferred_range" if version else "unknown",
        version_source_field="readme.txt.stable_tag" if version else None,
        product_source_field="readme.txt" if identified else "html.plugin_path",
        recipe="wordpress",
    )
    result["plugin_slug"] = slug
    result["advisory_product"] = slug.replace("-", "_")
    return result


def control_path(base: str) -> str:
    return f"{base}{CONTROL_PREFIX}{secrets.token_hex(8)}"


def request_ceiling() -> int:
    """Every request one action can send: the upper bound its reservation must fund."""
    per_base = 2 + len({probe for recipe in RECIPES for probe in recipe.probes if probe}) + MAX_PLUGIN_READMES
    # Each mount: its first probe, then (when it answers as the product) its base, control and
    # remaining probes; plugin readmes on the mounts that matched.
    mounts = sum(len(recipe.mounts) * (len(recipe.probes) + 2) for recipe in RECIPES)
    return per_base * MAX_BASES + mounts + MAX_MOUNT_BASES * MAX_PLUGIN_READMES


Fetch = Callable[[str], Awaitable["Response | None"]]


@dataclass
class IdentifyResult:
    components: list[dict[str, Any]]
    requests: int
    bases: list[str]
    controlled_out: int
    budget_exhausted: bool
    cancelled: bool
    timed_out: bool
    errors: list[str]

    def receipt(self) -> dict[str, Any]:
        return {
            "catalogue": RECIPE_CATALOGUE_VERSION,
            "recipes": len(RECIPES),
            "requests": self.requests,
            "bases": self.bases,
            "components": len(self.components),
            "probes_matching_control": self.controlled_out,
            "budget_exhausted": self.budget_exhausted,
            "cancelled": self.cancelled,
            "timed_out": self.timed_out,
        }


async def identify(*, bases: Iterable[str], fetch: Fetch, request_limit: int,
                   deadline_seconds: float, cancelled: Callable[[], bool] = lambda: False) -> IdentifyResult:
    """Run every recipe at each base path, mounts from ``/``; bounded by requests and time."""
    started = time.monotonic()
    state = {"requests": 0, "exhausted": False, "cancelled": False, "timed_out": False}
    errors: list[str] = []
    controlled = 0
    components: list[dict[str, Any]] = []

    def stop() -> bool:
        if cancelled():
            state["cancelled"] = True
        elif time.monotonic() - started > deadline_seconds:
            state["timed_out"] = True
        elif state["requests"] >= request_limit:
            state["exhausted"] = True
        return bool(state["cancelled"] or state["timed_out"] or state["exhausted"])

    async def get(path: str) -> Response | None:
        if stop():
            return None
        state["requests"] += 1
        try:
            return await fetch(path)
        except (OSError, ValueError, asyncio.TimeoutError) as exc:
            if len(errors) < 20:
                errors.append(type(exc).__name__)
            return None

    async def examine(base: str, recipes: Iterable[Recipe], *, evidence: _Evidence | None = None) -> _Evidence:
        nonlocal controlled
        evidence = evidence or _Evidence()
        if "" not in evidence.responses:
            root = await get(base)
            if root is not None:
                evidence.responses[""] = root
        if evidence.control is None:
            evidence.control = await get(control_path(base))
        for recipe in recipes:
            for probe in recipe.probes:
                if probe not in evidence.responses:
                    response = await get(base + probe)
                    if response is None:
                        continue
                    evidence.responses[probe] = response
                    if indistinguishable(response, evidence.control):
                        controlled += 1
            found = evaluate_recipe(recipe, base=base, evidence=evidence)
            if found is not None:
                found["connected_address"] = _address_of(evidence)
                components.append(found)
                if recipe.plugins:
                    for index, slug in enumerate(plugin_slugs(evidence.responses.get(""))):
                        readme = await get(f"{base}wp-content/plugins/{slug}/readme.txt") if index < MAX_PLUGIN_READMES else None
                        item = plugin_claim(slug, base=base, readme=readme, control=evidence.control)
                        item["connected_address"] = _address_of(evidence)
                        components.append(item)
        for item in [*header_claims(evidence.responses.get(""), base=base),
                     *error_page_claims(evidence.control, base=base)]:
            item["connected_address"] = _address_of(evidence)
            components.append(item)
        return evidence

    seen: list[str] = []
    for raw in bases:
        normalized = base_path(raw)
        if normalized and normalized not in seen and len(seen) < MAX_BASES:
            seen.append(normalized)
    if "/" not in seen:
        seen.insert(0, "/")
        seen = seen[:MAX_BASES]
    root_evidence: _Evidence | None = None
    examined: list[str] = []
    index = 0
    while index < len(seen):
        base = seen[index]
        index += 1
        evidence = await examine(base, RECIPES)
        examined.append(base)
        if base == "/":
            root_evidence = evidence
            # The root's own relative redirect (``/`` -> ``/app/login``) names the application base.
            root = evidence.responses.get("")
            location = str(root.headers.get("location") or "") if root is not None else ""
            if root is not None and 300 <= root.status < 400 and location.startswith("/") and not location.startswith("//"):
                redirected = base_of_url_path(urllib.parse.urlsplit(location[:2048]).path)
                if redirected not in seen and len(seen) < MAX_BASES:
                    seen.append(redirected)
        if stop():
            break
    # Mounts: a reverse proxy commonly serves a product under its own name. The mount's first
    # probe must answer unlike the root's control before the mount gets its own control.
    mount_bases = 0
    if root_evidence is not None and not stop():
        for recipe in RECIPES:
            for mount in recipe.mounts:
                if mount_bases >= MAX_MOUNT_BASES or stop():
                    break
                mount_base = "/" + mount
                if mount_base in examined:
                    continue
                first = recipe.probes[0] if recipe.probes else ""
                response = await get(mount_base + first)
                if response is None or indistinguishable(response, root_evidence.control):
                    controlled += response is not None
                    continue
                trial = _Evidence(responses={first: response}, control=root_evidence.control)
                if evaluate_recipe(recipe, base=mount_base, evidence=trial) is None:
                    continue
                mount_bases += 1
                examined.append(mount_base)
                await examine(mount_base, (recipe,), evidence=_Evidence(responses={first: response}))
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for item in components:
        key = (item["base_path"], item["role"], item["product_key"] or item["product"])
        prior = unique.get(key)
        if prior is None or _rank(item) > _rank(prior):
            unique[key] = item
    stop()
    return IdentifyResult(
        components=list(unique.values()), requests=state["requests"], bases=examined,
        controlled_out=controlled, budget_exhausted=bool(state["exhausted"]),
        cancelled=bool(state["cancelled"]), timed_out=bool(state["timed_out"]), errors=errors,
    )


def _rank(item: Mapping[str, Any]) -> tuple[int, int]:
    return (
        PRODUCT_STATUSES[::-1].index(item["product_status"]) if item["product_status"] in PRODUCT_STATUSES else -1,
        VERSION_STATUSES[::-1].index(item["version_status"]) if item["version_status"] in VERSION_STATUSES else -1,
    )


def _address_of(evidence: _Evidence) -> str | None:
    for response in evidence.responses.values():
        if response.connected_address:
            return response.connected_address
    return evidence.control.connected_address if evidence.control else None


__all__ = [
    "MAX_BASES", "PRODUCTS", "RECIPES", "RECIPE_CATALOGUE_VERSION", "ROLES", "Recipe", "Response",
    "VERSION_STATUSES", "PRODUCT_STATUSES", "base_of_url_path", "base_path", "claim",
    "component_cpes", "components_from_fingerprint", "error_page_claims", "evaluate_recipe",
    "header_claims", "identify", "indistinguishable", "plain_version", "product",
    "product_for_label", "request_ceiling", "response_from", "server_claim",
    "split_package_version",
]
