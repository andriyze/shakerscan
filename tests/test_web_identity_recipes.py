"""Product recipes against fixture sites: proxies, subpaths, and hostile uniform answers."""
from __future__ import annotations

import asyncio
import json

import pytest

from scanner.scanner_tools import web_identity as wi


class Site:
    """A fixture site: ``routes`` maps an exact path to (status, headers, body); ``fallback``
    answers everything else from the requested path."""

    def __init__(self, routes=None, fallback=None, address="192.0.2.20"):
        self.routes = routes or {}
        self.fallback = fallback or (lambda path: (404, {"content-type": "text/html"}, f"<h1>Not Found</h1><p>{path}</p>"))
        self.requests: list[str] = []
        self.address = address

    async def fetch(self, path):
        self.requests.append(path)
        status, headers, body = self.routes.get(path) or self.fallback(path)
        data = body.encode() if isinstance(body, str) else body
        return wi.response_from(status, headers, data, connected_address=self.address, requested_path=path)


def run(site, bases=("/",), limit=None, deadline=60.0):
    return asyncio.run(wi.identify(bases=bases, fetch=site.fetch,
                                   request_limit=limit or wi.request_ceiling(), deadline_seconds=deadline))


def named(result, role=None):
    return {(c["product"], c["base_path"]): c for c in result.components if role is None or c["role"] == role}


JENKINS_HEADERS = {"x-jenkins": "2.426.3", "x-hudson": "1.395", "content-type": "text/html"}
GRAFANA_INDEX = "<!doctype html><html><head><title>Grafana</title></head><body>" + "x" * 900 + "</body></html>"


def proxy_with_jenkins_and_grafana():
    routes = {
        "/": (200, {"server": "nginx/1.24.0", "content-type": "text/html"}, "<html><title>Portal</title>" + "p" * 400),
        "/jenkins/login": (200, JENKINS_HEADERS, '<form name="login" action="j_spring_security_check"><input name="j_username">'),
        "/jenkins/": (403, JENKINS_HEADERS, "Authentication required"),
        "/grafana/api/health": (200, {"content-type": "application/json"},
                                json.dumps({"commit": "abc", "database": "ok", "version": "10.2.3"})),
    }

    def fallback(path):
        if path.startswith("/jenkins/"):
            return 404, JENKINS_HEADERS, f"Jenkins 404 {path}"
        if path.startswith("/grafana/"):
            return 200, {"content-type": "text/html"}, GRAFANA_INDEX  # single-page catch-all
        return 404, {"server": "nginx/1.24.0", "content-type": "text/html"}, f"<html><center>nginx/1.24.0</center>{path}</html>"
    return Site(routes, fallback)


def test_applications_behind_one_proxy_under_subpaths_are_identified_with_reported_versions():
    result = run(proxy_with_jenkins_and_grafana())
    apps = named(result, "application")
    assert set(apps) == {("Jenkins", "/jenkins/"), ("Grafana", "/grafana/")}
    jenkins, grafana = apps[("Jenkins", "/jenkins/")], apps[("Grafana", "/grafana/")]
    assert (jenkins["product_status"], jenkins["version"], jenkins["version_status"]) == ("identified", "2.426.3", "reported")
    assert jenkins["version_source_field"] == "response.header.x-jenkins"
    assert (grafana["version"], grafana["version_status"], grafana["version_source_field"]) == ("10.2.3", "reported", "api/health.version")
    assert jenkins["connected_address"] == "192.0.2.20"
    assert jenkins["recipe_version"] == "web-identity/v1:jenkins@1"
    servers = named(result, "web_server")
    assert servers[("nginx", "/")]["version"] == "1.24.0"
    assert result.requests <= wi.request_ceiling()


def test_a_versionless_application_stays_version_unknown():
    site = proxy_with_jenkins_and_grafana()
    site.routes["/grafana/api/health"] = (200, {"content-type": "application/json"}, '{"commit":"abc","database":"ok"}')
    grafana = named(run(site), "application")[("Grafana", "/grafana/")]
    assert grafana["version"] is None and grafana["version_status"] == "unknown"


@pytest.mark.parametrize("status,body", [
    (200, "<html><title>Welcome</title>" + "u" * 2000 + "</html>"),
    (403, "<html><title>403 Forbidden</title>Request blocked by security policy. Incident 77.</html>"),
    (200, '{"status":"ok"}'),
])
def test_a_site_answering_every_path_alike_produces_no_recipe_match(status, body):
    site = Site(fallback=lambda path: (status, {"content-type": "text/html"}, body))
    result = run(site)
    assert [c for c in result.components if c["recipe"]] == []
    assert result.controlled_out > 10


def test_a_catch_all_that_echoes_product_words_on_every_path_is_not_a_product():
    words = ("Jenkins j_username grafanaBootData GitLab og:site_name wp-submit wp-content/plugins/x/ "
             "GlobalProtect Portal /dana-na/auth/url_default/login.cgi NetScaler Gateway webvpnlogin "
             "fgt_lang pma_username <prelogin-response> LogonPoint")
    site = Site(fallback=lambda path: (200, {"content-type": "text/html"}, f"<html>{words} {path}</html>"))
    assert [c for c in run(site).components if c["recipe"]] == []


def test_a_login_redirect_for_every_path_is_not_a_product():
    site = Site(fallback=lambda path: (302, {"location": f"/login?next={path}"}, ""))
    assert run(site).components == []


def test_hostile_version_strings_are_never_reported():
    site = proxy_with_jenkins_and_grafana()
    bad = {**JENKINS_HEADERS, "x-jenkins": "2.426.3<script>alert(1)</script>"}
    site.routes["/jenkins/login"] = (200, bad, '<input name="j_username">')
    site.routes["/jenkins/"] = (403, bad, "Authentication required")
    fallback = site.fallback
    site.fallback = lambda path: (404, bad, f"Jenkins 404 {path}") if path.startswith("/jenkins/") else fallback(path)
    site.routes["/grafana/api/health"] = (200, {"content-type": "application/json"},
                                          '{"database":"ok","version":"10.2.3; rm -rf /"}')
    apps = named(run(site), "application")
    grafana = apps[("Grafana", "/grafana/")]
    assert grafana["version"] is None
    jenkins = apps.get(("Jenkins", "/jenkins/"))
    assert jenkins is None or jenkins["version"] is None


def wordpress_site():
    home = ('<html><head><meta name="generator" content="WordPress 6.4.2" />'
            '<link href="/wp-content/plugins/contact-form-7/style.css?ver=5.8">'
            '<script src="/wp-content/plugins/elementor/app.js?ver=3.17.0"></script>'
            '<script src="/wp-content/plugins/../../etc/passwd"></script>' + "w" * 600 + "</head></html>")
    routes = {
        "/": (200, {"content-type": "text/html", "server": "Apache/2.4.58 (Debian)"}, home),
        "/wp-login.php": (200, {"content-type": "text/html"}, '<form name="loginform" id="loginform" action="https://blog.example.test/wp-login.php" method="post"><input type="submit" name="wp-submit">'),
        "/wp-json/": (200, {"content-type": "application/json"}, json.dumps({"name": "x", "namespaces": ["oembed/1.0", "wp/v2"]})),
        "/wp-content/plugins/contact-form-7/readme.txt": (200, {"content-type": "text/plain"}, "=== Contact Form 7 ===\nStable tag: 5.8.4\n"),
    }
    return Site(routes)


def test_wordpress_and_its_plugins_are_separate_components_with_honest_versions():
    result = run(wordpress_site())
    comps = named(result)
    wordpress = comps[("WordPress", "/")]
    assert (wordpress["product_status"], wordpress["version"], wordpress["version_status"]) == ("identified", "6.4.2", "reported")
    cf7 = comps[("WordPress plugin contact-form-7", "/")]
    assert (cf7["role"], cf7["product_status"], cf7["version"], cf7["version_status"]) == ("plugin", "identified", "5.8.4", "inferred_range")
    elementor = comps[("WordPress plugin elementor", "/")]
    # The asset's ?ver= is a generic asset parameter, never a version.
    assert (elementor["product_status"], elementor["version"]) == ("probable", None)
    assert not any(".." in c["product"] for c in result.components)
    server = comps[("Apache HTTP Server", "/")]
    assert (server["version"], server["distribution"]) == ("2.4.58", "debian")


def test_error_pages_and_auth_challenges_name_components():
    routes = {
        "/": (200, {"content-type": "text/html"}, "<html>" + "a" * 500 + "</html>"),
        "/manager/html": (401, {"www-authenticate": 'Basic realm="Tomcat Manager Application"'}, "401"),
    }
    site = Site(routes, lambda path: (404, {"content-type": "text/html"},
                                       f"<html><h3>Apache Tomcat/9.0.65</h3>{path}</html>"))
    comps = named(run(site))
    assert comps[("Apache Tomcat", "/")]["version"] == "9.0.65"
    assert comps[("Apache Tomcat", "/")]["basis"] == "error_page"
    assert comps[("Apache Tomcat Manager", "/")]["signals"] == ["realm:tomcat-manager"]


def test_edge_headers_name_the_edge_in_front_of_the_listener():
    site = Site({"/": (200, {"cf-ray": "8a1b2c3d4e5f6a7b-FRA", "server": "cloudflare"}, "home" * 100)})
    comps = named(run(site), "edge")
    assert ("Cloudflare", "/") in comps and comps[("Cloudflare", "/")]["product_status"] == "identified"


def test_the_request_budget_bounds_the_run():
    site = proxy_with_jenkins_and_grafana()
    result = run(site, limit=7)
    assert result.requests == 7 == len(site.requests)
    assert result.budget_exhausted


def test_ceiling_covers_three_bases_and_every_mount():
    site = Site(fallback=lambda path: (200, {"content-type": "text/html"}, f"<html>{path}" + "z" * 50 * len(path) + "</html>"))
    result = run(site, bases=("/", "/app/", "/other/", "/fourth/"))
    assert not result.budget_exhausted
    assert result.bases[:3] == ["/", "/app/", "/other/"]


@pytest.mark.parametrize("value", ["/../x/", "/a b/", "relative/", "/" + "a/" * 6, "/a\n/"])
def test_base_paths_are_plain(value):
    assert wi.base_path(value) is None


def test_the_roots_relative_redirect_names_the_application_base():
    site = proxy_with_jenkins_and_grafana()
    site.routes["/"] = (302, {"location": "/jenkins/login?from=%2F"}, "")
    result = run(site)
    assert "/jenkins/" in result.bases[:2]
    assert ("Jenkins", "/jenkins/") in named(result, "application")


def test_the_scan_report_lists_recipe_components_as_sanitized_claims():
    from api.scan.finalizer import _posture_sections

    result = run(proxy_with_jenkins_and_grafana())
    rows = [{**item, "kind": "http_component", "url": "https://app.example.test" + item["base_path"]}
            for item in result.components]
    rows.append({"kind": "http_component", "role": "application", "base_path": "/", "product_key": "evil",
                 "product": "<b>x</b>", "product_status": "identified", "basis": "recipe"})
    section = _posture_sections({"discover.identify": rows})["discovery"]["web_components"]
    products = {(item["product"], item["base_path"]) for item in section["items"]}
    assert ("Jenkins", "/jenkins/") in products and ("Grafana", "/grafana/") in products
    assert not any("<" in item["product"] for item in section["items"])
