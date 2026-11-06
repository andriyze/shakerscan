"""Several components per listener: upgrade of retained data, provenance, freshness and
applicability (unit fixtures; hostile observation values included)."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from api.exposure.service_inventory import build_inventory, normalized_observation
from api.exposure.service_intel import enrich_service
from scanner.scanner_tools import device_advisories

ROOT = Path(__file__).resolve().parent
NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)
TARGET = {"id": "11111111-1111-4111-8111-111111111111", "kind": "web", "locator": "https://app.example.test"}
LEGACY_KEYS = (
    "id", "target_id", "target_kind", "evidence", "history", "evidence_truncated", "first_seen_at",
    "identity_observed_at", "address", "transport", "port", "application_origin", "state", "service",
    "product", "version", "cpes", "identity_basis", "detection_method", "detection_confidence",
    "encrypted", "tunnel", "last_seen_at", "observation_status", "freshness", "identity_stale",
    "presence", "binding_status",
)


def source(ref, when, *rows):
    return {"ref": ref, "observed_at": when, "status": "success", "observations": list(rows)}


def recipe(base="/jenkins/", key="jenkins", version="2.401.3", **extra):
    return {"kind": "http_component", "url": f"https://app.example.test{base}", "status": 200,
            "connected_address": "192.0.2.10", "role": "application", "base_path": base,
            "product_key": key, "product": "ignored", "product_status": "identified",
            "version": version, "version_status": "reported" if version else "unknown",
            "basis": "recipe", "recipe": key, "recipe_version": f"web-identity/v1:{key}@1",
            "signals": ["header:x-jenkins"], "product_source_field": "recipe.header:x-jenkins",
            "version_source_field": "response.header.x-jenkins", **extra}


def by_role(service):
    return {(c["role"], c["product"], c["base_path"]): c for c in service["components"]}


def test_inventory_written_by_2_11_5_keeps_ids_evidence_and_history_and_gains_components():
    fixture = json.loads((ROOT / "fixtures/service_inventory/inventory_2_11_5.json").read_text())
    services, rejected = build_inventory(fixture["target"], fixture["sources"], now=NOW)
    assert rejected == 0
    assert [s["id"] for s in services] == [s["id"] for s in fixture["services"]]
    for new, old in zip(services, fixture["services"]):
        assert {k: new[k] for k in LEGACY_KEYS} == {k: old[k] for k in LEGACY_KEYS}
    web = next(s for s in services if s["address"] is None)
    components = by_role(web)
    server = components[("web_server", "Apache HTTP Server", "/")]
    assert server["version"] == "2.4.58" and server["version_status"] == "reported"
    assert server["distribution"] == "ubuntu" and server["package_version"] == "2.4.58 (Ubuntu)"
    assert [c["kind"] for c in server["changes"]] == ["version_changed"]
    assert server["changes"][0]["from"] == "2.4.41" and server["changes"][0]["to"] == "2.4.58"
    jenkins = components[("application", "Jenkins", "/")]
    # A technology fingerprint names a probable product and an inferred version, never exact.
    assert jenkins["product_status"] == "probable" and jenkins["version_status"] == "inferred_range"
    ssh = next(s for s in services if s["port"] == 22)
    openssh, = ssh["components"]
    assert (openssh["role"], openssh["version"], openssh["distribution"]) == ("service", "8.2p1", "ubuntu")
    assert openssh["package_version"] == "8.2p1 Ubuntu 4ubuntu0.5"


def test_one_listener_carries_edge_server_and_applications_under_subpaths_each_with_evidence():
    fingerprint = {"kind": "http_fingerprint", "url": "https://app.example.test/", "status": 200,
                   "webserver": "cloudflare", "technologies": []}
    services, _ = build_inventory(TARGET, [
        source("scan:a:discover.web_probe", "2026-11-05T00:00:00Z", fingerprint),
        source("scan:a:discover.identify", "2026-11-05T00:01:00Z",
               recipe("/jenkins/"), recipe("/grafana/", key="grafana", version="10.2.3"),
               {**recipe("/", key="nginx", version="1.24.0"), "role": "web_server", "basis": "server_header",
                "recipe": None, "recipe_version": None}),
    ], now=NOW)
    edge_only = next(s for s in services if s["address"] is None)
    assert [(c["role"], c["product"]) for c in edge_only["components"]] == [("edge", "Cloudflare")]
    bound = next(s for s in services if s["address"] == "192.0.2.10")
    components = by_role(bound)
    assert set(components) == {("web_server", "nginx", "/"), ("application", "Jenkins", "/jenkins/"),
                               ("application", "Grafana", "/grafana/")}
    grafana = components[("application", "Grafana", "/grafana/")]
    claim = grafana["claims"]["version"]
    assert claim["recipe_version"] == "web-identity/v1:grafana@1"
    assert (claim["connected_address"], claim["host"], claim["sni"]) == ("192.0.2.10", "app.example.test", "app.example.test")
    assert claim["evidence_ref"] == "scan:a:discover.identify" and claim["observed_at"].startswith("2026-11-05")
    assert len({c["id"] for c in bound["components"]}) == 3
    # The unknown application at "/" is shown, not guessed.
    assert {"role": "application", "base_path": "/", "field": "product", "component_id": None,
            "reason": "no_identity_signal"} in bound["component_unknowns"]
    assert bound["product"] == "Grafana" or bound["product"] == "Jenkins"


@pytest.mark.parametrize("hostile", [
    {"product_key": "not-a-product"},
    {"base_path": "/../admin/"},
    {"base_path": "/a\nb/"},
    {"role": "kernel"},
    {"product_status": "certain"},
    {"basis": "llm_guess"},
    {"url": "javascript:alert(1)"},
    {"status": 999},
])
def test_hostile_component_observations_are_rejected(hostile):
    assert normalized_observation(recipe(**hostile)) is None


def test_labels_and_versions_never_come_from_target_text():
    item = normalized_observation(recipe(product="<script>Jenkins 99</script>", version="2.1;rm -rf /",
                                         signals=["header:x-jenkins", "bad\nsignal"]))
    component, = item["components"]
    assert component["product"] == "Jenkins"
    assert component["version"] is None and component["version_status"] == "unknown"
    assert component["signals"] == ["header:x-jenkins"]
    plugin = normalized_observation(recipe("/", key=None, version="5.1", role="plugin", basis="wordpress_plugin",
                                           product="WordPress plugin contact-form-7", recipe="wordpress",
                                           version_status="inferred_range"))
    assert plugin["components"][0]["advisory_product"] == "contact_form_7"
    assert normalized_observation(recipe("/", key=None, role="plugin", basis="wordpress_plugin",
                                         product="WordPress plugin ../../etc")) is None


def test_freshness_is_per_field_and_a_versionless_observation_keeps_the_reported_version():
    services, _ = build_inventory(TARGET, [
        source("scan:old", "2026-10-01T00:00:00Z", recipe("/jenkins/", version="2.401.3")),
        source("scan:new", "2026-11-05T00:00:00Z", recipe("/jenkins/", version=None)),
    ], now=NOW)
    jenkins, = services[0]["components"]
    assert jenkins["version"] == "2.401.3"
    assert jenkins["freshness"] == {"product": "recent", "version": "stale"}
    assert jenkins["claims"]["version"]["evidence_ref"] == "scan:old"
    assert jenkins["claims"]["product"]["evidence_ref"] == "scan:new"


def test_new_component_on_a_known_listener_is_a_material_change():
    services, _ = build_inventory(TARGET, [
        source("scan:1", "2026-11-01T00:00:00Z", recipe("/jenkins/")),
        source("scan:2", "2026-11-05T00:00:00Z", recipe("/jenkins/"), recipe("/grafana/", key="grafana", version="10.2.3")),
    ], now=NOW)
    components = by_role(services[0])
    assert components[("application", "Jenkins", "/jenkins/")]["changes"] == []
    assert components[("application", "Grafana", "/grafana/")]["changes"] == [
        {"kind": "new_component", "observed_at": "2026-11-05T00:00:00+00:00"}]


def _snapshot(*records):
    return {"status": "available", "advisories": list(records)}


def _advisory(cve, cpe, end, published="2026-01-01"):
    return {"cve": cve, "advisory_id": cve, "cpe": cpe, "product": cpe.split(":")[4],
            "version_end_excluding": end, "severity": "high", "published": published}


def _enriched(snapshot, *rows, when="2026-11-05T00:00:00Z"):
    services, _ = build_inventory(TARGET, [source("scan:x", when, *rows)], now=NOW)
    for service in services:
        enrich_service(service, snapshot, device_advisories.match_advisories)
    return services


def test_applicability_is_affected_only_for_a_reported_upstream_version_without_a_package_suffix():
    cpe = "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*"
    snapshot = _snapshot(_advisory("CVE-2026-1001", cpe, "2.500"), _advisory("CVE-2026-1002", cpe, "2.300"))
    service, = _enriched(snapshot, recipe("/jenkins/", version="2.401.3"))
    candidate, = service["cve_candidates"]
    assert (candidate["id"], candidate["applicability_status"], candidate["unresolved_reason"]) == ("CVE-2026-1001", "affected", None)
    assert candidate["component"]["base_path"] == "/jenkins/"
    assert service["components"][0]["advisories_not_affected"] == {"count": 1, "ids": ["CVE-2026-1002"]}
    assert service["advisory_follow_up"] == []


def test_inferred_versions_and_distribution_packages_stay_unresolved_with_only_the_missing_follow_up():
    snapshot = _snapshot(_advisory("CVE-2026-2001", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "2.4.60"),
                         _advisory("CVE-2026-2002", "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*", "2.500"))
    fingerprint = {"kind": "http_fingerprint", "url": "https://app.example.test/", "status": 200,
                   "webserver": "Apache/2.4.58 (Ubuntu)", "technologies": ["Jenkins:2.401.1"]}
    service, = _enriched(snapshot, fingerprint)
    reasons = {c["id"]: (c["applicability_status"], c["unresolved_reason"]) for c in service["cve_candidates"]}
    assert reasons == {"CVE-2026-2001": ("unresolved", "distribution_package"),
                       "CVE-2026-2002": ("unresolved", "product_probable")}
    needs = {(item["product"], item["need"]) for item in service["advisory_follow_up"]}
    assert needs == {("Apache HTTP Server", "package_fix_status"), ("Jenkins", "confirm_product")}


def test_a_changed_advisory_bundle_rematches_retained_inventory_and_flags_only_new_applicability():
    row = recipe("/jenkins/", version="2.401.3")
    cpe = "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*"
    before = _enriched(_snapshot(_advisory("CVE-2026-3001", cpe, "2.500")), row)[0]
    assert before["advisory_changes"] == []
    after = _enriched(_snapshot(_advisory("CVE-2026-3001", cpe, "2.500"),
                                _advisory("CVE-2026-3002", cpe, "2.450", published="2026-11-06")), row)[0]
    assert {c["id"]: c["new_since_observation"] for c in after["cve_candidates"]} == {
        "CVE-2026-3001": False, "CVE-2026-3002": True}
    assert [(c["kind"], c["advisory_id"]) for c in after["advisory_changes"]] == [("newly_applicable", "CVE-2026-3002")]


def test_hunt_projection_carries_http_components():
    item = normalized_observation({"kind": "service", "address": "192.0.2.10", "transport": "tcp", "port": 443,
                                   "state": "open", "service": "https", "method": "http_response",
                                   "web_origin": "https://app.example.test",
                                   "components": [normalized_observation(recipe())["components"][0], {"role": "x"}]})
    assert [c["product"] for c in item["components"]] == ["Jenkins"]


def test_network_component_keeps_the_announced_build_suffix_for_backport_aware_matching():
    item = normalized_observation({"kind": "service", "address": "192.0.2.10", "transport": "tcp", "port": 22,
                                   "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9p1",
                                   "version_reported": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "method": "probed"})
    component, = item["components"]
    assert (component["version"], component["package_version"], component["distribution"]) == (
        "8.9p1", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "ubuntu")
