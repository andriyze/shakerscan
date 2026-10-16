"""Corporate application and edge-appliance leads from passive evidence (unit fixtures)."""

from __future__ import annotations

from pathlib import Path

from scanner.scanner_tools import corporate_identity as ci
from api.exposure import service_intel
from api.exposure.service_inventory import normalized_observation
from api.scan.finalizer import _posture_sections

ROOT = Path(__file__).resolve().parents[1]


def _fingerprint(**extra):
    return {"kind": "http_fingerprint", "url": "https://ci.example.test/", "status": 200, **extra}


def test_technology_name_and_exact_version_become_a_lead_with_cpes():
    leads = ci.identities_from_fingerprint(_fingerprint(technologies=["Jenkins:2.401.1", "Java"]))
    assert [lead["product"] for lead in leads] == ["Jenkins"]
    lead = leads[0]
    assert lead["version"] == "2.401.1"
    assert lead["status"] == "lead" and lead["applicability"] == "unconfirmed"
    assert lead["cpes"] == ["cpe:2.3:a:jenkins:jenkins:2.401.1:*:*:*:*:*:*:*"]
    assert lead["origin"] == "https://ci.example.test"


def test_free_text_suffix_is_never_a_version():
    assert ci.split_technology("Jenkins:latest") == ("Jenkins:latest", None)
    assert ci.version_text("2.4.x") is None
    assert ci.version_text("15.2.1118.7") == "15.2.1118.7"
    assert ci.identities_from_fingerprint(_fingerprint(technologies=["Jenkins:latest"])) == []


def test_products_without_one_to_one_cpe_get_a_version_but_no_cpe():
    # Exchange build numbers do not map onto NVD's cumulative-update product names.
    lead = ci.identities_from_fingerprint(
        _fingerprint(technologies=["Outlook Web App:15.2.1118.7"]))[0]
    assert lead["version"] == "15.2.1118.7"
    assert lead["cpes"] == []


def test_titles_must_match_whole_anchored_product_titles():
    assert [lead["product"] for lead in ci.identities_from_fingerprint(
        _fingerprint(title="GlobalProtect Portal"))] == ["Palo Alto Networks GlobalProtect"]
    assert ci.identities_from_fingerprint(_fingerprint(title="Blog about GlobalProtect Portal")) == []
    assert ci.identities_from_fingerprint(_fingerprint(title="My Grafana dashboards")) == []


def _hit(path, status=200, length=500, origin="https://www.example.test", control=False):
    row = {"kind": "content_discovery", "url": f"{origin}{path}", "status": status, "length": length}
    if control:
        row["negative_control"] = True
    return row


def test_path_marker_needs_a_distinguishable_negative_control():
    controls = [_hit(f"/.shakerscan-absent-{index:016x}", 404, 10, control=True) for index in range(3)]
    leads, controlled = ci.identities_from_content_discovery([*controls, _hit("/remote/login")])
    assert [lead["product"] for lead in leads] == ["Fortinet FortiGate SSL VPN"]
    assert leads[0]["basis"] == ["path_marker"] and controlled == 0
    # Without any measured absent answer nothing is claimed.
    leads, controlled = ci.identities_from_content_discovery([_hit("/remote/login")])
    assert leads == [] and controlled == 1


def test_soft_404_host_produces_no_path_leads():
    origin = "https://soft.example.test"
    controls = [_hit(f"/.shakerscan-absent-{index:016x}", 200, 812, origin, True) for index in range(3)]
    hits = [_hit(path, 200, 812, origin) for path in ("/remote/login", "/owa/auth/logon.aspx")]
    leads, controlled = ci.identities_from_content_discovery([*controls, *hits])
    assert leads == [] and controlled == 2


def test_404_and_unknown_paths_are_not_leads():
    controls = [_hit(f"/.shakerscan-absent-{index:016x}", 404, 10, control=True) for index in range(3)]
    leads, _ = ci.identities_from_content_discovery([*controls, _hit("/remote/login", 404, 20),
                                                     _hit("/not-a-product", 200)])
    assert leads == []


def test_report_section_lists_bounded_unconfirmed_leads():
    sections = _posture_sections({
        "discover.web_probe": [_fingerprint(technologies=["Kibana:7.17.9"], title="Kibana")],
        "discover.web_content": [
            *[_hit(f"/.shakerscan-absent-{index:016x}", 404, 10, control=True) for index in range(3)],
            _hit("/dana-na/auth/url_default/welcome.cgi", 200, 900),
        ],
    })
    surface = sections["discovery"]["corporate_surface"]
    assert surface["scope"] == "unconfirmed_leads"
    by_product = {item["product"]: item for item in surface["items"]}
    assert by_product["Kibana"]["version"] == "7.17.9"
    assert set(by_product["Kibana"]["basis"]) == {"technology", "page_title"}
    assert by_product["Ivanti Connect Secure (Pulse Secure)"]["basis"] == ["path_marker"]


def test_service_inventory_takes_the_corporate_version_and_cpes_follow():
    observation = normalized_observation(_fingerprint(
        technologies=["Kibana:7.17.9"], webserver="nginx", pinned_address="192.0.2.10"))
    assert observation["product"] == "Kibana" and observation["version"] == "7.17.9"
    assert service_intel.derived_cpes("Kibana", "7.17.9") == [
        "cpe:2.3:a:elastic:kibana:7.17.9:*:*:*:*:*:*:*"]
    # A versioned Server banner still wins over a version-less corporate lead.
    observation = normalized_observation(_fingerprint(
        technologies=["Fortinet FortiGate"], webserver="nginx/1.25.3", pinned_address="192.0.2.10"))
    assert (observation["product"], observation["version"]) == ("nginx", "1.25.3")
    assert service_intel.derived_cpes("Microsoft Outlook Web App", "15.2.1118.7") == []


def test_corporate_wordlist_is_authored_and_carries_every_catalogue_path():
    lines = (ROOT / "scanner/wordlists/corporate.txt").read_text().splitlines()
    assert lines[0].startswith("# ShakerScan corporate content-discovery list")
    entries = [line for line in lines if line and not line.startswith("#")]
    assert len(entries) == len(set(entries))
    assert [path.lstrip("/") for path in ci.catalogue_paths()] == entries[:len(ci.catalogue_paths())]
    assert "actuator/heapdump" not in entries
