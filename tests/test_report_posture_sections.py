"""The report must carry the posture sections AGENTS.md documents.

V2's report contained only score and grade. `result.tls.certificate`,
`result.http.security_headers`, `result.dns` and `result.discovery.tech.items` -- all documented,
all present in 0.8.18 -- silently disappeared. The data was never lost: the baseline HTTP, TLS, DNS
and probe actions all recorded it and the finalizer simply never projected it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from scan.finalizer import _evaluate_csp, _posture_sections  # noqa: E402


def _observations(**overrides):
    base = {
        "baseline.http": [{
            "kind": "http_observation",
            "response": {
                "status": 200, "http_version": "HTTP/1.1", "content_type": "text/html",
                "security_headers": {
                    "strict-transport-security": "max-age=31536000",
                    "x-frame-options": "DENY",
                    "content-security-policy": "default-src 'self'; object-src 'none'",
                },
            },
            "set_cookie_metadata": [{"secure": True, "httponly": True, "samesite": "lax"}],
        }],
        "baseline.dns": [{
            "kind": "dns_posture",
            "records": {"host_caa": [], "dmarc": []},
            "query_count": 8,
            "bound_addresses": {"A": ["192.0.2.10"]},
            "errors": [],
        }],
        # The real observation shape: kind `tls_protocol`, certificate facts as flat fields.
        "baseline.tls": [{
            "kind": "tls_protocol", "status": "success", "port": 443,
            "protocol": "TLSv1.3", "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
            "cipher_bits": 128, "weak_cipher": False, "alpn_protocol": "h2",
            "certificate_issuer": "CN=Test CA",
            "certificate_subject": "CN=target.test",
            "certificate_not_after": "2026-11-03T19:41:03+00:00",
            "certificate_expired": False,
            "certificate_trust": "trusted",
        }],
        "discover.web_probe": [{
            "kind": "http_fingerprint", "webserver": "nginx",
            "technologies": [{"name": "React", "version": "18"}],
        }],
    }
    base.update(overrides)
    return base


def test_security_headers_are_reported_with_what_is_missing():
    sections = _posture_sections(_observations())
    http = sections["http"]
    assert http["security_headers"]["x-frame-options"] == "DENY"
    # The report should say what is absent, not only what is present.
    assert "referrer-policy" in http["missing_security_headers"]
    assert "x-frame-options" not in http["missing_security_headers"]
    assert http["set_cookie_metadata"][0]["httponly"] is True


def test_the_certificate_section_is_projected():
    tls = _posture_sections(_observations())["tls"]
    assert tls["protocol"] == "TLSv1.3"
    assert tls["cipher_bits"] == 128
    # Flat `certificate_*` fields are gathered under the documented `certificate` path.
    assert tls["certificate"]["issuer"] == "CN=Test CA"
    assert tls["certificate"]["subject"] == "CN=target.test"
    assert tls["certificate"]["expired"] is False
    assert "certificate_issuer" not in tls, "the flat form should not leak alongside the nested one"


def test_a_successful_handshake_is_preferred_over_a_failed_one():
    obs = _observations()
    obs["baseline.tls"] = [
        {"kind": "tls_protocol", "status": "failed", "origin": "https://a.test/"},
        {"kind": "tls_protocol", "status": "success", "origin": "https://b.test/",
         "protocol": "TLSv1.3"},
    ]
    assert _posture_sections(obs)["tls"]["origin"] == "https://b.test/"


def test_dns_posture_is_projected():
    dns = _posture_sections(_observations())["dns"]
    assert dns["query_count"] == 8
    assert dns["bound_addresses"]["A"] == ["192.0.2.10"]


def test_technologies_are_collected_without_duplicates():
    obs = _observations()
    obs["discover.web_probe"].append(obs["discover.web_probe"][0])
    items = _posture_sections(obs)["discovery"]["tech"]["items"]
    names = [item["name"] for item in items]
    assert names.count("React") == 1
    assert "nginx" in names


def test_a_section_with_no_observations_is_omitted_not_faked():
    # An http-only target has no TLS action, and reporting an empty certificate would imply one was
    # inspected.
    obs = _observations()
    obs.pop("baseline.tls")
    sections = _posture_sections(obs)
    assert "tls" not in sections
    assert "http" in sections


def test_an_absent_csp_is_not_a_failing_grade():
    # No policy and a broken policy are different findings; conflating them misreports both.
    absent = _evaluate_csp(None)
    assert absent["present"] is False
    assert absent["grade"] is None


def test_a_permissive_csp_is_graded_down_with_reasons():
    weak = _evaluate_csp("default-src *; script-src 'unsafe-inline' 'unsafe-eval'")
    assert weak["present"] is True
    assert weak["grade"] in {"C", "D", "F"}
    assert any("unsafe-inline" in issue for issue in weak["issues"])
    assert any("unsafe-eval" in issue for issue in weak["issues"])


def test_a_strict_csp_grades_well():
    strong = _evaluate_csp("default-src 'self'; object-src 'none'; script-src 'self'")
    assert strong["grade"] == "A"
    assert strong["issues"] == []


def test_projection_is_pure():
    # Finalization performs no network, filesystem or clock access; the projection must not either.
    import inspect

    source = inspect.getsource(_posture_sections)
    for forbidden in ("requests", "urlopen", "socket", "open(", "datetime.now", "time."):
        assert forbidden not in source, forbidden
