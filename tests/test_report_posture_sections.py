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
                # The capability builds this inside the response summary. An earlier
                # version of this fixture put it at the observation root, which is a
                # shape production never emits -- so the test passed while real reports
                # carried an empty cookie list.
                "set_cookie_metadata": [{"secure": True, "httponly": True, "samesite": "lax"}],
            },
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
            "certificate_public_key_bits": 2048,
            "certificate_public_key_type": "RSAPublicKey",
            "certificate_signature_hash": "sha256",
            "certificate_signature_algorithm": "1.2.840.113549.1.1.11",
        }],
        "discover.web_probe": [{
            "kind": "http_fingerprint", "webserver": "nginx",
            # The probe emits plain strings, not objects. An earlier fixture used
            # objects, which took a different branch than production ever does.
            "technologies": ["React", "HTTP/3"],
        }],
    }
    base.update(overrides)
    return base


def test_security_headers_are_reported_with_what_is_missing():
    sections = _posture_sections(_observations())
    http = sections["http"]
    # Keyed as the report contract names them, not as the wire header spells them.
    assert http["security_headers"]["x_frame_options"] == "DENY"
    assert "referrer_policy" not in http["security_headers"]
    # The raw capture stays available alongside the projection.
    assert http["observed_headers"]["x-frame-options"] == "DENY"
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
    # Subject renders as the common name; the full DN stays under subject_dn.
    assert tls["certificate"]["subject"] == "target.test"
    assert tls["certificate"]["subject_dn"] == "CN=target.test"
    # The documented reader-facing names are present alongside the X.509 ones.
    assert tls["certificate"]["key_size"] == 2048
    assert tls["certificate"]["key_algo"] == "RSAPublicKey"
    assert tls["certificate"]["sig_algo"] == "sha256"
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


def test_cookie_posture_is_read_from_the_response_summary():
    """The observation root never carries it; reading there yields a silent empty list."""
    obs = _observations()
    root_shaped = dict(obs["baseline.http"][0])
    response = dict(root_shaped["response"])
    root_shaped["set_cookie_metadata"] = response.pop("set_cookie_metadata")
    root_shaped["response"] = response
    obs["baseline.http"] = [root_shaped]

    assert _posture_sections(obs)["http"]["set_cookie_metadata"] == []


def test_an_absent_csp_is_reported_missing_not_graded_zero():
    """A scoring card reading "/100" for a policy that does not exist states nothing."""
    obs = _observations()
    http = dict(obs["baseline.http"][0])
    response = dict(http["response"])
    headers = dict(response["security_headers"])
    headers.pop("content-security-policy")
    response["security_headers"] = headers
    http["response"] = response
    obs["baseline.http"] = [http]

    section = _posture_sections(obs)["http"]
    assert "csp_evaluation" not in section
    assert "content-security-policy" in section["missing_security_headers"]


def test_a_present_csp_is_still_graded():
    section = _posture_sections(_observations())["http"]
    assert section["csp_evaluation"]["grade"]


def test_observed_technologies_carry_a_label_not_an_invented_percentage():
    items = _posture_sections(_observations())["discovery"]["tech"]["items"]
    assert items, "the fixture should produce technologies"
    assert {item["name"] for item in items} == {"React", "HTTP/3", "nginx"}
    for item in items:
        assert "confidence" not in item, "the probe assigns no numeric confidence"
        assert item["confidence_label"] == "observed"
