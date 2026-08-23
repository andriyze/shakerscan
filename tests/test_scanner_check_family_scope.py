import asyncio
import importlib.util
import inspect
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
_added_scanner_dir = False
if _SCANNER_DIR not in sys.path:
    sys.path.insert(0, _SCANNER_DIR)
    _added_scanner_dir = True

_spec = importlib.util.spec_from_file_location(
    "shaker_scanner_scope_under_test", os.path.join(_SCANNER_DIR, "scanner.py")
)
scanner_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner_mod)
from findings import apply_dast_precision_policy
from scanner_tools.finding_validator import (
    apply_validation_to_finding,
    validate_finding,
)
if _added_scanner_dir:
    sys.path.remove(_SCANNER_DIR)


def _template_placement_summary():
    return {
        "schema_version": "canonical-scan-template-execution/v1",
        "capability_name": "templates.scan",
        "enabled": True,
        "status": "success",
        "reason": None,
        "observations": [{
            "kind": "template_match",
            "template_id": "example-cve",
            "name": "Example CVE",
            "severity": "high",
            "matched_at": "https://app.example.test/account",
            "matcher_name": "body",
            "proof_state": "candidate",
        }],
        "observation_count": 1,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {"http_requests": 3, "tool_wall_seconds": 2},
        "receipt": {"receipt_hash": "c" * 64},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _web_probe_placement_summary():
    return {
        "schema_version": "canonical-scan-web-probe-execution/v1",
        "capability_name": "web.probe",
        "enabled": True,
        "status": "success",
        "reason": None,
        "observations": [{
            "kind": "http_fingerprint",
            "url": "https://app.example.test/",
            "status": 200,
            "title": "Example",
            "webserver": "nginx",
            "technologies": ["nginx"],
        }],
        "observation_count": 1,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {"http_requests": 1, "tool_wall_seconds": 1},
        "receipt": {"receipt_hash": "d" * 64},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _web_crawl_placement_summary():
    return {
        "schema_version": "canonical-scan-web-crawl-execution/v1",
        "capability_name": "web.crawl",
        "enabled": True,
        "status": "success",
        "reason": None,
        "observations": [{
            "kind": "discovered_route",
            "url": "https://app.example.test/api/orders",
            "method": "GET",
            "source": "https://app.example.test/",
        }],
        "observation_count": 1,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {"http_requests": 2, "tool_wall_seconds": 2},
        "receipt": {"receipt_hash": "e" * 64},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _content_discovery_placement_summary():
    return {
        "schema_version": "canonical-scan-content-discovery-execution/v1",
        "capability_name": "web.content_discover",
        "enabled": True,
        "status": "success",
        "reason": None,
        "observations": [{
            "kind": "content_discovery",
            "url": "https://app.example.test/admin",
            "status": 403,
            "length": 120,
            "redirect_location": None,
        }],
        "observation_count": 1,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {"http_requests": 2, "tool_wall_seconds": 2},
        "receipt": {"receipt_hash": "f" * 64},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _tls_placement_summary():
    return {
        "schema_version": "canonical-scan-tls-inspection-execution/v1",
        "capability_name": "tls.inspect",
        "enabled": True,
        "status": "success",
        "reason": None,
        "observations": [{
            "kind": "tls_protocol",
            "origin": "https://app.example.test",
            "server_hostname": "app.example.test",
            "pinned_address": "192.0.2.10",
            "port": 443,
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "alpn_protocol": "h2",
            "certificate_sha256": "7" * 64,
            "certificate_bytes": 11,
        }],
        "observation_count": 1,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {
            "tcp_ports_attempted": 1,
            "tool_wall_seconds": 1,
        },
        "receipt": {"receipt_hash": "6" * 64},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _http_baseline_placement_summary():
    return {
        "schema_version": "canonical-scan-http-baseline-execution/v1",
        "capability_name": "http.request",
        "enabled": True,
        "status": "success",
        "reason": None,
        "observations": [{
            "kind": "http_observation",
            "request": {
                "method": "HEAD",
                "origin": "https://app.example.test",
                "path": "/",
                "pinned_address": "192.0.2.10",
                "follow_redirects": True,
            },
            "response": {
                "status": 200,
                "http_version": "HTTP/2",
                "final_url": "https://app.example.test/home",
                "selected_headers": {
                    "server": "nginx",
                    "strict-transport-security": "max-age=31536000",
                    "alt-svc": 'h3=":443"',
                },
                "set_cookie_metadata": [{
                    "secure": True,
                    "httponly": True,
                    "samesite": "lax",
                }],
            },
            "redirect_chain": [{
                "status": 302,
                "location": "/home",
                "followed": True,
            }],
        }],
        "observation_count": 1,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {"http_requests": 2, "tool_wall_seconds": 1},
        "receipt": {"receipt_hash": "5" * 64},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _http_redirect_placement_summary():
    return {
        "schema_version": "canonical-scan-http-redirect-execution/v1",
        "capability_name": "http.request",
        "enabled": True,
        "status": "success",
        "reason": None,
        "observations": [{
            "kind": "http_observation",
            "request": {
                "method": "HEAD",
                "origin": "http://app.example.test",
                "path": "/",
                "pinned_address": "192.0.2.10",
                "follow_redirects": True,
            },
            "response": {
                "status": 200,
                "http_version": "HTTP/1.1",
                "final_url": "https://app.example.test/home",
                "selected_headers": {"server": "nginx"},
                "set_cookie_metadata": [],
            },
            "redirect_chain": [{
                "status": 301,
                "location": "https://app.example.test/home",
                "followed": True,
            }],
        }],
        "observation_count": 1,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {"http_requests": 2, "tool_wall_seconds": 1},
        "receipt": {"receipt_hash": "4" * 64},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _security_txt_placement_summary():
    return {
        "schema_version": "canonical-scan-security-txt-execution/v1",
        "capability_name": "http.request",
        "enabled": True,
        "status": "success",
        "reason": None,
        "observations": [{
            "kind": "http_observation",
            "request": {
                "method": "GET",
                "origin": "https://app.example.test",
                "path": "/.well-known/security.txt",
                "pinned_address": "192.0.2.10",
                "follow_redirects": True,
            },
            "response": {
                "status": 200,
                "http_version": "HTTP/2",
                "final_url": (
                    "https://app.example.test/.well-known/security.txt"
                ),
                "selected_headers": {},
                "set_cookie_metadata": [],
                "security_txt": {
                    "present": True,
                    "url": (
                        "https://app.example.test/.well-known/security.txt"
                    ),
                    "sample": "Contact: mailto:security@example.test",
                },
            },
            "redirect_chain": [],
        }],
        "observation_count": 1,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {"http_requests": 1, "tool_wall_seconds": 1},
        "receipt": {"receipt_hash": "3" * 64},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _dns_placement_summary():
    host = "app.example.test"
    labels = {
        "host_cname": host,
        "host_mx": host,
        "host_txt": host,
        "host_caa": host,
        "host_dnskey": host,
        "dmarc": f"_dmarc.{host}",
        "tls_rpt": f"_smtp._tls.{host}",
        "mta_sts": f"_mta-sts.{host}",
    }
    return {
        "schema_version": "canonical-scan-dns-inspection-execution/v1",
        "capability_name": "dns.inspect",
        "enabled": True,
        "status": "success",
        "reason": None,
        "observations": [{
            "kind": "dns_posture",
            "canonical_host": host,
            "bound_addresses": {"A": ["192.0.2.10"], "AAAA": []},
            "query_names": labels,
            "records": {
                "host_cname": [],
                "host_mx": [{"priority": 10, "host": "mail.example.test"}],
                "host_txt": ["v=spf1 -all"],
                "host_caa": [{
                    "flags": 0, "tag": "issue", "value": "ca.test",
                }],
                "host_dnskey": [{
                    "flags": 257, "protocol": 3, "algorithm": 13,
                }],
                "dmarc": ["v=DMARC1; p=reject; rua=mailto:d@example.test"],
                "tls_rpt": [
                    "v=TLSRPTv1; rua=mailto:tls@example.test",
                ],
                "mta_sts": ["v=STSv1; id=20260822"],
            },
            "authenticated_queries": ["host_dnskey"],
            "query_count": 8,
            "errors": [],
        }],
        "observation_count": 1,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {"hosts_attempted": 4, "tool_wall_seconds": 1},
        "receipt": {"receipt_hash": "2" * 64},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _xss_verification_placement_summary():
    return {
        "schema_version": "canonical-scan-xss-verification-execution/v1",
        "capability_name": "xss.verify",
        "enabled": True,
        "status": "success",
        "reason": None,
        "observations": [{
            "kind": "xss_alert",
            "alert_type": "V",
            "url": "https://app.example.test/search?q=%3Credacted%3E",
            "param": "q",
            "payload_sha256": "a" * 64,
            "message": "verified alert",
            "proof_state": "verified",
        }],
        "observation_count": 1,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {"http_requests": 2, "tool_wall_seconds": 2},
        "receipt": {"receipt_hash": "9" * 64},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _sqli_verification_placement_summary():
    return {
        "schema_version": "canonical-scan-sqli-verification-execution/v1",
        "capability_name": "sqli.verify",
        "enabled": True,
        "status": "success",
        "reason": None,
        "observations": [{
            "kind": "sqli_finding",
            "url": "https://app.example.test/search?q=%3Credacted%3E",
            "method": "GET",
            "param": "q",
            "message": "Parameter 'q' is vulnerable.",
            "proof_state": "candidate",
        }, {
            "kind": "sqli_dbms_fingerprint",
            "url": "https://app.example.test/search?q=%3Credacted%3E",
            "method": "GET",
            "message": "[INFO] back-end DBMS: PostgreSQL",
            "proof_state": "candidate",
        }],
        "observation_count": 2,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {"http_requests": 2, "tool_wall_seconds": 2},
        "receipt": {"receipt_hash": "8" * 64},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def test_canonical_sqli_verification_is_bound_and_stays_suspected(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
    }
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            **execution,
            "capabilities": {
                "sqli.verify": _sqli_verification_placement_summary(),
            },
        }),
    )

    placements = scanner_mod._load_canonical_scan_placements(execution)
    observations = scanner_mod._canonical_sqli_observations(
        placements["sqli.verify"]
    )

    assert observations[0] == {
        "url": "https://app.example.test/search?q=%3Credacted%3E",
        "method": "GET",
        "param": "q",
        "message": "Parameter 'q' is vulnerable.",
        "kind": "sqli_finding",
        "proof_state": "candidate",
        "canonical_capability": "sqli.verify",
    }
    findings = scanner_mod._canonical_sqli_findings(
        placements["sqli.verify"]
    )
    assert len(findings) == 1
    assert findings[0]["tool"] == "sqlmap"
    assert findings[0]["cwe"] == "CWE-89"
    assert findings[0]["evidence"]["capability_receipt"]["receipt_hash"] == (
        "8" * 64
    )
    validated = apply_validation_to_finding(
        findings[0], validate_finding(findings[0], ""),
    )
    [suspected] = apply_dast_precision_policy([validated])
    assert suspected["verified"] is False
    assert suspected["needs_verification"] is True
    assert suspected["proof_state"] == "likely_vulnerable"
    assert "proof_contract_v2" not in suspected
    assert suspected["registry_contract"]["contract_satisfied"] is False
    assert {"payload", "response_delta"}.issubset(
        suspected["registry_contract"]["proof_fields_missing"]
    )


def test_canonical_xss_verification_is_bound_and_adapted(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
    }
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            **execution,
            "capabilities": {"xss.verify": _xss_verification_placement_summary()},
        }),
    )

    placements = scanner_mod._load_canonical_scan_placements(execution)
    observations = scanner_mod._canonical_xss_observations(
        placements["xss.verify"]
    )

    assert observations == [{
        "url": "https://app.example.test/search?q=%3Credacted%3E",
        "type": "V",
        "param": "q",
        "message": "verified alert",
        "payload_sha256": "a" * 64,
        "proof_state": "verified",
        "canonical_capability": "xss.verify",
    }]
    findings = scanner_mod._canonical_xss_findings(placements["xss.verify"])
    assert len(findings) == 1
    assert findings[0]["tool"] == "dalfox"
    assert findings[0]["cwe"] == "CWE-79"
    assert findings[0]["evidence"]["capability_receipt"]["receipt_hash"] == (
        "9" * 64
    )
    validated = apply_validation_to_finding(
        findings[0], validate_finding(findings[0], ""),
    )
    [promoted] = apply_dast_precision_policy([validated])
    assert promoted["verified"] is True
    assert promoted["proof_state"] == "exploited"
    assert promoted["proof_contract_v2"]["promotable"] is True


def test_canonical_xss_candidate_never_becomes_a_finding():
    summary = _xss_verification_placement_summary()
    summary["observations"][0]["proof_state"] = "candidate"

    assert scanner_mod._canonical_xss_findings(summary) == []


def test_canonical_content_discovery_is_bound_and_adapted(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
    }
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            **execution,
            "capabilities": {
                "web.content_discover": _content_discovery_placement_summary(),
            },
        }),
    )

    placements = scanner_mod._load_canonical_scan_placements(execution)
    observations = scanner_mod._canonical_ffuf_observations(
        placements["web.content_discover"]
    )

    assert observations == [{
        "url": "https://app.example.test/admin",
        "status": 403,
        "length": 120,
        "redirect_location": None,
    }]


def test_canonical_tls_placement_is_bound_to_origin_and_address(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
        "target_binding": {
            "canonical_host": "app.example.test",
            "allowed_origins": ["https://app.example.test"],
            "allowed_addresses": ["192.0.2.10"],
        },
    }
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            "execution_plan_digest": execution["execution_plan_digest"],
            "target_binding_digest": execution["target_binding_digest"],
            "capabilities": {"tls.inspect": _tls_placement_summary()},
        }),
    )

    placements = scanner_mod._load_canonical_scan_placements(execution)
    assert placements["tls.inspect"]["observations"][0]["protocol"] == (
        "TLSv1.3"
    )

    tampered = _tls_placement_summary()
    tampered["observations"][0]["pinned_address"] = "192.0.2.99"
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            "execution_plan_digest": execution["execution_plan_digest"],
            "target_binding_digest": execution["target_binding_digest"],
            "capabilities": {"tls.inspect": tampered},
        }),
    )
    with pytest.raises(SystemExit, match="observation contract"):
        scanner_mod._load_canonical_scan_placements(execution)


def test_canonical_http_baseline_is_bound_and_adapted(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
        "target_binding": {
            "canonical_host": "app.example.test",
            "allowed_origins": ["https://app.example.test"],
            "allowed_addresses": ["192.0.2.10"],
        },
    }
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            "execution_plan_digest": execution["execution_plan_digest"],
            "target_binding_digest": execution["target_binding_digest"],
            "capabilities": {
                "http.request": _http_baseline_placement_summary(),
            },
        }),
    )

    placements = scanner_mod._load_canonical_scan_placements(execution)
    result = scanner_mod._canonical_http_baseline_result(
        placements["http.request"],
        base_url="https://app.example.test",
    )

    assert result["status"] == "HTTP/2 200"
    assert result["headers"]["server"] == ["nginx"]
    assert result["headers"]["set-cookie"] == [
        "redacted=1; Secure; HttpOnly; SameSite=Lax",
    ]
    assert result["redirect_chain"] == [
        "https://app.example.test/home",
    ]
    assert result["remote_ip"] == "192.0.2.10"
    assert result["advertises_h3"] is True


def test_canonical_http_protocol_posture_reuses_placed_evidence():
    assert scanner_mod._canonical_http_protocol_posture(
        _http_baseline_placement_summary(),
        _tls_placement_summary(),
    ) == (True, None)

    http3 = _http_baseline_placement_summary()
    http3["observations"][0]["response"]["http_version"] = "HTTP/3"
    assert scanner_mod._canonical_http_protocol_posture(
        http3, {"observations": []},
    ) == (False, True)
    assert scanner_mod._canonical_http_protocol_posture(None, None) == (
        False, None,
    )


def test_canonical_http_redirect_is_bound_and_adapted(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
        "target_binding": {
            "canonical_host": "app.example.test",
            "allowed_origins": [
                "https://app.example.test", "http://app.example.test",
            ],
            "allowed_addresses": ["192.0.2.10"],
        },
    }
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            "execution_plan_digest": execution["execution_plan_digest"],
            "target_binding_digest": execution["target_binding_digest"],
            "capabilities": {
                "http.request.scheme_redirect": (
                    _http_redirect_placement_summary()
                ),
            },
        }),
    )

    placements = scanner_mod._load_canonical_scan_placements(execution)
    result = scanner_mod._canonical_http_baseline_result(
        placements["http.request.scheme_redirect"],
        base_url="http://app.example.test",
    )

    assert result["status"] == "HTTP/1.1 200"
    assert result["final_url"] == "https://app.example.test/home"
    assert result["remote_ip"] == "192.0.2.10"


def test_canonical_http_redirect_rejects_unbound_http_origin(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
        "target_binding": {
            "canonical_host": "app.example.test",
            "allowed_origins": ["https://app.example.test"],
            "allowed_addresses": ["192.0.2.10"],
        },
    }
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            "execution_plan_digest": execution["execution_plan_digest"],
            "target_binding_digest": execution["target_binding_digest"],
            "capabilities": {
                "http.request.scheme_redirect": (
                    _http_redirect_placement_summary()
                ),
            },
        }),
    )

    with pytest.raises(SystemExit, match="observation contract"):
        scanner_mod._load_canonical_scan_placements(execution)


def test_canonical_security_txt_is_bound_and_adapted(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
        "target_binding": {
            "canonical_host": "app.example.test",
            "allowed_origins": ["https://app.example.test"],
            "allowed_addresses": ["192.0.2.10"],
        },
    }
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            "execution_plan_digest": execution["execution_plan_digest"],
            "target_binding_digest": execution["target_binding_digest"],
            "capabilities": {
                "http.request.security_txt": _security_txt_placement_summary(),
            },
        }),
    )

    placements = scanner_mod._load_canonical_scan_placements(execution)
    result = scanner_mod._canonical_security_txt_result(
        placements["http.request.security_txt"],
        base_url="https://app.example.test",
    )

    assert result == {
        "present": True,
        "url": "https://app.example.test/.well-known/security.txt",
        "sample": "Contact: mailto:security@example.test",
        "canonical_capability": "http.request",
        "capability_receipt": {"receipt_hash": "3" * 64},
    }


def test_canonical_security_txt_rejects_non_fixed_path(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
        "target_binding": {
            "canonical_host": "app.example.test",
            "allowed_origins": ["https://app.example.test"],
            "allowed_addresses": ["192.0.2.10"],
        },
    }
    tampered = _security_txt_placement_summary()
    tampered["observations"][0]["request"]["path"] = "/private"
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            "execution_plan_digest": execution["execution_plan_digest"],
            "target_binding_digest": execution["target_binding_digest"],
            "capabilities": {"http.request.security_txt": tampered},
        }),
    )

    with pytest.raises(SystemExit, match="observation contract"):
        scanner_mod._load_canonical_scan_placements(execution)


def test_canonical_pre_scan_uses_frozen_receipts_without_network():
    execution = {
        "target_binding": {
            "canonical_host": "app.example.test",
            "allowed_origins": ["https://app.example.test"],
            "allowed_addresses": ["192.0.2.10"],
        },
    }
    result = scanner_mod._canonical_pre_scan_validation(
        "https://app.example.test",
        execution,
        {
            "http.request": _http_baseline_placement_summary(),
            "tls.inspect": _tls_placement_summary(),
        },
    )

    assert result["can_proceed"] is True
    assert result["validation_attempts"] == 0
    assert result["validation_source"] == "canonical_capability_receipts"
    assert result["warnings"] == []
    assert result["connectivity"]["details"] == {
        "hostname": "app.example.test",
        "scheme": "https",
        "target_port": 443,
        "ip_addresses": ["192.0.2.10"],
        "http_status": 200,
        "http_url": "https://app.example.test/home",
        "target_port_open": True,
        "reachable_via": "canonical_http_receipt",
        "canonical_preflight": True,
    }


def test_canonical_pre_scan_fails_closed_without_settled_reachability():
    result = scanner_mod._canonical_pre_scan_validation(
        "https://app.example.test",
        {
            "target_binding": {
                "canonical_host": "app.example.test",
                "allowed_origins": ["https://app.example.test"],
                "allowed_addresses": ["192.0.2.10"],
            },
        },
        {},
    )

    assert result["can_proceed"] is False
    assert result["connectivity"]["http_ok"] is False
    assert result["warnings"] == [
        "Canonical preflight found no settled HTTP or TLS reachability evidence"
    ]


def test_canonical_dns_posture_is_bound_and_adapted(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
        "target_binding": {
            "canonical_host": "app.example.test",
            "allowed_origins": ["https://app.example.test"],
            "allowed_addresses": ["192.0.2.10"],
        },
    }
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            "execution_plan_digest": execution["execution_plan_digest"],
            "target_binding_digest": execution["target_binding_digest"],
            "capabilities": {"dns.inspect": _dns_placement_summary()},
        }),
    )

    placements = scanner_mod._load_canonical_scan_placements(execution)
    result = scanner_mod._canonical_dns_placement_result(
        placements["dns.inspect"], host="app.example.test",
    )

    assert result["dns"]["A"] == ["192.0.2.10"]
    assert result["dns"]["MX"] == [{
        "priority": 10, "host": "mail.example.test",
    }]
    assert result["dns"]["canonical_capability"] == "dns.inspect"
    assert result["dmarc"]["fields"]["p"] == "reject"
    assert result["dnssec"] == {"status": "secure", "algorithm": "13"}
    assert result["caa"]["records"] == ["0 issue ca.test"]
    assert result["tls_rpt"]["rua"] == "tls@example.test"
    assert result["mta_sts"]["record"] == "v=STSv1; id=20260822"
    assert result["mta_sts"]["policy_present"] is False
    assert result["mta_sts"]["reason"] == "mta_sts_policy_origin_not_bound"


def test_canonical_dns_posture_rejects_unbound_addresses(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
        "target_binding": {
            "canonical_host": "app.example.test",
            "allowed_origins": ["https://app.example.test"],
            "allowed_addresses": ["192.0.2.10"],
        },
    }
    tampered = _dns_placement_summary()
    tampered["observations"][0]["bound_addresses"]["A"] = ["192.0.2.99"]
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            "execution_plan_digest": execution["execution_plan_digest"],
            "target_binding_digest": execution["target_binding_digest"],
            "capabilities": {"dns.inspect": tampered},
        }),
    )

    with pytest.raises(SystemExit, match="observation contract"):
        scanner_mod._load_canonical_scan_placements(execution)


def test_canonical_report_assembly_never_repeats_base_header_request():
    source = inspect.getsource(scanner_mod.build_report)
    start = source.index("if canonical_scan_execution is not None:", source.index(
        "canonical_tls_task = None"
    ))
    head = source.index("head_task", start)
    redirect = source.index("http_redirect_task", head)
    baseline_block = source[head:redirect]

    assert "_canonical_http_baseline_result(" in baseline_block
    assert "else:" in baseline_block
    assert "curl_headers(base_url)" in baseline_block
    assert baseline_block.index("_canonical_http_baseline_result(") < (
        baseline_block.index("else:")
    ) < baseline_block.index("curl_headers(base_url)")


def test_canonical_report_assembly_never_repeats_http_redirect_request():
    source = inspect.getsource(scanner_mod.build_report)
    start = source.index("# Check HTTP->HTTPS redirect explicitly")
    end = source.index("if focused_scope.skip_posture():", start)
    redirect_block = source[start:end]

    assert 'get("http.request.scheme_redirect")' in redirect_block
    assert "_canonical_http_baseline_result(" in redirect_block
    assert "if canonical_scan_execution is not None:" in redirect_block
    assert "else:" in redirect_block
    assert 'curl_headers(f"http://{host}")' in redirect_block
    assert redirect_block.index("_canonical_http_baseline_result(") < (
        redirect_block.index("else:")
    ) < redirect_block.index('curl_headers(f"http://{host}")')


def test_canonical_report_assembly_reuses_protocol_evidence():
    source = inspect.getsource(scanner_mod.build_report)
    start = source.index(
        "if focused_scope.skip_posture():",
        source.index("# Check HTTP->HTTPS redirect explicitly"),
    )
    end = source.index("# Email/DNS security extras", start)
    posture_block = source[start:end]
    canonical_start = posture_block.index(
        "elif canonical_scan_execution is not None:"
    )
    legacy_start = posture_block.index("\n    else:", canonical_start)
    canonical_block = posture_block[canonical_start:legacy_start]

    assert "_canonical_http_protocol_posture(" in canonical_block
    assert "_canonical_security_txt_result(" in canonical_block
    assert "supports_http2(" not in canonical_block
    assert "supports_http3(" not in canonical_block
    assert "fetch_security_txt(" not in canonical_block
    assert "supports_http2(base_url)" in posture_block[legacy_start:]
    assert "supports_http3(base_url)" in posture_block[legacy_start:]
    assert "fetch_security_txt(base_url)" in posture_block[legacy_start:]


def test_canonical_report_assembly_reuses_pre_scan_evidence():
    source = inspect.getsource(scanner_mod.build_report)
    start = source.index("# Pre-scan connectivity validation")
    end = source.index('emit_progress("pre_scan", 10', start)
    preflight_block = source[start:end]
    canonical_start = preflight_block.index(
        "if canonical_scan_execution is not None:"
    )
    legacy_start = preflight_block.index("\n        else:", canonical_start)
    canonical_block = preflight_block[canonical_start:legacy_start]

    assert "_canonical_pre_scan_validation(" in canonical_block
    assert "pre_scan_validation(" not in canonical_block.replace(
        "_canonical_pre_scan_validation(", "",
    )
    assert "await pre_scan_validation(target)" in preflight_block[legacy_start:]


def test_canonical_report_assembly_uses_placed_dns_posture():
    source = inspect.getsource(scanner_mod.build_report)
    start = source.index("# parallel tasks (infra)")
    end = source.index("# New: IP Reputation", start)
    infra_block = source[start:end]
    canonical_start = infra_block.index(
        "if canonical_scan_execution is not None:"
    )
    focused_start = infra_block.index(
        "elif focused_scope.skip_posture():", canonical_start,
    )
    canonical_block = infra_block[canonical_start:focused_start]

    assert "_canonical_dns_placement_result(" in canonical_block
    assert "resolve_dns(" not in canonical_block
    assert "fetch_dmarc(" not in canonical_block
    assert "check_dnssec(" not in canonical_block
    assert "fetch_caa(" not in canonical_block
    assert "fetch_mta_sts(" not in canonical_block
    assert "fetch_tls_rpt(" not in canonical_block

    extras_start = infra_block.index("# Email/DNS security extras")
    extras_block = infra_block[extras_start:]
    extras_canonical = extras_block.index(
        "if canonical_dns_posture is not None:"
    )
    extras_focused = extras_block.index(
        "elif focused_scope.skip_posture():", extras_canonical,
    )
    extras_legacy = extras_block.index("\n    else:", extras_focused)
    placed_block = extras_block[extras_canonical:extras_focused]

    assert 'canonical_dns_posture["caa"]' in placed_block
    assert 'canonical_dns_posture["mta_sts"]' in placed_block
    assert 'canonical_dns_posture["tls_rpt"]' in placed_block
    assert "fetch_caa(" not in placed_block
    assert "fetch_mta_sts(" not in placed_block
    assert "fetch_tls_rpt(" not in placed_block
    assert "fetch_caa(host)" in extras_block[extras_legacy:]
    assert "fetch_mta_sts(host)" in extras_block[extras_legacy:]
    assert "fetch_tls_rpt(host)" in extras_block[extras_legacy:]


def test_canonical_web_crawl_placement_is_bound_and_adapted(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
    }
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            **execution,
            "capabilities": {"web.crawl": _web_crawl_placement_summary()},
        }),
    )

    placements = scanner_mod._load_canonical_scan_placements(execution)
    observations = scanner_mod._canonical_katana_observations(
        placements["web.crawl"]
    )

    assert observations == [{
        "url": "https://app.example.test/api/orders",
        "method": "GET",
        "source": "https://app.example.test/",
    }]


def test_canonical_web_probe_placement_is_bound_and_adapted(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
    }
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            **execution,
            "capabilities": {"web.probe": _web_probe_placement_summary()},
        }),
    )

    placements = scanner_mod._load_canonical_scan_placements(execution)
    rows = scanner_mod._canonical_httpx_rows(placements["web.probe"])

    assert rows == [{
        "url": "https://app.example.test/",
        "status_code": 200,
        "title": "Example",
        "webserver": "nginx",
        "tech": ["nginx"],
        "canonical_capability": "web.probe",
    }]


def test_canonical_template_placement_is_bound_and_adapted_to_candidates(
    monkeypatch,
):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
    }
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            **execution,
            "capabilities": {
                "templates.scan": _template_placement_summary(),
            },
        }),
    )

    placements = scanner_mod._load_canonical_scan_placements(execution)
    result = scanner_mod._canonical_nuclei_result(
        placements["templates.scan"]
    )

    assert result["scan_completed"] is True
    assert result["templates_used"] == 1
    assert result["vulnerabilities"][0] == {
        "template_id": "example-cve",
        "name": "Example CVE",
        "severity": "high",
        "matched_at": "https://app.example.test/account",
        "matcher_name": "body",
        "proof_state": "candidate",
        "tags": [],
        "cwe_ids": [],
    }
    assert result["canonical_capability"]["receipt"]["receipt_hash"] == (
        "c" * 64
    )


def test_canonical_template_placement_rejects_other_authority(monkeypatch):
    execution = {
        "execution_plan_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
    }
    monkeypatch.setenv(
        "SHAKERSCAN_CANONICAL_SCAN_PLACEMENTS",
        json.dumps({
            "schema_version": "canonical-scan-placements/v1",
            "execution_plan_digest": "d" * 64,
            "target_binding_digest": "b" * 64,
            "capabilities": {
                "templates.scan": _template_placement_summary(),
            },
        }),
    )

    with pytest.raises(SystemExit, match="do not match"):
        scanner_mod._load_canonical_scan_placements(execution)


def test_network_discovery_plan_is_permission_gated_even_for_deep_complete_mode():
    disabled = scanner_mod.resolve_network_discovery_plan(
        permitted=False, quick_mode=False, smart_mode=False, complete_mode=True,
        grpc_discovery=True, focused_manual_active_scope=False, exploit_level="aggressive",
    )
    assert disabled == (None, False)

    enabled = scanner_mod.resolve_network_discovery_plan(
        permitted=True, quick_mode=False, smart_mode=False, complete_mode=True,
        grpc_discovery=False, focused_manual_active_scope=False, exploit_level="safe",
    )
    assert enabled == ({"top_ports": 1000, "scripts": False}, True)


def test_check_family_scope_marks_focused_sqli():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=False,
        active_sqli=True,
        requested_family="sqli",
    )

    assert scope["mode"] == "focused"
    assert scope["focused"] is True
    assert scope["focused_family"] == "sqli"
    assert scope["families"] == ["sqli"]
    assert scope["source"] == "check_family"
    assert scope["requested_family"] == "sqli"
    assert scope["legacy_flags"] == {"xss": False, "sqli": True}


def test_check_family_scope_marks_focused_bola():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=False,
        active_sqli=False,
        requested_family="bola",
    )

    assert scope["mode"] == "focused"
    assert scope["focused"] is True
    assert scope["focused_family"] == "bola"
    assert scope["families"] == ["bola"]
    assert scope["source"] == "check_family"
    assert scope["requested_family"] == "bola"
    assert scope["legacy_flags"] == {"xss": False, "sqli": False}


def test_bola_candidate_budget_distinguishes_inventory_from_execution_ceiling():
    summary = scanner_mod.summarize_bola_candidate_budget(500, 300)

    assert summary == {
        "candidate_endpoints": 500,
        "max_endpoints": 300,
        "scheduled_endpoints_upper_bound": 300,
    }


def test_bola_candidate_budget_normalizes_invalid_or_negative_values():
    assert scanner_mod.summarize_bola_candidate_budget("invalid", -5) == {
        "candidate_endpoints": 0,
        "max_endpoints": 0,
        "scheduled_endpoints_upper_bound": 0,
    }


def test_check_family_scope_marks_focused_auth():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=False,
        active_sqli=False,
        requested_family="auth",
    )

    assert scope["mode"] == "focused"
    assert scope["focused"] is True
    assert scope["focused_family"] == "auth"
    assert scope["families"] == ["auth"]
    assert scope["source"] == "check_family"
    assert scope["requested_family"] == "auth"
    assert scope["legacy_flags"] == {"xss": False, "sqli": False}


def test_bola_resource_mapper_uses_manual_path_placeholders():
    endpoints = scanner_mod.normalize_manual_endpoints(
        "https://crapi.test",
        scanner_mod.parse_manual_endpoints([
            "GET /workshop/api/shop/orders/<orderId>?order_id=42&limit=1",
        ]),
    )

    resources = scanner_mod.bola_resource_endpoints_from_manual_endpoints(endpoints)

    assert resources[0]["path"] == "/workshop/api/shop/orders/{id}?order_id={id}&limit=1"
    assert resources[0]["ids"][:2] == ["42", "1"]


def test_bola_resource_mapper_uses_id_query_params_and_skips_posts():
    endpoints = scanner_mod.normalize_manual_endpoints(
        "https://api.test",
        scanner_mod.parse_manual_endpoints([
            "GET /api/orders?order_id=7&limit=1",
            "POST /api/orders json:{\"order_id\":7}",
        ]),
    )

    resources = scanner_mod.bola_resource_endpoints_from_manual_endpoints(endpoints)

    assert resources == [
        {"path": "/api/orders?order_id={id}&limit=1", "ids": ["7", "1", "2", "100", "999"]}
    ]


def test_check_family_scope_marks_normal_active_mix():
    scope = scanner_mod.build_check_family_scope(True, active_xss=True, active_sqli=True)

    assert scope["mode"] == "active_mix"
    assert scope["focused"] is False
    assert scope["focused_family"] is None
    assert scope["families"] == ["xss", "sqli"]


def test_check_family_scope_includes_legacy_mass_assignment_executor():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=True,
        active_sqli=True,
        mass_assignment=True,
    )

    assert scope["mode"] == "active_mix"
    assert scope["families"] == ["xss", "sqli", "mass_assignment"]


def test_check_family_scope_keeps_explicit_mass_assignment_without_global_active_flag():
    scope = scanner_mod.build_check_family_scope(
        False,
        active_xss=True,
        active_sqli=True,
        mass_assignment=True,
    )

    assert scope["families"] == ["mass_assignment"]
    assert scope["mode"] == "focused"
    assert scope["focused_family"] == "mass_assignment"


def test_check_family_scope_includes_automatic_advanced_jwt_executor():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=True,
        active_sqli=True,
        jwt=True,
    )

    assert scope["families"] == ["xss", "sqli", "jwt"]


def test_check_family_scope_plans_broad_smart_bola_without_legacy_override():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=True,
        active_sqli=True,
        jwt=True,
        bola=True,
    )
    plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="smart",
        public_only=False,
        quick_mode=False,
        active_checks=True,
        check_family_scope=scope,
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )
    families = {item["name"]: item for item in plan["families"]}

    assert scope["families"] == ["xss", "sqli", "jwt", "bola"]
    assert families["bola"]["enabled"] is True
    assert scanner_mod.registry_dispatch_enabled(plan, "bola") is True


def test_check_family_scope_marks_inactive_scan():
    scope = scanner_mod.build_check_family_scope(False, active_xss=True, active_sqli=True)

    assert scope["mode"] == "inactive"
    assert scope["focused"] is False
    assert scope["families"] == []


def test_discovery_manifest_clears_legacy_active_family_metadata():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=True,
        active_sqli=True,
        requested_family="all",
        discovery_manifest_only=True,
    )

    assert scope["mode"] == "inactive"
    assert scope["families"] == []
    assert scope["legacy_flags"] == {"xss": False, "sqli": False}


def test_nuclei_dispatch_requires_active_permission_and_profile_gate():
    standard_plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="standard",
        public_only=False,
        quick_mode=False,
        active_checks=True,
        check_family_scope={"families": []},
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )
    quick_plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="quick",
        public_only=False,
        quick_mode=True,
        active_checks=True,
        check_family_scope={"families": []},
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )

    assert scanner_mod.registry_dispatch_decision(standard_plan, "nuclei")["dispatch_enabled"] is True
    assert scanner_mod.registry_dispatch_decision(quick_plan, "nuclei")["dispatch_enabled"] is False


def test_nuclei_template_phase_dispatches_only_active_registry_adapter():
    called = []
    standard_plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="standard",
        public_only=False,
        quick_mode=False,
        active_checks=True,
        check_family_scope={"families": []},
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )
    quick_plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="quick",
        public_only=False,
        quick_mode=True,
        active_checks=True,
        check_family_scope={"families": []},
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )

    async def nuclei_adapter():
        await asyncio.sleep(0)
        called.append("nuclei")

    standard_receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        standard_plan,
        "template",
        {"legacy_nuclei_template": nuclei_adapter},
    ))
    quick_receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        quick_plan,
        "template",
        {"legacy_nuclei_template": nuclei_adapter},
    ))

    assert called == ["nuclei"]
    assert standard_receipts == [{
        "family": "nuclei",
        "phase": "template",
        "dispatch_adapter": "legacy_nuclei_template",
        "status": "completed",
        "telemetry_schema": "nuclei_template",
        "proof_contract": ["template_id", "matched_at", "matcher_name", "request_url"],
    }]
    assert quick_receipts[0]["status"] == "skipped"
    assert quick_receipts[0]["reason"] == "quick_mode"


def test_recon_phase_dispatches_normal_plan_and_skips_zero_rediscovery():
    called = []
    standard_plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="standard",
        public_only=False,
        quick_mode=False,
        active_checks=False,
        check_family_scope={"families": []},
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )
    zero_plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="smart",
        public_only=False,
        quick_mode=False,
        active_checks=True,
        check_family_scope={"families": ["sqli"], "focused": True},
        skip_global_checks=True,
        focused_endpoints_only=True,
        zero_rediscovery=True,
    )

    async def recon_adapter():
        called.append("recon")
        return scanner_mod.RegistryPhaseOutcome(
            "completed",
            telemetry={"discovered_urls": 3, "browser_pages": 1},
        )

    standard_receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        standard_plan,
        "recon",
        {"legacy_discovery": recon_adapter},
    ))
    zero_receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        zero_plan,
        "recon",
        {"legacy_discovery": recon_adapter},
    ))

    assert called == ["recon"]
    assert standard_receipts[0]["status"] == "completed"
    assert standard_receipts[0]["adapter_telemetry"]["discovered_urls"] == 3
    assert zero_receipts[0]["status"] == "skipped"
    assert zero_receipts[0]["reason"] == "zero_rediscovery_scope"


def test_resolve_active_check_flags_uses_registry_family_aliases():
    active_xss, active_sqli, family = scanner_mod.resolve_active_check_flags(check_family="sql")

    assert active_xss is False
    assert active_sqli is True
    assert family == "sqli"


def test_resolve_active_check_flags_all_family_keeps_active_mix():
    active_xss, active_sqli, family = scanner_mod.resolve_active_check_flags(check_family="all")

    assert active_xss is True
    assert active_sqli is True
    assert family == "all"


def test_resolve_active_check_flags_accepts_bola_without_injection_flags():
    active_xss, active_sqli, family = scanner_mod.resolve_active_check_flags(check_family="idor")

    assert active_xss is False
    assert active_sqli is False
    assert family == "bola"


def test_resolve_active_check_flags_accepts_auth_without_injection_flags():
    active_xss, active_sqli, family = scanner_mod.resolve_active_check_flags(check_family="authentication")

    assert active_xss is False
    assert active_sqli is False
    assert family == "auth"


def test_resolve_active_check_flags_rejects_unsupported_family():
    with pytest.raises(ValueError, match="not runnable"):
        scanner_mod.resolve_active_check_flags(check_family="ssrf")


def test_resolve_active_check_flags_rejects_conflicting_legacy_flags():
    with pytest.raises(ValueError, match="conflicts"):
        scanner_mod.resolve_active_check_flags(check_family="sqli", xss=True)


def test_focused_sqli_does_not_allow_xss_or_bola_enrichment():
    assert scanner_mod.focused_family_allows_active_module("sqli", "dom_xss") is False
    assert scanner_mod.focused_family_allows_active_module("sqli", "bola_idor") is False
    assert scanner_mod.focused_family_allows_active_module("sqli", "nosql_injection") is True
    assert scanner_mod.focused_family_allows_active_module("sqli", "sqlmap") is True


def test_focused_xss_and_bola_allow_only_their_enrichment_modules():
    assert scanner_mod.focused_family_allows_active_module("xss", "dom_xss") is True
    assert scanner_mod.focused_family_allows_active_module("xss", "bola_idor") is False
    assert scanner_mod.focused_family_allows_active_module("bola", "bola_idor") is True
    assert scanner_mod.focused_family_allows_active_module("bola", "dom_xss") is False


def test_focused_bola_uses_bola_deadline_even_when_primary_active_budget_is_exhausted():
    active_block = {"post_active_enrichment_skipped": "active_time_budget_exhausted"}

    decision = scanner_mod.bola_enrichment_decision(
        bola_focused=True,
        post_active_budget_exhausted=True,
        active_block=active_block,
    )

    assert decision.run is True
    assert decision.reason is None
    assert active_block["active_enrichment_decisions"]["bola_idor"] == {
        "run": True,
        "reason": None,
        "source": "focused_bola_deadline",
    }


def test_broad_bola_still_respects_post_active_budget_gate():
    active_block = {"post_active_enrichment_skipped": "active_time_budget_exhausted"}

    decision = scanner_mod.bola_enrichment_decision(
        bola_focused=False,
        post_active_budget_exhausted=True,
        active_block=active_block,
    )

    assert decision.run is False
    assert decision.reason == "active_time_budget_exhausted"


def test_focused_bola_poe_settings_are_bounded_and_faster_than_global_safe_delay():
    assert scanner_mod.resolve_focused_bola_poe_settings(1) == {
        "bola_max_requests_per_target": 800,
        "rate_limit_ms": 100,
    }
    assert scanner_mod.resolve_focused_bola_poe_settings(500) == {
        "bola_max_requests_per_target": 10000,
        "rate_limit_ms": 100,
    }


def test_focused_bola_keeps_phase4_bola_checker_enabled():
    assert scanner_mod.focused_mode_keeps_phase4_bola("bola", False) is True
    assert scanner_mod.focused_mode_keeps_phase4_bola("idor", False) is True


def test_other_focused_families_disable_phase4_bola_checker():
    assert scanner_mod.focused_mode_keeps_phase4_bola("sqli", True) is False
    assert scanner_mod.focused_mode_keeps_phase4_bola("xss", True) is False
    assert scanner_mod.focused_mode_keeps_phase4_bola(None, True) is True
    assert scanner_mod.focused_mode_keeps_phase4_bola(None, False) is False


def test_broad_active_scan_allows_enrichment_modules():
    assert scanner_mod.focused_family_allows_active_module(None, "dom_xss") is True
    assert scanner_mod.focused_family_allows_active_module("all", "bola_idor") is True


# --- ACTIVE_CHECK_FAMILIES registry: single source of truth (keystone) ---

def test_registry_is_single_source_of_truth_for_runnable_families():
    assert scanner_mod.runnable_active_families() == ("all", "sqli", "xss", "auth", "bola")
    assert set(scanner_mod.ACTIVE_CHECK_FAMILIES) == {"all", "sqli", "xss", "auth", "bola"}


def test_legacy_flag_view_is_derived_byte_identical():
    assert scanner_mod.SCANNER_ACTIVE_FAMILY_FLAGS == {
        "all": (True, True),
        "sqli": (False, True),
        "xss": (True, False),
        "auth": (False, False),
        "bola": (False, False),
    }
    # order is preserved so the "allowed families" error message is unchanged
    assert ", ".join(scanner_mod.SCANNER_ACTIVE_FAMILY_FLAGS) == "all, sqli, xss, auth, bola"


def test_alias_view_is_derived_byte_identical():
    assert scanner_mod.SCANNER_ACTIVE_FAMILY_ALIASES == {
        "all": "all",
        "sql": "sqli",
        "sql-injection": "sqli",
        "sql_injection": "sqli",
        "cross-site-scripting": "xss",
        "cross_site_scripting": "xss",
        "authentication": "auth",
        "access-control": "auth",
        "access_control": "auth",
        "idor": "bola",
        "object_authorization": "bola",
        "object-authorization": "bola",
    }


def test_focused_rules_view_is_derived_and_excludes_all():
    rules = scanner_mod.FOCUSED_FAMILY_RULES
    assert set(rules) == {"sqli", "xss", "auth", "bola"}  # "all" carries no focused rules
    # representative entries preserve their content exactly
    assert rules["sqli"]["tools"] == {"smart_sqli", "custom_sqli", "sqlmap", "nosql_injection"}
    assert rules["sqli"]["cwes"] == {"CWE-89", "CWE-943"}
    assert rules["bola"]["cwes"] == {"CWE-639"}
    assert rules["bola"]["remediation"][0].startswith("Enforce object-level authorization")
    assert isinstance(rules["auth"]["title_markers"], tuple)
    assert isinstance(rules["xss"]["remediation"], list)


def test_family_requires_two_auth_states_is_registry_driven():
    assert scanner_mod.family_requires_two_auth_states("bola") is True
    assert scanner_mod.family_requires_two_auth_states("idor") is True  # alias resolves
    assert scanner_mod.family_requires_two_auth_states("sqli") is False
    assert scanner_mod.family_requires_two_auth_states("xss") is False
    assert scanner_mod.family_requires_two_auth_states("auth") is False
    assert scanner_mod.family_requires_two_auth_states("nope") is False


def test_scanner_execution_plan_is_registry_driven_for_focused_family():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=False,
        active_sqli=True,
        requested_family="sqli",
    )

    plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="smart",
        public_only=False,
        quick_mode=False,
        active_checks=True,
        check_family_scope=scope,
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
    )
    families = {item["name"]: item for item in plan["families"]}

    assert plan["registry_version"] == "check_family_v1"
    assert plan["check_family_scope"]["focused_family"] == "sqli"
    assert plan["summary"]["proof_contracts"]["sqli"] == families["sqli"]["proof_contract"]
    assert "sqli" in plan["summary"]["enabled_families"]
    assert families["sqli"]["enabled"] is True
    assert families["sqli"]["telemetry_schema"] == "active_endpoint_attempt_v1"
    assert "payload" in families["sqli"]["proof_contract"]
    assert families["xss"]["enabled"] is False
    assert families["headers"]["enabled"] is True


def test_scanner_execution_plan_applies_family_policy_to_real_dispatch_rows():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=True,
        active_sqli=True,
    )
    plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="canonical",
        public_only=False,
        quick_mode=False,
        active_checks=True,
        check_family_scope=scope,
        skip_global_checks=False,
        focused_endpoints_only=False,
        zero_rediscovery=False,
        include_families=("xss",),
        exclude_families=("nuclei",),
    )
    families = {item["name"]: item for item in plan["families"]}

    assert families["xss"]["enabled"] is True
    assert families["sqli"]["enabled"] is False
    assert families["sqli"]["reason"] == "policy_not_included"
    assert families["nuclei"]["enabled"] is False
    assert families["nuclei"]["reason"] == "policy_excluded"


def test_scanner_execution_plan_records_zero_rediscovery_and_public_skips():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=True,
        active_sqli=False,
        requested_family="xss",
    )

    plan = scanner_mod.build_scanner_execution_plan(
        scan_mode="quick",
        public_only=True,
        quick_mode=True,
        active_checks=True,
        check_family_scope=scope,
        skip_global_checks=True,
        focused_endpoints_only=True,
        zero_rediscovery=True,
    )
    families = {item["name"]: item for item in plan["families"]}

    assert families["recon"]["reason"] == "zero_rediscovery_scope"
    assert families["headers"]["reason"] == "global_checks_skipped"
    assert families["nuclei"]["reason"] == "public_only"
    assert families["xss"]["enabled"] is False
    assert plan["summary"]["skip_reason_counts"]["public_only"] >= 1
    assert families["xss"]["reason"] == "public_only"


def test_scanner_execution_plan_fails_loudly_when_registry_is_unavailable(monkeypatch):
    monkeypatch.setattr(scanner_mod, "_check_registry", None)

    with pytest.raises(RuntimeError, match="scanner_check_registry_unavailable"):
        scanner_mod.build_scanner_execution_plan(
            scan_mode="smart",
            public_only=False,
            quick_mode=False,
            active_checks=True,
            check_family_scope={"families": ["sqli"]},
            skip_global_checks=False,
            focused_endpoints_only=False,
            zero_rediscovery=False,
        )


def test_scanner_execution_plan_fails_loudly_on_partial_registry(monkeypatch):
    monkeypatch.setattr(
        scanner_mod,
        "_check_registry",
        SimpleNamespace(scanner_execution_plan=lambda **_kwargs: {
            "registry_version": "check_family_v1",
            "families": [{"name": "sqli"}],
            "summary": {},
        }),
    )

    with pytest.raises(RuntimeError, match="required_families_missing"):
        scanner_mod.build_scanner_execution_plan(
            scan_mode="smart",
            public_only=False,
            quick_mode=False,
            active_checks=True,
            check_family_scope={"families": ["sqli"]},
            skip_global_checks=False,
            focused_endpoints_only=False,
            zero_rediscovery=False,
        )


def test_registry_dispatch_enabled_is_authoritative_for_explicit_family():
    plan = {
        "check_family_scope": {"requested_family": "bola"},
        "families": [
            {"name": "bola", "enabled": False, "runnable": True, "dispatch_adapter": "asm_endpoint_batch"},
            {"name": "auth", "enabled": True, "runnable": True, "dispatch_adapter": "asm_endpoint_batch"},
        ],
    }

    assert scanner_mod.registry_dispatch_enabled(plan, "bola") is False
    assert scanner_mod.registry_dispatch_enabled(plan, "auth") is True


def test_registry_dispatch_enabled_does_not_override_disabled_broad_plan():
    plan = {
        "check_family_scope": {"requested_family": None},
        "families": [{"name": "bola", "enabled": False, "runnable": True, "dispatch_adapter": "asm_endpoint_batch"}],
    }

    assert scanner_mod.registry_dispatch_enabled(plan, "bola") is False
    assert scanner_mod.registry_dispatch_enabled(plan, "auth") is False


def test_registry_dispatch_decision_fails_closed_on_adapter_contract_drift():
    plan = {
        "check_family_scope": {"requested_family": "jwt"},
        "families": [{
            "name": "jwt",
            "phase": "active",
            "enabled": True,
            "runnable": True,
            "dispatch_adapter": "wrong_adapter",
            "blocked_by": [],
        }],
    }

    decision = scanner_mod.registry_dispatch_decision(
        plan,
        "jwt",
        expected_adapter="legacy_advanced_jwt",
    )

    assert decision["dispatch_enabled"] is False
    assert decision["decision"] == "blocked"
    assert decision["reason"] == "registry_dispatch_adapter_mismatch"
    assert decision["dispatch_adapter"] == "wrong_adapter"


def test_scanner_adapter_contracts_match_canonical_runnable_registry():
    assert scanner_mod._check_registry is not None
    for family, adapter in scanner_mod.SCANNER_REGISTRY_ADAPTER_CONTRACTS.items():
        spec = scanner_mod._check_registry.get_check_family(family)
        assert spec is not None
        assert spec.runnable is True
        assert spec.dispatch_adapter == adapter


def test_registry_dispatch_decision_rejects_unmapped_scanner_adapter():
    plan = {
        "check_family_scope": {"requested_family": "new_family"},
        "families": [{
            "name": "new_family",
            "phase": "active",
            "enabled": True,
            "runnable": True,
            "dispatch_adapter": "new_adapter",
            "blocked_by": [],
        }],
    }

    decision = scanner_mod.registry_dispatch_decision(plan, "new_family")

    assert decision["dispatch_enabled"] is False
    assert decision["reason"] == "scanner_adapter_contract_missing"


def test_release_critical_active_families_have_no_eager_registry_bypass():
    source = inspect.getsource(scanner_mod.build_report)

    assert "create_task(nosql_injection_test" not in source
    assert "create_task(check_bola" not in source
    assert 'families={"sqli", "xss"}' in source
    assert 'families={"bola"}' in source


def test_registry_dispatch_decision_keeps_disabled_broad_family_skipped():
    plan = {
        "check_family_scope": {"requested_family": None},
        "families": [{
            "name": "bola",
            "phase": "active",
            "enabled": False,
            "runnable": True,
            "dispatch_adapter": "asm_endpoint_batch",
            "blocked_by": [],
            "reason": "not_selected",
        }],
    }

    decision = scanner_mod.registry_dispatch_decision(
        plan,
        "bola",
        expected_adapter="asm_endpoint_batch",
    )

    assert decision["dispatch_enabled"] is False
    assert decision["decision"] == "skipped"
    assert decision["reason"] == "not_selected"


def test_registry_report_phase_dispatches_only_enabled_declared_adapters():
    called = []
    plan = {"families": [
        {
            "name": "headers", "phase": "passive", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_config_findings",
            "telemetry_schema": "planned_passive_attempt", "proof_contract": ["response_headers"],
        },
        {"name": "recon", "phase": "recon", "enabled": True, "dispatch_adapter": "recon_adapter"},
    ]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan, "passive", {"legacy_config_findings": lambda: called.append("headers")}
    ))

    assert called == ["headers"]
    assert receipts[0]["status"] == "completed"
    assert receipts[0]["dispatch_adapter"] == "legacy_config_findings"
    assert receipts[0]["telemetry_schema"] == "planned_passive_attempt"
    assert receipts[0]["proof_contract"] == ["response_headers"]


def test_registry_report_phase_records_disabled_family_as_skipped():
    called = []
    plan = {"families": [{
        "name": "headers", "phase": "passive", "enabled": False, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "reason": "global_checks_skipped",
        "dispatch_adapter": "legacy_config_findings",
    }]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan, "passive", {"legacy_config_findings": lambda: called.append("headers")}
    ))

    assert called == []
    assert receipts[0]["status"] == "skipped"
    assert receipts[0]["reason"] == "global_checks_skipped"


def test_registry_report_phase_records_missing_adapter_without_running():
    plan = {"families": [{
        "name": "headers", "phase": "passive", "enabled": True, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_config_findings",
    }]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(plan, "passive", {}))

    assert receipts[0]["status"] == "blocked"
    assert receipts[0]["reason"] == "dispatch_adapter_not_registered"


def test_registry_report_phase_awaits_async_adapter():
    called = []
    plan = {"families": [{
        "name": "headers", "phase": "passive", "enabled": True, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_config_findings",
    }]}

    async def adapter():
        await asyncio.sleep(0)
        called.append("headers")

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan, "passive", {"legacy_config_findings": adapter}
    ))

    assert called == ["headers"]
    assert receipts[0]["status"] == "completed"


def test_registry_report_phase_uses_typed_adapter_outcome():
    plan = {"families": [{
        "name": "nuclei", "phase": "template", "enabled": True, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_nuclei_template",
        "telemetry_schema": "nuclei_template", "proof_contract": ["template_id"],
    }]}

    async def incomplete_nuclei():
        return scanner_mod.RegistryPhaseOutcome(
            "failed",
            "nuclei_scan_incomplete",
            {"scan_completed": False, "templates_used": 0, "findings_count": 0},
        )

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan,
        "template",
        {"legacy_nuclei_template": incomplete_nuclei},
    ))

    assert receipts == [{
        "family": "nuclei",
        "phase": "template",
        "dispatch_adapter": "legacy_nuclei_template",
        "status": "failed",
        "telemetry_schema": "nuclei_template",
        "proof_contract": ["template_id"],
        "reason": "nuclei_scan_incomplete",
        "adapter_telemetry": {
            "scan_completed": False,
            "templates_used": 0,
            "findings_count": 0,
        },
    }]


def test_registry_report_phase_rejects_invalid_typed_adapter_outcome():
    plan = {"families": [{
        "name": "nuclei", "phase": "template", "enabled": True, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_nuclei_template",
    }]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan,
        "template",
        {"legacy_nuclei_template": lambda: scanner_mod.RegistryPhaseOutcome("partial")},
    ))

    assert receipts[0]["status"] == "failed"
    assert receipts[0]["reason"] == "invalid_adapter_outcome_status:partial"


def test_registry_report_phase_blocks_adapter_contract_drift():
    plan = {"families": [{
        "name": "headers", "phase": "passive", "enabled": True, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "wrong_adapter",
    }]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan, "passive", {"wrong_adapter": lambda: None}
    ))

    assert receipts[0]["status"] == "blocked"
    assert receipts[0]["reason"] == "registry_dispatch_adapter_mismatch"


def test_registry_report_phase_records_cancellation_without_dispatch():
    called = []
    plan = {"families": [{
        "name": "headers", "phase": "passive", "enabled": True, "runnable": True,
        "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_config_findings",
    }]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan,
        "passive",
        {"legacy_config_findings": lambda: called.append("headers")},
        cancel_requested=lambda: True,
    ))

    assert called == []
    assert receipts[0]["status"] == "cancelled"
    assert receipts[0]["reason"] == "scanner_cancel_requested"


def test_registry_report_phase_limits_dispatch_to_explicit_family_subset():
    called = []
    plan = {"families": [
        {
            "name": "jwt", "phase": "active", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_advanced_jwt",
        },
        {
            "name": "mass_assignment", "phase": "active", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_phase4_mass_assignment",
        },
    ]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan,
        "active",
        {
            "legacy_advanced_jwt": lambda: called.append("jwt"),
            "legacy_phase4_mass_assignment": lambda: called.append("mass_assignment"),
        },
        families={"jwt"},
    ))

    assert called == ["jwt"]
    assert [receipt["family"] for receipt in receipts] == ["jwt"]


def test_registry_report_phase_runs_shared_batch_adapter_once_with_family_outcomes():
    calls = []
    plan = {"families": [
        {
            "name": "sqli", "phase": "active", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_active_loop",
        },
        {
            "name": "xss", "phase": "active", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_active_loop",
        },
    ]}

    async def active_batch(rows):
        calls.append([row["name"] for row in rows])
        return scanner_mod.RegistryPhaseBatchOutcome({
            "sqli": scanner_mod.RegistryPhaseOutcome(
                "completed", telemetry={"attempted_params_count": 3}
            ),
            "xss": scanner_mod.RegistryPhaseOutcome(
                "failed", "xss_budget_exhausted", {"attempted_params_count": 1}
            ),
        })

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan,
        "active",
        {
            "legacy_active_loop": scanner_mod.RegistryPhaseBatchAdapter(active_batch),
        },
        families={"sqli", "xss"},
    ))

    assert calls == [["sqli", "xss"]]
    assert [receipt["status"] for receipt in receipts] == ["completed", "failed"]
    assert receipts[1]["reason"] == "xss_budget_exhausted"


def test_registry_report_phase_fails_closed_when_batch_omits_family_outcome():
    plan = {"families": [
        {
            "name": "sqli", "phase": "active", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_active_loop",
        },
        {
            "name": "xss", "phase": "active", "enabled": True, "runnable": True,
            "scanner_enabled": True, "blocked_by": [], "dispatch_adapter": "legacy_active_loop",
        },
    ]}

    receipts = asyncio.run(scanner_mod.dispatch_registry_report_phase(
        plan,
        "active",
        {
            "legacy_active_loop": scanner_mod.RegistryPhaseBatchAdapter(
                lambda rows: scanner_mod.RegistryPhaseBatchOutcome({
                    "sqli": scanner_mod.RegistryPhaseOutcome("completed"),
                })
            ),
        },
        families={"sqli", "xss"},
    ))

    assert receipts[0]["status"] == "completed"
    assert receipts[1]["status"] == "failed"
    assert receipts[1]["reason"] == "batch_adapter_family_outcome_missing"


def test_auth_and_bola_network_checks_are_registry_adapter_owned():
    source = Path(scanner_mod.__file__).read_text(encoding="utf-8")

    assert "xss_dispatch_decision = registry_dispatch_decision" not in source
    assert "sqli_dispatch_decision = registry_dispatch_decision" not in source
    assert "auth_dispatch_decision = registry_dispatch_decision" not in source
    assert "bola_dispatch_decision = registry_dispatch_decision" not in source
    assert "async def run_legacy_active_loop(" in source
    assert "RegistryPhaseBatchAdapter(\n                    run_legacy_active_loop" in source
    assert "async def run_asm_endpoint_batch_auth()" in source
    assert "async def run_asm_endpoint_batch_bola()" in source
    assert 'families={"auth"}' in source
    assert 'families={"bola"}' in source


def _load_reporting_module():
    import importlib.util as _ilu
    scanner_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
    spec = _ilu.spec_from_file_location(
        "shaker_reporting_under_test", os.path.join(scanner_dir, "reporting.py")
    )
    module = _ilu.module_from_spec(spec)
    added = scanner_dir not in sys.path
    if added:
        sys.path.insert(0, scanner_dir)
    try:
        spec.loader.exec_module(module)
    finally:
        if added:
            sys.path.remove(scanner_dir)
    return module


def test_emit_config_findings_is_the_host_posture_funnel():
    """emit_config_findings is the single source of host-level posture findings
    (CSP/headers/TLS/DNS). build_report gates this call on skip_global_checks so
    parallel coverage shards don't each re-emit them; if posture emission ever
    moves elsewhere this test flags that the gate has become incomplete."""
    reporting = _load_reporting_module()
    report = {
        "input": {"normalized_host": "example.com", "port": 443},
        "http": {
            "final_url": "https://example.com",
            "security_headers": {},
            "csp_evaluation": {"present": False},
        },
        "dns": {},
        "tls": {},
        "discovery": {},
        "findings": [],
    }
    reporting.emit_config_findings(report)
    titles = [f.get("title", "") for f in report["findings"]]
    assert any("CSP header missing" in t for t in titles)
    assert any("HSTS header missing" in t for t in titles)
