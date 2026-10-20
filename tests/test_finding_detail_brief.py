"""The per-class finding brief: concrete facts, proof, reproduce/verify commands, fix and severity."""

from __future__ import annotations

import json
import shlex

import pytest

from api.finding_detail import build_finding_detail, related_findings
from api.scan.severity_calibration import calibrate_finding

SECRET_VALUE = "AKIA" + "ZOOFIXTUREVALUE1"  # split: a synthetic fixture, not a real key


def _tls(check, **evidence):
    return {"title": "x", "severity": "high", "tool": "tls.inspect", "proof_state": "verified",
            "url": "https://app.fixture.invalid:8444", "evidence": {
                "check": check, "origin": "https://app.fixture.invalid:8444", "port": 8444,
                "pinned_address": "10.0.0.5", "requested_host": "app.fixture.invalid", **evidence}}


def test_hostname_mismatch_names_the_certificate_and_the_virtual_host_fix():
    brief = build_finding_detail(_tls("tls_certificate_hostname_mismatch", requested_host_kind="dns",
        certificate={"dns_names": ["other.fixture.invalid"], "issuer_cn": "Fixture CA"}, trust={"result": "trusted"}))
    assert brief["class"] == "tls.certificate_hostname_mismatch"
    assert "other.fixture.invalid" in brief["summary"] and "app.fixture.invalid" in brief["summary"]
    assert any("default certificate" in line for line in brief["context"])
    assert "-servername app.fixture.invalid" in brief["reproduce"]["command"]
    assert "10.0.0.5:8444" in brief["reproduce"]["command"]
    assert brief["verify"]["expect"] == "Verify return code: 0 (ok)"
    assert any("server_name (SNI)" in step for step in brief["fix"])
    assert brief["confidence"]["level"] == "confirmed"
    # Stored at the producer's high; the brief states the current rule without rewriting the row.
    assert brief["severity"]["severity"] == "high"
    assert brief["severity"]["current_rule"]["severity"] == "medium"


@pytest.mark.parametrize("failure,needle", [
    ("self_signed", "public CA"), ("issuer_not_found", "full chain"), ("untrusted_root", "public trust stores"),
])
def test_untrusted_chain_fix_follows_the_verifier_reason(failure, needle):
    brief = build_finding_detail(_tls("tls_certificate_untrusted", chain_length=1,
        certificate={"issuer": "CN=Fixture Intermediate", "aia_ca_issuers": ["http://ca.fixture.invalid/int.crt"]},
        chain=[{"subject": "CN=Fixture Root"}], trust={"result": "untrusted", "failure": failure, "error_code": 20}))
    assert needle in " ".join(brief["fix"])
    assert any(fact["label"] == "Certificates sent by the server" for fact in brief["observed"])


def test_expired_and_legacy_and_cipher_briefs_carry_the_observed_values():
    expired = build_finding_detail(_tls("tls_certificate_expired", certificate={"not_after": "2025-01-01", "days_remaining": -400, "serial_hex": "0A"}))
    assert "2025-01-01" in expired["summary"] and "400 days ago" in expired["summary"]
    legacy = build_finding_detail(_tls("tls_legacy_protocol", protocol="TLSv1", protocol_attempts=[
        {"protocol": "TLSv1", "supported": True}, {"protocol": "TLSv1.2", "supported": False}]))
    assert "TLSv1" in legacy["summary"] and "ssl_protocols TLSv1.2 TLSv1.3;" in " ".join(legacy["fix"])
    weak = build_finding_detail(_tls("tls_weak_cipher", cipher="DES-CBC3-SHA", cipher_bits=112, protocol="TLSv1.2"))
    assert "DES-CBC3-SHA" in weak["summary"] and "nmap" in weak["reproduce"]["command"]


def test_commands_quote_target_controlled_values():
    hostile = "app.fixture.invalid;touch${IFS}/tmp/pwned"
    brief = build_finding_detail(_tls("tls_certificate_hostname_mismatch", requested_host=hostile, certificate={}))
    command = brief["reproduce"]["command"]
    assert shlex.quote(hostile) in command
    header = build_finding_detail({"tool": "http_baseline", "severity": "low", "url": "https://x.invalid/a'$(id)",
                                   "evidence": {"check": "missing_header_content-security-policy", "url": "https://x.invalid/a'$(id)", "header": "content-security-policy"}})
    assert "'\"'\"'$(id)" in header["reproduce"]["command"]


def test_missing_header_uses_the_recorded_response_and_the_detected_server():
    brief = build_finding_detail({"tool": "http_baseline", "severity": "low", "url": "https://app.fixture.invalid",
        "proof_state": "verified", "evidence": {"check": "missing_header_strict-transport-security",
        "header": "strict-transport-security", "url": "https://app.fixture.invalid", "observed_response": {
            "request_line": "GET https://app.fixture.invalid/", "response_status": 200,
            "observed_headers": {"server": "nginx/1.25.3", "x-frame-options": "DENY"}}}})
    assert brief["class"] == "header.missing"
    assert brief["stack"] == "nginx" and brief["examples"][0]["label"] == "nginx"
    assert "add_header Strict-Transport-Security" in brief["examples"][0]["code"]
    assert brief["expected"] == ["Strict-Transport-Security: max-age=31536000; includeSubDomains"]
    assert any(fact["value"] == "nginx/1.25.3" for fact in brief["observed"])
    assert brief["severity"]["reason"]  # current rule explains low


def test_frame_options_notes_an_existing_frame_ancestors_policy():
    brief = build_finding_detail({"tool": "nuclei", "severity": "info", "url": "https://app.fixture.invalid",
        "evidence": {"template_id": "http-missing-security-headers", "header_name": "x-frame-options",
                     "observed_response": {"observed_headers": {"content-security-policy": "frame-ancestors 'none'"}}}})
    assert any("frame-ancestors" in line for line in brief["context"])


def test_cookie_brief_never_holds_a_cookie_value():
    brief = build_finding_detail({"tool": "http_baseline", "severity": "low", "url": "https://app.fixture.invalid",
        "evidence": {"check": "session_cookie_missing_httponly", "cookie_name": "sessionid",
                     "cookie_flags": {"secure": False, "httponly": False, "samesite": None}, "url": "https://app.fixture.invalid"}})
    assert brief["class"] == "cookie.missing_httponly"
    assert "sessionid" in brief["summary"] and "document.cookie" in brief["context"][0]
    assert "proxy_cookie_flags sessionid" in json.dumps(brief["examples"])


def test_exposure_brief_lists_masked_secrets_and_links_stored_references():
    ref = "secret://12345678-1234-1234-1234-123456789abc"
    finding = {"tool": "shakerscan_exposure_probe", "severity": "high", "proof_state": "verified",
        "url": "http://exp.fixture.invalid/.env", "evidence": {
            "exposure_class": "environment_secret_file", "request_url": "http://exp.fixture.invalid/.env",
            "response_status": 200, "content_type": "text/plain",
            "redacted_excerpt": "[environment_secret_file detected - content withheld]",
            "exposure_fingerprints": [
                {"field": "AWS_ACCESS_KEY_ID", "category": "aws_access_key", "value_fingerprint": "f1", "value_length": 20, "stored_as": ref},
                {"field": "DB_PASSWORD", "category": "password", "value_fingerprint": "f2", "value_length": 9}],
            "discovered_refs": [ref]}}
    brief = build_finding_detail(finding)
    assert brief["class"] == "exposure.environment_secret_file"
    assert [secret["field"] for secret in brief["secrets"]] == ["AWS_ACCESS_KEY_ID", "DB_PASSWORD"]
    assert brief["secrets"][0]["ref"] == ref and brief["secret_refs"] == [ref]
    assert "Rotate every credential" in " ".join(brief["fix"])
    assert "-o /dev/null" in brief["reproduce"]["command"]  # never prints the body
    assert SECRET_VALUE not in json.dumps(brief) and "f1" not in json.dumps(brief["secrets"])


def test_verbose_error_is_calibrated_low_but_a_proven_secret_keeps_high():
    plain = calibrate_finding({"tool": "shakerscan_exposure_probe", "severity": "medium", "evidence": {"exposure_class": "verbose_error_disclosure"}})
    assert plain["severity"] == "low"
    proven = calibrate_finding({"tool": "shakerscan_exposure_probe", "severity": "high", "evidence": {
        "exposure_class": "verbose_error_disclosure", "exposure_fingerprints": [{"category": "aws_access_key"}]}})
    assert proven["severity"] == "high"


def test_sqli_proof_brief_states_parameter_dbms_and_differential():
    brief = build_finding_detail({"tool": "shakerscan_sqli_proof", "severity": "critical", "proof_state": "verified",
        "url": "http://sqli.fixture.invalid/product", "title": "Verified SQL injection", "evidence": {
            "method": "GET", "field_path": "id", "technique": "error_based_repeated", "repetitions": 2,
            "database_error_signatures": ["SQLITE_ERROR"], "payload_shape": "<original>'",
            "response_pairs": [{"control_status": 200, "payload_status": 500}],
            "redacted_excerpt": "SQLITE_ERROR near \"'\": syntax error"}})
    assert brief["class"] == "injection.sqli"
    assert "id" in brief["summary"] and "SQLite" in brief["summary"]
    assert brief["pairs"] == [{"control": "200", "payload": "500"}]
    assert "id=%27" in brief["reproduce"]["command"]
    assert any(fact["label"] == "Payload sent" for fact in brief["observed"])
    assert "Why" not in brief["severity"]["reason"] and brief["severity"]["reason"]


def test_candidate_template_cve_brief_uses_the_offline_snapshot(monkeypatch):
    from api.finding_detail import other
    monkeypatch.setattr(other, "_snapshot_rows", lambda cve: [{
        "advisory_id": cve, "product": "http_server", "version_start_including": "2.4.49",
        "version_end_excluding": "2.4.51", "known_exploited": {"date_added": "2021-11-03", "ransomware": True},
        "epss": {"score": 0.97, "percentile": 0.99}}])
    brief = build_finding_detail({"tool": "nuclei", "severity": "critical", "proof_state": "candidate",
        "url": "http://outdated.fixture.invalid/cgi-bin/", "title": "Apache 2.4.49 - Path Traversal", "evidence": {
            "template_id": "CVE-2021-41773", "cve_ids": ["CVE-2021-41773"], "matched_at": "http://outdated.fixture.invalid/cgi-bin/"}})
    assert brief["class"] == "vuln.cve" and brief["confidence"]["level"] == "tentative"
    cve = brief["cves"][0]
    assert cve["known_exploited"]["ransomware"] is True and cve["fixed_in"] == ["http_server 2.4.51"]
    assert brief["fix"][0].startswith("Upgrade to a fixed release: http_server 2.4.51")
    assert "nuclei -u" in brief["reproduce"]["command"]


def test_default_login_template_reads_as_default_credentials():
    brief = build_finding_detail({"tool": "nuclei", "severity": "high", "title": "Apache Tomcat Manager Default Login",
        "evidence": {"template_id": "tomcat-default-login", "template_tags": ["default-login", "tomcat"],
                     "matched_at": "http://dc.fixture.invalid/manager/html", "extracted_result_lengths": [6]}})
    assert brief["class"] == "auth.default_credentials"
    assert any("values not stored" in fact["value"] for fact in brief["observed"])


def test_graphql_takeover_xss_and_generic_fallback():
    gql = build_finding_detail({"tool": "shakerscan_graphql_probe", "severity": "low", "evidence": {
        "check": "field_suggestions", "endpoint": "http://g.invalid/graphql", "misspelling": "usr", "suggested_fields": ["user", "users"]}})
    assert "user" in gql["summary"] and "Did you mean" in gql["reproduce"]["expect"]
    takeover = build_finding_detail({"tool": "subdomain_takeover", "severity": "high", "evidence": {
        "check": "subdomain_takeover", "host": "old.fixture.invalid", "cname_chain": ["x.s3.amazonaws.com"],
        "terminal": "x.s3.amazonaws.com", "service": "AWS S3"}})
    assert takeover["class"] == "dns.takeover" and "dig" in takeover["reproduce"]["command"]
    xss = build_finding_detail({"tool": "shakerscan_browser_proof", "severity": "high", "proof_state": "verified",
        "cwe": "CWE-79", "evidence": {"parameter_name": "q", "injection_location": "query",
        "request_url": "http://x.invalid/search?q=%3Csvg%3E", "technique": "headless_xss_dialog"}})
    assert xss["class"] == "injection.xss" and "q" in xss["summary"]
    generic = build_finding_detail({"tool": "device_policy", "title": "Deny device service", "description": "Telnet on 23/tcp",
        "severity": "high", "evidence": {"port": 23, "api_token": SECRET_VALUE, "capability_receipt": {"x": 1}}})
    assert generic["class"] == "generic" and generic["summary"] == "Telnet on 23/tcp"
    assert SECRET_VALUE not in json.dumps(generic)


@pytest.mark.parametrize("evidence", [None, "not json", "[]", {"check": 5, "certificate": "bad", "chain": "bad"}])
def test_malformed_historical_rows_still_get_a_brief(evidence):
    brief = build_finding_detail({"tool": "tls.inspect", "severity": "high", "evidence": evidence})
    assert brief["schema"] == "finding-detail/v1" and brief["class"]


def test_related_findings_rank_same_certificate_then_same_check():
    finding = {"id": "a", "tool": "tls.inspect", "url": "https://h.invalid:8444", "evidence": {"certificate_sha256": "c" * 64}}
    rows = [
        {"id": "00000000-0000-4000-8000-000000000001", "title": "Missing CSP", "severity": "low", "url": "https://h.invalid:8444", "tool": "http_baseline"},
        {"id": "00000000-0000-4000-8000-000000000002", "title": "Untrusted", "severity": "medium", "url": "https://other.invalid", "tool": "tls.inspect", "certificate_sha256": "c" * 64},
        {"id": "00000000-0000-4000-8000-000000000003", "title": "Expiring", "severity": "low", "url": "https://h.invalid:8444", "tool": "tls.inspect"},
    ]
    related = related_findings(finding, rows)
    assert [item["relation"] for item in related] == ["Same certificate", "Same check on this origin"]


def test_finalizer_records_the_baseline_response_for_header_and_cookie_findings():
    from api.scan.finalizer import _findings_for_action
    from tests.test_scan_finalizer import _result_with_observation_count
    from tests.test_scan_orchestrator import _action
    action = _action("baseline.http", 0, capability_name="http.request")
    result = _result_with_observation_count(action, 1)
    findings = _findings_for_action(result, [{
        "kind": "http_observation",
        "request": {"origin": "https://app.fixture.invalid", "method": "GET", "path": "/"},
        # The dispatcher baseline selects no headers: the posture record alone proves absence.
        "response": {"status": 200, "security_headers": {"server": "nginx", "x-frame-options": "DENY"},
                     "set_cookie_metadata": [{"name": "sessionid", "secure": False, "httponly": False}]},
    }])
    checks = {finding["evidence"].get("check") for finding in findings}
    assert "missing_header_content-security-policy" in checks
    assert "session_cookie_missing_httponly" in checks
    for finding in findings:
        observed = finding["evidence"]["observed_response"]
        assert observed["request_line"] == "GET https://app.fixture.invalid/"
        assert observed["observed_headers"]["server"] == "nginx"
    cookie = next(f for f in findings if f["evidence"]["check"] == "session_cookie_missing_httponly")
    assert cookie["evidence"]["severity_basis"]["rule"] == "session_cookie_missing_httponly"


def test_finalizer_keeps_the_sqlmap_dbms_and_the_proof_payload_shape():
    from api.scan.finalizer import _findings_for_action
    from tests.test_scan_finalizer import _result_with_observation_count
    from tests.test_scan_orchestrator import _action
    action = _action("dast.sqli", 0, capability_name="sqli.verify_batch")
    result = _result_with_observation_count(action, 2)
    findings = _findings_for_action(result, [
        {"kind": "sqli_finding", "url": "http://s.invalid/p?id=1", "param": "id", "message": "id is vulnerable"},
        {"kind": "sqli_dbms_fingerprint", "message": "[INFO] back-end DBMS: MySQL >= 5.0"},
    ])
    assert findings[0]["evidence"]["dbms"] == "MySQL >= 5.0"
    action = _action("dast.sqli_prove", 0, capability_name="sqli.prove_batch")
    result = _result_with_observation_count(action, 1)
    proven = _findings_for_action(result, [{
        "kind": "sqli_proof", "proof_state": "verified", "finding_verdict": "verified",
        "proof_contract": "sqli_error_differential/v2", "repetitions": 2, "canonical_path": "/p",
        "technique": "error_based_repeated", "payload_shape": "<original>'"}])
    assert proven[0]["evidence"]["payload_shape"] == "<original>'"


def test_ai_gate_brief_is_tentative_about_model_variance():
    brief = build_finding_detail({"source": "ai_gate", "title": "System prompt disclosure", "severity": "high",
        "proof_state": "verified", "ai_target_url": "http://ai.fixture.invalid/chat",
        "evidence": {"probe_family": "prompt_leakage", "judge_layer": "regex_classifier", "matched_markers": ["CANARY"]}})
    assert brief["class"] == "ai.prompt_leakage"
    assert brief["confidence"]["level"] == "likely" and "varies" in brief["confidence"]["reason"]


def test_a_missing_header_proven_by_the_baseline_is_not_reported_again_by_the_template():
    from api.scan.finalizer import _fold_duplicate_header_findings
    baseline = {"tool": "http_baseline", "url": "https://app.fixture.invalid",
                "evidence": {"check": "missing_header_referrer-policy"}}
    template = {"tool": "nuclei", "url": "https://app.fixture.invalid", "evidence": {
        "template_id": "http-missing-security-headers", "header_name": "referrer-policy",
        "matched_urls": ["https://app.fixture.invalid/a"], "matched_url_count": 7}}
    frame = {"tool": "nuclei", "url": "https://app.fixture.invalid", "evidence": {
        "template_id": "http-missing-security-headers", "header_name": "x-frame-options"}}
    kept = _fold_duplicate_header_findings([baseline, template, frame])
    assert kept == [baseline, frame]
    assert baseline["evidence"]["matched_url_count"] == 7


@pytest.mark.parametrize("url,klass,needle", [
    ("https://app.fixture.invalid/actuator/env", "actuator_secret_disclosure", "location ^~ /actuator/ { deny all; }"),
    ("https://app.fixture.invalid/.git-credentials", "configuration_secret_file", "location = /.git-credentials { return 404; }"),
    ("https://app.fixture.invalid/swagger.json", "api_specification_secret", "location = /swagger.json { return 404; }"),
    ("https://app.fixture.invalid/files/", "directory_listing", "location /files/ { autoindex off; }"),
])
def test_exposure_fix_and_check_use_the_finding_path(url, klass, needle):
    brief = build_finding_detail({"tool": "shakerscan_exposure_probe", "severity": "high", "url": url,
                                  "evidence": {"exposure_class": klass, "request_url": url, "response_status": 200}})
    assert needle in json.dumps(brief["examples"])
    assert url in brief["verify"]["command"] and "example.com" not in json.dumps(brief)


def test_knowledge_base_check_commands_target_the_finding_not_example_com():
    from api.finding_routes.remediation import finding_remediation, localize_command
    finding = {"tool": "shakerscan_exposure_probe", "title": "Sensitive exposure: actuator secret disclosure",
               "url": "https://app.fixture.invalid/actuator/env",
               "evidence": {"exposure_class": "actuator_secret_disclosure", "request_url": "https://app.fixture.invalid/actuator/env"}}
    assert localize_command("curl -sI https://example.com/.env", finding) == "curl -sI https://app.fixture.invalid/actuator/env"
    assert localize_command("curl -sI https://example.com | grep -i csp", finding) == "curl -sI https://app.fixture.invalid | grep -i csp"
    assert localize_command("dig +short CAA example.com", finding) == "dig +short CAA app.fixture.invalid"
    hostile = {"url": "https://app.fixture.invalid/a'$(id)"}
    assert "'\"'\"'$(id)" in localize_command("curl https://example.com/x", hostile)
    remediation = finding_remediation(finding)
    assert "https://app.fixture.invalid/actuator/env" in remediation["verification"]
    assert "example.com" not in remediation["verification"]


def test_hsts_absence_on_plain_http_is_not_a_finding():
    # The template projection drops an HSTS match on a plain-HTTP URL (one implementation, at
    # template time); the header fold leaves an HTTPS match without a baseline twin alone.
    from api.scan.finalizer import _fold_duplicate_header_findings
    from tests.test_scan_finalizer import _hsts_template_findings
    assert _hsts_template_findings("http://app.fixture.invalid") == ["x-frame-options"]
    assert "strict-transport-security" in _hsts_template_findings("https://app.fixture.invalid")
    https_hsts = {"tool": "nuclei", "url": "https://app.fixture.invalid", "evidence": {
        "template_id": "http-missing-security-headers", "header_name": "strict-transport-security"}}
    assert _fold_duplicate_header_findings([https_hsts]) == [https_hsts]


def test_redacted_query_values_read_as_masked_in_the_brief_and_dates_are_short():
    sqli = build_finding_detail({"tool": "sqlmap", "severity": "high", "proof_state": "candidate",
        "url": "http://s.invalid/product?id=%3Credacted%3E", "evidence": {"url": "http://s.invalid/product?id=%3Credacted%3E", "param": "id"}})
    assert "redacted" not in sqli["summary"] and "id=•••" in sqli["summary"]
    assert "redacted" not in sqli["reproduce"]["command"]
    key = build_finding_detail(_tls("tls_certificate_weak_public_key", certificate={"public_key_type": "RSAPublicKey", "public_key_bits": 1024}))
    assert "1024-bit RSA key" in key["summary"]
    expired = build_finding_detail(_tls("tls_certificate_expired", certificate={"not_after": "2025-01-01T00:00:00+00:00"}))
    assert "expired on 2025-01-01" in expired["summary"] and "T00" not in expired["summary"]


# Unit fixtures below reproduce the stored evidence and sqlmap output of a recorded 2.11.0 scan of
# lab targets (hosts renamed to .invalid). A sqlmap run under --batch prints this prompt before its
# "back-end DBMS:" summary line.
_SQLMAP_DBMS_PROMPT = (
    "it looks like the back-end DBMS is 'SQLite'. Do you want to skip test payloads specific for "
    "other DBMSes? [Y/n] Y"
)


def test_finalizer_takes_the_dbms_from_the_sqlmap_summary_line_not_the_batch_prompt():
    from api.scan.finalizer import _findings_for_action
    from tests.test_scan_finalizer import _result_with_observation_count
    from tests.test_scan_orchestrator import _action
    action = _action("dast.sqli", 0, capability_name="sqli.verify_batch")
    result = _result_with_observation_count(action, 4)
    findings = _findings_for_action(result, [
        {"kind": "sqli_finding", "url": "http://s.invalid/product?id=%3Credacted%3E", "param": "id",
         "message": "GET parameter 'id' is vulnerable."},
        # Recorded by a worker whose parser kept every line that mentioned the DBMS.
        {"kind": "sqli_dbms_fingerprint", "message": _SQLMAP_DBMS_PROMPT},
        {"kind": "sqli_dbms_fingerprint", "message": "[03:35:12] [INFO] the back-end DBMS is SQLite"},
        {"kind": "sqli_dbms_fingerprint", "message": "back-end DBMS: SQLite"},
    ])
    assert findings[0]["evidence"]["dbms"] == "SQLite"
    # Only the prompt: no DBMS is recorded rather than the prompt text.
    result = _result_with_observation_count(action, 2)
    findings = _findings_for_action(result, [
        {"kind": "sqli_finding", "url": "http://s.invalid/product?id=1", "param": "id", "message": "x"},
        {"kind": "sqli_dbms_fingerprint", "message": _SQLMAP_DBMS_PROMPT},
    ])
    assert "dbms" not in findings[0]["evidence"]


def test_sqli_brief_reads_a_stored_sqlmap_prompt_as_the_database_name():
    brief = build_finding_detail({"tool": "sqlmap", "severity": "high", "proof_state": "likely_vulnerable",
        "url": "http://sqli.fixture.invalid/product?id=%3Credacted%3E", "title": "Potential SQL injection",
        "evidence": {"url": "http://sqli.fixture.invalid/product?id=%3Credacted%3E", "param": "id", "method": "GET",
                     "dbms": _SQLMAP_DBMS_PROMPT, "sqlmap_message": "GET parameter 'id' is vulnerable."}})
    database = next(fact["value"] for fact in brief["observed"] if fact["label"] == "Database")
    assert database == "SQLite"
    assert "Do you want" not in json.dumps(brief)


def test_sqlmap_path_marker_brief_quotes_the_segment_and_hides_the_marker():
    # Stored as recorded: the candidate reached sqlmap as /products/1*, and sqlmap names it "#1*".
    url = "http://sqli-path.fixture.invalid/products/1*"
    brief = build_finding_detail({"tool": "sqlmap", "severity": "high", "proof_state": "likely_vulnerable",
        "url": url, "title": "Potential SQL injection", "target_url": "http://sqli-path.fixture.invalid",
        "evidence": {"url": url, "param": "#1*", "method": "GET", "sqlmap_message": "URI parameter '#1*' is vulnerable."}})
    where = {fact["label"]: fact["value"] for fact in brief["where"]}
    assert where["Endpoint"] == "GET http://sqli-path.fixture.invalid/products/1"
    assert where["Parameter"] == "path_2"
    assert "#1*" not in brief["summary"] and "products/1*" not in brief["summary"]
    assert not any("#1*" in step for step in brief["fix"])
    command = brief["reproduce"]["command"]
    assert shlex.split(command)[2] == "http://sqli-path.fixture.invalid/products/1%27"
    assert brief["verify"]["command"] == command


@pytest.mark.parametrize("canonical,quoted", [
    ("/products/{int}", "/products/1%27"),
    ("/orders/{int}/items/{uuid}", "/orders/1/items/00000000-0000-4000-8000-000000000000%27"),
])
def test_verified_path_sqli_brief_quotes_the_segment_with_the_value_the_scan_sent(canonical, quoted):
    field = f"path_{len(canonical.split('/')) - 1}"
    brief = build_finding_detail({"tool": "shakerscan_sqli_proof", "severity": "critical", "proof_state": "verified",
        "url": canonical, "title": "Verified SQL injection", "target_url": "http://sqli-path.fixture.invalid",
        "evidence": {"method": "GET", "field_path": field, "technique": "error_based_repeated", "repetitions": 2,
                     "payload_shape": "<original>'", "request_class": "safe_read", "request_ref_id": None}})
    command = brief["reproduce"]["command"]
    assert shlex.split(command)[2] == "http://sqli-path.fixture.invalid" + quoted
    assert "{" not in command and f"{field}=" not in command


def test_query_proved_nosqli_brief_reproduces_with_query_brackets_not_a_json_body():
    brief = build_finding_detail({"tool": "shakerscan_nosqli_verify", "severity": "high", "proof_state": "verified",
        "url": "/api/users", "title": "Verified NoSQL injection", "target_url": "http://nosqli.fixture.invalid",
        "evidence": {"method": "GET", "field_path": "username", "operator": "$ne", "request_ref_id": None,
                     "request_class": "safe_read", "technique": "operator_equality_complement_differential",
                     "repetitions": 2}})
    words = shlex.split(brief["reproduce"]["command"])
    assert words[:2] == ["curl", "-sS"] and "-d" not in words and "-X" not in words
    sent = next(word for word in words if word.startswith("http"))
    assert sent.startswith("http://nosqli.fixture.invalid/api/users?username%5B%24ne%5D=")
    assert "req.query.username" in brief["examples"][0]["code"]


def test_body_proved_nosqli_brief_keeps_the_json_body_request():
    brief = build_finding_detail({"tool": "shakerscan_nosqli_verify", "severity": "critical", "proof_state": "verified",
        "url": "/api/login", "title": "Verified NoSQL injection authentication bypass",
        "target_url": "http://nosqli.fixture.invalid",
        "evidence": {"method": "POST", "field_path": "password", "operator": "$ne", "request_ref_id": "ref-1",
                     "request_class": "safe_authentication", "repetitions": 2}})
    words = shlex.split(brief["reproduce"]["command"])
    assert words[words.index("-X") + 1] == "POST"
    assert json.loads(words[words.index("-d") + 1]) == {"password": {"$ne": None}}
    assert "req.body.username" in brief["examples"][0]["code"]
