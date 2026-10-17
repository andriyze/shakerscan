from __future__ import annotations

from copy import deepcopy
import asyncio
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from api.agent_tools import parse_scanner_output
from api.capabilities import tls
from api.scan.finding_evidence import template_classification, tls_finding_evidence
from api.scan.severity_calibration import calibrate_finding, current_rule_severity


def test_extractor_metadata_never_copies_a_secret_or_a_prefix():
    secret = "fixture-password-short-or-long"
    result = parse_scanner_output("nuclei", json.dumps({
        "template-id": "fixture", "matched-at": "https://app.example.test/",
        "info": {"name": "Fixture", "severity": "high", "classification": {
            "cve-id": ["CVE-2026-12345"], "cwe-id": ["CWE-200"], "cvss-score": 7.5}},
        "extracted-results": [secret, "pw"],
    }))
    serialized = json.dumps(result)
    assert secret not in serialized and "fixture-pass" not in serialized
    assert '"pw"' not in serialized
    item = result["records"][0]
    evidence = template_classification(item)
    assert evidence["extracted_result_lengths"] == [len(secret), 2]
    assert evidence["cve_ids"] == ["CVE-2026-12345"]
    assert evidence["cvss_score"] == 7.5
    assert "extracted_results" not in template_classification({"extracted_results": [secret]})


@pytest.mark.parametrize("value", [float("inf"), float("nan"), -1, True, 11, "invalid"])
def test_invalid_template_scores_are_not_public_json(value):
    evidence = template_classification({"cvss_score": value, "epss_score": value})
    assert "cvss_score" not in evidence and "epss_score" not in evidence
    json.dumps(evidence, allow_nan=False)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "93.184.215.14"])
def test_tls_severity_does_not_disappear_on_private_assets_and_is_idempotent(address):
    finding = {"severity": "high", "cvss_score": 8.0, "tool": "tls.inspect",
               "verified": True, "proof_state": "verified", "evidence": {
                   "check": "tls_certificate_hostname_mismatch", "requested_host": address,
                   "pinned_address": address}}
    calibrate_finding(finding)
    assert finding["severity"] == "medium" and finding["cvss_score"] == 5.5
    assert finding["verified"] is True and finding["proof_state"] == "verified"
    assert finding["evidence"]["severity_basis"]["producer_severity"] == "high"
    before = deepcopy(finding)
    assert calibrate_finding(finding) == before
    assert current_rule_severity(finding) == before["evidence"]["severity_basis"]
    assert finding == before


def test_proven_exposure_secret_keeps_its_severity():
    finding = {"tool": "shakerscan_exposure_probe", "severity": "high", "evidence": {
        "exposure_class": "directory_listing", "exposure_fingerprints": [{"category": "provider_secret"}]}}
    assert calibrate_finding(finding)["severity"] == "high"


def test_tls_guidance_matches_the_check_and_keeps_legacy_findings_useful():
    from scanner.scanner_tools.remediation_kb import match_remediation
    mismatch, source = match_remediation({'tool': 'tls.inspect', 'title': 'unhelpful title',
        'evidence': {'check': 'tls_certificate_hostname_mismatch'}})
    assert source == 'finding_type'
    assert 'subjectAltName' in ' '.join(mismatch['remediation_steps'])
    untrusted, source = match_remediation({'tool': 'tls.inspect',
        'title': 'TLS certificate chain is not trusted', 'evidence': {}})
    assert source == 'finding_type'
    assert 'intermediates' in ' '.join(untrusted['remediation_steps'])
    assert 'do not disable verification' in ' '.join(untrusted['remediation_steps'])


def test_certificate_names_dates_chain_and_trust_reason_survive_projection():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "fixture.invalid")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=3))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("fixture.invalid"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    raw = cert.public_bytes(serialization.Encoding.DER)
    details = tls._certificate_details(raw, hostname="127.0.0.1", chain_certificates=(raw,))
    assert details["certificate_hostname_matches"] is True
    assert details["certificate_ip_addresses"] == ["127.0.0.1"]
    observation = {"server_hostname": "127.0.0.1", **details,
                   "certificate_trust": "untrusted", "certificate_trust_failure": "self_signed"}
    evidence = tls_finding_evidence(observation, [], check="tls_certificate_untrusted")
    assert evidence["certificate"]["subject_cn"] == "fixture.invalid"
    assert evidence["certificate"]["public_key_bits"] == 2048
    assert evidence["chain"][0]["subject_cn"] == "fixture.invalid"
    assert evidence["trust"]["failure"] == "self_signed"
    assert tls._hostname_matches("127.0.0.1", ("127.0.0.1",), ()) is False
    assert tls._hostname_matches("fixture.invalid", (), ()) is False
    assert tls._hostname_matches("a.b.fixture.invalid", ("*.fixture.invalid",), ()) is False


def test_openssl_trust_codes_use_the_current_issuer_and_ca_errors():
    for code, reason in [(24, "issuer_public_key_missing"), (79, "invalid_ca"), (20, "issuer_not_found")]:
        error = ssl.SSLCertVerificationError(1, "fixture")
        error.verify_code, error.verify_message = code, "fixture validation reason"
        assert tls._trust_error(error)["certificate_trust_failure"] == reason


def test_trusted_chain_and_wrong_hostname_are_independent_on_a_real_tls_connection(tmp_path, monkeypatch):
    from api.runtime.models import TargetBinding
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "fixture.invalid")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(2)
            .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("fixture.invalid")]), False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    monkeypatch.setenv('SSL_CERT_FILE', str(cert_path))

    async def exercise():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        async def connected(_reader, writer):
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass
        server = await asyncio.start_server(connected, '127.0.0.1', 0, ssl=context)
        async with server:
            port = server.sockets[0].getsockname()[1]
            origin = f'https://wrong.fixture.invalid:{port}'
            target = TargetBinding(target_id='fixture', target_kind='web',
                canonical_host='wrong.fixture.invalid', allowed_origins=(origin,),
                allowed_addresses=('127.0.0.1',), allowed_root_domains=('fixture.invalid',))
            result = await tls.inspect_tls_origin(origin, target=target, timeout_seconds=5)
            assert result['status'] == 'success'
            observation = result['observation']
            assert observation['certificate_trust'] == 'trusted'
            assert observation['certificate_hostname_matches'] is False
            assert observation['certificate_chain_details'][0]['subject_cn'] == 'fixture.invalid'
    asyncio.run(exercise())


def test_finalizer_persists_certificate_details_and_calibrated_severity_with_the_receipt():
    from api.scan.finalizer import _findings_for_action
    from tests.test_scan_finalizer import _result_with_observation_count
    from tests.test_scan_orchestrator import _action
    action = _action('baseline.tls', 0, capability_name='tls.inspect')
    result = _result_with_observation_count(action, 1)
    findings = _findings_for_action(result, [{
        'kind': 'tls_protocol', 'origin': 'https://fixture.invalid', 'status': 'success',
        'server_hostname': 'fixture.invalid', 'certificate_hostname_matches': False,
        'certificate_issuer': 'CN=Fixture Issuer', 'certificate_dns_names': ['other.invalid'],
        'certificate_not_after': '2026-01-01',
    }])
    assert len(findings) == 1
    finding = findings[0]
    assert finding['severity'] == 'medium'
    assert finding['proof_state'] == 'verified'
    assert finding['evidence']['certificate']['issuer'] == 'CN=Fixture Issuer'
    assert finding['evidence']['severity_basis']['producer_severity'] == 'high'
    assert finding['evidence']['capability_receipt']
