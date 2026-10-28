"""TLS findings report each defect once, with the chain the server sent and checks that can fail.

Unit fixtures: the observation and evidence dictionaries below are shaped like recorded
``tls.inspect`` observations of lab servers (a SHA-1 leaf, an RSA-1024 leaf, a leaf issued by a
private root, servers that also accept RC4/3DES and TLS 1.0). The real-connection tests start a
local TLS server with a generated CA hierarchy.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from api.capabilities import tls
from api.capabilities.tls_legacy_probe import TLS10, TLS12
from api.finding_detail import build_finding_detail
from api.runtime.models import TargetBinding
from api.scan.finding_evidence import tls_finding_evidence
from tests.test_canonical_tls_runtime import _TlsObject, _Writer as _ModernWriter, _target
from tests.test_detect211_tls_legacy import _Reader as _LegacyReader, _Writer as _LegacyWriter

HOST = "app.fixture.invalid"
ORIGIN = f"https://{HOST}:8450/"
# OpenSSL's default security level refuses RSA keys below 2048 bits; the weak fixtures use half.
WEAK_RSA_BITS = 2048 // 2


# ---------------------------------------------------------------- fixtures

def _key(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _cert(subject: str, issuer: str, public_key, signer, *, ca: bool, sans=()):
    """A certificate that also passes strict (RFC 5280) verification, the default from Python 3.13."""
    now = datetime.now(timezone.utc)
    name = lambda cn: x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])  # noqa: E731
    builder = (
        x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer))
        .public_key(public_key).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=200))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
        .add_extension(x509.KeyUsage(
            digital_signature=not ca, content_commitment=False, key_encipherment=not ca,
            data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca,
            encipher_only=False, decipher_only=False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False)
    )
    if not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), False)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), False)
    return builder.sign(signer, hashes.SHA256())


def _hierarchy(*, intermediate_bits=2048):
    root_key, inter_key, leaf_key = _key(), _key(intermediate_bits), _key()
    root = _cert("Fixture Root", "Fixture Root", root_key.public_key(), root_key, ca=True)
    inter = _cert("Fixture Intermediate", "Fixture Root", inter_key.public_key(), root_key, ca=True)
    leaf = _cert(HOST, "Fixture Intermediate", leaf_key.public_key(), inter_key, ca=False, sans=(HOST,))
    return root, inter, leaf, leaf_key


def _pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _inspect_real_server(tmp_path, monkeypatch, *, served, leaf_key, root):
    """Serve ``served`` (leaf first) from a local TLS server whose root the verifier trusts."""
    chain_path, key_path, root_path = tmp_path / "chain.pem", tmp_path / "key.pem", tmp_path / "root.pem"
    chain_path.write_bytes(b"".join(_pem(cert) for cert in served))
    key_path.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    root_path.write_bytes(_pem(root))
    monkeypatch.setenv("SSL_CERT_FILE", str(root_path))

    async def exercise():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.set_ciphers("DEFAULT:@SECLEVEL=0")  # the server under test may serve weak material
        context.load_cert_chain(chain_path, key_path)

        async def connected(_reader, writer):
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass

        server = await asyncio.start_server(connected, "127.0.0.1", 0, ssl=context)
        async with server:
            port = server.sockets[0].getsockname()[1]
            origin = f"https://{HOST}:{port}"
            target = TargetBinding(target_id="fixture", target_kind="web", canonical_host=HOST,
                                   allowed_origins=(origin,), allowed_addresses=("127.0.0.1",),
                                   allowed_root_domains=("fixture.invalid",))
            return await tls.inspect_tls_origin(origin, target=target, timeout_seconds=5, legacy_probes=False)

    return asyncio.run(exercise())


def _findings(observation):
    from api.scan.finalizer import _findings_for_action
    from tests.test_scan_finalizer import _result_with_observation_count
    from tests.test_scan_orchestrator import _action
    action = _action("baseline.tls", 0, capability_name="tls.inspect")
    return _findings_for_action(_result_with_observation_count(action, 1), [observation])


def _observation(**fields):
    return {
        "kind": "tls_protocol", "origin": ORIGIN, "status": "success", "server_hostname": HOST,
        "pinned_address": "10.0.0.5", "port": 8450, "protocol": "TLSv1.2",
        "cipher": "ECDHE-RSA-AES256-GCM-SHA384", "certificate_hostname_matches": True,
        "certificate_issuer": "CN=Fixture Intermediate", "certificate_self_signed": False,
        **fields,
    }


def _brief(check, **evidence):
    return build_finding_detail({
        "title": "x", "severity": "medium", "tool": "tls.inspect", "proof_state": "verified", "url": ORIGIN,
        "evidence": {"check": check, "origin": ORIGIN, "port": 8450, "pinned_address": "10.0.0.5",
                     "requested_host": HOST, **evidence},
    })


# ---------------------------------------------- one defect, one finding

@pytest.mark.parametrize("code,failure", [(66, "weak_key"), (67, "weak_key"), (68, "weak_signature")])
def test_verifier_refusals_for_weak_algorithms_are_named(code, failure):
    error = ssl.SSLCertVerificationError(1, "fixture")
    error.verify_code, error.verify_message = code, "fixture verifier message"
    assert tls._trust_error(error)["certificate_trust_failure"] == failure


@pytest.mark.parametrize("fields,title", [
    # A SHA-1 leaf under a trusted intermediate: verify code 68, "CA signature digest algorithm too weak".
    ({"certificate_weak_signature": True, "certificate_signature_hash": "sha1",
      "certificate_trust_error_code": 68, "certificate_trust_error": "CA signature digest algorithm too weak"},
     "TLS certificate uses a weak signature"),
    # An RSA-1024 leaf: verify code 66, "EE certificate key too weak". The verifier refuses the
    # key before it builds the chain; judged on its own, the chain is trusted.
    ({"certificate_weak_public_key": True, "certificate_public_key_bits": 1024,
      "certificate_public_key_type": "RSAPublicKey",
      "certificate_trust_error_code": 66, "certificate_trust_error": "EE certificate key too weak",
      "certificate_chain_trust": "trusted"},
     "TLS certificate uses a weak public key"),
])
def test_a_leaf_weakness_the_verifier_refused_is_reported_once(fields, title):
    findings = _findings(_observation(certificate_trust="untrusted", certificate_trust_failure="other", **fields))
    assert [finding["title"] for finding in findings] == [title]


@pytest.mark.parametrize("fields", [
    # 67: an issuer's key; no leaf finding explains it.
    {"certificate_trust_error_code": 67},
    # 68 from an intermediate: the leaf itself is SHA-256.
    {"certificate_trust_error_code": 68, "certificate_signature_hash": "sha256"},
    # A self-signed 1024-bit leaf: OpenSSL stops at the key (66) before it builds the chain, and
    # only the untrusted finding says that no CA vouches for it.
    {"certificate_trust_error_code": 66, "certificate_weak_public_key": True, "certificate_self_signed": True,
     "certificate_chain_trust": "untrusted", "certificate_chain_trust_error_code": 18},
    # A 1024-bit leaf from a CA the verifier does not know: the key and the chain both fail.
    {"certificate_trust_error_code": 66, "certificate_weak_public_key": True,
     "certificate_chain_trust": "untrusted", "certificate_chain_trust_error_code": 20,
     "certificate_chain_trust_failure": "issuer_not_found"},
    # A 1024-bit leaf whose chain was not judged on its own (an observation recorded before it was,
    # or a handshake that did not complete): trust was never established, so the finding stays.
    {"certificate_trust_error_code": 66, "certificate_weak_public_key": True},
    {"certificate_trust_error_code": 66, "certificate_weak_public_key": True,
     "certificate_chain_trust": "not_evaluated"},
    # Any other refusal.
    {"certificate_trust_error_code": 20, "certificate_weak_signature": True},
])
def test_a_refusal_no_leaf_finding_explains_stays_reported(fields):
    titles = [finding["title"] for finding in _findings(_observation(certificate_trust="untrusted", **fields))]
    assert "TLS certificate chain is not trusted" in titles


def test_a_kept_strength_refusal_names_the_weak_issuer():
    brief = _brief("tls_certificate_untrusted", chain_status="peer_chain", chain_length=2,
        certificate={"issuer_cn": "Fixture Intermediate", "signature_hash": "sha256"},
        chain=[{"subject": f"CN={HOST}"}, {"subject": "CN=Fixture Intermediate", "public_key_bits": 1024,
               "public_key_type": "RSAPublicKey", "weak_public_key": True}],
        trust={"result": "untrusted", "failure": "weak_key", "error_code": 67, "error": "CA certificate key too weak"})
    assert "a key smaller than the verifier accepts" in brief["summary"]
    assert "CN=Fixture Intermediate uses a 1024-bit RSA key." in brief["fix"]
    # A row recorded before the codes had names still gets the specific fix.
    old = _brief("tls_certificate_untrusted", chain_status="peer_chain", chain_length=2,
        certificate={"signature_hash": "sha256"},
        chain=[{"subject": f"CN={HOST}"}, {"subject": "CN=Fixture Intermediate", "signature_hash": "sha1",
               "weak_signature": True}],
        trust={"result": "untrusted", "failure": "other", "error_code": 68})
    assert "CN=Fixture Intermediate is signed with SHA1." in old["fix"]


def test_weak_signature_and_key_checks_print_the_weakness():
    signature = _brief("tls_certificate_weak_signature", certificate={"signature_hash": "sha1"},
                       trust={"result": "untrusted", "failure": "weak_signature", "error_code": 68,
                              "error": "CA signature digest algorithm too weak"})
    assert "openssl x509 -noout -text" in signature["reproduce"]["command"]
    assert "Signature Algorithm" in signature["reproduce"]["command"]
    assert "Signature Algorithm" in signature["verify"]["command"] and "sha1" in signature["verify"]["expect"]
    assert any("code 68" in line for line in signature["context"])
    key = _brief("tls_certificate_weak_public_key", certificate={"public_key_bits": 1024, "public_key_type": "RSAPublicKey"},
                 trust={"result": "untrusted", "failure": "weak_key", "error_code": 66, "error": "EE certificate key too weak"})
    assert "Public-Key" in key["reproduce"]["command"] and "-text" in key["reproduce"]["command"]
    assert "2048 bit" in key["verify"]["expect"]
    assert any("before it builds the chain" in line for line in key["context"])


def _weak_leaf_hierarchy():
    """An RSA-1024 server certificate issued by a 2048-bit intermediate under its own root."""
    root_key, inter_key, leaf_key = _key(), _key(), _key(WEAK_RSA_BITS)
    root = _cert("Fixture Root", "Fixture Root", root_key.public_key(), root_key, ca=True)
    inter = _cert("Fixture Intermediate", "Fixture Root", inter_key.public_key(), root_key, ca=True)
    leaf = _cert(HOST, "Fixture Intermediate", leaf_key.public_key(), inter_key, ca=False, sans=(HOST,))
    return root, inter, leaf, leaf_key


def _weak_leaf_inspection(tmp_path, monkeypatch, *, issuer_trusted):
    root, inter, leaf, leaf_key = _weak_leaf_hierarchy()
    trusted = root
    if not issuer_trusted:  # the verifier trusts only a root that did not issue this chain
        other_key = _key()
        trusted = _cert("Unrelated Root", "Unrelated Root", other_key.public_key(), other_key, ca=True)
    observation = _inspect_real_server(tmp_path, monkeypatch, served=(leaf, inter), leaf_key=leaf_key,
                                       root=trusted)["observation"]
    if observation.get("certificate_trust_error_code") != 66:
        pytest.skip("this OpenSSL accepts 1024-bit server keys at the default security level")
    return observation


def test_a_weak_leaf_from_an_unknown_ca_keeps_the_untrusted_chain_finding(tmp_path, monkeypatch):
    observation = _weak_leaf_inspection(tmp_path, monkeypatch, issuer_trusted=False)
    assert observation["certificate_chain_trust"] == "untrusted"
    assert observation["certificate_chain_trust_error_code"] == 20
    assert observation["certificate_chain_trust_failure"] == "issuer_not_found"
    findings = _findings(observation)
    titles = [finding["title"] for finding in findings]
    assert "TLS certificate chain is not trusted" in titles
    assert "TLS certificate uses a weak public key" in titles
    untrusted = next(item for item in findings if item["title"] == "TLS certificate chain is not trusted")
    brief = build_finding_detail(untrusted)
    # The chain's own failure (a private CA or missing intermediate), with the key as a second line.
    assert "neither sent by the server nor found in the trust store" in brief["summary"]
    assert any("also below the verifier's minimum" in line for line in brief["fix"])
    weak = build_finding_detail(next(item for item in findings if item["title"] == "TLS certificate uses a weak public key"))
    assert any("the chain is not trusted either" in line for line in weak["context"])


def test_a_weak_leaf_from_a_trusted_ca_is_reported_once(tmp_path, monkeypatch):
    observation = _weak_leaf_inspection(tmp_path, monkeypatch, issuer_trusted=True)
    assert observation["certificate_chain_trust"] == "trusted"
    findings = _findings(observation)
    assert [finding["title"] for finding in findings] == ["TLS certificate uses a weak public key"]
    weak = build_finding_detail(findings[0])
    assert any("the chain reaches a trusted root" in line for line in weak["context"])


def test_a_weak_leaf_under_a_weak_intermediate_keeps_the_finding_that_names_it(tmp_path, monkeypatch):
    """The chain check runs with every strength check off, so a 1024-bit intermediate under a
    trusted root reads trusted there. It is weak all the same: clients refuse it once the server
    key is replaced, and only the untrusted-chain finding names it."""
    root_key, inter_key, leaf_key = _key(), _key(WEAK_RSA_BITS), _key(WEAK_RSA_BITS)
    root = _cert("Fixture Root", "Fixture Root", root_key.public_key(), root_key, ca=True)
    inter = _cert("Fixture Intermediate", "Fixture Root", inter_key.public_key(), root_key, ca=True)
    leaf = _cert(HOST, "Fixture Intermediate", leaf_key.public_key(), inter_key, ca=False, sans=(HOST,))
    observation = _inspect_real_server(tmp_path, monkeypatch, served=(leaf, inter), leaf_key=leaf_key,
                                       root=root)["observation"]
    if observation.get("certificate_trust_error_code") != 66:
        pytest.skip("this OpenSSL accepts 1024-bit server keys at the default security level")
    assert observation["certificate_chain_trust"] == "trusted"
    assert [link["weak_public_key"] for link in observation["certificate_chain_details"]] == [True, True]
    findings = _findings(observation)
    titles = [finding["title"] for finding in findings]
    assert "TLS certificate uses a weak public key" in titles
    assert "TLS certificate chain is not trusted" in titles
    untrusted = build_finding_detail(next(item for item in findings if item["title"] == "TLS certificate chain is not trusted"))
    assert "CN=Fixture Intermediate uses a 1024-bit RSA key." in untrusted["fix"]
    assert any("also below the verifier's minimum" in line for line in untrusted["fix"])
    weak = build_finding_detail(next(item for item in findings if item["title"] == "TLS certificate uses a weak public key"))
    assert not any(line.endswith("Judged on its own, the chain reaches a trusted root.") for line in weak["context"])
    assert any("an issuing certificate in it is weak too" in line for line in weak["context"])


def _weak_leaf_trusted_chain(*issuers):
    """A weak-key leaf whose chain, judged with the strength checks off, is trusted (unit fixture)."""
    leaf = {"subject": f"CN={HOST}", "issuer": "CN=Fixture Intermediate", "public_key_type": "RSAPublicKey",
            "public_key_bits": 1024, "weak_public_key": True, "weak_signature": False, "self_signed": False}
    return _observation(
        certificate_trust="untrusted", certificate_trust_error_code=66, certificate_trust_failure="other",
        certificate_trust_error="ee key too small", certificate_weak_public_key=True, certificate_public_key_bits=1024,
        certificate_public_key_type="RSAPublicKey", certificate_chain_trust="trusted",
        certificate_chain_details=[leaf, *issuers],
    )


@pytest.mark.parametrize("issuer,kept,named", [
    # An intermediate signed with SHA-1: kept, and named.
    ({"subject": "CN=Fixture Intermediate", "issuer": "CN=Fixture Root", "signature_hash": "sha1",
      "public_key_bits": 2048, "public_key_type": "RSAPublicKey", "weak_public_key": False,
      "weak_signature": True, "self_signed": False}, True, "CN=Fixture Intermediate is signed with SHA1."),
    # A sound intermediate: folded into the weak-key finding.
    ({"subject": "CN=Fixture Intermediate", "issuer": "CN=Fixture Root", "signature_hash": "sha256",
      "public_key_bits": 2048, "public_key_type": "RSAPublicKey", "weak_public_key": False,
      "weak_signature": False, "self_signed": False}, False, None),
    # A root the server also sent, self-signed with SHA-1: its own signature is never checked.
    ({"subject": "CN=Fixture Root", "issuer": "CN=Fixture Root", "signature_hash": "sha1",
      "public_key_bits": 2048, "public_key_type": "RSAPublicKey", "weak_public_key": False,
      "weak_signature": True, "self_signed": True}, False, None),
])
def test_a_trusted_chain_with_a_weak_issuer_keeps_the_untrusted_finding(issuer, kept, named):
    findings = _findings(_weak_leaf_trusted_chain(issuer))
    titles = [finding["title"] for finding in findings]
    assert ("TLS certificate chain is not trusted" in titles) is kept
    assert "TLS certificate uses a weak public key" in titles
    if named:
        untrusted = build_finding_detail(next(item for item in findings if item["title"] == "TLS certificate chain is not trusted"))
        assert named in untrusted["fix"]


def test_the_chain_check_stays_within_the_pairs_four_handshakes(tmp_path, monkeypatch):
    from api.scan.capability_execution import TLS_HANDSHAKE_CONNECTIONS_PER_PAIR

    root, inter, leaf, leaf_key = _weak_leaf_hierarchy()
    result = _inspect_real_server(tmp_path, monkeypatch, served=(leaf, inter), leaf_key=leaf_key, root=root)
    if result["observation"].get("certificate_trust_error_code") != 66:
        pytest.skip("this OpenSSL accepts 1024-bit server keys at the default security level")
    # TLS 1.2, TLS 1.3, the trust handshake and the chain check; legacy probes are off here.
    assert result["budget_consumed"]["tcp_ports_attempted"] == 4 <= TLS_HANDSHAKE_CONNECTIONS_PER_PAIR


def test_a_weak_intermediate_key_on_a_real_connection_is_named(tmp_path, monkeypatch):
    root, inter, leaf, leaf_key = _hierarchy(intermediate_bits=WEAK_RSA_BITS)
    result = _inspect_real_server(tmp_path, monkeypatch, served=(leaf, inter), leaf_key=leaf_key, root=root)
    observation = result["observation"]
    if observation.get("certificate_trust") != "untrusted":
        pytest.skip("this OpenSSL accepts 1024-bit CA keys at the default security level")
    assert observation["certificate_trust_error_code"] == 67
    assert observation["certificate_trust_failure"] == "weak_key"
    chain = observation["certificate_chain_details"]
    assert [link["weak_public_key"] for link in chain] == [False, True]
    findings = _findings(observation)
    assert [finding["title"] for finding in findings] == ["TLS certificate chain is not trusted"]
    brief = build_finding_detail(findings[0])
    assert "CN=Fixture Intermediate uses a 1024-bit RSA key." in brief["fix"]


# ------------------------------------------- the chain the server sent

class _Python312Chain:
    """``_ssl._SSLSocket`` on Python 3.10-3.12: the chain loader exists only here."""

    def __init__(self, certificates):
        self.certificates = certificates

    def get_unverified_chain(self):
        return [_PemCertificate(raw) for raw in self.certificates]


class _PemCertificate:
    def __init__(self, raw):
        self.raw = raw

    def public_bytes(self):
        return ssl.DER_cert_to_PEM_cert(self.raw)  # the private object's default encoding is PEM


class _Python312TlsObject(_TlsObject):
    def __init__(self, leaf, chain):
        self.leaf, self._sslobj = leaf, _Python312Chain(chain)

    def getpeercert(self, *, binary_form=False):
        return self.leaf if binary_form else {}


def _fake_connections(monkeypatch, tls_object):
    class Writer(_ModernWriter):
        def get_extra_info(self, name):
            return tls_object if name == "ssl_object" else None

    async def fake_open_connection(**kwargs):
        if kwargs.get("ssl") is None:
            raise ConnectionRefusedError("no legacy service")
        return object(), Writer()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)


def test_the_served_chain_is_read_where_python_3_12_keeps_it(monkeypatch):
    _root, inter, leaf, _key_ = _hierarchy()
    der = [cert.public_bytes(serialization.Encoding.DER) for cert in (leaf, inter)]
    _fake_connections(monkeypatch, _Python312TlsObject(der[0], der))
    observation = asyncio.run(tls.inspect_tls_origin("https://app.example.test", target=_target(),
                                                     timeout_seconds=15))["observation"]
    assert observation["certificate_chain_length"] == 2
    assert observation["certificate_chain_status"] == "peer_chain"
    assert [link["subject_cn"] for link in observation["certificate_chain_details"]] == [HOST, "Fixture Intermediate"]


def test_a_chain_this_runtime_cannot_read_is_not_counted(monkeypatch):
    _root, _inter, leaf, _key_ = _hierarchy()
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)

    class NoChainLoader(_TlsObject):
        def getpeercert(self, *, binary_form=False):
            return leaf_der if binary_form else {}

    _fake_connections(monkeypatch, NoChainLoader())
    observation = asyncio.run(tls.inspect_tls_origin("https://app.example.test", target=_target(),
                                                     timeout_seconds=15))["observation"]
    assert observation["certificate_chain_status"] == "not_captured"
    brief = _brief("tls_certificate_untrusted", chain_status="not_captured", chain_length=1,
                   certificate={"issuer_cn": "Fixture Intermediate"},
                   trust={"result": "untrusted", "failure": "issuer_not_found", "error_code": 20})
    assert not any(fact["label"] == "Certificates sent by the server" for fact in brief["observed"])
    assert not any("The server sent" in line for line in brief["fix"])


def test_a_full_chain_on_a_real_connection_is_counted(tmp_path, monkeypatch):
    root, inter, leaf, leaf_key = _hierarchy()
    observation = _inspect_real_server(tmp_path, monkeypatch, served=(leaf, inter), leaf_key=leaf_key,
                                       root=root)["observation"]
    assert observation["certificate_trust"] == "trusted"
    assert (observation["certificate_chain_length"], observation["certificate_chain_status"]) == (2, "peer_chain")
    leaf_only = _inspect_real_server(tmp_path, monkeypatch, served=(leaf,), leaf_key=leaf_key,
                                     root=root)["observation"]
    assert (leaf_only["certificate_chain_length"], leaf_only["certificate_chain_status"]) == (1, "leaf_only")
    assert leaf_only["certificate_trust_failure"] == "issuer_not_found"


def test_the_untrusted_reproduce_lists_the_served_chain():
    brief = _brief("tls_certificate_untrusted", chain_status="leaf_only", chain_length=1,
                   certificate={"issuer_cn": "Fixture Intermediate"},
                   trust={"result": "untrusted", "failure": "issuer_not_found", "error_code": 20})
    assert "Certificate chain" in brief["reproduce"]["command"]


# ----------------------------------------------- unknown root guidance

def test_an_issuer_without_a_download_location_gets_both_causes():
    # A leaf issued directly by a private root, served alone: verify code 20.
    brief = _brief("tls_certificate_untrusted", chain_status="leaf_only", chain_length=1,
                   certificate={"issuer_cn": "Fixture Private Root", "issuer": "CN=Fixture Private Root"},
                   chain=[{"subject": f"CN={HOST}", "issuer_cn": "Fixture Private Root"}],
                   trust={"result": "untrusted", "failure": "issuer_not_found", "error_code": 20,
                          "error": "unable to get local issuer certificate"})
    fix = " ".join(brief["fix"])
    assert "Fixture Private Root" in fix
    assert "CA the clients do not trust" in fix and "Sending a root in the chain does not make it trusted" in fix
    assert "usually a missing intermediate" not in brief["summary"]


# --------------------------------------------------- weak cipher suites

# A server whose normal handshake negotiates ECDHE-RSA-AES256-GCM-SHA384 and which also accepts
# ECDHE-RSA-RC4-SHA (128 bits) and ECDHE-RSA-DES-CBC3-SHA (112 bits) at TLS 1.2.
WEAK_CIPHER_OBSERVATION = _observation(
    cipher="ECDHE-RSA-AES256-GCM-SHA384", cipher_bits=256, cipher_protocol="TLSv1.2",
    supported_protocols=["TLSv1.2"], weak_cipher=True,
    weak_ciphers_supported=["ECDHE-RSA-RC4-SHA", "ECDHE-RSA-DES-CBC3-SHA"],
    weak_cipher_probes=[
        {"group": "rc4", "supported": True, "result": "accepted", "negotiated_protocol": "TLSv1.2",
         "cipher": "ECDHE-RSA-RC4-SHA", "cipher_bits": 128, "weakness": "rc4"},
        {"group": "des_3des", "supported": True, "result": "accepted", "negotiated_protocol": "TLSv1.2",
         "cipher": "ECDHE-RSA-DES-CBC3-SHA", "cipher_bits": 112, "weakness": "3des"},
        {"group": "null_export_anonymous", "supported": False, "result": "refused"},
    ],
)


def test_the_weak_suite_carries_its_own_bits_and_protocol():
    evidence = tls_finding_evidence(WEAK_CIPHER_OBSERVATION, [], check="tls_weak_cipher")
    assert evidence["cipher"] == "ECDHE-RSA-RC4-SHA"
    assert evidence["cipher_bits"] == 128 and evidence["cipher_protocol"] == "TLSv1.2"
    assert evidence["negotiated_cipher"] == "ECDHE-RSA-AES256-GCM-SHA384"


def test_the_weak_cipher_check_offers_the_suites_itself():
    finding = _findings(WEAK_CIPHER_OBSERVATION)
    brief = build_finding_detail(next(item for item in finding if item["evidence"]["check"] == "tls_weak_cipher"))
    verify = brief["verify"]
    # `openssl s_client -cipher RC4-...` fails locally with "no cipher match" on an OpenSSL without
    # RC4, which the old grep read the same as a server that refuses RC4.
    assert "s_client" not in verify["command"] and verify["command"].startswith("nmap --script ssl-enum-ciphers")
    assert "RC4" in verify["command"] and "RC4" in verify["expect"]


def test_protocols_the_raw_probes_saw_accepted_are_listed_with_the_modern_ones(monkeypatch):
    async def fake_open_connection(**kwargs):
        if kwargs.get("ssl") is not None:
            return object(), _ModernWriter()
        writer = _LegacyWriter({TLS10, TLS12}, {0xC02F, 0x0005})
        return _LegacyReader(writer), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    observation = asyncio.run(tls.inspect_tls_origin("https://app.example.test", target=_target(),
                                                     timeout_seconds=15))["observation"]
    assert observation["legacy_protocols_supported"] == ["TLSv1"]
    assert observation["supported_protocols"] == ["TLSv1", "TLSv1.2", "TLSv1.3"]


def test_refused_versions_exclude_the_scans_own_fallback_label():
    brief = _brief("tls_legacy_protocol", protocol="TLSv1", legacy_protocols_supported=["TLSv1"], protocol_attempts=[
        {"protocol": "TLSv1.2", "supported": False}, {"protocol": "TLSv1.3", "supported": False},
        {"protocol": "default_negotiation", "supported": False}],
        legacy_protocol_probes=[{"protocol": "SSLv3", "supported": False}, {"protocol": "TLSv1", "supported": True}])
    refused = next(fact["value"] for fact in brief["observed"] if fact["label"] == "Protocol versions refused")
    assert refused == "SSLv3, TLSv1.2, TLSv1.3"
