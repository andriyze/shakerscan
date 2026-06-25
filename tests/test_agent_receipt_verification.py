"""R5: cryptographic verification of agent execution receipts.

Beyond field presence, ShakerScan now verifies the receipt content-hash, the
prev_hash chain linkage, and the signature. A forged/tampered/broken-chain or
bad-signature receipt is flagged; a correctly chained+signed set verifies.
"""

import base64
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import ai_gate_scan as ag  # noqa: E402


def _canonical(content):
    return json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)


def _build_receipt(content, prev_hash, priv=None):
    """Build a receipt following ShakerScan's verifiable convention."""
    h = hashlib.sha256(f"{prev_hash}.{_canonical(content)}".encode()).hexdigest()
    receipt = dict(content)
    receipt["prev_hash"] = prev_hash
    receipt["receipt_hash"] = h
    if priv is not None:
        receipt["signature"] = base64.b64encode(priv.sign(h.encode())).decode()
    return receipt, h


def _privileged_content(i, approval):
    return {
        "tool_name": "transfer_funds",
        "approval_id": approval,
        "scope": "tenant-001/account-1",
        "input_hash": f"in{i}",
        "output_hash": f"out{i}",
        "policy_decision": "allow",
        "privileged": True,
    }


def _chain(n, priv=None):
    receipts, prev = [], ""
    for i in range(n):
        r, prev = _build_receipt(_privileged_content(i, f"appr-{i}"), prev, priv=priv)
        receipts.append(r)
    return receipts


def _ids(findings):
    return {f["id"].rsplit(":", 1)[-1] for f in findings}


def test_valid_chain_verifies_with_no_crypto_findings():
    receipts = _chain(3)
    findings, summary = ag._agent_execution_receipt_findings({"agent_execution_receipts": receipts})
    assert findings == [], _ids(findings)
    assert summary["chain_verified"] is True
    assert summary["hash_verified_count"] == 3
    assert summary["hash_mismatch_count"] == 0
    assert summary["chain_break_count"] == 0


def test_tampered_content_breaks_hash():
    receipts = _chain(2)
    receipts[1]["scope"] = "tenant-999/account-evil"  # mutate after hashing
    findings, summary = ag._agent_execution_receipt_findings({"agent_execution_receipts": receipts})
    assert "hash_mismatch" in _ids(findings)
    assert summary["chain_verified"] is False
    assert summary["hash_mismatch_count"] >= 1


def test_broken_chain_is_flagged():
    receipts = _chain(3)
    receipts[2]["prev_hash"] = "0" * 64  # does not link to receipt[1]
    findings, summary = ag._agent_execution_receipt_findings({"agent_execution_receipts": receipts})
    ids = _ids(findings)
    assert "chain_broken" in ids
    assert summary["chain_break_count"] >= 1


def test_presence_checks_still_fire_for_missing_approval():
    # A privileged allow with no approval id and no hashes — pure presence path.
    receipts = [{"tool_name": "delete_db", "policy_decision": "allow", "privileged": True}]
    findings, summary = ag._agent_execution_receipt_findings({"agent_execution_receipts": receipts})
    ids = _ids(findings)
    assert "missing_approval" in ids
    assert summary["available"] is True


def test_valid_signatures_verify():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    receipts = _chain(3, priv=priv)
    findings, summary = ag._agent_execution_receipt_findings({
        "agent_execution_receipts": receipts,
        "receipt_public_key": pub_pem,
    })
    assert "signature_invalid" not in _ids(findings)
    assert summary["signature_verified_count"] == 3
    assert summary["signature_attempted"] is True
    assert summary["chain_verified"] is True


def test_valid_signature_without_trust_anchor_is_consistent_but_untrusted():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    receipts = _chain(3, priv=priv)
    findings, summary = ag._agent_execution_receipt_findings({
        "agent_execution_receipts": receipts, "receipt_public_key": pub_pem,
    })
    # Internally consistent, but self-attested: not trusted provenance.
    assert summary["chain_verified"] is True
    assert summary["chain_trusted"] is False
    assert summary["signature_trusted_root"] is None
    assert "untrusted_signing_key" in _ids(findings)


def test_valid_signature_with_configured_trust_anchor_is_trusted(monkeypatch):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    monkeypatch.setenv("AI_GATE_TRUSTED_RECEIPT_KEY_SHA256", ag._receipt_key_sha256(pub_pem))
    receipts = _chain(3, priv=priv)
    findings, summary = ag._agent_execution_receipt_findings({
        "agent_execution_receipts": receipts, "receipt_public_key": pub_pem,
    })
    assert summary["chain_trusted"] is True
    assert summary["signature_trusted_root"] is True
    assert "untrusted_signing_key" not in _ids(findings)


def test_invalid_signature_is_flagged():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    signer = ed25519.Ed25519PrivateKey.generate()
    other = ed25519.Ed25519PrivateKey.generate()
    pub_pem = other.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    receipts = _chain(2, priv=signer)  # signed with a key that does not match pub_pem
    findings, summary = ag._agent_execution_receipt_findings({
        "agent_execution_receipts": receipts,
        "receipt_public_key": pub_pem,
    })
    assert "signature_invalid" in _ids(findings)
    assert summary["signature_invalid_count"] >= 1
    assert summary["chain_verified"] is False
