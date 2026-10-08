"""Secret fingerprints and secret-bearing body digests are keyed to the installation.

Audit note: the scrypt salt was a published constant, and a fast SHA-256 of the whole leaked
body was stored next to it, so anyone holding the evidence could confirm a guess of a small
leaked file (or of a weak password) offline. Both are now keyed with a private key derived
from the installation's stable credential key: stable across Scans of one installation, so
repeat sightings still deduplicate, and useless for guessing anywhere else.
"""

from __future__ import annotations

import hashlib

import pytest
from cryptography.fernet import Fernet

from api.capabilities import secret_material
from api.capabilities.exposure_probe import classify_exposure

PASSWORD = "Vt9qLx2Rm7Zp4Kw8sJ3n"
DOTENV = f"DB_PASSWORD={PASSWORD}\nAPP_ENV=prod\n".encode()


def _install(monkeypatch, key: str | None, tmp_path=None) -> None:
    """Switch to an installation with credential key ``key`` (None: no stable key at all)."""
    if key is None:
        monkeypatch.delenv("AI_CREDENTIAL_ENC_KEY", raising=False)
        # A key file that cannot be created: the process has no stable key.
        monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY_FILE", "/dev/null/no-such-dir/key")
    else:
        monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", key)
    reset = getattr(secret_material, "_reset_installation_keys", None)
    if reset is not None:
        reset()


@pytest.fixture(autouse=True)
def _forget_keys():
    yield
    reset = getattr(secret_material, "_reset_installation_keys", None)
    if reset is not None:
        reset()


def _published_constant_salt(value: str) -> str:
    return hashlib.scrypt(value.encode(), salt=b"shakerscan-secret-fingerprint/v1\x00",
                          n=2**14, r=8, p=1, dklen=12).hex()


def test_fingerprints_are_stable_within_an_installation_and_differ_across_them(monkeypatch):
    key_a, key_b = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    _install(monkeypatch, key_a)
    first = secret_material.value_fingerprint(PASSWORD)
    _install(monkeypatch, key_a)  # a restart of the same installation
    assert secret_material.value_fingerprint(PASSWORD) == first
    assert first.startswith("scrypt-keyed:")
    _install(monkeypatch, key_b)
    assert secret_material.value_fingerprint(PASSWORD) != first
    # Nobody without the installation key can recompute it from the published salt.
    assert _published_constant_salt(PASSWORD) not in first


def test_without_a_stable_key_fingerprints_are_private_and_say_so(monkeypatch):
    _install(monkeypatch, None)
    fingerprint = secret_material.value_fingerprint(PASSWORD)
    assert fingerprint.startswith("scrypt-ephemeral:")
    assert _published_constant_salt(PASSWORD) not in fingerprint
    assert secret_material.value_fingerprint(PASSWORD) == fingerprint


def test_a_secret_bearing_body_keeps_only_a_keyed_digest(monkeypatch):
    from tests.test_exposure_verified_checks import _finalized, _observation

    key = Fernet.generate_key().decode()
    _install(monkeypatch, key)
    plain = hashlib.sha256(DOTENV).hexdigest()
    observation = _observation("/.env", DOTENV, "text/plain")
    assert observation["response_body_sha256"] is None
    assert str(observation["response_body_hmac"]).startswith("hmac-sha256-keyed:")
    assert plain not in str(observation)
    # The keyed digest is stable within the installation and still promotes the finding.
    assert _observation("/.env", DOTENV, "text/plain")["response_body_hmac"] == \
        observation["response_body_hmac"]
    report = _finalized(observation)
    assert len(report["findings"]) == 1
    evidence = report["findings"][0]["evidence"]
    assert evidence["response_body_hmac"] == observation["response_body_hmac"]
    assert plain not in str(report)
    fingerprints = [item["value_fingerprint"] for item in evidence["exposure_fingerprints"]]
    assert fingerprints and all(item.startswith("scrypt-keyed:") for item in fingerprints)


def test_a_body_without_secret_material_keeps_its_plain_digest():
    from tests.test_exposure_verified_checks import _observation

    body = b"# HELP up 1\n# TYPE up gauge\nup 1\n"
    signature = classify_exposure(path="/metrics", status=200, headers={}, body=body)
    assert signature is not None and signature.exposure_class == "metrics_endpoint"
    observation = _observation("/metrics", body, "text/plain")
    assert observation["response_body_sha256"] == hashlib.sha256(body).hexdigest()
    assert "response_body_hmac" not in observation
