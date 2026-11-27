"""
JWT attack suite tests for scanner_tools/active_checks.

Covers the pure-python JWT forgery helpers, the weak-HS256-key dictionary
attack, the bounded kid-header injection check (SQLi / SSRF / kid-swap
confusion), and a regression test for the RS256->HS256 algorithm confusion
check. HTTP replay is mocked by monkeypatching active_checks.run with an
oracle that validates Bearer tokens with a known server-side HMAC secret.
"""

import asyncio
import json
import sys
import os
from types import SimpleNamespace

import pytest

# Add scanner directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scanner'))

import scanner_tools.active_checks as active_checks  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bearer_token(cmd) -> str | None:
    for i, part in enumerate(cmd):
        if part == "-H" and i + 1 < len(cmd):
            value = str(cmd[i + 1])
            if value.startswith("Authorization: Bearer "):
                return value[len("Authorization: Bearer "):]
    return None


def _make_jwt_oracle_run(server_secret: str = "secret", jwks_body: str | None = None):
    """Fake `run` that acts as a JWT-validating server.

    Status-code probes (curl -w '%{http_code}') get 200 for tokens whose
    HMAC signature verifies against server_secret, 401 otherwise. Other
    requests (JWKS discovery/fetch) optionally serve jwks_body.
    """
    calls: list[list[str]] = []

    async def fake_run(cmd, timeout=10):
        calls.append(cmd)
        if "-w" in cmd and "%{http_code}" in cmd:
            token = _bearer_token(cmd)
            if token and active_checks._jwt_hmac_verify(token, server_secret):
                return "200", "", 0
            return "401", "", 0
        if jwks_body is not None and any(
            str(part).endswith(("/.well-known/jwks.json", "/jwks.json"))
            for part in cmd
        ):
            return jwks_body, "", 0
        return "", "", 0

    return fake_run, calls


def _probe_calls(calls) -> list[list[str]]:
    return [cmd for cmd in calls if "-w" in cmd and "%{http_code}" in cmd]


def _hs256_token(secret: str, payload: dict | None = None, header: dict | None = None) -> str:
    return active_checks._jwt_hmac_token(
        header or {"alg": "HS256", "typ": "JWT", "kid": "key-1"},
        payload or {"sub": "user-1", "role": "user"},
        secret,
        "HS256",
    )


# ---------------------------------------------------------------------------
# Token crafting correctness (pure-python HMAC)
# ---------------------------------------------------------------------------

def test_jwt_hmac_token_structure_and_signature():
    token = _hs256_token("secret")

    parts = token.split(".")
    assert len(parts) == 3 and all(parts)

    header, payload, signature = active_checks._decode_jwt_parts(token)
    assert header["alg"] == "HS256"
    assert header["typ"] == "JWT"
    assert header["kid"] == "key-1"
    assert payload == {"sub": "user-1", "role": "user"}

    assert active_checks._jwt_hmac_verify(token, "secret")
    assert not active_checks._jwt_hmac_verify(token, "wrong-secret")
    tampered = f"{parts[0]}.{parts[1]}.{parts[2][:-1]}{'A' if parts[2][-1] != 'A' else 'B'}"
    assert not active_checks._jwt_hmac_verify(tampered, "secret")


def test_jwt_hmac_token_supports_hs384_hs512_and_rejects_asymmetric():
    for alg in ("HS384", "HS512"):
        token = active_checks._jwt_hmac_token(
            {"typ": "JWT"}, {"sub": "u"}, "secret", alg
        )
        header, _, _ = active_checks._decode_jwt_parts(token)
        assert header["alg"] == alg
        assert active_checks._jwt_hmac_verify(token, "secret", alg)
        assert not active_checks._jwt_hmac_verify(token, "secret", "HS256")

    with pytest.raises(ValueError):
        active_checks._jwt_hmac_token({"typ": "JWT"}, {"sub": "u"}, "secret", "RS256")
    assert not active_checks._jwt_hmac_verify(_hs256_token("secret"), "secret", "RS256")


def test_jwt_hmac_token_verifies_against_hmac_directly():
    import base64 as _b64
    import hashlib as _hashlib
    import hmac as _hmac

    token = _hs256_token("your-256-bit-secret")
    header_b64, payload_b64, signature_b64 = token.split(".")
    expected_signature = _b64.urlsafe_b64encode(
        _hmac.new(
            b"your-256-bit-secret",
            f"{header_b64}.{payload_b64}".encode(),
            _hashlib.sha256,
        ).digest()
    ).rstrip(b"=").decode()
    assert signature_b64 == expected_signature


# ---------------------------------------------------------------------------
# Weak-secret dictionary attack
# ---------------------------------------------------------------------------

def test_weak_secret_bruteforce_finds_curated_secret_and_honors_discovered_alg():
    token = _hs256_token("your-256-bit-secret")
    result = active_checks.jwt_weak_secret_bruteforce(
        token, ["secret", "your-256-bit-secret", "jwt"]
    )
    assert result["vulnerable"] is True
    assert result["secret"] == "your-256-bit-secret"
    assert result["alg"] == "HS256"
    assert result["issues"] == ["weak_secret"]

    hs384 = active_checks._jwt_hmac_token({"typ": "JWT"}, {"sub": "u"}, "jwt_secret", "HS384")
    result384 = active_checks.jwt_weak_secret_bruteforce(hs384, ["jwt_secret"])
    assert result384["vulnerable"] is True
    assert result384["alg"] == "HS384"


def test_weak_secret_bruteforce_skips_asymmetric_algorithms():
    rs256_token = active_checks._encode_jwt_parts(
        {"alg": "RS256", "typ": "JWT"}, {"sub": "user-1"}, "forged-signature"
    )
    result = active_checks.jwt_weak_secret_bruteforce(rs256_token, ["secret"])
    assert result["vulnerable"] is False
    assert result["secret"] is None
    assert result["alg"] == "RS256"
    assert "not HMAC-brute-forceable" in result["reason"]


def test_weak_secret_bruteforce_finding_shape_contract():
    result = active_checks.jwt_weak_secret_bruteforce(_hs256_token("supersecret"), ["supersecret"])
    assert result["vulnerable"] is True
    evidence = result["evidence"][0]
    assert evidence["type"] == "weak_secret"
    assert evidence["secret"] == "supersecret"
    assert evidence["severity"] == "high"
    assert evidence["cwe"] == "CWE-326"
    assert "supersecret" in evidence["description"]


def test_curated_wordlist_contains_key_entries():
    curated = active_checks.JWT_WEAK_SECRETS_CURATED
    assert len(curated) >= 90
    assert len(curated) == len(set(curated))
    for required in (
        "secret", "your-256-bit-secret", "jwt_secret", "supersecret",
        "keyboard cat", "sUP3rs3cr3t", "c2VjcmV0", "changeme", "hmac_secret",
    ):
        assert required in curated


def test_load_jwt_secrets_wordlist_merges_curated_entries():
    merged = active_checks._load_jwt_secrets_wordlist()
    # No duplicates, file entries preserved, curated entries merged in.
    assert len(merged) == len(set(merged))
    for required in ("your-256-bit-secret", "keyboard cat", "sUP3rs3cr3t"):
        assert required in merged
    # Substantially larger than the raw file wordlist alone.
    assert len(merged) > 250


# ---------------------------------------------------------------------------
# kid attack payload list (bounded, techniques)
# ---------------------------------------------------------------------------

def test_jwt_kid_payloads_bounded_and_techniques():
    # No OOB callback: SQLi only, never more than the global attempt budget.
    payloads = active_checks._jwt_kid_attack_payloads()
    assert 0 < len(payloads) <= active_checks.JWT_KID_MAX_ATTEMPTS
    assert {p["technique"] for p in payloads} == {"kid_sqli_injection"}
    assert all("http" not in p["kid"] for p in payloads)

    # With an OOB callback: SSRF-style kid URLs are included.
    payloads_oob = active_checks._jwt_kid_attack_payloads(
        oob_callback_url="collaborator.example.net"
    )
    assert len(payloads_oob) <= active_checks.JWT_KID_MAX_ATTEMPTS
    ssrf = [p for p in payloads_oob if p["technique"] == "kid_ssrf_oob"]
    assert len(ssrf) == 2
    assert ssrf[0]["kid"] == "http://collaborator.example.net"
    assert ssrf[1]["kid"] == "http://collaborator.example.net/jwks.json"

    # A known weak secret adds a signed UNION payload selecting it.
    payloads_known = active_checks._jwt_kid_attack_payloads(known_secret="supersecret")
    assert any(
        p["kid"] == "' UNION SELECT 'supersecret'-- -" and p["secret"] == "supersecret"
        for p in payloads_known
    )


def test_jwt_kid_titles_distinct_per_technique():
    titles = list(active_checks.JWT_KID_ATTACK_TITLES.values())
    assert len(titles) == len(set(titles)) == 3
    assert set(active_checks.JWT_KID_ATTACK_TITLES) == {
        "kid_sqli_injection", "kid_ssrf_oob", "kid_algorithm_confusion",
    }


# ---------------------------------------------------------------------------
# kid injection replay (mocked HTTP)
# ---------------------------------------------------------------------------

def test_jwt_kid_injection_detects_accepted_sqli_kid(monkeypatch):
    fake_run, calls = _make_jwt_oracle_run(server_secret="secret")
    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(active_checks.jwt_kid_injection_test(
        "https://example.test/api/user",
        _hs256_token("secret"),
    ))

    assert result["vulnerable"] is True
    assert "kid_sqli_injection" in result["issues"]
    evidence = result["evidence"]
    assert evidence
    winning = [ev for ev in evidence if ev["kid_payload"] == "' UNION SELECT 'secret'-- -"]
    assert winning
    ev = winning[0]
    assert ev["type"] == "kid_sqli_injection"
    assert ev["severity"] == "high"
    assert ev["cwe"] == "CWE-347"
    assert ev["forged_token_status"] == 200
    assert ev["tampered_signature_status"] == 401
    # The accepted kid payload is named in the description evidence.
    assert "' UNION SELECT 'secret'-- -" in ev["description"]

    # Differential guard ran first: a tampered signature was replayed.
    assert any("invalidsignature" in str(cmd) for cmd in _probe_calls(calls))


def test_jwt_kid_injection_no_finding_when_signatures_not_validated(monkeypatch):
    async def always_200_run(cmd, timeout=10):
        if "-w" in cmd and "%{http_code}" in cmd:
            return "200", "", 0
        return "", "", 0

    monkeypatch.setattr(active_checks, "run", always_200_run)

    result = asyncio.run(active_checks.jwt_kid_injection_test(
        "https://example.test/api/user",
        _hs256_token("secret"),
    ))

    # Public/no-auth endpoint: tampered signature is 2xx, so no kid finding.
    assert result["vulnerable"] is False
    assert result["evidence"] == []
    assert result["issues"] == []


def test_jwt_kid_injection_skips_ssrf_without_oob_callback(monkeypatch):
    fake_run, calls = _make_jwt_oracle_run(server_secret="secret")
    monkeypatch.setattr(active_checks, "run", fake_run)

    asyncio.run(active_checks.jwt_kid_injection_test(
        "https://example.test/api/user",
        _hs256_token("secret"),
        oob_callback_url=None,
    ))

    forged_tokens = [
        _bearer_token(cmd) for cmd in _probe_calls(calls)
        if _bearer_token(cmd) and "invalidsignature" not in str(cmd)
    ]
    for token in forged_tokens:
        header, _, _ = active_checks._decode_jwt_parts(token)
        assert "http" not in str(header.get("kid", ""))


def test_jwt_kid_injection_attempts_are_bounded(monkeypatch):
    fake_run, calls = _make_jwt_oracle_run(server_secret="secret")
    monkeypatch.setattr(active_checks, "run", fake_run)

    asyncio.run(active_checks.jwt_kid_injection_test(
        "https://example.test/api/user",
        _hs256_token("secret"),
        oob_callback_url="http://collaborator.example.net",
        known_secret="supersecret",
    ))

    probes = _probe_calls(calls)
    # 1 differential-guard baseline + at most JWT_KID_MAX_ATTEMPTS forgeries.
    assert len(probes) <= active_checks.JWT_KID_MAX_ATTEMPTS + 1
    assert len(probes) >= 2  # baseline + at least one kid forgery


def test_jwt_kid_injection_rejects_unreadable_token():
    result = asyncio.run(active_checks.jwt_kid_injection_test(
        "https://example.test", "not-a-jwt"
    ))
    assert result == {"vulnerable": False, "issues": [], "evidence": []}


# ---------------------------------------------------------------------------
# Comprehensive wiring
# ---------------------------------------------------------------------------

def test_jwt_comprehensive_wires_weak_secret_and_kid_checks(monkeypatch):
    fake_run, calls = _make_jwt_oracle_run(server_secret="supersecret")
    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(active_checks.jwt_comprehensive_test(
        "https://example.test/api/user",
        sample_token=_hs256_token("supersecret"),
    ))

    # Weak secret discovered offline by the pure-python dictionary attack.
    assert result["weak_secret_found"] == "supersecret"
    assert "weak_secret_extended" in result["tests_run"]
    assert "kid_injection" in result["tests_run"]
    assert any(ev["type"] == "weak_secret" for ev in result["evidence"])
    # kid SQLi forged with the discovered secret is accepted by the oracle.
    kid_evidence = [ev for ev in result["evidence"] if ev["type"] == "kid_sqli_injection"]
    assert kid_evidence
    assert all(ev["severity"] == "high" and ev["cwe"] == "CWE-347" for ev in kid_evidence)
    assert result["vulnerable"] is True


def test_jwt_comprehensive_passes_oob_callback_to_kid_check(monkeypatch):
    fake_run, calls = _make_jwt_oracle_run(server_secret="secret")
    monkeypatch.setattr(active_checks, "run", fake_run)

    asyncio.run(active_checks.jwt_comprehensive_test(
        "https://example.test/api/user",
        sample_token=_hs256_token("secret"),
        oob_callback_url="http://collaborator.example.net",
    ))

    forged = [
        _bearer_token(cmd) for cmd in _probe_calls(calls)
        if _bearer_token(cmd) and "invalidsignature" not in str(cmd)
    ]
    kids = []
    for token in forged:
        header, _, _ = active_checks._decode_jwt_parts(token)
        if header and "kid" in header:
            kids.append(str(header["kid"]))
    assert any("collaborator.example.net" in kid for kid in kids)


# ---------------------------------------------------------------------------
# RS256 -> HS256 algorithm confusion regression
# ---------------------------------------------------------------------------

def _rs256_fixture_token(kid: str = "confusion-key") -> str:
    return active_checks._encode_jwt_parts(
        {"alg": "RS256", "typ": "JWT", "kid": kid},
        {"sub": "user-1", "role": "user"},
        "unused-rs256-signature-material",
    )


def test_jwt_algorithm_confusion_degrades_gracefully_without_crypto_libs(monkeypatch):
    # Force ImportError for jwt/cryptography so the JWK->PEM conversion is
    # unavailable, and serve a JWKS so discovery itself succeeds.
    jwks_body = json.dumps({"keys": [{"kty": "RSA", "kid": "k1", "n": "AQAB", "e": "AQAB"}]})
    fake_run, calls = _make_jwt_oracle_run(server_secret="secret", jwks_body=jwks_body)
    monkeypatch.setattr(active_checks, "run", fake_run)
    monkeypatch.setitem(sys.modules, "jwt", None)
    monkeypatch.setitem(sys.modules, "cryptography", None)

    result = asyncio.run(active_checks.jwt_algorithm_confusion_test(
        "https://example.test/api/user",
        _rs256_fixture_token(),
    ))

    assert result == {"vulnerable": False, "issues": [], "evidence": []}
    # JWKS discovery was attempted against the well-known endpoint.
    assert any("/.well-known/jwks.json" in str(cmd) for cmd in calls)


def test_jwt_algorithm_confusion_regression_full_path(monkeypatch):
    pytest.importorskip("jwt")
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk["kid"] = "confusion-key"
    jwks_body = json.dumps({"keys": [jwk]})

    async def fake_run(cmd, timeout=10):
        cmd_str = [str(part) for part in cmd]
        if any(part.endswith("/.well-known/jwks.json") for part in cmd_str):
            return jwks_body, "", 0
        if any(part.startswith("Authorization: Bearer ") for part in cmd_str):
            # Confusion check replays and inspects the body: simulate an
            # authenticated 200 response with no auth-failure markers.
            return "ok-user-data", "", 0
        return "", "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(active_checks.jwt_algorithm_confusion_test(
        "https://example.test/api/user",
        _rs256_fixture_token(),
    ))

    assert result["vulnerable"] is True
    assert "algorithm_confusion" in result["issues"]
    evidence = result["evidence"][0]
    assert evidence["type"] == "algorithm_confusion"
    assert evidence["original_alg"] == "RS256"
    assert evidence["attack_alg"] == "HS256"
    assert evidence["severity"] == "high"
    assert evidence["cwe"] == "CWE-347"
    assert evidence["jwks_url"].endswith("/.well-known/jwks.json")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
