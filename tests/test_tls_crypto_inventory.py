from scanner.scanner_tools.tls_scanner import build_crypto_inventory


def test_crypto_inventory_flags_legacy_posture_and_pqc_blockers():
    tls = {
        "certificate": {
            "not_after": "2026-06-01T00:00:00+00:00",
            "days_remaining": 20,
            "key_algo": "RSA 2048",
            "sig_algo": "sha1WithRSAEncryption",
        },
        "sslyze": {"tls_versions": {"tls_1_0": True, "tls_1_2": True}},
        "cipher_suites": {
            "tls_1_0": [{"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}],
            "tls_1_2": [{"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}],
        },
    }

    inventory = build_crypto_inventory(tls, "example.test", 443)

    assert inventory["protocols"]["legacy"] == ["tls_1_0"]
    assert inventory["algorithms"]["static_rsa_key_exchange"] is True
    assert inventory["algorithms"]["weak_ciphers"] == ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]
    assert inventory["algorithms"]["weak_signatures"] == ["sha1WithRSAEncryption"]
    assert "expires_within_30_days" in inventory["certificate_lifecycle"]["flags"]
    assert inventory["pqc_readiness"]["status"] == "migration_blocked_by_legacy_posture"
    assert "legacy_tls_enabled" in inventory["pqc_readiness"]["blockers"]


def test_crypto_inventory_marks_hybrid_pqc_when_observed():
    tls = {
        "certificate": {"key_algo": "ECDSA", "sig_algo": "sha256WithECDSA"},
        "endpoints": [{"tlsversion": "tls13", "cipher": "TLS_AES_256_GCM_SHA384"}],
        "cipher_suites": {"tls_1_3": [{"name": "TLS_X25519MLKEM768_AES_256_GCM_SHA384"}]},
        "testssl": {"supports_tls13": True},
    }

    inventory = build_crypto_inventory(tls)

    assert inventory["protocols"]["tls_1_3"] is True
    assert inventory["pqc_readiness"]["status"] == "hybrid_or_pqc_observed"
    assert inventory["pqc_readiness"]["hybrid_or_pqc_observed"] is True
    assert inventory["pqc_readiness"]["blockers"] == []
