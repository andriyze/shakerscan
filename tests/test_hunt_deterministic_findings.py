from api.hunt.deterministic_findings import verified_xss_observations


def test_verified_xss_observations_accept_only_bound_content_free_proof():
    records = verified_xss_observations([
        {
            "kind": "xss_alert",
            "proof_state": "verified",
            "url": "https://app.example.test/search?q=%3Cscript%3E",
            "param": "q",
            "payload_sha256": "a" * 64,
            "message": "raw tool text must not survive",
        },
        {
            "kind": "xss_alert",
            "proof_state": "candidate",
            "url": "https://app.example.test/search?q=signal",
            "payload_sha256": "b" * 64,
        },
        {
            "kind": "xss_alert",
            "proof_state": "verified",
            "url": "https://other.example.test/search?q=proof",
            "payload_sha256": "c" * 64,
        },
    ], target_url="https://app.example.test")

    assert records == [{
        "url": "https://app.example.test/search?q=",
        "path": "/search",
        "param": "q",
        "payload_sha256": "a" * 64,
        "alert_type": None,
    }]


def test_verified_xss_observations_require_payload_receipt():
    assert verified_xss_observations([{
        "kind": "xss_alert",
        "proof_state": "verified",
        "url": "https://app.example.test/search?q=test",
    }], target_url="https://app.example.test") == []
