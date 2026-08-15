import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import ssh_scanner  # noqa: E402


def test_ssh_algorithm_classification_calibrates_sha1_but_blocks_stronger_legacy_markers():
    weak, severity = ssh_scanner.classify_negotiated_ssh_algorithms(
        {"mac_in": "hmac-sha1", "cipher_in": "aes256-ctr"},
        key_type="ssh-rsa",
        key_bits=3072,
    )
    assert weak == ["mac_in:hmac-sha1"]
    assert severity == "medium"

    weak, severity = ssh_scanner.classify_negotiated_ssh_algorithms(
        {"mac_in": "hmac-sha1", "cipher_in": "3des-cbc"},
        key_type="ssh-rsa",
        key_bits=1024,
    )
    assert severity == "high"
    assert "cipher_in:3des-cbc" in weak
    assert "host_key:ssh-rsa-1024" in weak


def test_ssh_result_contract_has_algorithm_evidence_when_dependency_is_absent_or_connection_fails():
    # The shape is stable even on a host without Paramiko or a listening SSH server.
    import asyncio

    result = asyncio.run(ssh_scanner.ssh_auth_methods("127.0.0.1", port=1, timeout=1))
    assert "host_key" in result
    assert "negotiated_algorithms" in result
    assert "weak_algorithms" in result
    assert isinstance(result["findings"], list)
