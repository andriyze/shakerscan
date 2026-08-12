import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import ssh_scanner  # noqa: E402


def test_ssh_result_contract_has_algorithm_evidence_when_dependency_is_absent_or_connection_fails():
    # The shape is stable even on a host without Paramiko or a listening SSH server.
    import asyncio

    result = asyncio.run(ssh_scanner.ssh_auth_methods("127.0.0.1", port=1, timeout=1))
    assert "host_key" in result
    assert "negotiated_algorithms" in result
    assert "weak_algorithms" in result
    assert isinstance(result["findings"], list)
