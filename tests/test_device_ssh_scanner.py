import os
import sys
import asyncio
import hashlib
import base64
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import ssh_scanner  # noqa: E402


def _fake_paramiko(*, offered, password_outcome="success"):
    class AuthenticationException(Exception):
        pass

    class BadAuthenticationType(AuthenticationException):
        def __init__(self, allowed_types):
            super().__init__("rejected")
            self.allowed_types = allowed_types

    class SSHException(Exception):
        pass

    class Key:
        def get_name(self): return "ssh-ed25519"
        def get_bits(self): return 256
        def asbytes(self): return b"fixture-host-key"

    transports = []

    class Transport:
        def __init__(self, _sock):
            self.remote_version = "SSH-2.0-fixture"
            self.remote_cipher = self.local_cipher = "aes256-ctr"
            self.remote_mac = self.local_mac = "hmac-sha2-256"
            self.authenticated = False
            transports.append(self)

        def connect(self): return None
        def close(self): return None
        def get_remote_server_key(self): return Key()
        def auth_none(self, _username): raise BadAuthenticationType(offered)
        def auth_password(self, _username, _secret, fallback=False):
            if password_outcome == "reject": raise AuthenticationException("credential text must not leak")
            if password_outcome == "value_error": raise ValueError("backend secret text")
            self.authenticated = True
        def auth_publickey(self, _username, _key): self.authenticated = True
        def is_authenticated(self): return self.authenticated

    class PrivateKey:
        @classmethod
        def from_private_key(cls, _stream, password=None): return cls()

    return SimpleNamespace(
        Transport=Transport,
        AuthenticationException=AuthenticationException,
        BadAuthenticationType=BadAuthenticationType,
        SSHException=SSHException,
        Ed25519Key=PrivateKey,
        ECDSAKey=None,
        RSAKey=None,
        DSSKey=None,
    )


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
    assert "authentication_attempted" in result
    assert "auth_methods_complete" in result
    assert "authentication_succeeded" in result
    assert isinstance(result["findings"], list)


def test_credential_rejection_keeps_independently_enumerated_methods(monkeypatch):
    fake = _fake_paramiko(offered=["publickey", "password"], password_outcome="reject")
    monkeypatch.setattr(ssh_scanner, "paramiko", fake, raising=False)
    monkeypatch.setattr(ssh_scanner, "HAS_PARAMIKO", True)
    monkeypatch.setattr(ssh_scanner.socket, "create_connection", lambda *_args, **_kwargs: object())
    result = asyncio.run(ssh_scanner.ssh_auth_methods("192.0.2.10", credential={
        "auth_kind": "ssh_password", "username": "operator", "secret": "hidden",
    }))
    assert result["auth_methods"] == ["password", "publickey"]
    assert result["auth_methods_complete"] is True
    assert result["password_auth_enabled"] is True
    assert result["publickey_enabled"] is True
    assert result["authentication_succeeded"] is False
    assert result["authentication_error"] == "authentication_rejected"


def test_private_key_success_does_not_conceal_password_and_raw_value_errors_are_stable(monkeypatch):
    fake = _fake_paramiko(offered=["password", "publickey"])
    monkeypatch.setattr(ssh_scanner, "paramiko", fake, raising=False)
    monkeypatch.setattr(ssh_scanner, "HAS_PARAMIKO", True)
    monkeypatch.setattr(ssh_scanner.socket, "create_connection", lambda *_args, **_kwargs: object())
    result = asyncio.run(ssh_scanner.ssh_auth_methods("192.0.2.10", credential={
        "auth_kind": "ssh_private_key", "username": "operator", "secret": "fixture-key",
    }))
    assert result["authentication_succeeded"] is True
    assert result["password_auth_enabled"] is True

    fake = _fake_paramiko(offered=["password"], password_outcome="value_error")
    monkeypatch.setattr(ssh_scanner, "paramiko", fake)
    result = asyncio.run(ssh_scanner.ssh_auth_methods("192.0.2.10", credential={
        "auth_kind": "ssh_password", "username": "operator", "secret": "hidden",
    }))
    assert result["authentication_error"] == "authentication_error:ValueError"
    assert "backend secret text" not in str(result)


def test_host_key_fingerprint_and_mismatch_block_credentials(monkeypatch):
    class Key:
        def asbytes(self): return b"known-host-key"

    expected = "SHA256:" + base64.b64encode(hashlib.sha256(b"known-host-key").digest()).decode().rstrip("=")
    assert ssh_scanner.ssh_host_key_fingerprint(Key()) == expected

    fake = _fake_paramiko(offered=["publickey"])
    monkeypatch.setattr(ssh_scanner, "paramiko", fake, raising=False)
    monkeypatch.setattr(ssh_scanner, "HAS_PARAMIKO", True)
    monkeypatch.setattr(ssh_scanner.socket, "create_connection", lambda *_args, **_kwargs: object())
    result = asyncio.run(ssh_scanner.ssh_auth_methods(
        "192.0.2.10",
        credential={"auth_kind": "ssh_private_key", "username": "operator", "secret": "fixture-key"},
        expected_host_key_fingerprint="SHA256:not-the-device-key",
    ))
    assert result["authentication_attempted"] is False
    assert result["authentication_error"] == "host_key_mismatch"
    assert result["pinned_host_key_fingerprint"] == "SHA256:not-the-device-key"
    assert result["host_key"]["fingerprint_sha256"] != result["pinned_host_key_fingerprint"]


def test_authenticated_host_review_uses_fixed_bundles_and_redacts_output(monkeypatch):
    fake = _fake_paramiko(offered=["publickey"])

    class Channel:
        def __init__(self):
            self.output = bytearray(b"uid=1000 password=supersecret\n")
            self.command = None

        def settimeout(self, _timeout): return None
        def exec_command(self, command): self.command = command
        def recv_ready(self): return bool(self.output)
        def recv(self, size):
            chunk = bytes(self.output[:size]); del self.output[:size]; return chunk
        def recv_stderr_ready(self): return False
        def recv_stderr(self, _size): return b""
        def exit_status_ready(self): return not self.output
        def recv_exit_status(self): return 0
        def close(self): return None

    opened = []
    def open_session(self, timeout=None):
        channel = Channel(); opened.append(channel); return channel
    fake.Transport.open_session = open_session
    monkeypatch.setattr(ssh_scanner, "paramiko", fake, raising=False)
    monkeypatch.setattr(ssh_scanner, "HAS_PARAMIKO", True)
    monkeypatch.setattr(ssh_scanner.socket, "create_connection", lambda *_args, **_kwargs: object())
    result = asyncio.run(ssh_scanner.ssh_auth_methods(
        "192.0.2.10",
        credential={"auth_kind": "ssh_private_key", "username": "operator", "secret": "fixture-key"},
        host_review_bundles=["identity_runtime"],
    ))
    review = result["host_review"]
    assert review["status"] == "completed"
    assert review["commands_server_owned"] is True
    assert review["bundles"][0]["stdout"] == "uid=1000 password=***\n"
    assert "supersecret" not in str(review)
    assert opened[0].command == ssh_scanner.SSH_HOST_REVIEW_BUNDLES["identity_runtime"]
