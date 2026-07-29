import asyncio
import hashlib
import io

import pytest

from scanner.scanner_tools import model_intake_acquisition as acquisition


def _dns(monkeypatch, mapping):
    def fake_getaddrinfo(host, port, type=0):
        values = mapping.get(host)
        if values is None:
            raise AssertionError(f"unexpected DNS lookup: {host}")
        return [
            (acquisition.socket.AF_INET6 if ":" in ip else acquisition.socket.AF_INET,
             acquisition.socket.SOCK_STREAM, 6, "", (ip, port))
            for ip in values
        ]

    monkeypatch.setattr(acquisition.socket, "getaddrinfo", fake_getaddrinfo)


def test_https_public_destination_is_resolved_and_pinned(monkeypatch):
    _dns(monkeypatch, {"models.example.test": ["93.184.216.34"]})

    result = acquisition.validate_url_destination("https://models.example.test/model.safetensors")

    assert result["host"] == "models.example.test"
    assert result["port"] == 443
    assert result["addresses"] == ["93.184.216.34"]


@pytest.mark.parametrize(
    "host,ip",
    [
        ("loopback.example.test", "127.0.0.1"),
        ("private.example.test", "10.10.0.8"),
        ("metadata.example.test", "169.254.169.254"),
        ("ipv6-local.example.test", "::1"),
        ("ula.example.test", "fd00::1"),
        ("decimal-ip.example.test", "127.0.0.1"),
    ],
)
def test_non_global_destinations_are_blocked_before_connect(monkeypatch, host, ip):
    _dns(monkeypatch, {host: [ip]})

    with pytest.raises(acquisition.AcquisitionPolicyError, match="blocked network range"):
        acquisition.validate_url_destination(f"https://{host}/artifact")


def test_mixed_public_and_private_dns_answer_is_blocked(monkeypatch):
    _dns(monkeypatch, {"mixed.example.test": ["93.184.216.34", "10.0.0.9"]})

    with pytest.raises(acquisition.AcquisitionPolicyError, match="private"):
        acquisition.validate_url_destination("https://mixed.example.test/model")


def test_plain_http_requires_explicit_development_exception(monkeypatch):
    _dns(monkeypatch, {"models.example.test": ["93.184.216.34"]})

    with pytest.raises(acquisition.AcquisitionPolicyError, match="Plain HTTP acquisition is disabled"):
        acquisition.validate_url_destination("http://models.example.test/model")

    policy = acquisition.acquisition_policy({"allow_insecure_http": True})
    result = acquisition.validate_url_destination("http://models.example.test/model", policy)
    assert result["port"] == 80


def test_private_network_exception_is_explicit(monkeypatch):
    _dns(monkeypatch, {"fixture.internal": ["10.0.0.8"]})
    policy = acquisition.acquisition_policy({"allow_private_networks": True})

    result = acquisition.validate_url_destination("https://fixture.internal/model", policy)

    assert result["addresses"] == ["10.0.0.8"]


def test_embedded_credentials_and_noncanonical_ports_are_rejected(monkeypatch):
    _dns(monkeypatch, {"models.example.test": ["93.184.216.34"]})

    with pytest.raises(acquisition.AcquisitionPolicyError, match="embedded credentials"):
        acquisition.validate_url_destination("https://user:secret@models.example.test/model")
    with pytest.raises(acquisition.AcquisitionPolicyError, match="port 8443"):
        acquisition.validate_url_destination("https://models.example.test:8443/model")


def test_hostname_allowlist_supports_exact_and_explicit_wildcard(monkeypatch):
    _dns(
        monkeypatch,
        {
            "models.example.test": ["93.184.216.34"],
            "cdn.example.test": ["93.184.216.35"],
            "example.test": ["93.184.216.36"],
        },
    )
    policy = acquisition.acquisition_policy(
        {"allowed_acquisition_hosts": ["models.example.test", "*.example.test"]}
    )

    assert acquisition.validate_url_destination("https://models.example.test/a", policy)
    assert acquisition.validate_url_destination("https://cdn.example.test/a", policy)
    with pytest.raises(acquisition.AcquisitionPolicyError, match="allowlist"):
        acquisition.validate_url_destination(
            "https://example.test/a",
            acquisition.acquisition_policy({"allowed_acquisition_hosts": ["*.example.test"]}),
        )


def test_redirect_is_revalidated_and_cross_origin_credentials_are_removed(monkeypatch):
    _dns(
        monkeypatch,
        {
            "models.example.test": ["93.184.216.34"],
            "cdn.example.test": ["93.184.216.35"],
        },
    )
    observed = []

    def fake_request(destination, headers, max_bytes, timeout_seconds):
        observed.append((destination["host"], dict(headers)))
        if destination["host"] == "models.example.test":
            return b"", {
                "status": 302,
                "reason": "Found",
                "headers": {"Location": "https://cdn.example.test/model"},
                "remote_ip": destination["addresses"][0],
            }
        return b"model", {
            "status": 200,
            "reason": "OK",
            "headers": {"Content-Length": "5", "Content-Type": "application/octet-stream"},
            "remote_ip": destination["addresses"][0],
        }

    monkeypatch.setattr(acquisition, "_request_once", fake_request)

    data, meta = acquisition.download_http(
        "https://models.example.test/model",
        1024,
        5,
        headers={"Authorization": "Bearer secret", "X-Request": "safe"},
    )

    assert data == b"model"
    assert meta["redirect_chain"] == ["https://cdn.example.test/model"]
    assert meta["resolution_chain"][-1]["ips"] == ["93.184.216.35"]
    assert observed[0][1]["Authorization"] == "Bearer secret"
    assert "Authorization" not in observed[1][1]
    assert observed[1][1]["X-Request"] == "safe"


def test_redirect_to_private_address_is_blocked_before_second_request(monkeypatch):
    _dns(
        monkeypatch,
        {
            "models.example.test": ["93.184.216.34"],
            "metadata.internal": ["169.254.169.254"],
        },
    )
    requests = []

    def fake_request(destination, headers, max_bytes, timeout_seconds):
        requests.append(destination["host"])
        return b"", {
            "status": 302,
            "reason": "Found",
            "headers": {"Location": "https://metadata.internal/latest/meta-data"},
            "remote_ip": destination["addresses"][0],
        }

    monkeypatch.setattr(acquisition, "_request_once", fake_request)

    with pytest.raises(acquisition.AcquisitionPolicyError, match="blocked network range"):
        acquisition.download_http("https://models.example.test/model", 1024, 5)
    assert requests == ["models.example.test"]


def test_redirect_limit_is_fail_closed(monkeypatch):
    _dns(monkeypatch, {"models.example.test": ["93.184.216.34"]})

    def fake_request(destination, headers, max_bytes, timeout_seconds):
        return b"", {
            "status": 302,
            "reason": "Found",
            "headers": {"Location": "/again"},
            "remote_ip": destination["addresses"][0],
        }

    monkeypatch.setattr(acquisition, "_request_once", fake_request)
    policy = acquisition.acquisition_policy({"max_acquisition_redirects": 1})

    with pytest.raises(acquisition.AcquisitionPolicyError, match="redirect limit"):
        acquisition.download_http("https://models.example.test/model", 1024, 5, policy=policy)


@pytest.mark.parametrize("status", [199, 300, 403, 404, 500])
def test_bounded_download_rejects_non_success_response_bodies(monkeypatch, status):
    _dns(monkeypatch, {"models.example.test": ["93.184.216.34"]})

    monkeypatch.setattr(
        acquisition,
        "_request_once",
        lambda destination, headers, max_bytes, timeout_seconds: (
            b'{"error":"not an artifact"}',
            {
                "status": status,
                "reason": "Error",
                "headers": {"Content-Type": "application/json"},
                "remote_ip": destination["addresses"][0],
            },
        ),
    )

    with pytest.raises(acquisition.AcquisitionPolicyError, match=f"HTTP {status}"):
        acquisition.download_http("https://models.example.test/model", 1024, 5)


def test_model_intake_huggingface_routing_does_not_accept_lookalike_host(monkeypatch):
    from scanner.scanner_tools import model_intake

    observed = []

    def fake_download(url, max_bytes, timeout_seconds, headers=None, fetch_policy=None):
        observed.append(url)
        return b"model", {"source": "http", "bytes_observed": 5, "truncated": False}

    monkeypatch.setattr(model_intake, "_download_http", fake_download)
    data, meta = asyncio.run(
        model_intake._fetch_artifact("https://huggingface.co.evil.test/model.bin", 1024, 5)
    )

    assert data == b"model"
    assert meta["source"] == "http"
    assert observed == ["https://huggingface.co.evil.test/model.bin"]


def test_complete_http_acquisition_streams_to_content_addressed_quarantine(monkeypatch, tmp_path):
    _dns(monkeypatch, {"models.example.test": ["93.184.216.34"]})
    payload = b"0123456789" * 1000

    class FakeResponse:
        status = 200
        reason = "OK"

        def __init__(self):
            self.body = io.BytesIO(payload)

        def getheaders(self):
            return [("Content-Length", str(len(payload))), ("Content-Type", "application/octet-stream")]

        def read(self, size):
            return self.body.read(size)

    class FakeConnection:
        def close(self):
            return None

    monkeypatch.setattr(
        acquisition,
        "_open_response",
        lambda destination, headers, timeout: (FakeConnection(), FakeResponse()),
    )

    prefix, meta = acquisition.download_http_to_quarantine(
        "https://models.example.test/model.bin",
        inspection_bytes=128,
        max_artifact_bytes=20_000,
        timeout_seconds=5,
        quarantine_dir=tmp_path,
    )

    expected_sha = hashlib.sha256(payload).hexdigest()
    object_path = tmp_path / "sha256" / expected_sha[:2] / expected_sha
    assert prefix == payload[:128]
    assert object_path.read_bytes() == payload
    assert meta["sha256"] == expected_sha
    assert meta["quarantine_object"] == f"sha256:{expected_sha}"
    assert meta["bytes_observed"] == len(payload)
    assert meta["complete"] is True
    assert meta["truncated"] is False
    assert meta["inspection_truncated"] is True


def test_complete_acquisition_rejects_declared_oversize_without_object(monkeypatch, tmp_path):
    _dns(monkeypatch, {"models.example.test": ["93.184.216.34"]})

    class FakeResponse:
        status = 200
        reason = "OK"

        def getheaders(self):
            return [("Content-Length", "5000")]

        def read(self, size):
            raise AssertionError("oversized response body must not be read")

    class FakeConnection:
        def close(self):
            return None

    monkeypatch.setattr(
        acquisition,
        "_open_response",
        lambda destination, headers, timeout: (FakeConnection(), FakeResponse()),
    )

    with pytest.raises(acquisition.AcquisitionPolicyError, match="complete acquisition limit"):
        acquisition.download_http_to_quarantine(
            "https://models.example.test/model.bin",
            inspection_bytes=128,
            max_artifact_bytes=1024,
            timeout_seconds=5,
            quarantine_dir=tmp_path,
        )
    assert list(tmp_path.rglob("*")) == []


def test_local_quarantine_deduplicates_and_revalidates_existing_object(tmp_path):
    source = tmp_path / "source.bin"
    quarantine = tmp_path / "quarantine"
    payload = b"safe-model" * 100
    source.write_bytes(payload)

    first_prefix, first_meta = acquisition.quarantine_local_file(
        source, quarantine, inspection_bytes=32, max_artifact_bytes=10_000
    )
    second_prefix, second_meta = acquisition.quarantine_local_file(
        source, quarantine, inspection_bytes=32, max_artifact_bytes=10_000
    )

    assert first_prefix == second_prefix == payload[:32]
    assert first_meta["quarantine_object"] == second_meta["quarantine_object"]
    object_files = [path for path in quarantine.rglob("*") if path.is_file()]
    assert len(object_files) == 1

    object_files[0].write_bytes(b"tampered")
    with pytest.raises(acquisition.AcquisitionPolicyError, match="integrity verification"):
        acquisition.quarantine_local_file(
            source, quarantine, inspection_bytes=32, max_artifact_bytes=10_000
        )
