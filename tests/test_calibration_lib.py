"""Unit tests for scripts/lib/calibration.py shared helpers."""

import os
import sys
import urllib.error
import urllib.request
from io import BytesIO


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from lib import calibration  # noqa: E402

sys.path.pop(0)


class _FakeResponse:
    def __init__(self, payload: bytes):
        self._buf = BytesIO(payload)

    def read(self) -> bytes:
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_request_json_decodes_response(monkeypatch):
    def fake_urlopen(req, timeout=None):
        assert req.full_url == "http://example.test/scans"
        assert req.method == "GET"
        return _FakeResponse(b'{"ok": true}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert calibration.request_json("http://example.test/scans") == {"ok": True}


def test_request_json_empty_body_returns_empty_dict(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: _FakeResponse(b""))
    assert calibration.request_json("http://example.test/empty") == {}


def test_request_json_raises_runtime_error_on_http_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(
            url=req.full_url,
            code=500,
            msg="Internal Server Error",
            hdrs=None,
            fp=BytesIO(b"boom"),
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    try:
        calibration.request_json("http://example.test/err")
    except RuntimeError as exc:
        assert "HTTP 500" in str(exc)
        assert "boom" in str(exc)
    else:
        raise AssertionError("expected RuntimeError")


def test_try_request_json_swallows_errors(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise OSError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert calibration.try_request_json("http://example.test/down") is None


def test_wait_for_scans_polls_until_terminal(monkeypatch):
    statuses = {
        "scan-1": ["pending", "running", "completed"],
        "scan-2": ["pending", "completed"],
    }

    def fake_request_json(url, *, method="GET", payload=None, timeout=30):
        scan_id = url.rsplit("/", 1)[-1]
        return {"status": statuses[scan_id].pop(0), "id": scan_id}

    monkeypatch.setattr(calibration, "request_json", fake_request_json)
    monkeypatch.setattr(calibration.time, "sleep", lambda _: None)

    queued = [
        {"scan_id": "scan-1", "name": "first"},
        {"scan_id": "scan-2", "name": "second"},
    ]

    result = calibration.wait_for_scans(
        "http://example.test", queued, timeout=10, poll_interval=0.01
    )

    assert result[0]["detail"]["status"] == "completed"
    assert result[1]["detail"]["status"] == "completed"
    assert result[0]["name"] == "first"


def test_wait_for_scans_passes_through_missing_scan_id(monkeypatch):
    monkeypatch.setattr(
        calibration,
        "request_json",
        lambda *a, **k: {"status": "completed"},
    )
    monkeypatch.setattr(calibration.time, "sleep", lambda _: None)

    queued = [{"scan_id": None, "name": "queue-error"}]

    result = calibration.wait_for_scans(
        "http://example.test", queued, timeout=10, poll_interval=0.01
    )

    # An item without a scan_id is returned with an empty detail rather than
    # crashing the wait loop.
    assert result[0]["detail"] == {}
    assert result[0]["name"] == "queue-error"
