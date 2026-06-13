"""
Tests for the exposed-file retest prover and shared exposure marker logic.
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import proof_of_exploit as poe  # noqa: E402
from scanner_tools.exposure_markers import (  # noqa: E402
    derive_markers,
    looks_like_soft_404,
    match_critical_validator,
)
from scanner_tools.verification_engine import dispatch_ladder_step  # noqa: E402


PEM_KEY_BODY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"


def _fake_fetch(response: dict):
    async def fake_fetch_with_capture(url, **kwargs):
        return {
            "status_code": 0,
            "headers": {},
            "body": "",
            "final_url": url,
            "elapsed_ms": 1.0,
            "error": None,
            **response,
        }

    return fake_fetch_with_capture


def _routed_fetch(main: dict, probe: dict | None = None):
    """Fake that distinguishes the real path from the catch-all probe sibling.

    The probe defaults to a clean 404 (server correctly rejects nonexistent
    paths) so shape-match can prove. Pass `probe` to simulate a catch-all.
    """
    probe_response = probe if probe is not None else {"status_code": 404, "body": "not found"}

    async def fake_fetch_with_capture(url, **kwargs):
        is_probe = "_shakerscan_" in url or ".nonexistent" in url
        chosen = probe_response if is_probe else main
        return {
            "status_code": 0,
            "headers": {},
            "body": "",
            "final_url": url,
            "elapsed_ms": 1.0,
            "error": None,
            **chosen,
        }

    return fake_fetch_with_capture


# ---------------------------------------------------------------------------
# exposure_markers
# ---------------------------------------------------------------------------

def test_derive_markers_detects_private_key_and_dotenv():
    assert "private_key_marker" in derive_markers("id_rsa", PEM_KEY_BODY)
    assert "dotenv_format" in derive_markers(".env", "DB_PASSWORD=hunter2\nAPI_KEY=abc\n")
    assert derive_markers("readme.txt", "hello world") == []


def test_match_critical_validator_for_key_files():
    validator = match_critical_validator("/some/dir/id_rsa")
    assert validator is not None
    assert validator(PEM_KEY_BODY) is True
    assert validator("<html>404 not found</html>") is False
    assert match_critical_validator("/index.html") is None


def test_looks_like_soft_404():
    assert looks_like_soft_404("<html><body>404 Page Not Found</body></html>") is True
    assert looks_like_soft_404("") is True
    assert looks_like_soft_404("Service Unavailable") is True
    # Config-style content with error-like words is not a soft 404
    assert looks_like_soft_404("error_reporting=E_ALL\npassword=secret\n") is False
    # Long content is not treated as a soft 404
    assert looks_like_soft_404("x" * 5000) is False


def test_looks_like_soft_404_does_not_flag_log_files():
    # A real, still-exposed log file mentions error words but is NOT a soft 404.
    # The stricter heuristic must not mark it remediated on retest.
    log_body = ("[2024-01-01 12:00:00] GET /admin handled in 12ms\n" * 20) + \
        "[2024-01-01 12:05:00] ERROR: database connection refused, server error\n"
    assert len(log_body) >= 256
    assert looks_like_soft_404(log_body) is False


# ---------------------------------------------------------------------------
# prove_exposed_file
# ---------------------------------------------------------------------------

def test_prove_exposed_file_still_exposed_private_key(monkeypatch):
    monkeypatch.setattr(poe, "fetch_with_capture", _fake_fetch({
        "status_code": 200,
        "body": PEM_KEY_BODY,
        "headers": {"content-type": "application/octet-stream"},
    }))
    proof = asyncio.run(poe.prove_exposed_file(
        "https://example.com/id_rsa",
        evidence={"path": "id_rsa", "markers": ["private_key_marker"]},
    ))
    assert proof.proven is True
    assert proof.confidence >= 0.9
    assert proof.evidence_type == "critical_file_content"


def test_prove_exposed_file_fixed_when_404(monkeypatch):
    monkeypatch.setattr(poe, "fetch_with_capture", _fake_fetch({"status_code": 404, "body": "not found"}))
    proof = asyncio.run(poe.prove_exposed_file(
        "https://example.com/id_rsa",
        evidence={"path": "id_rsa", "markers": ["private_key_marker"]},
    ))
    assert proof.proven is False
    assert proof.evidence_type == "not_found"


def test_prove_exposed_file_access_denied_counts_as_remediated(monkeypatch):
    monkeypatch.setattr(poe, "fetch_with_capture", _fake_fetch({"status_code": 403, "body": "forbidden"}))
    proof = asyncio.run(poe.prove_exposed_file("https://example.com/id_rsa", evidence={"path": "id_rsa"}))
    assert proof.proven is False
    assert proof.evidence_type == "access_denied"


def test_prove_exposed_file_markers_gone_means_remediated(monkeypatch):
    # Path still answers 200 but the sensitive content was replaced.
    monkeypatch.setattr(poe, "fetch_with_capture", _fake_fetch({
        "status_code": 200,
        "body": "<html><body>Welcome to our homepage</body></html>",
        "headers": {"content-type": "text/html"},
    }))
    proof = asyncio.run(poe.prove_exposed_file(
        "https://example.com/id_rsa",
        evidence={"path": "id_rsa", "markers": ["private_key_marker"], "preview_hash16": "deadbeefdeadbeef"},
    ))
    assert proof.proven is False
    assert proof.evidence_type == "sensitive_markers_absent"


def test_prove_exposed_file_forced_browsing_shape_match(monkeypatch):
    # forced_browsing evidence has no markers/hash; corroborate on response shape
    # when the server correctly rejects random sibling paths (not a catch-all).
    body = '{"aws_access_key_id": "AKIA..."}' + " " * 370
    main = {"status_code": 200, "body": body, "headers": {"content-type": "application/json"}}
    monkeypatch.setattr(poe, "fetch_with_capture", _routed_fetch(main))
    proof = asyncio.run(poe.prove_exposed_file(
        "https://example.com/credentials.json",
        evidence={"path": "/credentials.json", "content_type": "application/json", "content_length": 402},
    ))
    assert proof.proven is True
    assert proof.evidence_type == "content_shape_match"


def test_prove_exposed_file_catch_all_server_is_inconclusive(monkeypatch):
    # Server answers EVERY path (including a random nonexistent sibling) with the
    # same JSON 200 shape. Shape-match must not falsely claim "still exposed".
    body = '{"message": "ok"}' + " " * 385
    same = {"status_code": 200, "body": body, "headers": {"content-type": "application/json"}}
    monkeypatch.setattr(poe, "fetch_with_capture", _routed_fetch(same, probe=same))
    proof = asyncio.run(poe.prove_exposed_file(
        "https://example.com/credentials.json",
        evidence={"path": "/credentials.json", "content_type": "application/json", "content_length": 402},
    ))
    assert proof.proven is False
    assert proof.evidence_type == "catch_all_server"


def test_prove_exposed_file_log_file_with_error_words_still_proven(monkeypatch):
    # A still-exposed log file mentions error words but is genuinely served
    # (random siblings 404). It must prove via shape, not be marked soft_404.
    log_body = ("[2024-01-01 12:00:00] GET /admin handled in 12ms\n" * 20) + \
        "[2024-01-01 12:05:00] ERROR: database connection refused, server error\n"
    main = {"status_code": 200, "body": log_body, "headers": {"content-type": "text/plain"}}
    monkeypatch.setattr(poe, "fetch_with_capture", _routed_fetch(main))
    proof = asyncio.run(poe.prove_exposed_file(
        "https://example.com/error_log",
        evidence={"path": "/error_log", "content_type": "text/plain", "content_length": len(log_body)},
    ))
    assert proof.proven is True
    assert proof.evidence_type == "content_shape_match"


def test_prove_exposed_file_transport_error_raises(monkeypatch):
    monkeypatch.setattr(poe, "fetch_with_capture", _fake_fetch({
        "status_code": 0,
        "error": "connection refused",
    }))
    with pytest.raises(RuntimeError):
        asyncio.run(poe.prove_exposed_file("https://example.com/id_rsa", evidence={"path": "id_rsa"}))


def test_dispatch_ladder_step_routes_exposed_file():
    called = {}

    async def fake_prover(url, evidence=None):
        called["url"] = url
        called["evidence"] = evidence
        return None

    coro, meta = dispatch_ladder_step(
        "exposed_file",
        "content_marker_replay",
        "https://example.com/id_rsa",
        "",
        None,
        evidence={"path": "id_rsa"},
        prove_exposed_file=fake_prover,
    )
    assert coro is not None
    asyncio.run(coro)
    assert called["url"] == "https://example.com/id_rsa"
    assert called["evidence"] == {"path": "id_rsa"}
    assert meta["strategy"] == "content_marker_replay"


def test_dispatch_ladder_step_exposed_file_without_prover():
    coro, _meta = dispatch_ladder_step(
        "exposed_file",
        "content_marker_replay",
        "https://example.com/id_rsa",
        "",
        None,
    )
    assert coro is None
