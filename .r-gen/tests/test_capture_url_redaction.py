"""Capture index rows lose ;matrix parameters and token-like path segments (url_redaction).
Unit fixtures only."""
from __future__ import annotations

import json

import pytest

from api.capture.flows import CaptureFlow, har_entry
from scanner.scanner_tools.request_collections import index_appended_har_entries
from scanner.scanner_tools.url_redaction import redact_path, token_like_segment


@pytest.mark.parametrize(("segment", "token"), [
    ("Zx9Qp2Lm7Rt4Wv8Yb3Nc", True),
    ("x1y2z3w4v5u6t7s8", True),
    ("a8f3k2m9x7q1w5e4z0p2", True),
    ("iPhone15ProMax2024", False),
    ("ProductCategory12", False),
    ("getting-started-guide", False),
    ("main.3f9a2b1c.chunk.js", False),
    ("2024-10-16", False),
    ("1234567890123456", False),
])
def test_token_like_segments(segment, token):
    assert token_like_segment(segment) is token


def test_redact_path_drops_matrix_parameters():
    assert redact_path("/a;jsessionid=XYZ/b;v=1") == "/a/b"


@pytest.mark.parametrize(("url", "path"), [
    ("https://app.example.test/app;jsessionid=ABC123SECRET/home", "/app/home"),
    ("https://app.example.test/verify/Zx9Qp2Lm7Rt4Wv8Yb3Nc", "/verify/<redacted>"),
    ("https://app.example.test/s/x1y2z3w4v5u6t7s8/view", "/s/<redacted>/view"),
    ("https://app.example.test/products/ProductCategory12", "/products/ProductCategory12"),
    ("https://app.example.test/docs/getting-started-guide", "/docs/getting-started-guide"),
])
def test_capture_index_rows_drop_matrix_parameters_and_token_like_segments(url, path):
    entry, _size = har_entry(CaptureFlow.model_validate({"method": "GET", "url": url}))
    (row,) = index_appended_har_entries([entry], start_index=0)
    assert row["normalized_path"] == path
    assert row["redacted_url"] == "https://app.example.test" + path
    assert row["name"] == f"GET {path}"
    assert "ABC123SECRET" not in json.dumps(row) and "Zx9Qp2Lm7Rt4Wv8Yb3Nc" not in json.dumps(row)
