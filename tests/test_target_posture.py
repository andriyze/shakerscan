"""Target posture is derived on read from the newest scans that observed each section.

A fast profile that skipped cipher enumeration or DNS used to leave the result page blank for
those sections even when an earlier run on the same target had the data. Each section names the
scan it came from, so the page can say "observed in this run" or "from an earlier scan" honestly.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from target_posture import (  # noqa: E402
    SECTIONS,
    load_target_posture,
    posture_sections_from_result,
    shape_http_headers,
    shape_tls,
)


def _result():
    return {
        "http": {
            "status": 200,
            "posture_observed": True,
            "security_headers": {"x_frame_options": "SAMEORIGIN", "x_content_type_options": "nosniff"},
            "missing_security_headers": ["content-security-policy", "referrer-policy"],
            "observed_headers": {"set-cookie": "session=SECRET-VALUE; Path=/"},
            "cookies": [{"name": "session", "secure": False, "httponly": True, "samesite": "Lax", "value": "SECRET-VALUE"}],
        },
        "tls": {
            "endpoints": [{"host": "t", "port": 443}],
            "certificate": {"subject": "CN=t", "issuer": "CN=ca", "not_after": "2027-01-01", "public_key_bits": 2048,
                            "signature_algorithm": "sha256WithRSA", "subject_alt_names": ["t", "www.t"]},
            "cipher_suites": {"TLSv1.2": ["ECDHE-RSA-AES128-GCM-SHA256"], "TLSv1.3": ["TLS_AES_128_GCM_SHA256"]},
            "testssl": {"grade": "A", "vulnerabilities": []},
            "ocsp": {"stapled": True},
        },
        "dns": {"records": {"host_a": ["10.0.0.1"], "dmarc": ["v=DMARC1; p=reject"], "host_mx": []},
                "dnssec": {"status": "unsigned"}, "mta_sts": {"enabled": False}},
        "infrastructure": {"addresses": [{"ip": "10.0.0.1", "asn": "AS64500", "organization": "Example Org"}],
                           "registration": {"registrar": "Example Registrar", "expires": "2030-01-01"},
                           "related_names": ["a", "b"]},
    }


def test_every_section_is_shaped_from_one_result_and_secrets_never_leak():
    shaped = posture_sections_from_result(_result())
    assert set(shaped) == set(SECTIONS)
    headers = shaped["http_headers"]
    assert headers["missing"] == ["content-security-policy", "referrer-policy"]
    assert headers["present"]["x_frame_options"] == "SAMEORIGIN"
    assert headers["cookies"] == [{"name": "session", "secure": False, "httponly": True, "samesite": "Lax"}]
    assert "SECRET-VALUE" not in str(shaped)
    tls = shaped["tls"]
    assert tls["certificate"]["san_count"] == 2
    assert tls["protocols"] == ["TLSv1.2", "TLSv1.3"]
    assert tls["grade"] == "A" and tls["ocsp_stapled"] is True
    assert shaped["dns"]["dmarc_present"] is True
    assert shaped["network"]["addresses"][0]["asn"] == "AS64500"
    assert shaped["network"]["related_names_count"] == 2
    assert shaped["network"]["informational_only"] is True


def test_sections_the_scan_did_not_observe_are_absent_not_empty():
    assert shape_http_headers({"status": 200}) is None
    assert shape_tls({"endpoints": [], "certificate": {}}) is None
    shaped = posture_sections_from_result({"http": {"status": 200}, "dns": {"records": {"host_a": []}}})
    assert shaped == {}


class _Conn:
    """Newest-first rows per section; the loader must skip rows whose section is empty."""

    def __init__(self, rows_by_key):
        self.rows_by_key = rows_by_key
        self.queries = []

    async def fetch(self, query, target_id, scan_id=None):
        self.queries.append(query)
        for key, rows in self.rows_by_key.items():
            if f"result->'{key}' AS section" in query:
                if scan_id is not None:
                    return [row for row in rows if row["id"] == scan_id]
                return rows
        return []


def test_loader_names_the_newest_scan_that_actually_observed_each_section():
    newest = datetime(2026, 9, 3, 6, 0, tzinfo=timezone.utc)
    older = datetime(2026, 9, 1, 6, 0, tzinfo=timezone.utc)
    conn = _Conn({
        "http": [
            {"id": "new-scan", "completed_at": newest, "created_at": newest, "section": {"status": 200}},
            {"id": "old-scan", "completed_at": older, "created_at": older, "section": _result()["http"]},
        ],
        "tls": [{"id": "old-scan", "completed_at": older, "created_at": older, "section": _result()["tls"]}],
        "dns": [],
        "infrastructure": [],
    })
    posture = asyncio.run(load_target_posture(conn, "target-1"))
    assert posture["schema_version"] == "target-posture/v1"
    assert posture["sections"]["http_headers"]["scan_id"] == "old-scan"
    assert posture["sections"]["http_headers"]["observed_at"].startswith("2026-09-01")
    assert posture["sections"]["tls"]["payload"]["grade"] == "A"
    assert posture["sections"]["dns"] is None and posture["sections"]["network"] is None
    assert all("status = 'completed'" in q and "scan_role" in q for q in conn.queries)


def test_the_current_scan_wins_over_a_newer_scan_for_sections_it_observed():
    newer = datetime(2026, 9, 3, 6, 0, tzinfo=timezone.utc)
    current = datetime(2026, 9, 2, 6, 0, tzinfo=timezone.utc)
    conn = _Conn({
        "http": [
            {"id": "newer-scan", "completed_at": newer, "created_at": newer, "section": _result()["http"]},
            {"id": "this-scan", "completed_at": current, "created_at": current, "section": _result()["http"]},
        ],
        "tls": [{"id": "newer-scan", "completed_at": newer, "created_at": newer, "section": _result()["tls"]}],
        "dns": [], "infrastructure": [],
    })
    posture = asyncio.run(load_target_posture(conn, "target-1", prefer_scan_id="this-scan"))
    assert posture["sections"]["http_headers"]["scan_id"] == "this-scan"
    # A section this run did not observe still falls back to the newest other scan.
    assert posture["sections"]["tls"]["scan_id"] == "newer-scan"
