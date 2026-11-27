"""Reputation API keys are only ever sent over a verified TLS connection."""

from __future__ import annotations

import ssl

from scanner_tools import ip_reputation


def test_reputation_api_context_verifies_certificate_and_hostname():
    assert ip_reputation.ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert ip_reputation.ssl_context.check_hostname is True
