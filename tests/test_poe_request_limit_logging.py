"""
Unit tests for PoE request-limit warning behavior.
"""
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import proof_of_exploit as poe


def test_poe_limit_warning_emitted_once_per_scan_domain_budget(caplog):
    original_config = poe._poe_config
    cfg = poe.PoEConfig.safe()
    cfg.bola_max_requests_per_target = 1

    poe.configure_poe(cfg)
    poe.reset_request_counts()
    poe.start_scan_session("scan-test-1")

    try:
        with caplog.at_level(logging.WARNING, logger="scanner_tools.proof_of_exploit"):
            assert poe._check_request_limit("http://example.com/api/users/1", budget_key="bola") is True
            assert poe._check_request_limit("http://example.com/api/users/2", budget_key="bola") is False
            assert poe._check_request_limit("http://example.com/api/users/3", budget_key="bola") is False
            assert poe._check_request_limit("http://example.com/api/users/4", budget_key="bola") is False

        warnings = [r.message for r in caplog.records if "PoE request limit reached for example.com" in r.message]
        assert len(warnings) == 1
        assert "budget=bola" in warnings[0]
        assert "further warnings suppressed" in warnings[0]
    finally:
        poe.end_scan_session("scan-test-1")
        poe.reset_request_counts()
        poe.configure_poe(original_config)
