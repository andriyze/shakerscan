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


def test_resolve_scan_poe_config_only_aggressive_unlocks_and_clamps():
    safe = poe.resolve_scan_poe_config("safe")
    assert safe.safe_mode is True and safe.skip_time_based is True and safe.skip_rce is True

    for level in ("", "moderate", None, "SAFE"):
        assert poe.resolve_scan_poe_config(level).safe_mode is True

    agg = poe.resolve_scan_poe_config("aggressive")
    assert agg.safe_mode is False and agg.skip_time_based is False
    assert agg.skip_rce is False and agg.skip_data_modification is False
    assert agg.max_requests_per_target == 400 and agg.bola_max_requests_per_target == 800

    # Clamp to the resolved scan budget (api_probe_limit), never below the safe floor.
    clamped = poe.resolve_scan_poe_config("aggressive", request_ceiling=400)
    assert clamped.max_requests_per_target == 400 and clamped.bola_max_requests_per_target == 400
    low = poe.resolve_scan_poe_config("aggressive", request_ceiling=150)
    assert low.max_requests_per_target == 200 and low.bola_max_requests_per_target == 400
    high = poe.resolve_scan_poe_config("aggressive", request_ceiling=1500)
    assert high.max_requests_per_target == 400 and high.bola_max_requests_per_target == 800
    # Case-insensitive.
    assert poe.resolve_scan_poe_config("AGGRESSIVE").safe_mode is False


def test_focused_bola_poe_config_inherits_the_scan_session_profile():
    # An operator-confirmed aggressive scan must not be silently downgraded to the
    # safe proof profile when the focused-BOLA lane reconfigures PoE mid-scan.
    original_config = poe._poe_config
    try:
        poe.configure_poe(poe.PoEConfig.aggressive())
        focused = poe.focused_bola_poe_config(bola_max_requests_per_target=600, rate_limit_ms=250)
        assert focused.safe_mode is False
        assert focused.skip_time_based is False and focused.skip_rce is False
        assert focused.skip_data_modification is False
        assert focused.bola_max_requests_per_target == 600
        assert focused.rate_limit_ms == 250
        assert focused.max_requests_per_target == poe.PoEConfig.aggressive().max_requests_per_target

        poe.configure_poe(poe.PoEConfig.safe())
        focused_safe = poe.focused_bola_poe_config(bola_max_requests_per_target=300, rate_limit_ms=400)
        assert focused_safe.safe_mode is True
        assert focused_safe.skip_rce is True and focused_safe.skip_time_based is True
        assert focused_safe.bola_max_requests_per_target == 300
    finally:
        poe.configure_poe(original_config)


def test_focused_bola_poe_config_explicit_base_is_not_mutated():
    base = poe.PoEConfig.aggressive()
    derived = poe.focused_bola_poe_config(base, bola_max_requests_per_target=111, rate_limit_ms=50)
    assert derived.bola_max_requests_per_target == 111 and derived.rate_limit_ms == 50
    assert base.bola_max_requests_per_target != 111 and base.rate_limit_ms != 50
    assert derived.skip_rce is False and base.skip_rce is False
