"""Tests for scanner_tools.focused_scope.

The FocusedScope helper centralizes the previously open-coded
`focused_manual_active_scope` flag. These tests pin its contract so future
module migrations don't accidentally drift.
"""

import os
import sys


_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
if _SCANNER_DIR not in sys.path:
    sys.path.insert(0, _SCANNER_DIR)

from scanner_tools.focused_scope import (  # noqa: E402
    CORS_SHAPE,
    DMARC_SHAPE,
    FOCUSED_SKIP_REASON,
    FocusedScope,
    NO_FOCUSED_SCOPE,
)


def test_scanner_zero_rediscovery_flag_guards_discovery_branches():
    from pathlib import Path

    source = Path(__file__).resolve().parents[1].joinpath("scanner", "scanner.py").read_text()

    assert "--zero-rediscovery" in source
    assert "zero_rediscovery=getattr(args, \"zero_rediscovery\", False)" in source
    assert "zero_rediscovery_scope = bool(zero_rediscovery and focused_manual_active_scope)" in source
    assert "if zero_rediscovery_scope:\n        async def dummy_katana_zero" in source
    assert "if zero_rediscovery_scope:\n        browser_task = asyncio.create_task(_focused_async_value(None))" in source
    assert "elif smart_mode and not zero_rediscovery_scope:\n        # Smart mode: Use recursive discovery" in source
    assert "elif smart_mode and not zero_rediscovery_scope:\n        js_urls =" in source
    assert "if json_link_following and not public_only and not zero_rediscovery_scope" in source
    assert "if options_method_discovery and not public_only and not zero_rediscovery_scope" in source
    assert "reason\": \"zero_rediscovery_child\"" in source


def test_from_request_active_requires_smart_family_and_endpoints():
    scope = FocusedScope.from_request(
        smart_mode=True,
        family="xss",
        manual_endpoints=[{"url": "/login", "method": "POST"}],
    )
    assert scope.active is True
    assert scope.family == "xss"
    assert scope.manual_endpoint_count == 1
    assert bool(scope) is True


def test_from_request_inactive_without_smart_mode():
    scope = FocusedScope.from_request(
        smart_mode=False,
        family="xss",
        manual_endpoints=[{"url": "/login"}],
    )
    assert scope.active is False
    assert scope.family is None
    assert scope.manual_endpoint_count == 0


def test_from_request_inactive_without_family():
    scope = FocusedScope.from_request(
        smart_mode=True,
        family=None,
        manual_endpoints=[{"url": "/login"}],
    )
    assert scope.active is False


def test_from_request_inactive_without_endpoints():
    scope = FocusedScope.from_request(
        smart_mode=True,
        family="xss",
        manual_endpoints=[],
    )
    assert scope.active is False
    assert scope.manual_endpoint_count == 0


def test_skip_predicates_follow_active_flag():
    scope = FocusedScope.from_request(
        smart_mode=True,
        family="sqli",
        manual_endpoints=[{"url": "/api/items"}],
    )
    assert scope.skip_posture() is True
    assert scope.skip_discovery() is True
    assert scope.skip_module("dom_xss") is True


def test_no_focused_scope_skips_nothing():
    assert NO_FOCUSED_SCOPE.active is False
    assert NO_FOCUSED_SCOPE.skip_posture() is False
    assert NO_FOCUSED_SCOPE.skip_discovery() is False
    assert bool(NO_FOCUSED_SCOPE) is False


def test_skipped_result_merges_shape_with_markers():
    scope = FocusedScope.from_request(
        smart_mode=True,
        family="xss",
        manual_endpoints=[{"url": "/login"}],
    )
    result = scope.skipped_result(DMARC_SHAPE)

    # Shape preserved.
    assert result["record"] is None
    assert result["fields"] == {}
    # Markers added.
    assert result["skipped"] is True
    assert result["reason"] == FOCUSED_SKIP_REASON


def test_skipped_result_accepts_custom_reason():
    scope = NO_FOCUSED_SCOPE
    result = scope.skipped_result(CORS_SHAPE, reason="public_quick_mode")
    assert result["reason"] == "public_quick_mode"
    assert result["vulnerable"] is False


def test_skipped_result_does_not_mutate_input_shape():
    before = dict(CORS_SHAPE)
    scope = FocusedScope.from_request(
        smart_mode=True,
        family="xss",
        manual_endpoints=[{"url": "/x"}],
    )
    _ = scope.skipped_result(CORS_SHAPE)
    # The module-level shape constant must not be polluted.
    assert CORS_SHAPE == before
    assert "skipped" not in CORS_SHAPE


def test_skipped_result_works_with_empty_shape():
    scope = FocusedScope.from_request(
        smart_mode=True,
        family="xss",
        manual_endpoints=[{"url": "/x"}],
    )
    result = scope.skipped_result(None)
    assert result == {"skipped": True, "reason": FOCUSED_SKIP_REASON}


def test_focused_scope_is_immutable():
    scope = FocusedScope(active=True, family="xss", manual_endpoint_count=2)
    # @dataclass(frozen=True) — assignment raises.
    try:
        scope.active = False  # type: ignore[misc]
    except Exception as exc:
        assert "frozen" in str(exc).lower() or "cannot assign" in str(exc).lower()
    else:
        raise AssertionError("expected frozen dataclass to reject assignment")
