import importlib.util
import os
import sys

import pytest


_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
_added_scanner_dir = False
if _SCANNER_DIR not in sys.path:
    sys.path.insert(0, _SCANNER_DIR)
    _added_scanner_dir = True

_spec = importlib.util.spec_from_file_location(
    "shaker_scanner_scope_under_test", os.path.join(_SCANNER_DIR, "scanner.py")
)
scanner_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner_mod)
if _added_scanner_dir:
    sys.path.remove(_SCANNER_DIR)


def test_check_family_scope_marks_focused_sqli():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=False,
        active_sqli=True,
        requested_family="sqli",
    )

    assert scope["mode"] == "focused"
    assert scope["focused"] is True
    assert scope["focused_family"] == "sqli"
    assert scope["families"] == ["sqli"]
    assert scope["source"] == "check_family"
    assert scope["requested_family"] == "sqli"
    assert scope["legacy_flags"] == {"xss": False, "sqli": True}


def test_check_family_scope_marks_focused_bola():
    scope = scanner_mod.build_check_family_scope(
        True,
        active_xss=False,
        active_sqli=False,
        requested_family="bola",
    )

    assert scope["mode"] == "focused"
    assert scope["focused"] is True
    assert scope["focused_family"] == "bola"
    assert scope["families"] == ["bola"]
    assert scope["source"] == "check_family"
    assert scope["requested_family"] == "bola"
    assert scope["legacy_flags"] == {"xss": False, "sqli": False}


def test_check_family_scope_marks_normal_active_mix():
    scope = scanner_mod.build_check_family_scope(True, active_xss=True, active_sqli=True)

    assert scope["mode"] == "active_mix"
    assert scope["focused"] is False
    assert scope["focused_family"] is None
    assert scope["families"] == ["xss", "sqli"]


def test_check_family_scope_marks_inactive_scan():
    scope = scanner_mod.build_check_family_scope(False, active_xss=True, active_sqli=True)

    assert scope["mode"] == "inactive"
    assert scope["focused"] is False
    assert scope["families"] == []


def test_resolve_active_check_flags_uses_registry_family_aliases():
    active_xss, active_sqli, family = scanner_mod.resolve_active_check_flags(check_family="sql")

    assert active_xss is False
    assert active_sqli is True
    assert family == "sqli"


def test_resolve_active_check_flags_all_family_keeps_active_mix():
    active_xss, active_sqli, family = scanner_mod.resolve_active_check_flags(check_family="all")

    assert active_xss is True
    assert active_sqli is True
    assert family == "all"


def test_resolve_active_check_flags_accepts_bola_without_injection_flags():
    active_xss, active_sqli, family = scanner_mod.resolve_active_check_flags(check_family="idor")

    assert active_xss is False
    assert active_sqli is False
    assert family == "bola"


def test_resolve_active_check_flags_rejects_unsupported_family():
    with pytest.raises(ValueError, match="not runnable"):
        scanner_mod.resolve_active_check_flags(check_family="ssrf")


def test_resolve_active_check_flags_rejects_conflicting_legacy_flags():
    with pytest.raises(ValueError, match="conflicts"):
        scanner_mod.resolve_active_check_flags(check_family="sqli", xss=True)
