import importlib.util
import os
import sys


_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
if _SCANNER_DIR not in sys.path:
    sys.path.insert(0, _SCANNER_DIR)

_spec = importlib.util.spec_from_file_location(
    "shaker_scanner_scope_under_test", os.path.join(_SCANNER_DIR, "scanner.py")
)
scanner_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner_mod)


def test_check_family_scope_marks_focused_sqli():
    scope = scanner_mod.build_check_family_scope(True, active_xss=False, active_sqli=True)

    assert scope["mode"] == "focused"
    assert scope["focused"] is True
    assert scope["focused_family"] == "sqli"
    assert scope["families"] == ["sqli"]
    assert scope["legacy_flags"] == {"xss": False, "sqli": True}


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
