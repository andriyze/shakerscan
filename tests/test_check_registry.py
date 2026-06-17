import pytest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import check_registry as r  # noqa: E402


def test_registry_exposes_runnable_asm_focus_families():
    names = r.asm_focus_family_names()

    assert names == ("all", "sqli", "xss")
    assert r.CHECK_REGISTRY_BY_NAME["sqli"].scanner_options == {
        "sqli": True,
        "xss": False,
        "asm_check_family": "sqli",
    }
    assert r.CHECK_REGISTRY_BY_NAME["xss"].scanner_options == {
        "xss": True,
        "sqli": False,
        "asm_check_family": "xss",
    }


def test_registry_contains_planned_high_risk_families_without_enabling_them():
    bola = r.CHECK_REGISTRY_BY_NAME["bola"]
    ssrf = r.CHECK_REGISTRY_BY_NAME["ssrf"]

    assert bola.runnable is False
    assert bola.requires_auth_states is True
    assert bola.requires_credentials is True
    assert ssrf.risk_level == "high"
    assert ssrf.allowed_presets == ("lab",)


def test_validate_asm_focus_rejects_registered_but_unrunnable_family():
    with pytest.raises(ValueError, match="registered but not runnable"):
        r.validate_asm_focus_family("bola")


def test_validate_asm_focus_rejects_unknown_family_with_allowed_list():
    with pytest.raises(ValueError, match="allowed families: all, sqli, xss"):
        r.validate_asm_focus_family("nosuch")


def test_apply_asm_focus_uses_registry_scanner_options():
    opts, family = r.apply_asm_focus({"scan_type": "smart", "xss": True}, "sql")

    assert family == "sqli"
    assert opts["sqli"] is True
    assert opts["xss"] is False
    assert opts["asm_check_family"] == "sqli"


def test_all_focus_preserves_normal_mix_and_clears_marker():
    opts, family = r.apply_asm_focus({"scan_type": "smart", "asm_check_family": "xss"}, "all")

    assert family is None
    assert "asm_check_family" not in opts
