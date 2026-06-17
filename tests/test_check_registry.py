import pytest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import check_registry as r  # noqa: E402


def test_registry_exposes_runnable_asm_focus_families():
    names = r.asm_focus_family_names()

    assert names == ("all", "sqli", "xss", "bola")
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
    assert r.CHECK_REGISTRY_BY_NAME["bola"].scanner_options == {
        "sqli": False,
        "xss": False,
        "asm_check_family": "bola",
    }


def test_registry_gates_high_risk_families_by_runnable_state():
    bola = r.CHECK_REGISTRY_BY_NAME["bola"]
    ssrf = r.CHECK_REGISTRY_BY_NAME["ssrf"]

    assert bola.runnable is True
    assert bola.requires_auth_states is True
    assert bola.requires_credentials is True
    assert bola.allowed_presets == ("lab",)
    assert ssrf.risk_level == "high"
    assert ssrf.allowed_presets == ("lab",)
    assert ssrf.runnable is False


def test_validate_asm_focus_rejects_registered_but_unrunnable_family():
    with pytest.raises(ValueError, match="registered but not runnable"):
        r.validate_asm_focus_family("ssrf")


def test_validate_asm_focus_rejects_unknown_family_with_allowed_list():
    with pytest.raises(ValueError, match="allowed families: all, sqli, xss, bola"):
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


def test_default_parallel_focus_families_exclude_high_risk_bola():
    assert tuple(spec.name for spec in r.default_parallel_focus_families()) == ("sqli", "xss")
