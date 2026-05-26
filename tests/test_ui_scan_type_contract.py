from pathlib import Path


def test_ui_scan_presets_send_explicit_scan_type():
    constants = Path(__file__).resolve().parents[1] / "ui" / "src" / "lib" / "constants.ts"
    source = constants.read_text()

    for scan_type in ("quick", "standard", "deep", "full", "aggressive", "smart"):
        assert f"value: '{scan_type}'" in source
        assert f"scan_type: '{scan_type}'" in source


def test_ui_get_scan_options_returns_copy():
    constants = Path(__file__).resolve().parents[1] / "ui" / "src" / "lib" / "constants.ts"
    source = constants.read_text()

    assert "return type ? { ...type.options } : {}" in source
