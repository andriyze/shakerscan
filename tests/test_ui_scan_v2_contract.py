from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_new_scan_ui_has_one_scan_and_no_legacy_type_picker():
    source = (ROOT / "ui" / "src" / "app" / "scan" / "new" / "page.tsx").read_text()

    assert "submitScanV2" in source
    assert "budget_profile" in source
    assert "active_testing" in source
    assert "getScanPublicContract" in source
    assert "include_families" in source
    assert "exclude_families" in source
    assert "scan.execute" not in source
    assert "legacy_capability" not in source
    assert "removeConfirmedActiveSelections" in source
    assert "minimum === 0 ? ' · zero allowed'" in source
    assert "Run Scan" in source
    assert "SCAN_TYPES" not in source
    assert "scan_type" not in source
    for legacy_label in ("Quick", "Standard", "Deep", "Full", "Aggressive", "Smart"):
        assert f">{legacy_label}<" not in source


def test_request_collection_picker_reports_exact_replay_policy_to_scan_form():
    picker = (ROOT / "ui" / "src" / "components" / "RequestCollectionPicker.tsx").read_text()
    page = (ROOT / "ui" / "src" / "app" / "scan" / "new" / "page.tsx").read_text()

    assert "onMetadataChange" in picker
    assert "replayPolicy: selection.replay_policy" in picker
    assert "onMetadataChange={setRequestCollectionMetadata}" in page
    assert "replay_policy: requestCollectionMetadata[id].replayPolicy" in page


def test_primary_rescan_and_schedule_surfaces_use_v2_budget_not_type_picker():
    scans = (ROOT / "ui" / "src" / "app" / "scans" / "page.tsx").read_text()
    targets = (ROOT / "ui" / "src" / "app" / "targets" / "page.tsx").read_text()
    schedules = (ROOT / "ui" / "src" / "app" / "schedules" / "page.tsx").read_text()

    assert "submitScanV2" in scans and "SCAN_TYPES" not in scans
    assert "budget_profile: 'balanced'" in targets and "SCAN_TYPES" not in targets
    assert "formBudgetProfile" in schedules and "SCAN_TYPES" not in schedules
