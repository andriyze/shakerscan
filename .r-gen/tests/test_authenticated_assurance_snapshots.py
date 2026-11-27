from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_authenticated_assurance import configuration, valid, NOW, GENERATION
from api.authenticated_assurance.models import ProfileConfiguration
from api.authenticated_assurance.snapshots import (
    ScanProfileSelection, snapshot_for_scan, attach_scan_snapshots, snapshot_authority_current,
)
from api.authenticated_assurance.store import ProfileConflict


def inputs(configuration):
    config = ProfileConfiguration.model_validate({**configuration.model_dump(), "lifecycle_state": "ready"})
    record = valid(config).model_copy(update={"evidence_reference": uuid4()})
    profile = {"configuration": config.model_dump(mode="json"), "revision": 1, "current_profile_revision": 1,
        "current_lifecycle_state": "ready", "target_active": True, "current_target_url": "https://app.example.test",
        "credential_version": 1, "credential_record_version": 1, "current_version": 1, "current_record_version": 1,
        "configuration_digest": config.digest(1, 1), "validation": record.model_dump(mode="json"),
        "credential_active": True, "credential_expires_at": None}
    selection = ScanProfileSelection(profile_id=config.credential_reference, revision=1, reviewed=True)
    ref = {"profile_id": str(config.credential_reference), "profile_version": 1, "credential_record_version": 1}
    return config, profile, selection, ref


def snapshot(config, profile, selection, ref, **overrides):
    kwargs = {"target_id": config.target_id, "target_url": "https://app.example.test", "now": NOW, "generation": GENERATION}
    kwargs.update(overrides)
    return snapshot_for_scan(profile, selection, ref, **kwargs)


def test_snapshot_preserves_history_without_claiming_future_identity(configuration):
    args = inputs(configuration)
    config, profile, selection, ref = args
    pinned = snapshot(*args)
    original = pinned.model_dump(mode="json")
    profile["configuration"]["display_name"] = "Changed later"
    profile["current_profile_revision"] = 2
    assert pinned.model_dump(mode="json") == original
    assert pinned.assessment_authentication_state == "unknown"
    assert not pinned.continuous_authentication_proven
    assert "validation_policy" not in original
    assert "expected_identity" not in str(original)
    with pytest.raises(ProfileConflict, match="profile_changed"):
        snapshot(config, profile, selection, ref)


@pytest.mark.parametrize("changes,reason", [
    ({"credential_active": False}, "credential_revoked"),
    ({"current_record_version": 2}, "credential_changed"),
    ({"current_version": 2}, "credential_changed"),
    ({"current_profile_revision": 2}, "profile_changed"),
    ({"current_lifecycle_state": "disabled"}, "profile_disabled"),
    ({"target_active": False}, "destination_rejected"),
    ({"current_target_url": "https://app.example.test:8443"}, "destination_rejected"),
    ({"validation": None}, "not_validated"),
])
def test_snapshot_refuses_changed_or_unverified_configuration(configuration, changes, reason):
    config, profile, selection, ref = inputs(configuration)
    profile.update(changes)
    with pytest.raises(ProfileConflict, match=reason):
        snapshot(config, profile, selection, ref)


def test_snapshot_target_restart_and_expiry_boundaries(configuration):
    config, profile, selection, ref = inputs(configuration)
    for overrides, reason in [({"target_id": uuid4()}, "target_mismatch"),
                              ({"target_url": "http://app.example.test"}, "destination_rejected"),
                              ({"generation": uuid4()}, "process_restarted"),
                              ({"now": NOW + timedelta(seconds=301)}, "validation_stale")]:
        with pytest.raises(ProfileConflict, match=reason):
            snapshot(config, profile, selection, ref, **overrides)
    profile["credential_expires_at"] = NOW + timedelta(seconds=60)
    assert snapshot(config, profile, selection, ref).setup_valid_until == profile["credential_expires_at"]


def test_snapshot_is_bound_into_existing_action_identity(configuration):
    from api.scan.action_plan import credential_profile_action_refs, ScanActionPlanError

    args = inputs(configuration)
    config, profile, selection, ref = args
    ref.update(scan_lane="primary", auth_kind="bearer_token", target_kind="web")
    pinned = snapshot(*args).model_dump(mode="json")
    bound = attach_scan_snapshots([ref], [pinned])
    first = credential_profile_action_refs(bound)[0]
    assert "authenticated_profile_snapshot" not in ref
    assert first["digest"] != credential_profile_action_refs([ref])[0]["digest"]
    for change in [{"revision": 2}, {"configuration_digest": "a" * 64}, {"display_name": "Later name"}]:
        changed = attach_scan_snapshots([ref], [{**pinned, **change}])
        assert credential_profile_action_refs(changed)[0]["digest"] != first["digest"]
    pinned["display_name"] = "Caller mutation"
    assert credential_profile_action_refs(bound)[0] == first
    for invalid in [None, {}, {**bound[0]["authenticated_profile_snapshot"], "credential_version": 2}]:
        with pytest.raises(ScanActionPlanError, match="snapshot is invalid"):
            credential_profile_action_refs([{**ref, "authenticated_profile_snapshot": invalid}])


@pytest.mark.parametrize("change", [
    {"current_lifecycle_state": "disabled"}, {"current_profile_revision": 2},
    {"configuration_digest": "a" * 64}, {"current_record_version": 2},
    {"current_version": 2}, {"target_active": False},
    {"current_target_url": "https://app.example.test:8443"},
])
def test_snapshot_authority_detects_changes_without_rewriting_history(configuration, change):
    args = inputs(configuration)
    config, profile, _, _ = args
    pinned = snapshot(*args)
    assert snapshot_authority_current(pinned, profile, str(config.target_id))
    assert not snapshot_authority_current(pinned, {**profile, **change}, str(config.target_id))
    assert pinned.revision == 1 and pinned.assessment_authentication_state == "unknown"


def test_report_snapshot_is_historical_metadata_not_scan_health(configuration):
    from api.authenticated_assurance.evaluation import scan_authentication_summary

    args = inputs(configuration)
    refs = attach_scan_snapshots([args[3]], [snapshot(*args).model_dump(mode="json")])
    refs[0]["auth_header"] = "seeded-secret"
    summary = scan_authentication_summary({"credential_profile_refs": refs})
    recorded = summary["profiles"][0]["assessment_snapshot"]
    assert recorded["revision"] == 1 and recorded["display_name"] == args[0].display_name
    assert recorded["setup_evidence_reference"]
    assert summary["reason_code"] == "not_validated" and summary["state"] == "unknown"
    assert summary["coverage"] == "unverified" and not summary["continuous_authentication_proven"]
    assert "seeded-secret" not in str(summary)
    assert scan_authentication_summary({"credential_profile_refs": refs}, interrupted_action_count=1)["reason_code"] == "authentication_gap"
    refs[0]["authenticated_profile_snapshot"]["credential_version"] = 99
    invalid = scan_authentication_summary({"credential_profile_refs": refs})
    assert "assessment_snapshot" not in invalid["profiles"][0]
    assert invalid["state"] == "unknown"
