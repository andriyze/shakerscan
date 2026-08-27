"""A recurring Scan must not be a way around canonical credential authority.

`POST /scans` rejects inline authentication and admits secrets only as versioned, target-bound
encrypted credential-profile references carried through the approval and action-plan contract.
`POST /schedules` took an unvalidated `scan_options` dict, so the same fields the direct route
refuses were accepted and persisted verbatim in JSONB -- a bearer token and a plaintext password
at rest, outside the encrypted credential store, feeding scans that the canonical path would have
refused to queue. These pin the boundary closed for create and update, on every schedule kind.
"""

from __future__ import annotations

import sys
from pathlib import Path

from tests.api_sources import definition_source

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from scan.contracts import (  # noqa: E402
    SCAN_AUTHENTICATION_KEYS,
    raw_scan_authentication_keys,
)


def test_raw_authentication_is_detected_by_the_shared_canonical_helper():
    # The schedule boundary must reuse the direct route's vocabulary, not keep a parallel list
    # that drifts: a key added to SCAN_AUTHENTICATION_KEYS has to be refused everywhere at once.
    assert raw_scan_authentication_keys({"budget_profile": "fast"}) == []
    assert raw_scan_authentication_keys({"auth_header": "Bearer x"}) == ["auth_header"]
    assert raw_scan_authentication_keys(
        {"login_username": "u", "login_password": "p"}
    ) == ["login_password", "login_username"]
    # Empty values carry no private material, so they are not a rejection reason.
    for empty in (None, "", [], {}):
        assert raw_scan_authentication_keys({"auth_header": empty}) == []
    # ...but an explicit boolean true does (auto_auth).
    assert raw_scan_authentication_keys({"auto_auth": True}) == ["auto_auth"]
    assert raw_scan_authentication_keys({"auto_auth": False}) == []


def test_every_authentication_key_is_covered():
    # No key may be silently exempt: each one alone must be enough to refuse the options.
    for key in SCAN_AUTHENTICATION_KEYS:
        assert raw_scan_authentication_keys({key: "value"}) == [key], key


def test_legacy_managed_profile_references_are_refused_too():
    # Legacy managed_credential_profiles survived into worker-side hydration that decrypts without
    # the canonical approval, version, capability and placement checks, so a schedule must not be
    # able to reintroduce it. credential_profile_ids is the canonical, validated form.
    assert raw_scan_authentication_keys(
        {"managed_credential_profiles": [{"id": "x"}]}
    ) == ["managed_credential_profiles"]
    assert raw_scan_authentication_keys({"credential_profile_ids": ["x"]}) == []


def test_schedule_create_refuses_raw_authentication():
    assert "_refuse_raw_schedule_authentication(scan_options)" in definition_source(
        "create_schedule")


def test_schedule_update_refuses_raw_authentication():
    assert "_refuse_raw_schedule_authentication(scan_options)" in definition_source(
        "update_schedule")


def test_the_refusal_uses_the_canonical_vocabulary_and_names_the_supported_form():
    refusal = definition_source("_refuse_raw_schedule_authentication")
    assert "raw_scan_authentication_keys" in refusal
    # The error has to tell the operator what to do instead, or the fix reads as an outage.
    assert "credential_profile_ids" in refusal
    assert "approval receipt" in refusal
    assert "status_code=422" in refusal


def test_the_refusal_is_not_limited_to_one_schedule_kind():
    # ASM waves carry scan_options too; scoping the check inside the normal_scan branch would leave
    # the same bypass open one kind over.
    for handler, branch in (
        ("create_schedule", 'if schedule_kind == "normal_scan"'),
        ("update_schedule", 'if effective_schedule_kind == "normal_scan"'),
    ):
        source = definition_source(handler)
        guard = source.index("_refuse_raw_schedule_authentication(scan_options)")
        assert source.rfind(branch, 0, guard) == -1, (
            f"{handler} must refuse raw authentication before its per-kind branch")
