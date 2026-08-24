from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import sys
import uuid

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from scan.private_state import (  # noqa: E402
    ScanPrivateStateError,
    generate_scan_private_state_key,
    open_scan_auth_session_state,
    seal_scan_auth_session_state,
)


def _checkpoint(*, now: datetime, expires_at: datetime):
    key = generate_scan_private_state_key()
    values = {
        "scan_id": str(uuid.uuid4()),
        "action_id": "inputs.auth_primary",
        "action_digest": "a" * 64,
        "target_binding_digest": "b" * 64,
        "lane": "primary",
        "credential_binding_digest": "c" * 64,
        "profile_id": str(uuid.uuid4()),
        "profile_version": 3,
        "principal": "primary-user",
    }
    checkpoint = seal_scan_auth_session_state(
        key,
        **values,
        headers={"Cookie": "session=private-canary"},
        established_at=now,
        expires_at=expires_at,
        refresh_after=now + timedelta(minutes=5),
        compatible_capabilities=("auth.session.establish", "http.request"),
        evidence_receipt_digest="d" * 64,
    )
    return key, values, checkpoint


def test_checkpoint_records_authority_metadata_without_secret_values():
    pytest.importorskip("cryptography")
    now = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
    key, values, checkpoint = _checkpoint(
        now=now, expires_at=now + timedelta(hours=1),
    )

    serialized = json.dumps(checkpoint)
    assert "private-canary" not in serialized
    assert checkpoint["profile_id"] == values["profile_id"]
    assert checkpoint["profile_version"] == 3
    assert checkpoint["principal"] == "primary-user"
    assert checkpoint["evidence_receipt_digest"] == "d" * 64
    assert open_scan_auth_session_state(
        key,
        checkpoint,
        **values,
        now=now + timedelta(minutes=10),
    ) == {"Cookie": "session=private-canary"}


def test_checkpoint_rejects_expiry_profile_rotation_and_revocation():
    pytest.importorskip("cryptography")
    now = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
    key, values, checkpoint = _checkpoint(
        now=now, expires_at=now + timedelta(hours=1),
    )

    with pytest.raises(ScanPrivateStateError, match="expired or revoked"):
        open_scan_auth_session_state(
            key,
            checkpoint,
            **values,
            now=now + timedelta(hours=2),
        )
    with pytest.raises(ScanPrivateStateError, match="profile version changed"):
        open_scan_auth_session_state(
            key,
            checkpoint,
            **{**values, "profile_version": 4},
            now=now + timedelta(minutes=10),
        )
    revoked = dict(checkpoint)
    revoked["status"] = "revoked"
    with pytest.raises(ScanPrivateStateError, match="metadata changed"):
        open_scan_auth_session_state(
            key,
            revoked,
            **values,
            now=now + timedelta(minutes=10),
        )
