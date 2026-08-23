from __future__ import annotations

import copy

import pytest

from api.runtime.sealed_inputs import (
    SealedInputError,
    generate_sealed_input_keypair,
    open_private_input,
    seal_private_input,
    validate_sealed_input_public_key,
)


AUTHORITY = {
    "lease_id": "10000000-0000-4000-8000-000000000001",
    "worker_id": "broker:worker-1",
    "plan_digest": "a" * 64,
    "target_binding_digest": "b" * 64,
    "lease_expires_at": "2026-08-23T20:00:00+00:00",
}


def test_private_input_round_trip_is_lease_bound_and_ciphertext_only():
    private_key, public_key = generate_sealed_input_keypair()
    payload = {
        "schema_version": "broker-private-scan-input/v1",
        "auth_header": "Bearer canary-secret",
        "request": {"method": "POST", "body": "canary-body"},
    }

    envelope = seal_private_input(
        payload, recipient_public_key=public_key, authority=AUTHORITY,
    )

    assert "canary-secret" not in str(envelope)
    assert "canary-body" not in str(envelope)
    assert open_private_input(
        envelope, recipient_private_key=private_key, authority=AUTHORITY,
    ) == payload
    assert validate_sealed_input_public_key(public_key) == public_key


def test_private_input_rejects_wrong_worker_key_authority_and_tamper():
    private_key, public_key = generate_sealed_input_keypair()
    other_private_key, _ = generate_sealed_input_keypair()
    envelope = seal_private_input(
        {"secret": "value"},
        recipient_public_key=public_key,
        authority=AUTHORITY,
    )

    with pytest.raises(SealedInputError, match="authentication failed"):
        open_private_input(
            envelope,
            recipient_private_key=other_private_key,
            authority=AUTHORITY,
        )
    with pytest.raises(SealedInputError, match="authority does not match"):
        open_private_input(
            envelope,
            recipient_private_key=private_key,
            authority={**AUTHORITY, "worker_id": "broker:worker-2"},
        )

    changed = copy.deepcopy(envelope)
    changed["ciphertext"] = changed["ciphertext"][:-4] + "AAAA"
    with pytest.raises(SealedInputError):
        open_private_input(
            changed,
            recipient_private_key=private_key,
            authority=AUTHORITY,
        )


def test_private_input_keys_and_envelope_shape_fail_closed():
    with pytest.raises(SealedInputError, match="wrong size"):
        validate_sealed_input_public_key("YWJj")
    private_key, public_key = generate_sealed_input_keypair()
    envelope = seal_private_input(
        {"value": 1}, recipient_public_key=public_key, authority=AUTHORITY,
    )
    envelope["unexpected"] = True
    with pytest.raises(SealedInputError, match="shape"):
        open_private_input(
            envelope,
            recipient_private_key=private_key,
            authority=AUTHORITY,
        )
