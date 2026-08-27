from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json

from api.runtime.credential_resolver import (
    WorkerCredentialResolver,
    validate_worker_credential_authority,
)
from api.runtime.credential_store import (
    CredentialProfileMetadata,
    WorkerCredentialCiphertext,
)
from api.runtime.credentials import (
    build_credential_secret,
    parse_credential_secret,
    public_credential_configuration,
)
from api.runtime.models import TargetBinding
from api.runtime.request_replay_executor import (
    ReplayTransportResult,
    execute_replay_plan,
)
from scanner.scanner_tools.request_replay import (
    bind_replay_credential_headers,
    build_replay_plan,
)


TARGET_ID = "22222222-2222-4222-8222-222222222222"
PROFILE_ID = "11111111-1111-4111-8111-111111111111"
APPROVAL_ID = "44444444-4444-4444-8444-444444444444"


class Connection:
    async def fetchrow(self, query, *args):
        assert "approval_receipts" in query
        return {
            "scope_receipt_id": "scope-1",
            "risk_tier": "credential",
            "confirmations": ["confirm_authorized"],
            "approved_by": "operator",
            "denial_reason": None,
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
            "action_name": "hunt.capability:collections.replay_safe",
            "target_id": TARGET_ID,
            "verdict": "allowed",
            # approval_receipts.status is NOT NULL DEFAULT 'active' and revoked_at is set only by
            # revocation; the worker reload fails closed when they are absent, because a row that
            # cannot exist in the real table means the reload did not read what it thinks it did.
            "status": "active",
            "revoked_at": None,
        }


class Store:
    def __init__(self, profile):
        self.profile = profile

    async def load_for_worker(self, conn, **kwargs):
        assert kwargs == {
            "profile_id": PROFILE_ID,
            "target_kind": "api",
            "target_id": TARGET_ID,
            "capability": "request.replay",
        }
        return WorkerCredentialCiphertext(
            metadata=self.profile,
            encrypted_secret="cipher-secret",
            encrypted_metadata="cipher-metadata",
            allowed_capabilities=("request.replay",),
        )


class Transport:
    def __init__(self):
        self.headers = None

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        self.headers = dict(request.headers)
        return ReplayTransportResult(
            status_code=200,
            connected_address="192.0.2.20",
            final_url=request.url,
            response_headers={"Content-Type": "application/json"},
            response_body=b"{}",
            elapsed_ms=1,
        )


def test_worker_authority_resolution_binding_execution_and_receipt_are_one_chain():
    target = TargetBinding(
        target_id=TARGET_ID,
        target_kind="api",
        canonical_host="example.test",
        allowed_origins=("https://example.test",),
        allowed_addresses=("192.0.2.20",),
        allowed_root_domains=("example.test",),
        scope_receipt_id="scope-1",
    )
    envelope = build_credential_secret("bearer_token", secret="managed-secret")
    configuration = public_credential_configuration(
        parse_credential_secret("bearer_token", envelope)
    )
    now = datetime.now(timezone.utc)
    profile = CredentialProfileMetadata(
        profile_id=PROFILE_ID,
        target_kind="api",
        target_id=TARGET_ID,
        name="primary",
        auth_kind="bearer_token",
        principal_label=None,
        principal_slot="primary",
        configuration=configuration,
        current_version=7,
        record_version=8,
        is_active=True,
        expires_at=None,
        rotated_at=now,
        created_at=now,
        updated_at=now,
        allowed_capabilities=("request.replay",),
    )
    metadata = json.dumps({
        "schema_version": "credential-private-metadata/v1",
        "created_by": "test",
    })
    resolver = WorkerCredentialResolver(
        store=Store(profile),
        decryptor=lambda value: {
            "cipher-secret": envelope,
            "cipher-metadata": metadata,
        }[value],
    )
    captured_plan = build_replay_plan(
        [{
            "id": "read-1",
            "method": "GET",
            "url": "https://example.test/private",
            "headers": {
                "Authorization": "Bearer captured-secret",
                "Cookie": "captured=cookie-secret",
                "Accept": "application/json",
            },
        }],
        allowed_origins=target.allowed_origins,
    )
    transport = Transport()

    async def exercise():
        authority = await validate_worker_credential_authority(
            Connection(),
            owner_kind="hunt",
            owner_id="hunt-1",
            target=target,
            approval_receipt_id=APPROVAL_ID,
            scope_receipt_id="scope-1",
            action_name="hunt.capability:collections.replay_safe",
        )
        async with resolver.resolve(
            object(),
            profile_id=PROFILE_ID,
            target=target,
            capability="request.replay",
            authority=authority,
        ) as credential:
            bound_plan = bind_replay_credential_headers(
                captured_plan,
                credential.http_headers().as_dict(),
                auth_kind=credential.profile.auth_kind,
            )
            outcome = await execute_replay_plan(
                bound_plan,
                target=target,
                owner_kind="hunt",
                owner_id="hunt-1",
                worker_id="worker-1",
                limits={"http_requests": 2},
                consumed={"http_requests": 0},
                transport=transport,
                receipt_context={
                    "principal_profile_ref": credential.profile.profile_id,
                    "principal_profile_version": credential.profile.current_version,
                    "principal_slot": credential.profile.principal_slot,
                },
            )
        return outcome

    outcome = asyncio.run(exercise())
    assert transport.headers == {
        "Accept": "application/json",
        "Authorization": "Bearer managed-secret",
    }
    public = outcome.receipt.public_dict()
    assert public["redacted_execution"]["principal_profile_ref"] == PROFILE_ID
    assert public["redacted_execution"]["principal_profile_version"] == 7
    rendered = repr(public)
    assert "managed-secret" not in rendered
    assert "captured-secret" not in rendered
    assert "cookie-secret" not in rendered
