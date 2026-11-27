"""A run starts from another run's live login for the same credential and target, or logs in."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import json
import uuid

import pytest

pytest.importorskip("cryptography")

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
PROFILE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
TARGET_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


@pytest.fixture(autouse=True)
def encryption_key(monkeypatch):
    from cryptography.fernet import Fernet
    import secret_store

    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    # Both caches: the key, and whether it was loaded (a loaded-but-empty cache refuses encryption).
    monkeypatch.setattr(secret_store, "_fernet", None)
    monkeypatch.setattr(secret_store, "_loaded", False)


def _target():
    from runtime.models import TargetBinding

    return TargetBinding(
        target_id=TARGET_ID, target_kind="web", canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",), allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",), environment="test", scope_receipt_id="scope-2",
    )


def _credential(target):
    from capabilities.auth import TargetBoundSessionCredential

    return TargetBoundSessionCredential(
        lane="primary", auth_kind="form_login", endpoint_url="https://app.example.test/login",
        binding_digest=target.digest, username="alice", secret="never-sent",
        profile_id=PROFILE_ID, profile_version=2, principal="alice",
        compatible_capabilities=("http.request", "auth.session.refresh"),
    )


def _row(headers=None):
    import secret_store

    return {
        "id": uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
        "principal_label": "alice",
        "encrypted_headers": secret_store.encrypt_secret(json.dumps(headers or {"Cookie": "sid=live; theme=dark"})),
        "established_at": NOW - timedelta(minutes=20),
        "expires_at": NOW + timedelta(hours=1),
        "refresh_after": NOW + timedelta(minutes=30),
    }


class _Pool:
    def __init__(self, result):
        self.result = result
        self.queries = []

    @asynccontextmanager
    async def acquire(self):
        pool = self

        class Conn:
            async def fetchrow(self, query, *args):
                pool.queries.append(args)
                if isinstance(pool.result, Exception):
                    raise pool.result
                return pool.result

        yield Conn()


def _run(pool):
    from capabilities.session_reuse import reuse_or_establish_session

    target = _target()
    logins = []

    async def login(credential, *, target):
        logins.append(credential.profile_id)
        return "logged-in"

    session = asyncio.run(reuse_or_establish_session(
        pool, _credential(target), target=target, now=NOW, establish=login,
    ))
    return session, logins


def test_a_live_session_is_adopted_without_sending_a_request():
    pool = _Pool(_row())
    session, logins = _run(pool)
    assert logins == []
    assert session.established and session.request_count == 0
    assert session.headers() == {"Cookie": "sid=live; theme=dark"}
    assert (session.expires_at, session.refresh_after) == (NOW + timedelta(hours=1), NOW + timedelta(minutes=30))
    observation = session.observation
    assert observation["reused"] is True
    assert observation["reused_session_ref"] == "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    assert observation["cookie_names"] == ["sid", "theme"]
    assert observation["session_ref"] != observation["reused_session_ref"]
    assert "live" not in json.dumps(observation)
    assert session.execution_result()["budget_consumed"] == {"http_requests": 0, "tool_wall_seconds": 0}
    # The lookup is for exactly this target, credential version, slot, kind and origin.
    target_text, target_uuid, kind, profile, version, slot, auth_kind, _now, origin, margin = pool.queries[0]
    assert (target_text, str(target_uuid), kind, str(profile), version, slot, auth_kind) == (
        TARGET_ID, TARGET_ID, "web", PROFILE_ID, 2, "primary", "form_login")
    assert origin == "https://app.example.test" and margin == timedelta(minutes=5)


@pytest.mark.parametrize("result", [None, RuntimeError("database unavailable")])
def test_without_a_reusable_session_the_run_logs_in(result):
    session, logins = _run(_Pool(result))
    assert session == "logged-in" and logins == [PROFILE_ID]


def test_an_unreadable_stored_session_is_not_reused():
    row = _row()
    row["encrypted_headers"] = "enc:fernet:not-a-token"
    session, logins = _run(_Pool(row))
    assert session == "logged-in" and logins == [PROFILE_ID]


def test_both_login_sites_go_through_reuse_and_refresh_still_logs_in():
    from pathlib import Path

    worker = (Path(__file__).resolve().parents[1] / "api" / "worker.py").read_text(encoding="utf-8")
    assert worker.count("await reuse_or_establish_session(") == 2
    # Refreshing an expiring session must perform a new exchange, never adopt another.
    assert "private_session = await establish_target_bound_http_session(\n                    credential,\n                    target=target,\n                    session_ref=session_metadata.session_ref," in worker
