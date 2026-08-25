"""Worker tests for canonical Scan and AI execution policy boundaries."""

import asyncio
import copy
from contextlib import asynccontextmanager
import json
import os
import sys
import types
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

import worker  # noqa: E402


def test_scope_refusal_reconciles_terminal_shard_parent(monkeypatch):
    parent_id = uuid.uuid4()
    scan_id = uuid.uuid4()

    class Conn:
        async def fetchrow(self, query, *args):
            assert "RETURNING parent_scan_id" in query
            assert args[0] == scan_id
            return {"parent_scan_id": parent_id}

    class Pool:
        def acquire(self):
            return self

        async def __aenter__(self):
            return Conn()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    reconciled = []

    async def reconcile(conn, candidate_parent_id, redis_client, queue_name):
        reconciled.append((candidate_parent_id, redis_client, queue_name))
        return True

    redis_client = object()
    monkeypatch.setattr(worker, "db_pool", Pool())
    monkeypatch.setattr(worker, "get_redis", lambda: redis_client)
    monkeypatch.setattr(worker.parallel_scan, "reconcile_parallel_parent", reconcile)

    asyncio.run(worker._fail_execution_scope(
        {"scan_id": str(scan_id), "job_id": ""},
        "persisted authority mismatch",
    ))

    assert reconciled == [(str(parent_id), redis_client, worker.QUEUE_NAME)]


class _ManagedCredentialConn:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    async def fetch(self, query, *args):
        self.calls.append((query, args))
        assert "JOIN target_credential_profiles cp ON cp.target_id = s.target_id" in query
        return self.rows


class _ManagedCredentialPool:
    def __init__(self, rows):
        self.conn = _ManagedCredentialConn(rows)

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _GenericCredentialConn:
    def __init__(self, target_id):
        self.target_id = target_id

    async def fetchrow(self, query, *_args):
        assert "FROM scans s JOIN targets t" in query
        return {
            "target_id": self.target_id,
            "target_url": "https://app.example.com",
            "root_domain": "example.com",
        }


class _GenericCredentialPool:
    def __init__(self, target_id):
        self.conn = _GenericCredentialConn(target_id)

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


def test_managed_credentials_are_hydrated_only_in_worker_memory(monkeypatch):
    p1 = uuid.uuid4()
    p2 = uuid.uuid4()
    monkeypatch.setattr(worker, "db_pool", _ManagedCredentialPool([
        {"id": p1, "auth_kind": "authorization_header", "secret_value": "enc-u1"},
        {"id": p2, "auth_kind": "cookie", "secret_value": "enc-u2"},
    ]))
    monkeypatch.setattr(worker, "decrypt_secret", lambda value: {"enc-u1": "Bearer user-one", "enc-u2": "session=user-two"}[value])
    queued = {
        "scan_type": "smart",
        "managed_credential_profiles": [
            {"auth_state": "user1", "profile_id": str(p1), "option_key": "auth_header"},
            {"auth_state": "user2", "profile_id": str(p2), "option_key": "user2_cookies"},
        ],
    }

    hydrated = asyncio.run(worker._hydrate_managed_scan_credentials(queued, str(uuid.uuid4())))

    assert "managed_credential_profiles" not in hydrated
    assert hydrated["auth_header"] == "Bearer user-one"
    assert hydrated["user2_cookies"] == "session=user-two"
    assert queued.get("auth_header") is None
    assert "user-one" not in json.dumps(queued)
    assert [item["profile_id"] for item in hydrated["resolved_credential_profiles"]] == [str(p1), str(p2)]


def test_worker_rejects_duplicate_managed_profile_refs(monkeypatch):
    profile_id = str(uuid.uuid4())
    monkeypatch.setattr(worker, "db_pool", _ManagedCredentialPool([]))
    queued = {"managed_credential_profiles": [
        {"auth_state": "user1", "profile_id": profile_id, "option_key": "auth_header"},
        {"auth_state": "user2", "profile_id": profile_id, "option_key": "user2_header"},
    ]}

    try:
        asyncio.run(worker._hydrate_managed_scan_credentials(queued, str(uuid.uuid4())))
    except ValueError as exc:
        assert "must be distinct" in str(exc)
    else:
        raise AssertionError("duplicate managed profile refs should fail closed")


def test_worker_rejects_unavailable_or_undecryptable_managed_profile(monkeypatch):
    profile_id = uuid.uuid4()
    queued = {"managed_credential_profiles": [{
        "auth_state": "user1", "profile_id": str(profile_id), "option_key": "auth_header",
    }]}
    monkeypatch.setattr(worker, "db_pool", _ManagedCredentialPool([]))
    try:
        asyncio.run(worker._hydrate_managed_scan_credentials(queued, str(uuid.uuid4())))
    except ValueError as exc:
        assert "unavailable" in str(exc)
    else:
        raise AssertionError("missing profile should fail closed")

    monkeypatch.setattr(worker, "db_pool", _ManagedCredentialPool([
        {"id": profile_id, "auth_kind": "authorization_header", "secret_value": "enc:fernet:unavailable"},
    ]))
    monkeypatch.setattr(worker, "decrypt_secret", lambda value: value)
    try:
        asyncio.run(worker._hydrate_managed_scan_credentials(queued, str(uuid.uuid4())))
    except ValueError as exc:
        assert "could not be decrypted" in str(exc)
    else:
        raise AssertionError("undecryptable profile should fail closed")


def test_generic_scan_credentials_are_revalidated_and_decrypted_only_on_worker(monkeypatch):
    target_id = uuid.uuid4()
    profile_id = uuid.uuid4()
    monkeypatch.setattr(worker, "db_pool", _GenericCredentialPool(target_id))

    async def validate(*_args, **_kwargs):
        return types.SimpleNamespace()

    class Resolver:
        @asynccontextmanager
        async def resolve(self, *_args, **_kwargs):
            profile = types.SimpleNamespace(
                profile_id=str(profile_id),
                current_version=2,
                auth_kind="bearer_token",
                principal_slot="primary",
                target_kind="web",
                allowed_capabilities=(),
            )
            yield types.SimpleNamespace(
                profile=profile,
                http_headers=lambda: types.SimpleNamespace(
                    as_dict=lambda: {"Authorization": "Bearer worker-only-secret"},
                ),
                receipt_metadata=lambda: {
                    "principal_profile_ref": str(profile_id),
                    "principal_profile_version": 2,
                    "secret_values_visible": False,
                },
            )

    monkeypatch.setattr(worker, "validate_worker_credential_authority", validate)
    monkeypatch.setattr(worker, "WorkerCredentialResolver", Resolver)
    queued = {
        "credential_profile_refs": [{
            "profile_id": str(profile_id),
            "profile_version": 2,
            "target_kind": "web",
            "principal_slot": "primary",
            "scan_lane": "primary",
            "auth_kind": "bearer_token",
            "source": "credential_profiles",
            "secret_values_visible": False,
        }],
        "credential_target_kind": "web",
        "credential_action_name": "scan.submit",
        "approval_receipt_id": str(uuid.uuid4()),
        "scope_receipt_id": "scope-1",
        "runtime_scope_guard": {
            "environment": "production",
            "allowed_root_domains": ["example.com"],
        },
    }

    hydrated = asyncio.run(
        worker._hydrate_generic_scan_credentials(queued, str(uuid.uuid4()))
    )

    assert hydrated["auth_header"] == "Bearer worker-only-secret"
    assert hydrated["credential_profile_refs"] == queued["credential_profile_refs"]
    assert hydrated["credential_target_kind"] == "web"
    assert hydrated["credential_action_name"] == "scan.submit"
    assert hydrated["resolved_credential_profiles"][0]["secret_values_visible"] is False
    assert "worker-only-secret" not in json.dumps(hydrated["credential_profile_refs"])
    assert "worker-only-secret" not in json.dumps(queued)


@pytest.mark.parametrize("conflict", [
    {"auth_header": "Bearer smuggled"},
    {"authentication": {"auth_header": "Bearer smuggled"}},
    {"managed_credential_profiles": [{"profile_id": str(uuid.uuid4())}]},
])
def test_generic_scan_worker_rejects_other_auth_paths_before_decryption(
    monkeypatch, conflict,
):
    monkeypatch.setattr(worker, "db_pool", _GenericCredentialPool(uuid.uuid4()))
    queued = {
        "credential_profile_refs": [{"profile_id": str(uuid.uuid4())}],
        "credential_target_kind": "web",
        "credential_action_name": "scan.submit",
        **conflict,
    }
    with pytest.raises(worker.ScanCredentialError, match="another authentication path"):
        asyncio.run(worker._hydrate_generic_scan_credentials(queued, str(uuid.uuid4())))


def test_asm_bola_user1_scope_preserves_second_user_comparator():
    opts = {
        "auth_header": "Bearer user1",
        "user2_header": "Bearer user2",
        "check_family": "bola",
        "asm_check_family": "bola",
    }

    bola = worker._asm_scan_options_for_auth_state(opts, "user1", check_family="bola")
    assert bola["auth_header"] == "Bearer user1"
    assert bola["user2_header"] == "Bearer user2"
    assert bola["auth_state"] == "user1"

    sqli = worker._asm_scan_options_for_auth_state(opts, "user1", check_family="sqli")
    assert sqli["auth_header"] == "Bearer user1"
    assert "user2_header" not in sqli
    assert sqli["auth_state"] == "user1"


def test_asm_user2_prescoped_child_keeps_auth_header():
    opts = {
        "auth_state": "user2",
        "auth_header": "Bearer user2",
        "coverage_dynamic_worker": True,
    }

    scoped = worker._asm_scan_options_for_auth_state(opts, "user2", check_family="sqli")

    assert scoped is not None
    assert scoped["auth_state"] == "user2"
    assert scoped["auth_header"] == "Bearer user2"


def test_asm_prescoped_child_keeps_managed_runtime_profile_ref():
    opts = {
        "auth_state": "user2",
        "managed_credential_profiles": [{
            "auth_state": "user1",
            "profile_id": "00000000-0000-4000-8000-000000000002",
            "option_key": "auth_header",
        }],
        "coverage_dynamic_worker": True,
    }

    scoped = worker._asm_scan_options_for_auth_state(opts, "user2", check_family="sqli")

    assert scoped is not None
    assert scoped["managed_credential_profiles"] == opts["managed_credential_profiles"]


def _runtime_scope_guard():
    return {
        "scope_receipt_id": "scope-1",
        "environment": "production",
        "allowed_hosts": ["app.example.com"],
        "allowed_root_domains": ["example.com"],
        "normalized_scope": {"host": "app.example.com"},
        "requires_runtime_destination_check": True,
    }


def _runtime_scope_guard_with_dns():
    return {**_runtime_scope_guard(), "requires_runtime_dns_check": True}


def test_runtime_scope_guard_allows_dast_final_url_in_scope():
    result = {
        "http": {"final_url": "https://api.example.com/dashboard"},
        "findings": [{"title": "kept"}],
        "result": {"score": 90, "grade": "A"},
    }

    checked = worker._apply_runtime_scope_guard_to_result(
        result,
        {"runtime_scope_guard": _runtime_scope_guard()},
    )

    assert checked.get("error") is None
    assert checked["findings"] == [{"title": "kept"}]
    assert checked["scan_metadata"]["runtime_scope_check"]["status"] == "allowed"


def test_runtime_scope_guard_blocks_dast_final_url_out_of_scope():
    result = {
        "http": {"final_url": "https://evil.example.net/callback"},
        "findings": [{"title": "must not persist"}],
        "result": {"score": 80, "grade": "B"},
    }

    checked = worker._apply_runtime_scope_guard_to_result(
        result,
        {"runtime_scope_guard": _runtime_scope_guard()},
    )

    assert checked["findings"] == []
    assert checked["result"]["score"] is None
    assert checked["result"]["grade"] is None
    assert checked["scan_metadata"]["runtime_scope_blocked"] is True
    assert "host_out_of_allowed_scope" in checked["error"]


def test_runtime_scope_guard_blocks_dast_when_final_url_missing():
    result = {
        "http": {},
        "findings": [{"title": "must not persist"}],
        "result": {"score": 80, "grade": "B"},
    }

    checked = worker._apply_runtime_scope_guard_to_result(
        result,
        {"runtime_scope_guard": _runtime_scope_guard()},
    )

    assert checked["findings"] == []
    assert "runtime_destination_unverified" in checked["error"]
    assert checked["scan_metadata"]["runtime_scope_check"]["status"] == "blocked"


def test_runtime_scope_guard_accepts_receipt_driven_dast_destination_evidence():
    result = {
        "runtime_destinations": [{
            "label": "baseline.http:0:0",
            "url": "https://app.example.com",
            "final_url": "https://app.example.com",
            "source": "http.request",
            "resolved_host": "app.example.com",
            "resolved_ips": ["8.8.8.8"],
        }],
        "findings": [{"title": "persisted finding"}],
        "result": {"score": 90, "grade": "A"},
    }

    checked = worker._apply_runtime_scope_guard_to_result(
        result,
        {"runtime_scope_guard": _runtime_scope_guard_with_dns()},
    )

    assert checked.get("error") is None
    assert checked["findings"] == [{"title": "persisted finding"}]
    assert checked["scan_metadata"]["runtime_scope_check"]["status"] == "allowed"


def test_runtime_scope_guard_allows_ai_gate_runtime_destination_in_scope():
    result = {
        "ai_gate": {
            "runtime_destinations": [
                {
                    "label": "ai_gate_request",
                    "url": "https://app.example.com/api/chat",
                    "final_url": "https://app.example.com/api/chat",
                }
            ],
        },
        "findings": [{"title": "ai finding"}],
        "result": {"score": 75, "grade": "C"},
    }

    checked = worker._apply_runtime_scope_guard_to_result(
        result,
        {"runtime_scope_guard": _runtime_scope_guard(), "run_kind": "ai_api"},
    )

    assert checked.get("error") is None
    assert checked["findings"] == [{"title": "ai finding"}]
    assert checked["scan_metadata"]["runtime_scope_check"]["status"] == "allowed"


def test_runtime_scope_guard_degrades_ai_gate_when_only_final_hop_dns_is_observed():
    result = {
        "ai_gate": {
            "runtime_destinations": [
                {
                    "label": "ai_gate_request",
                    "url": "https://app.example.com/api/chat",
                    "final_url": "https://api.example.com/v1/chat",
                    "redirect_urls": ["https://api.example.com/v1/chat"],
                    "resolved_host": "api.example.com",
                    "resolved_ips": ["8.8.8.8"],
                }
            ],
        },
        "findings": [{"title": "ai finding must persist"}],
        "result": {"score": 75, "grade": "C"},
    }

    checked = worker._apply_runtime_scope_guard_to_result(
        result,
        {"runtime_scope_guard": _runtime_scope_guard_with_dns(), "run_kind": "ai_api"},
    )

    assert checked.get("error") is None
    assert checked["findings"] == [{"title": "ai finding must persist"}]
    assert checked["scan_metadata"]["runtime_scope_check"]["status"] == "degraded"
    assert checked["scan_metadata"]["runtime_scope_check"]["warnings"] == ["runtime_dns_unverified"]


def test_runtime_scope_guard_blocks_model_intake_runtime_redirect_out_of_scope():
    result = {
        "model_intake": {
            "runtime_destinations": [
                {
                    "label": "artifact",
                    "url": "https://app.example.com/models/safe.safetensors",
                    "final_url": "https://evil.example.net/models/safe.safetensors",
                }
            ],
        },
        "findings": [{"title": "must not persist"}],
        "result": {"score": 75, "grade": "C"},
    }

    checked = worker._apply_runtime_scope_guard_to_result(
        result,
        {"runtime_scope_guard": _runtime_scope_guard(), "run_kind": "model_intake"},
    )

    assert checked["findings"] == []
    assert checked["result"]["score"] is None
    assert checked["scan_metadata"]["runtime_scope_blocked"] is True
    assert "redirect_out_of_scope" in checked["error"]


def test_runtime_scope_guard_blocks_product_executor_without_runtime_destination():
    result = {
        "ai_gate": {"runtime_destinations": []},
        "findings": [{"title": "must not persist"}],
        "result": {"score": 75, "grade": "C"},
    }

    checked = worker._apply_runtime_scope_guard_to_result(
        result,
        {"runtime_scope_guard": _runtime_scope_guard(), "run_kind": "ai_api"},
    )

    assert checked["findings"] == []
    assert "runtime_destination_unverified" in checked["error"]


def test_runtime_scope_guard_checks_every_dast_redirect_hop():
    result = {
        "http": {
            "request_url": "https://app.example.com/start",
            "final_url": "https://app.example.com/final",
            "redirect_chain": [
                "https://evil.example.net/bounce",
                "https://app.example.com/final",
            ],
            "remote_ip": "203.0.113.10",
        },
        "findings": [{"title": "must not persist"}],
        "result": {"score": 80, "grade": "B"},
    }

    checked = worker._apply_runtime_scope_guard_to_result(
        result,
        {"runtime_scope_guard": _runtime_scope_guard_with_dns()},
    )

    assert checked["findings"] == []
    assert "redirect_out_of_scope" in checked["error"]
    destinations = checked["scan_metadata"]["runtime_scope_check"]["destinations"]
    assert destinations[0]["redirect_urls"][0] == "https://evil.example.net/bounce"


def test_runtime_scope_guard_degrades_without_stripping_when_runtime_dns_is_unobserved():
    result = {
        "http": {
            "request_url": "https://app.example.com/start",
            "final_url": "https://app.example.com/final",
            "redirect_chain": ["https://app.example.com/final"],
        },
        "findings": [{"title": "must persist as degraded evidence"}],
        "result": {"score": 80, "grade": "B"},
    }

    checked = worker._apply_runtime_scope_guard_to_result(
        result,
        {"runtime_scope_guard": _runtime_scope_guard_with_dns()},
    )

    assert checked["findings"] == [{"title": "must persist as degraded evidence"}]
    assert checked["result"] == {"score": 80, "grade": "B"}
    assert checked["scan_metadata"]["runtime_scope_degraded"] is True
    assert checked["scan_metadata"]["runtime_scope_check"]["status"] == "degraded"
    assert "runtime_dns_unverified" in checked["scan_metadata"]["runtime_scope_degraded_reason"]
    assert "error" not in checked


def test_runtime_scope_guard_blocks_private_runtime_dns_resolution():
    result = {
        "http": {
            "request_url": "https://app.example.com/start",
            "final_url": "https://app.example.com/final",
            "redirect_chain": ["https://app.example.com/final"],
            "remote_ip": "127.0.0.1",
        },
        "findings": [{"title": "must not persist"}],
        "result": {"score": 80, "grade": "B"},
    }

    checked = worker._apply_runtime_scope_guard_to_result(
        result,
        {"runtime_scope_guard": _runtime_scope_guard_with_dns()},
    )

    assert checked["findings"] == []
    assert "runtime_dns_private_range" in checked["error"]


def test_runtime_scope_guard_allows_exact_frozen_private_address_and_blocks_drift():
    result = {
        "runtime_destinations": [{
            "label": "baseline.http:0:0",
            "url": "http://juice-shop:3000",
            "final_url": "http://juice-shop:3000",
            "source": "http.request",
            "resolved_host": "juice-shop",
            "resolved_ips": ["172.19.0.15"],
        }],
        "findings": [],
        "result": {"score": 100, "grade": "A"},
    }
    guard = {
        **_runtime_scope_guard_with_dns(),
        "allowed_hosts": ["juice-shop"],
        "allowed_root_domains": ["juice-shop"],
        "normalized_scope": {"host": "juice-shop"},
        "allowed_addresses": ["172.19.0.15"],
    }

    allowed = worker._apply_runtime_scope_guard_to_result(
        copy.deepcopy(result), {"runtime_scope_guard": guard},
    )
    assert allowed.get("error") is None
    assert allowed["scan_metadata"]["runtime_scope_check"]["status"] == "allowed"

    drifted = copy.deepcopy(result)
    drifted["runtime_destinations"][0]["resolved_ips"] = ["172.19.0.16"]
    blocked = worker._apply_runtime_scope_guard_to_result(
        drifted, {"runtime_scope_guard": guard},
    )
    assert "runtime_dns_address_drift" in blocked["error"]


class _RuntimeScopeCommandResultConn:
    def __init__(self):
        self.args = None

    async def fetchrow(self, query, *args):
        assert "INSERT INTO command_results" in query
        self.args = args
        return {"id": "44444444-4444-4444-8444-444444444444"}


def test_runtime_scope_block_records_command_result_row():
    conn = _RuntimeScopeCommandResultConn()
    command_result_id = asyncio.run(worker._record_runtime_scope_block_command_result(
        conn,
        scan_id="11111111-1111-4111-8111-111111111111",
        campaign_id="22222222-2222-4222-8222-222222222222",
        target="https://app.example.com",
        options={
            "scope_receipt_id": "scope-1",
            "approval_receipt_id": "33333333-3333-4333-8333-333333333333",
        },
        runtime_scope_check={
            "status": "blocked",
            "blocked_by": ["host_out_of_allowed_scope"],
            "normalized_scope": {"host": "evil.example.net"},
        },
    ))

    assert command_result_id == "44444444-4444-4444-8444-444444444444"
    assert conn.args[0] == "scan.runtime_scope_check"
    assert conn.args[1] == "blocked"
    assert conn.args[3] == "active"
    assert conn.args[5] == "scope-1"
    assert str(conn.args[6]) == "33333333-3333-4333-8333-333333333333"
    assert str(conn.args[7]) == "22222222-2222-4222-8222-222222222222"
    assert str(conn.args[8]) == "11111111-1111-4111-8111-111111111111"
    assert json.loads(conn.args[13]) == ["host_out_of_allowed_scope"]
    assert json.loads(conn.args[16])["runtime_scope_check"]["status"] == "blocked"
    assert conn.args[17] == "worker"


def test_runtime_scope_degraded_records_command_result_row():
    conn = _RuntimeScopeCommandResultConn()
    command_result_id = asyncio.run(worker._record_runtime_scope_command_result(
        conn,
        scan_id="11111111-1111-4111-8111-111111111111",
        campaign_id=None,
        target="https://app.example.com",
        options={"scope_receipt_id": "scope-1"},
        runtime_scope_check={
            "status": "degraded",
            "warnings": ["runtime_dns_unverified"],
            "destinations": [{"url": "https://app.example.com"}],
        },
    ))

    assert command_result_id == "44444444-4444-4444-8444-444444444444"
    assert conn.args[1] == "degraded"
    assert json.loads(conn.args[13]) == ["runtime_dns_unverified"]
    assert "Degraded scan at runtime" in conn.args[15]


def test_failure_result_preserves_runtime_scope_metadata():
    runtime_check = {"status": "blocked", "blocked_by": ["runtime_destination_unverified"]}
    result = {
        "scan_metadata": {
            "runtime_scope_blocked": True,
            "runtime_scope_check": runtime_check,
            "runtime_scope_command_result_id": "44444444-4444-4444-8444-444444444444",
        },
        "tool_receipt_ids": ["tool-1"],
    }

    failure = worker._failure_result_for_scan_error(result, "blocked", None)

    assert failure["scan_metadata"]["status"] == "failed"
    assert failure["scan_metadata"]["runtime_scope_check"] == runtime_check
    assert failure["scan_metadata"]["runtime_scope_command_result_id"] == "44444444-4444-4444-8444-444444444444"
    assert failure["tool_receipt_ids"] == ["tool-1"]


def test_ai_gate_weak_signal_becomes_replay_hypothesis():
    hypotheses = worker._product_signal_hypotheses(
        "11111111-1111-4111-8111-111111111111",
        None,
        "22222222-2222-4222-8222-222222222222",
        "https://ai.example.com/chat",
        {
            "ai_gate": {"probe_pack": "shaker-rag-lite", "scan_profile": "standard"},
            "findings": [
                {
                    "id": "ai_gate:rag_leak",
                    "title": "RAG leakage",
                    "severity": "high",
                    "cwe": "CWE-200",
                    "ai_verdict": "needs_review",
                    "ai_confidence": 0.55,
                    "ai_classification_source": "semantic_judge",
                    "evidence": {"probe_family": "rag", "semantic_result": {"confidence": 0.55}},
                }
            ],
        },
        {"run_kind": "ai_rag", "ai_probe_pack": "shaker-rag-lite", "ai_scan_profile": "standard"},
    )

    assert len(hypotheses) == 1
    hypothesis = hypotheses[0]
    assert hypothesis["source"] == "ai_gate"
    assert hypothesis["family"] == "ai_gate_rag"
    assert hypothesis["next_test_action"]["command"] == "ai_gate.replay_probe"
    assert hypothesis["next_test_action"]["parameters"]["source_finding_id"] == "ai_gate:rag_leak"
    assert "ai_target_id=22222222-2222-4222-8222-222222222222" in hypothesis["dedupe_key"]


def test_model_intake_trust_signal_becomes_trust_preview_hypothesis():
    target_id = "33333333-3333-4333-8333-333333333333"
    hypotheses = worker._product_signal_hypotheses(
        "11111111-1111-4111-8111-111111111111",
        target_id,
        None,
        "https://models.example.com/model.safetensors",
        {
            "model_intake": {
                "summary": {
                    "artifact_ref": "https://models.example.com/model.safetensors",
                    "signature_verification_status": "claimed_verified",
                    "checksum_status": "missing",
                },
            },
            "findings": [
                {
                    "id": "model_intake:signature_not_verified",
                    "title": "Model artifact signature is present but not cryptographically verified",
                    "severity": "high",
                    "tool": "model_intake",
                }
            ],
        },
        {"run_kind": "model_intake"},
    )

    assert len(hypotheses) == 1
    hypothesis = hypotheses[0]
    assert hypothesis["source"] == "model_intake"
    assert hypothesis["target_id"] == target_id
    assert hypothesis["family"] == "model_intake_trust"
    assert hypothesis["next_test_action"]["command"] == "model_intake.trust_preview"
    assert "finding_id=model_intake:signature_not_verified" in hypothesis["dedupe_key"]


def test_scanner_weak_signal_becomes_retest_hypothesis():
    target_id = "33333333-3333-4333-8333-333333333333"
    hypotheses = worker._product_signal_hypotheses(
        "11111111-1111-4111-8111-111111111111",
        target_id,
        None,
        "https://shop.example.com",
        {
            "findings": [
                {
                    "id": "smart_sqli:cart-search",
                    "title": "Possible SQL injection in cart search",
                    "severity": "high",
                    "tool": "smart_sqli",
                    "type": "sqli",
                    "cwe": "CWE-89",
                    "url": "https://shop.example.com/rest/products/search?q=test",
                    "evidence": {"method": "GET", "parameter": "q"},
                    "confidence": 0.68,
                    "proof_state": "suspected",
                    "needs_verification": True,
                }
            ],
        },
        {"scan_type": "smart"},
    )

    assert len(hypotheses) == 1
    hypothesis = hypotheses[0]
    assert hypothesis["source"] == "scanner_signal"
    assert hypothesis["target_id"] == target_id
    assert hypothesis["family"] == "sqli"
    assert hypothesis["next_test_action"]["command"] == "finding.retest"
    params = hypothesis["next_test_action"]["parameters"]
    assert params["finding_id"].startswith("t:")
    assert params["finding_id"] == hypothesis["metadata_json"]["finding_fingerprint"]
    assert hypothesis["metadata_json"]["scanner_finding_id"] == "smart_sqli:cart-search"
    assert params["mode"] == "deterministic"
    assert params["check_family"] == "sqli"
    assert "product=scanner_signal" in hypothesis["dedupe_key"]
    assert hypothesis["metadata_json"]["runtime_proof_required"] is True


def test_scanner_verified_signal_does_not_become_hypothesis():
    hypotheses = worker._product_signal_hypotheses(
        "11111111-1111-4111-8111-111111111111",
        "33333333-3333-4333-8333-333333333333",
        None,
        "https://shop.example.com",
        {
            "findings": [
                {
                    "id": "proof:xss",
                    "title": "Stored XSS executed in browser",
                    "severity": "critical",
                    "tool": "browser_replay",
                    "type": "xss",
                    "cwe": "CWE-79",
                    "proof_state": "verified",
                    "validation": {"poe_proven": True, "confidence": 0.95},
                }
            ],
        },
        {"scan_type": "smart"},
    )

    assert hypotheses == []


class _HypothesisPersistConn:
    def __init__(self):
        self.rows = []

    async def fetchrow(self, query, *args):
        assert "INSERT INTO hypotheses" in query
        self.rows.append(args)
        return {"id": "44444444-4444-4444-8444-444444444444"}


class _HypothesisPersistAcquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _HypothesisPersistPool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return _HypothesisPersistAcquire(self.conn)


def test_product_signal_hypotheses_are_persisted(monkeypatch):
    conn = _HypothesisPersistConn()
    monkeypatch.setattr(worker, "db_pool", _HypothesisPersistPool(conn))

    count = asyncio.run(worker.persist_product_signal_hypotheses(
        "11111111-1111-4111-8111-111111111111",
        None,
        "22222222-2222-4222-8222-222222222222",
        "https://ai.example.com/chat",
        {
            "ai_gate": {},
            "findings": [
                {
                    "id": "ai_gate:weak",
                    "title": "Weak AI Gate signal",
                    "severity": "medium",
                    "ai_verdict": "needs_review",
                    "confidence": 0.5,
                    "evidence": {"probe_family": "agent"},
                }
            ],
        },
        {"run_kind": "ai_trace"},
    ))

    assert count == 1
    args = conn.rows[0]
    assert args[1] == "ai_gate"
    assert args[2] == "ai_gate_agent"
    assert json.loads(args[9])["command"] == "ai_gate.replay_probe"
    assert json.loads(args[10])["source"] == "ai_gate"
    assert args[12] == "worker"


def test_uuid_shaped_scanner_fingerprint_resolves_to_canonical_finding_id(monkeypatch):
    scanner_fingerprint = str(uuid.uuid4())
    canonical_finding_id = uuid.uuid4()

    class Conn:
        def __init__(self):
            self.insert_args = None

        async def fetchrow(self, query, *args):
            if "fingerprint=$2" in query:
                assert str(args[1]) == scanner_fingerprint
                return {"id": canonical_finding_id}
            if "INSERT INTO hypotheses" in query:
                self.insert_args = args
                return {"id": uuid.uuid4()}
            raise AssertionError(query)

    conn = Conn()
    monkeypatch.setattr(worker, "db_pool", _HypothesisPersistPool(conn))
    count = asyncio.run(worker.persist_product_signal_hypotheses(
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        None,
        "https://app.example.test",
        {
            "findings": [{
                "id": scanner_fingerprint,
                "title": "Possible authorization bypass",
                "severity": "high",
                "tool": "authz",
                "type": "auth",
                "cwe": "CWE-287",
                "proof_state": "suspected",
            }],
        },
        {"scan_type": "smart"},
    ))
    assert count == 1
    next_action = json.loads(conn.insert_args[9])
    assert next_action["parameters"]["finding_id"] == str(canonical_finding_id)


class _FakeProcess:
    def __init__(self, stdout_payload: bytes, stderr_payload: bytes = b""):
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(stdout_payload)
        self.stdout.feed_eof()

        self.stderr = asyncio.StreamReader()
        if stderr_payload:
            self.stderr.feed_data(stderr_payload)
        self.stderr.feed_eof()
        self.returncode = 0

    async def wait(self):
        return self.returncode


class _CancellableFakeProcess:
    def __init__(self):
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.returncode = None
        self.terminated = False
        self.killed = False
        self._done = asyncio.Event()

    def terminate(self):
        self.terminated = True
        self.returncode = -15
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self._done.set()

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self._done.set()

    async def wait(self):
        await self._done.wait()
        return self.returncode


class _FakeCredentialPool:
    def acquire(self):
        return self

    async def __aenter__(self):
        return object()

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeFinalizeConnection:
    def __init__(self):
        self.executions = []

    async def execute(self, query, *args):
        self.executions.append((query, args))


class _FakeFinalizePool:
    def __init__(self):
        self.conn = _FakeFinalizeConnection()

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeReceiptConnection:
    def __init__(self, receipt_id=None, evidence_id=None):
        self.receipt_id = receipt_id or uuid.uuid4()
        self.evidence_id = evidence_id or uuid.uuid4()
        self.fetchrow_calls = []

    async def fetchrow(self, query, *args):
        self.fetchrow_calls.append((query, args))
        if "INSERT INTO evidence_objects" in query:
            return {"id": self.evidence_id}
        return {"id": self.receipt_id}

    async def fetchval(self, query, *args):
        if "pg_advisory_lock" in query or "pg_advisory_unlock" in query:
            return True
        return None


class _FakeSlotRedis:
    def __init__(self):
        self.zsets = {}
        self.legacy = {}
        self.expired = []
        self.deleted = []

    def type(self, key):
        if key in self.legacy:
            return b"string"
        if key in self.zsets:
            return b"zset"
        return b"none"

    def expire(self, key, ttl):
        self.expired.append((key, ttl))

    def delete(self, key):
        self.deleted.append(key)
        self.zsets.pop(key, None)
        self.legacy.pop(key, None)

    def eval(self, script, key_count, key, *args):
        assert key_count == 1
        members = self.zsets.setdefault(key, {})
        if "ZREMRANGEBYSCORE" in script:
            now, expires_at, limit, member, key_ttl = args
            members = {
                existing: score for existing, score in members.items()
                if score > float(now)
            }
            self.zsets[key] = members
            if str(member) in members:
                members[str(member)] = float(expires_at)
                self.expire(key, int(key_ttl))
                return 1
            if len(members) >= int(limit):
                return 0
            members[str(member)] = float(expires_at)
            self.expire(key, int(key_ttl))
            return 1
        member, expires_at, key_ttl = args
        if str(member) not in members:
            return 0
        members[str(member)] = float(expires_at)
        self.expire(key, int(key_ttl))
        return 1

    def zrem(self, key, member):
        return int(self.zsets.get(key, {}).pop(str(member), None) is not None)

    def zcard(self, key):
        return len(self.zsets.get(key, {}))


class _FakeJobRedis(_FakeSlotRedis):
    def __init__(self):
        super().__init__()
        self.hashes = []
        self.values = {}
        self.pushed = []
        self.sets = []

    def hset(self, key, *args, mapping=None):
        self.hashes.append((key, args, dict(mapping or {})))

    def get(self, key):
        return self.values.get(key)

    def expire(self, key, ttl):
        self.expired.append((key, ttl))

    def incr(self, key):
        self.values[key] = int(self.values.get(key, 0)) + 1
        return self.values[key]

    def decr(self, key):
        self.values[key] = int(self.values.get(key, 0)) - 1
        return self.values[key]

    def rpush(self, key, value):
        self.pushed.append((key, value))
        return len(self.pushed)

    def eval(self, script, numkeys, key, *args):
        if "ZREMRANGEBYSCORE" in script or "ZSCORE" in script:
            return super().eval(script, numkeys, key, *args)
        amount, cap, _ttl, *rest = args
        all_or_nothing = rest[0] if rest else "0"
        current = int(self.values.get(key) or 0)
        amount = int(amount)
        cap = int(cap)
        if amount <= 0:
            return 0
        if cap <= 0:
            return 0
        if current >= cap:
            return 0
        if str(all_or_nothing) == "1" and current + amount > cap:
            return 0
        granted = min(amount, cap - current)
        self.values[key] = current + granted
        return granted

    def set(self, key, value, nx=False, ex=None):
        self.sets.append((key, value, nx, ex))
        self.values[key] = value
        return True

    def delete(self, key):
        self.deleted.append(key)
        self.values.pop(key, None)
        self.zsets.pop(key, None)
        self.legacy.pop(key, None)


def test_worker_marks_fresh_processing_lease_immediately_after_queue_pop():
    cases = [
        (worker.QUEUE_NAME, "scan", "job:job-1"),
        (worker.RETEST_QUEUE_NAME, "finding_retest", "retest_job:job-1"),
    ]
    for source_queue, job_type, expected_key in cases:
        redis = _FakeJobRedis()
        worker._mark_worker_processing_lease(
            redis,
            {"job_id": "job-1", "type": job_type},
            source_queue,
        )

        key, _args, mapping = redis.hashes[-1]
        assert key == expected_key
        assert mapping["processing_lease_at"]
        assert mapping["processing_queue"] == source_queue
        assert redis.expired[-1] == (expected_key, 86400)


class _LostRetestClaimConnection:
    def __init__(self, *, verification, current_status):
        self.verification = verification
        self.current_status = current_status
        self.fetchrow_calls = []
        self.fetchval_calls = []
        self.execute_calls = []

    async def fetchrow(self, query, *args):
        self.fetchrow_calls.append((query, args))
        if "FROM finding_verifications fv" in query:
            return self.verification
        if "UPDATE finding_verifications" in query and "status = 'queued'" in query:
            return None
        raise AssertionError(f"unexpected fetchrow after retest claim was lost: {query}")

    async def fetchval(self, query, *args):
        self.fetchval_calls.append((query, args))
        assert "SELECT status FROM finding_verifications" in query
        return self.current_status

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        raise AssertionError(f"retest losing its claim must not update proof state: {query}")


class _LostRetestClaimPool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


def test_finding_retest_lost_atomic_claim_never_runs_provers(monkeypatch):
    verification_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    job_id = "lost-retest-claim"
    verification = {
        "id": verification_id,
        "finding_id": finding_id,
        "finding_type": "xss",
    }
    payload = worker.build_retest_job_payload(
        job_id=job_id,
        verification_id=str(verification_id),
        finding_id=str(finding_id),
        submitted_at=datetime.now(timezone.utc).isoformat(),
        trigger="unit_test",
    )
    work_calls = {"runtime_settings": 0, "deterministic": 0, "slot_releases": 0}

    def fail_if_runtime_settings_are_loaded():
        work_calls["runtime_settings"] += 1
        raise AssertionError("AI preparation must not run after another actor wins the claim")

    async def fail_if_deterministic_prover_runs(_verification):
        work_calls["deterministic"] += 1
        raise AssertionError("deterministic prover must not run after the claim is lost")

    monkeypatch.setattr(worker, "_try_acquire_retest_slot", lambda _redis: True)
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", fail_if_runtime_settings_are_loaded)
    monkeypatch.setattr(worker, "run_finding_retest", fail_if_deterministic_prover_runs)
    monkeypatch.setattr(
        worker,
        "_release_retest_slot",
        lambda _redis: work_calls.__setitem__("slot_releases", work_calls["slot_releases"] + 1),
    )

    for current_status, expected_mapping in (
        (
            "cancelled",
            {
                "status": "cancelled",
                "verification_id": str(verification_id),
                "finding_id": str(finding_id),
            },
        ),
        (
            "running",
            {
                "status": "running",
                "verification_id": str(verification_id),
                "note": "duplicate_or_nonqueued_retest_job",
            },
        ),
    ):
        conn = _LostRetestClaimConnection(
            verification=verification,
            current_status=current_status,
        )
        redis = _FakeJobRedis()
        monkeypatch.setattr(worker, "db_pool", _LostRetestClaimPool(conn))
        monkeypatch.setattr(worker, "get_redis", lambda: redis)

        asyncio.run(worker.process_finding_retest_job(payload))

        assert len(conn.fetchrow_calls) == 2
        claim_query, claim_args = conn.fetchrow_calls[1]
        assert "WHERE id = $1 AND status = 'queued'" in claim_query
        assert claim_args == (verification_id, 1)
        assert len(conn.fetchval_calls) == 1
        assert conn.execute_calls == []
        assert redis.hashes[-1] == (
            f"retest_job:{job_id}",
            (),
            expected_mapping,
        )
        assert redis.expired[-1] == (f"retest_job:{job_id}", 86400)

    assert work_calls == {
        "runtime_settings": 0,
        "deterministic": 0,
        "slot_releases": 2,
    }


def test_internal_ai_gate_executor_receipt_is_recorded_and_redacted():
    receipt_id = uuid.uuid4()
    conn = _FakeReceiptConnection(receipt_id)
    result = {
        "ai_gate": {"decision": {"decision": "block"}},
        "findings": [{"id": "ai_gate:test"}],
    }

    recorded = asyncio.run(worker._record_internal_executor_tool_receipt(
        conn,
        scan_id="11111111-1111-1111-1111-111111111111",
        job_id="job-ai-gate",
        target="https://example.test/chat?token=secret-token",
        target_id=None,
        ai_target_id="22222222-2222-2222-2222-222222222222",
        options={"run_kind": "ai_api", "scan_type": "ai_gate"},
        result=result,
        started_at=datetime(2026, 7, 6, tzinfo=timezone.utc),
        completed_at=datetime(2026, 7, 6, 0, 0, 5, tzinfo=timezone.utc),
        duration_seconds=5,
        error=None,
    ))

    assert recorded == str(receipt_id)
    assert result["tool_receipt_ids"] == [str(receipt_id)]
    assert result["metadata"]["tool_receipt_ids"] == [str(receipt_id)]
    assert result["scan_metadata"]["tool_receipt_ids"] == [str(receipt_id)]
    query, args = conn.fetchrow_calls[0]
    assert "INSERT INTO tool_receipts" in query
    assert args[0] == "ai_gate_probe_executor"
    assert args[1] == "internal"
    assert len(args[3]) == 64
    assert args[11] == "success"
    assert args[12] == "parsed"
    assert args[13] == 0
    assert "secret-token" not in json.dumps(args, default=str)
    target_scope = json.loads(args[7])
    assert target_scope["target"].endswith("***=***")


def test_internal_asm_recon_executor_receipt_is_recorded():
    receipt_id = uuid.uuid4()
    conn = _FakeReceiptConnection(receipt_id)
    result = {
        "discovery": {"summary": {"total_urls": 3}},
        "findings": [],
    }

    recorded = asyncio.run(worker._record_internal_executor_tool_receipt(
        conn,
        scan_id="11111111-1111-1111-1111-111111111111",
        job_id="job-asm-recon",
        target="https://example.test/?token=secret-token",
        target_id="33333333-3333-3333-3333-333333333333",
        ai_target_id=None,
        options={"run_kind": "asm_recon", "scan_type": "smart"},
        result=result,
        started_at=datetime(2026, 7, 6, tzinfo=timezone.utc),
        completed_at=datetime(2026, 7, 6, 0, 0, 4, tzinfo=timezone.utc),
        duration_seconds=4,
        error=None,
    ))

    assert recorded == str(receipt_id)
    assert result["scan_metadata"]["tool_receipt_ids"] == [str(receipt_id)]
    query, args = conn.fetchrow_calls[0]
    assert "INSERT INTO tool_receipts" in query
    assert args[0] == "asm_recon_executor"
    assert args[11] == "success"
    assert args[12] == "parsed"
    metadata = json.loads(args[21])
    assert metadata["parser"] == "asm-recon-summary-v1"
    assert metadata["proof_contract"] == "endpoint-inventory-evidence"
    assert "secret-token" not in json.dumps(args, default=str)


def test_redact_receipt_value_strips_url_userinfo():
    out = worker._redact_receipt_value("https://admin:hunter2@app.example.com/?token=secret-token")
    assert "hunter2" not in out and "admin:" not in out
    assert "secret-token" not in out
    assert urllib.parse.urlparse(out).hostname == "app.example.com"


def test_internal_model_intake_executor_receipt_records_failure():
    receipt_id = uuid.uuid4()
    conn = _FakeReceiptConnection(receipt_id)
    result = {"error": "signature secret-token mismatch", "findings": []}

    recorded = asyncio.run(worker._record_internal_executor_tool_receipt(
        conn,
        scan_id="11111111-1111-1111-1111-111111111111",
        job_id="job-model",
        target="https://models.example.test/model.safetensors",
        target_id="33333333-3333-3333-3333-333333333333",
        ai_target_id=None,
        options={"run_kind": "model_intake", "scan_type": "model_intake"},
        result=result,
        started_at=datetime(2026, 7, 6, tzinfo=timezone.utc),
        completed_at=datetime(2026, 7, 6, 0, 0, 2, tzinfo=timezone.utc),
        duration_seconds=2,
        error=result["error"],
    ))

    assert recorded == str(receipt_id)
    query, args = conn.fetchrow_calls[0]
    assert "INSERT INTO tool_receipts" in query
    assert args[0] == "model_intake_signature_verifier"
    assert args[11] == "failed"
    assert args[12] == "failed"
    assert args[13] == 1
    metadata = json.loads(args[21])
    assert metadata["parser"] == "model-intake-summary-v1"
    assert metadata["error"] == "signature *** mismatch"
    assert "secret-token" not in json.dumps(args, default=str)


def test_external_dast_tool_specs_from_parsed_result():
    specs = worker._external_dast_tool_specs(
        {
            "discovery": {
                "nuclei": {
                    "scan_completed": True,
                    "templates_used": 12,
                    "vulnerabilities": [{"template": "x"}],
                }
            },
            "active_checks": {
                "dalfox": [{"url": "https://app.example.com?q=x"}],
                "sqlmap_errors": ["timeout"],
            },
            "tls": {
                "nmap": {"raw": "Nmap scan report"},
                "sslyze": {"scan_completed": True, "vulnerabilities": []},
                "testssl": {"raw_present": True},
            },
        },
        {"scan_type": "smart"},
    )

    by_tool = {item["tool_name"]: item for item in specs}
    assert by_tool["nuclei"]["parser_status"] == "parsed"
    assert by_tool["nuclei"]["status"] == "success"          # scan_completed True
    assert by_tool["dalfox"]["status"] == "success"
    assert by_tool["sqlmap"]["status"] == "failed"
    assert by_tool["nmap"]["parser"] == "nmap-tls-summary-v1"
    assert by_tool["sslyze"]["status"] == "success"          # scan_completed True
    assert by_tool["sslyze"]["proof_contract"] == "tls-network-observation"
    # raw-only output (no scan_completed, no structured data) is NOT a confirmed
    # success/parse — `raw` may hold stderr/timeout text.
    assert by_tool["nmap"]["status"] == "recorded"
    assert by_tool["nmap"]["parser_status"] == "partial"
    assert by_tool["testssl"]["status"] == "recorded"
    assert by_tool["testssl"]["parser_status"] == "partial"


def test_external_dast_tool_specs_never_stamp_failed_or_timed_out_tools_success():
    specs = worker._external_dast_tool_specs(
        {
            "discovery": {
                # nuclei ran but reported errors and no explicit completion.
                "nuclei": {"errors": ["template load failed"], "templates_used": 3},
            },
            "tls": {
                # nmap TLS timeout: explicit failure flag + stderr echoed into raw.
                "nmap": {"scan_completed": False, "raw": "timeout after 120s"},
                # sslyze not installed: explicit failure.
                "sslyze": {"scan_completed": False, "error": "SSLyze not installed"},
            },
        },
        {"scan_type": "smart"},
    )
    by_tool = {item["tool_name"]: item for item in specs}
    # None of these may claim success — that is exactly the phantom-tool provenance
    # the no-phantom-tools gate is meant to prevent.
    assert by_tool["nuclei"]["status"] != "success"
    assert by_tool["nmap"]["status"] == "failed"      # completed=False despite raw
    assert by_tool["sslyze"]["status"] == "failed"


def test_external_dast_tool_specs_include_passive_discovery_receipts():
    specs = worker._external_dast_tool_specs(
        {
            "discovery": {
                "httpx": [{"url": "https://app.example.com", "status_code": 200, "tech": ["nginx"]}],
                "katana_sample": ["https://app.example.com/api/products"],
                "browser_api_endpoints": [{"url": "https://app.example.com/api/me"}],
                "browser_crawl": {"pages_visited": 3, "depth_reached": 1},
                "smart_discovery": {
                    "total_urls_discovered": 12,
                    "total_recursive_paths": 2,
                },
            },
            "subdomain_count": 4,
            "by_source": {"subfinder": ["a.example.com", "b.example.com"]},
            "input": {"sources": {"subfinder": True}},
        },
        {"scan_type": "smart", "subfinder": True},
    )

    by_tool = {item["tool_name"]: item for item in specs}
    assert by_tool["httpx"]["status"] == "success"
    assert by_tool["httpx"]["parser_status"] == "parsed"
    assert by_tool["katana"]["status"] == "success"
    assert by_tool["playwright"]["status"] == "success"
    assert by_tool["ffuf"]["status"] == "recorded"
    assert by_tool["ffuf"]["parser_status"] == "partial"
    assert by_tool["ffuf"]["summary"]["aggregate_discovery_only"] is True
    assert by_tool["subfinder"]["status"] == "success"
    assert by_tool["subfinder"]["summary"]["subfinder_rows_count"] == 2


def test_external_dast_tool_specs_do_not_claim_katana_success_from_aggregate_discovery():
    specs = worker._external_dast_tool_specs(
        {
            "discovery": {
                "katana_sample": [],
                "smart_discovery": {
                    "total_urls_discovered": 24,
                    "total_recursive_paths": 8,
                },
            },
            "subdomain_count": 3,
            "by_source": {},
            "input": {"sources": {"subfinder": True}},
        },
        {"scan_type": "smart", "subfinder": True},
    )

    by_tool = {item["tool_name"]: item for item in specs}
    assert by_tool["katana"]["status"] == "recorded"
    assert by_tool["katana"]["parser_status"] == "partial"
    assert by_tool["katana"]["summary"]["aggregate_discovery_only"] is True
    assert by_tool["ffuf"]["status"] == "recorded"
    assert by_tool["ffuf"]["parser_status"] == "partial"
    assert by_tool["ffuf"]["summary"]["aggregate_discovery_only"] is True
    assert by_tool["subfinder"]["status"] == "recorded"
    assert by_tool["subfinder"]["parser_status"] == "partial"
    assert by_tool["subfinder"]["summary"]["aggregate_discovery_only"] is True


def test_external_dast_tool_specs_record_passive_skips_and_partials_honestly():
    specs = worker._external_dast_tool_specs(
        {
            "discovery": {
                "httpx": [],
                "katana_sample": [],
                "summary": {"spa_catch_all": True},
                "smart_discovery": {"total_urls_discovered": 0, "total_recursive_paths": 0},
            },
            "subdomain_count": 0,
            "by_source": {},
            "input": {"sources": {"subfinder": False}},
        },
        {"scan_type": "quick", "zero_rediscovery": True, "no_browser": True},
    )

    by_tool = {item["tool_name"]: item for item in specs}
    assert by_tool["httpx"]["status"] == "recorded"
    assert by_tool["httpx"]["parser_status"] == "partial"
    assert by_tool["katana"]["status"] == "skipped"
    assert by_tool["katana"]["parser_status"] == "not_applicable"
    assert by_tool["playwright"]["status"] == "skipped"
    assert by_tool["playwright"]["parser_status"] == "not_applicable"
    assert by_tool["ffuf"]["status"] == "skipped"
    assert by_tool["ffuf"]["parser_status"] == "not_applicable"
    assert by_tool["subfinder"]["status"] == "skipped"
    assert by_tool["subfinder"]["parser_status"] == "not_applicable"


def test_external_dast_tool_receipts_are_recorded_and_attached():
    receipt_id = uuid.uuid4()
    conn = _FakeReceiptConnection(receipt_id)
    result = {
        "discovery": {"nuclei": {"scan_completed": True, "templates_used": 1}},
        "active_checks": {"sqlmap_errors": ["secret-token failed"]},
        "tls": {"nmap": {"raw": "Nmap done"}},
    }

    recorded = asyncio.run(worker._record_external_dast_tool_receipts(
        conn,
        scan_id="11111111-1111-1111-1111-111111111111",
        job_id="job-dast",
        target="https://example.test/?token=secret-token",
        target_id="33333333-3333-3333-3333-333333333333",
        options={"scan_type": "smart"},
        result=result,
        started_at=datetime(2026, 7, 6, tzinfo=timezone.utc),
        completed_at=datetime(2026, 7, 6, 0, 1, tzinfo=timezone.utc),
        duration_seconds=60,
    ))

    assert recorded == [str(receipt_id), str(receipt_id), str(receipt_id)]
    assert result["tool_receipt_ids"] == [str(receipt_id)]
    assert len(conn.fetchrow_calls) == 3
    first_query, first_args = conn.fetchrow_calls[0]
    assert "INSERT INTO tool_receipts" in first_query
    assert first_args[0] == "nuclei"
    assert first_args[1] == "scanner-output"
    assert first_args[11] == "success"
    assert first_args[12] == "parsed"
    assert "secret-token" not in json.dumps(first_args, default=str)
    tools = [args[0] for _query, args in conn.fetchrow_calls]
    assert tools == ["nuclei", "sqlmap", "nmap"]


def test_external_dast_subprocess_receipts_preserve_exact_outcome():
    receipt_id = uuid.uuid4()
    conn = _FakeReceiptConnection(receipt_id)
    command_hash = "a" * 64
    result = {
        "scan_metadata": {
            "subprocess_receipts": [
                {
                    "tool_name": "sqlmap.py",
                    "status": "timeout",
                    "parser_status": "not_applicable",
                    "exit_code": 124,
                    "timed_out": True,
                    "timeout_seconds": 9,
                    "duration_ms": 9010,
                    "redacted_argv": ["sqlmap.py", "-r", "[REDACTED]"],
                    "command_hash": command_hash,
                    "stdout_length": 0,
                    "stderr_length": 16,
                    "stderr_preview": "timeout after 9s",
                }
            ]
        }
    }

    recorded = asyncio.run(worker._record_external_dast_tool_receipts(
        conn,
        scan_id="11111111-1111-1111-1111-111111111111",
        job_id="job-subprocess",
        target="https://example.test/?token=secret-token",
        target_id="33333333-3333-3333-3333-333333333333",
        options={"scan_type": "smart"},
        result=result,
        started_at=datetime(2026, 7, 6, tzinfo=timezone.utc),
        completed_at=datetime(2026, 7, 6, 0, 0, 10, tzinfo=timezone.utc),
        duration_seconds=10,
    ))

    assert recorded == [str(receipt_id)]
    query, args = conn.fetchrow_calls[0]
    assert "INSERT INTO tool_receipts" in query
    assert args[0] == "sqlmap"
    assert args[1] == "scanner-subprocess"
    assert args[3] == command_hash
    assert json.loads(args[4]) == ["sqlmap.py", "-r", "[REDACTED]"]
    assert args[11] == "timeout"
    assert args[12] == "not_applicable"
    assert args[13] == 124
    assert args[14] is True
    metadata = json.loads(args[21])
    assert metadata["parser"] == "scanner-subprocess-outcome-v1"
    assert metadata["summary"]["exact_subprocess"] is True
    assert metadata["summary"]["stderr_preview"] == "timeout after 9s"
    assert "secret-token" not in json.dumps(args, default=str)


def test_external_dast_subprocess_receipts_match_absolute_tool_paths():
    # Deployed image invokes tools by absolute path (/opt/tools/nuclei); the receipt must
    # still be recorded by basename, not dropped as an unknown tool.
    receipt_id = uuid.uuid4()
    conn = _FakeReceiptConnection(receipt_id)
    result = {
        "scan_metadata": {
            "subprocess_receipts": [
                {
                    "tool_name": "/opt/tools/nuclei",
                    "status": "success",
                    "parser_status": "parsed",
                    "exit_code": 0,
                    "timed_out": False,
                    "redacted_argv": ["/opt/tools/nuclei", "-u", "[REDACTED]"],
                    "command_hash": "b" * 64,
                    "stdout_length": 100,
                    "stderr_length": 0,
                }
            ]
        }
    }

    recorded = asyncio.run(worker._record_external_dast_tool_receipts(
        conn,
        scan_id="11111111-1111-1111-1111-111111111111",
        job_id="job-abs-path",
        target="https://example.test",
        target_id="33333333-3333-3333-3333-333333333333",
        options={"scan_type": "smart"},
        result=result,
        started_at=datetime(2026, 7, 6, tzinfo=timezone.utc),
        completed_at=datetime(2026, 7, 6, 0, 0, 10, tzinfo=timezone.utc),
        duration_seconds=10,
    ))

    assert recorded == [str(receipt_id)]
    query, args = conn.fetchrow_calls[0]
    assert "INSERT INTO tool_receipts" in query
    assert args[0] == "nuclei"


def test_external_dast_subprocess_receipts_classify_parser_errors():
    receipt_id = uuid.uuid4()
    conn = _FakeReceiptConnection(receipt_id)
    result = {
        "scan_metadata": {
            "subprocess_receipts": [
                {
                    "tool_name": "ffuf",
                    "status": "failed",
                    "parser_status": "not_run",
                    "exit_code": 1,
                    "timed_out": False,
                    "timeout_seconds": 30,
                    "duration_ms": 100,
                    "redacted_argv": ["ffuf", "-of", "json"],
                    "command_hash": "b" * 64,
                    "stdout_length": 0,
                    "stderr_length": 68,
                    "stdout_preview": "",
                    "stderr_preview": "failed to parse JSON: invalid character '<' looking for beginning of value",
                }
            ]
        }
    }

    recorded = asyncio.run(worker._record_external_dast_tool_receipts(
        conn,
        scan_id="11111111-1111-1111-1111-111111111111",
        job_id="job-parser",
        target="https://example.test",
        target_id="33333333-3333-3333-3333-333333333333",
        options={"scan_type": "smart"},
        result=result,
        started_at=datetime(2026, 7, 6, tzinfo=timezone.utc),
        completed_at=datetime(2026, 7, 6, 0, 0, 1, tzinfo=timezone.utc),
        duration_seconds=1,
    ))

    assert recorded == [str(receipt_id)]
    _query, args = conn.fetchrow_calls[0]
    assert args[0] == "ffuf"
    assert args[11] == "parser_error"
    assert args[12] == "failed"
    assert args[13] == 1
    assert args[14] is False
    metadata = json.loads(args[21])
    assert metadata["summary"]["parser_error_reason"] == "invalid character"
    assert metadata["summary"]["stderr_preview"].startswith("failed to parse JSON")


def test_external_dast_subprocess_receipts_link_long_output_artifacts():
    receipt_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    conn = _FakeReceiptConnection(receipt_id, evidence_id=evidence_id)
    result = {
        "scan_metadata": {
            "subprocess_receipts": [
                {
                    "tool_name": "ffuf",
                    "status": "failed",
                    "parser_status": "not_run",
                    "exit_code": 1,
                    "timed_out": False,
                    "timeout_seconds": 30,
                    "duration_ms": 100,
                    "redacted_argv": ["ffuf", "-of", "json"],
                    "command_hash": "c" * 64,
                    "stdout_length": 0,
                    "stderr_length": 1000,
                    "stdout_preview": "",
                    "stderr_preview": "failed to parse JSON: invalid character '<'",
                    "stderr_artifact": {
                        "stream": "stderr",
                        "content": "failed to parse JSON: invalid character '<' " + ("x" * 900),
                        "content_sha256": "d" * 64,
                        "original_length": 1000,
                        "redacted_length": 1000,
                        "captured_length": 950,
                        "truncated": True,
                        "redaction_profile": "subprocess_output_redact_v1",
                    },
                }
            ]
        }
    }

    recorded = asyncio.run(worker._record_external_dast_tool_receipts(
        conn,
        scan_id="11111111-1111-1111-1111-111111111111",
        job_id="job-parser-artifact",
        target="https://example.test",
        target_id="33333333-3333-3333-3333-333333333333",
        options={"scan_type": "smart"},
        result=result,
        started_at=datetime(2026, 7, 6, tzinfo=timezone.utc),
        completed_at=datetime(2026, 7, 6, 0, 0, 1, tzinfo=timezone.utc),
        duration_seconds=1,
    ))

    assert recorded == [str(receipt_id)]
    evidence_query, evidence_args = conn.fetchrow_calls[0]
    receipt_query, receipt_args = conn.fetchrow_calls[1]
    assert "INSERT INTO evidence_objects" in evidence_query
    assert evidence_args[0] == uuid.UUID("11111111-1111-1111-1111-111111111111")
    assert evidence_args[2] == "tool_stderr_artifact"
    assert "failed to parse JSON" in json.dumps(evidence_args, default=str)
    assert "INSERT INTO tool_receipts" in receipt_query
    assert receipt_args[17] is None
    assert receipt_args[18] == evidence_id
    metadata = json.loads(receipt_args[21])
    assert metadata["summary"]["stderr_artifact_available"] is True


def test_asm_executor_receipt_records_partial_batch_and_links_metadata():
    receipt_id = uuid.uuid4()
    conn = _FakeReceiptConnection(receipt_id)
    result = {
        "target": "https://example.test",
        "findings": [],
        "scan_metadata": {"partial": True},
    }

    recorded = asyncio.run(worker._record_asm_executor_tool_receipt(
        conn,
        scan_id="11111111-1111-1111-1111-111111111111",
        job_id="job-asm",
        target="https://example.test/?token=secret-token",
        target_id="33333333-3333-3333-3333-333333333333",
        parent_scan_id="44444444-4444-4444-4444-444444444444",
        campaign_id="55555555-5555-5555-5555-555555555555",
        options={
            "scan_type": "smart",
            "run_kind": "asm_batch",
            "scope_receipt_id": "scope-1",
            "approval_receipt_id": "66666666-6666-4666-8666-666666666666",
        },
        result=result,
        action="batch",
        status="recorded",
        parser_status="partial",
        started_at=datetime(2026, 7, 6, tzinfo=timezone.utc),
        completed_at=datetime(2026, 7, 6, 0, 0, 8, tzinfo=timezone.utc),
        duration_seconds=8,
        endpoint_ids=["77777777-7777-4777-8777-777777777777"],
        auth_state="user1",
        check_family="bola",
        endpoint_filter="api",
        summary={"attempts_reported": 0, "telemetry_present": False},
    ))

    assert recorded == str(receipt_id)
    assert result["tool_receipt_ids"] == [str(receipt_id)]
    assert result["metadata"]["tool_receipt_ids"] == [str(receipt_id)]
    assert result["scan_metadata"]["tool_receipt_ids"] == [str(receipt_id)]
    assert result["scan_metadata"]["asm_executor_receipt_id"] == str(receipt_id)
    query, args = conn.fetchrow_calls[0]
    assert "INSERT INTO tool_receipts" in query
    assert args[0] == "asm_endpoint_batch_executor"
    assert args[1] == "internal"
    assert args[8] == "scope-1"
    assert args[9] == uuid.UUID("66666666-6666-4666-8666-666666666666")
    assert args[11] == "recorded"
    assert args[12] == "partial"
    assert args[14] is False
    target_scope = json.loads(args[7])
    assert target_scope["check_family"] == "bola"
    assert target_scope["endpoint_count"] == 1
    metadata = json.loads(args[21])
    assert metadata["parser"] == "asm-endpoint-batch-summary-v1"
    assert metadata["proof_contract"] == "endpoint-attempt-ledger"
    assert metadata["summary"]["telemetry_present"] is False
    assert "secret-token" not in json.dumps(args, default=str)


class _FakeCancelRedis:
    def __init__(self, cancelled: bool):
        self.cancelled = cancelled

    def get(self, key):
        return b"1" if self.cancelled else None


class _FakeAsmConn:
    def __init__(self, *, child_status="pending", parent_status="running", running_update_result="UPDATE 1"):
        self.executions = []
        self.child_status = child_status
        self.parent_status = parent_status
        self.running_update_result = running_update_result

    async def execute(self, query, *args):
        self.executions.append((query, args))
        if "UPDATE scans SET status='running'" in query and "asm_exploit" in query:
            return self.running_update_result
        return "UPDATE 1"

    async def fetchrow(self, query, *args):
        if "LEFT JOIN scans parent" in query:
            return {"status": self.child_status, "parent_status": self.parent_status}
        return {"status": self.child_status}


class _FakeRateConn:
    def __init__(self, *, root_domain="example.test", cap=5, used=0):
        self.root_domain = root_domain
        self.cap = cap
        self.used = used
        self.executions = []
        self.fetchrow_calls = []
        self.fetchval_calls = []

    async def fetchrow(self, query, *args):
        self.fetchrow_calls.append((query, args))
        if "SELECT root_domain, asm_config FROM targets" in query:
            return {
                "root_domain": self.root_domain,
                "asm_config": json.dumps({"max_requests_per_hour_per_domain": self.cap}),
            }
        return {"status": "running", "parent_status": "running"}

    async def fetchval(self, query, *args):
        self.fetchval_calls.append((query, args))
        return self.used

    async def execute(self, query, *args):
        self.executions.append((query, args))
        return "UPDATE 1"


class _FakeAsmPool:
    def __init__(self, conn=None):
        self.conn = conn or _FakeAsmConn()

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


def test_unexpected_scan_exception_becomes_bounded_terminal_failure():
    result = worker._unexpected_scan_exception_result(
        "https://example.test/model.safetensors",
        TypeError("adapter failed\x00" + "x" * 2000),
    )

    assert result["error"].startswith("TypeError: adapter failed")
    assert "\x00" not in result["error"]
    assert len(result["error"]) <= len("TypeError: ") + 1000
    assert result["findings"] == []
    assert result["failure_diagnostics"] == {
        "failure_type": "unhandled_scan_exception",
        "exception_type": "TypeError",
    }


def test_scan_worker_does_not_revive_failed_queue_handoff_during_claim(monkeypatch):
    class ClaimRaceConn:
        def __init__(self):
            self.executions = []
            self.status = "pending"

        async def fetchrow(self, query, *args):
            if "UPDATE scans" in query and "queue_handoff_confirmed" in query:
                self.executions.append((query, args))
                if self.status == "pending":
                    self.status = "failed"
                    return {
                        "status": "failed",
                        "campaign_id": "44444444-4444-4444-8444-444444444444",
                    }
                return None
            if "SELECT status" in query and "FROM scans" in query:
                return {
                    "status": self.status,
                    "options": {"queue_handoff_confirmed": False},
                    "campaign_id": "44444444-4444-4444-8444-444444444444",
                }
            raise AssertionError(f"unexpected fetchrow: {query}")

        async def fetchval(self, query, *args):
            assert "SELECT status FROM scans" in query
            return self.status

        async def execute(self, query, *args):
            self.executions.append((query, args))
            if "UPDATE scan_campaigns" in query:
                return "UPDATE 1"
            raise AssertionError(f"worker must not claim the failed scan: {query}")

    conn = ClaimRaceConn()
    redis = _FakeJobRedis()
    run_calls = []

    async def forbidden_run_scan(*args, **kwargs):
        run_calls.append((args, kwargs))
        raise AssertionError("failed queue handoff must not reach the scanner")

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "run_scan", forbidden_run_scan)
    monkeypatch.setattr(worker, "QUEUE_HANDOFF_CONFIRM_RECHECKS", 1)
    monkeypatch.setattr(worker, "QUEUE_HANDOFF_CONFIRM_RECHECK_SECONDS", 0)

    asyncio.run(worker.process_scan_job({
        "job_id": "job-lost-rpush-response",
        "scan_id": "22222222-2222-4222-8222-222222222222",
        "target": "https://example.test",
        "options": {"scan_type": "smart"},
    }))

    assert run_calls == []
    failure_query = next(query for query, _args in conn.executions if "UPDATE scans" in query)
    assert "options->>'queue_handoff_confirmed'='false'" in failure_query
    assert any("UPDATE scan_campaigns" in query for query, _args in conn.executions)
    assert redis.hashes[-1][2]["status"] == "failed"


def test_exploit_worker_does_not_claim_endpoints_for_failed_queue_handoff(monkeypatch):
    class FailedHandoffConn(_FakeAsmConn):
        def __init__(self):
            super().__init__(child_status="pending")
            self.status = "pending"

        async def fetchrow(self, query, *args):
            if "UPDATE scans" in query and "queue_handoff_confirmed" in query:
                self.executions.append((query, args))
                self.status = "failed"
                return {
                    "status": "failed",
                    "campaign_id": "44444444-4444-4444-8444-444444444444",
                }
            if "SELECT status" in query and "FROM scans" in query:
                return {
                    "status": self.status,
                    "options": {"queue_handoff_confirmed": False},
                    "campaign_id": "44444444-4444-4444-8444-444444444444",
                }
            return await super().fetchrow(query, *args)

        async def fetchval(self, query, *args):
            assert "SELECT status FROM scans" in query
            return self.status

    conn = FailedHandoffConn()
    redis = _FakeJobRedis()
    claim_calls = []

    async def forbidden_claim(*args, **kwargs):
        claim_calls.append((args, kwargs))
        raise AssertionError("failed queue handoff must not lease endpoints")

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", forbidden_claim)
    monkeypatch.setattr(worker, "QUEUE_HANDOFF_CONFIRM_RECHECKS", 1)
    monkeypatch.setattr(worker, "QUEUE_HANDOFF_CONFIRM_RECHECK_SECONDS", 0)

    asyncio.run(worker.process_exploit_batch_job({
        "job_id": "job-lost-rpush-response",
        "scan_id": "22222222-2222-4222-8222-222222222222",
        "target_id": "33333333-3333-4333-8333-333333333333",
        "target": "https://example.test",
        "campaign_id": "44444444-4444-4444-8444-444444444444",
        "batch_size": 1,
        "options": {"scan_type": "smart"},
    }))

    assert claim_calls == []
    failure_query = next(query for query, _args in conn.executions if "UPDATE scans" in query)
    assert "options->>'queue_handoff_confirmed'='false'" in failure_query
    assert redis.hashes[-1][2]["status"] == "failed"


def test_worker_waits_for_fast_queue_handoff_confirmation(monkeypatch):
    class ConfirmationRaceConn:
        def __init__(self):
            self.confirmed = False
            self.failure_updates = 0

        async def fetchrow(self, query, *args):
            if "UPDATE scans" in query:
                self.failure_updates += 1
                return None
            return {
                "status": "queued" if self.confirmed else "pending",
                "options": {"queue_handoff_confirmed": self.confirmed},
                "campaign_id": "44444444-4444-4444-8444-444444444444",
            }

        async def fetchval(self, query, *args):
            return "queued" if self.confirmed else "pending"

    conn = ConfirmationRaceConn()
    sleeps = []

    async def confirm_during_worker_recheck(delay):
        sleeps.append(delay)
        conn.confirmed = True

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker.asyncio, "sleep", confirm_during_worker_recheck)
    monkeypatch.setattr(worker, "QUEUE_HANDOFF_CONFIRM_RECHECKS", 1)

    status = asyncio.run(worker._confirmed_scan_handoff_status(
        "22222222-2222-4222-8222-222222222222"
    ))

    assert status == "queued"
    assert sleeps == [worker.QUEUE_HANDOFF_CONFIRM_RECHECK_SECONDS]
    assert conn.failure_updates == 0


class _FakePlanConn:
    def __init__(
        self, parent_id, target_id, campaign_id, parent_action_plan=None,
        continuation_allocation=None,
    ):
        self.parent_id = parent_id
        self.target_id = target_id
        self.campaign_id = campaign_id
        self.executions = []
        self.inserted_children = []
        self.persisted_action_scan_ids = set()
        self.persisted_manifest_rows = []
        self.parent_action_plan = parent_action_plan
        self.continuation_allocation = continuation_allocation

    async def fetchrow(self, query, *args):
        if "SELECT target_id, target_url, status FROM scans" in query:
            return {
                "target_id": self.target_id,
                "target_url": "https://example.test",
                "status": "pending",
            }
        if "SELECT budget_used_json, scan_action_plan_json" in query:
            if self.parent_action_plan is None:
                return None
            return {
                "budget_used_json": {},
                "scan_action_plan_json": self.parent_action_plan.canonical_dict(),
                "scan_action_plan_digest": self.parent_action_plan.plan_digest,
                "scan_continuation_allocation_json": (
                    self.continuation_allocation.canonical_dict()
                    if self.continuation_allocation is not None else None
                ),
                "scan_continuation_allocation_digest": (
                    self.continuation_allocation.allocation_digest
                    if self.continuation_allocation is not None else None
                ),
            }
        if "SET scan_action_plan_json=" in query:
            self.persisted_action_scan_ids.add(str(args[0]))
            return {"id": args[0], "scan_action_plan_digest": args[1]}
        if "INSERT INTO scan_capability_actions" in query:
            return {
                "id": uuid.uuid4(),
                "action_id": args[1],
                "action_digest": args[8],
                "ordinal": args[3],
                "status": args[17],
            }
        if "INSERT INTO scan_action_plan_revisions" in query:
            return {
                "scan_id": args[0],
                "revision": 0,
                "plan_digest": args[1],
            }
        if "INSERT INTO scan_work_manifests" in query:
            self.persisted_manifest_rows.append((str(args[1]), args[2]))
            return {"content_json": json.loads(args[11])}
        return None

    async def fetchval(self, query, *args):
        if "INSERT INTO scan_campaigns" in query:
            return self.campaign_id
        return None

    async def execute(self, query, *args):
        self.executions.append((query, args))
        if "INSERT INTO scans" in query:
            self.inserted_children.append(args)
        return "UPDATE 1"

    def transaction(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakePlanPool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _canonical_parallel_fixture(
    parent_id,
    target_id,
    *,
    policy=None,
    budget_profile="balanced",
    strategy="coverage",
    custom_endpoints=(),
):
    from runtime.models import TargetBinding
    from scan.action_plan import ScanActionPlanCompiler
    from scan.budget_allocator import allocate_scan_action_plan
    from scan.contracts import resolve_scan_contract
    from scan.jobs import CanonicalScanJob

    effective_policy = {"exclude_families": ["nuclei"], **(policy or {})}
    contract = resolve_scan_contract(
        budget_profile=budget_profile,
        policy=effective_policy,
        approval_receipt_id=(
            "approval-1" if effective_policy.get("active_testing") else None
        ),
    )
    target = TargetBinding(
        target_id=str(target_id),
        target_kind="web",
        canonical_host="example.test",
        allowed_origins=("https://example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
    )
    parent_job = CanonicalScanJob.create(
        job_id=f"job-{parent_id}",
        scan_id=parent_id,
        target=target,
        execution_plan=contract.execution_plan,
    )
    parent_plan = allocate_scan_action_plan(
        ScanActionPlanCompiler().compile(
            scan_id=parent_id,
            execution_plan=contract.execution_plan,
            target_binding=target,
        ),
        contract.budget,
    ).plan
    options = contract.option_metadata()
    options.update({
        "parallel": True,
        "shard_strategy": strategy,
        "runtime_scope_guard": {
            **parent_job.payload()["target"],
            "requires_runtime_destination_check": True,
            "requires_runtime_dns_check": True,
            "address_binding_source": "submission_dns_snapshot",
        },
    })
    if custom_endpoints:
        options["custom_endpoints"] = list(custom_endpoints)
    queue_payload = parent_job.payload()
    queue_payload.update({
        "type": worker.parallel_scan.PLAN_JOB_TYPE,
        "placement": {"node_scope": "local"},
        "attempt": 1,
        "plan_version": worker.parallel_scan.PLAN_VERSION,
        "parallel_worker_count": 3,
    })
    return parent_job, parent_plan, options, queue_payload


def test_scan_plan_queues_placed_discovery_without_running_target_traffic_locally(monkeypatch):
    parent_id = "51515151-5151-5151-5151-515151515151"
    target_id = uuid.UUID("31313131-3131-3131-3131-313131313131")
    parent_job, parent_plan, options, queue_payload = _canonical_parallel_fixture(
        parent_id, target_id,
    )
    options["placement"] = {
        "node_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    }
    conn = _FakePlanConn(parent_id, target_id, uuid.uuid4(), parent_plan)
    redis = _FakeJobRedis()

    async def forbidden_run(*args, **kwargs):
        raise AssertionError("the control-plane planner must not scan the target")

    monkeypatch.setattr(worker, "db_pool", _FakePlanPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "run_scan", forbidden_run)

    asyncio.run(worker.process_scan_plan_job({
        "job_id": parent_job.job_id,
        "scan_id": parent_id,
        "target": "https://example.test",
        "parallel_worker_count": 3,
        "options": options,
        "_canonical_queue_payload": queue_payload,
    }))

    jobs = [json.loads(payload) for _, payload in redis.pushed]
    assert len(jobs) == 1
    discovery = jobs[0]
    assert discovery["type"] == worker.parallel_scan.SHARD_JOB_TYPE
    from scan.jobs import CanonicalScanJob
    discovery_job = CanonicalScanJob.from_queue_payload(discovery)
    assert discovery_job.shard.parallel_discovery is True
    assert discovery["placement"] == {
        "node_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    }
    assert discovery_job.shard.sub_budget.max_state_changing_requests == 0
    assert discovery_job.shard.sub_budget.max_browser_actions == 0
    assert any(
        worker.parallel_scan.PARALLEL_DISCOVERY_ROLE in args
        for query, args in conn.executions if "INSERT INTO scans" in query
    )


def test_active_scope_fanout_uses_preallocated_continuation_authority(monkeypatch):
    from scan.action_plan import ScanActionPlanCompiler
    from scan.budget_allocator import allocate_scan_action_plan
    from scan.continuation import ScanContinuationAllocation

    parent_id = "51515151-5151-4515-8515-515151515152"
    target_id = uuid.UUID("31313131-3131-4313-8313-313131313132")
    endpoints = (
        "GET /rest/products/search?q=juice",
        "GET /api/Quantitys/",
        "GET /rest/admin/application-version",
        "GET /rest/products/1/reviews",
    )
    parent_job, _full_plan, options, queue_payload = (
        _canonical_parallel_fixture(
            parent_id,
            target_id,
            policy={
                "active_testing": True,
                "include_families": ["xss"],
            },
            strategy="scope",
            custom_endpoints=endpoints,
        )
    )
    admitted = allocate_scan_action_plan(
        ScanActionPlanCompiler().compile(
            scan_id=parent_id,
            execution_plan=parent_job.execution_plan,
            target_binding=parent_job.target,
            defer_manifest_actions=True,
            include_finalizer=False,
        ),
        parent_job.execution_plan.budget,
        assign_residual_to_finalizer=False,
        require_finalizer=False,
    )
    parent_plan = admitted.plan
    allocation = ScanContinuationAllocation(
        scan_id=parent_id,
        parent_plan_digest=parent_plan.plan_digest,
        execution_plan_digest=parent_plan.execution_plan_digest,
        target_binding_digest=parent_plan.target_binding_digest,
        parent_action_ids=tuple(
            action.action_id for action in parent_plan.actions
        ),
        budget_ceiling=admitted.residual_scan_execute_budget,
        max_endpoint_entries=parent_job.execution_plan.budget.max_endpoints,
        max_candidate_entries=parent_job.execution_plan.budget.max_http_requests,
        required_capabilities=("xss.verify",),
        allowed_capabilities=("xss.verify",),
    )
    conn = _FakePlanConn(
        parent_id, target_id, uuid.uuid4(), parent_plan, allocation,
    )
    redis = _FakeJobRedis()
    monkeypatch.setattr(worker, "db_pool", _FakePlanPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)

    asyncio.run(worker.process_scan_plan_job({
        "job_id": parent_job.job_id,
        "scan_id": parent_id,
        "target": "https://example.test",
        "options": options,
        "parallel_worker_count": 3,
        "_canonical_queue_payload": queue_payload,
    }))

    queued = [json.loads(payload) for _, payload in redis.pushed]
    assert len(queued) >= 2
    parent_update = next(
        json.loads(args[2])
        for query, args in conn.executions
        if "UPDATE scans SET current_phase" in query
        and "sharded:" in str(args)
    )
    record = parent_update["parallel_action_partition_record"]
    assert record["continuation_allocation_digest"] == (
        allocation.allocation_digest
    )
    assert record["allowed_continuation_capabilities"] == ["xss.verify"]
    assert any(
        "verify.xss" in child["expected_action_ids"]
        for child in record["children"]
    )


def test_canonical_shard_builder_emits_secret_free_v2_queue_authority():
    from runtime.models import TargetBinding
    from scan.contracts import resolve_scan_contract
    from scan.jobs import CanonicalScanJob

    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={"exclude_families": ["nuclei"]},
    )
    parent = CanonicalScanJob.create(
        job_id="parent-job",
        scan_id="parent-scan",
        target=TargetBinding(
            target_id="target-1",
            target_kind="web",
            canonical_host="example.test",
            allowed_origins=("https://example.test",),
            allowed_addresses=("192.0.2.10",),
            allowed_root_domains=("example.test",),
        ),
        execution_plan=contract.execution_plan,
    )
    options = contract.option_metadata()
    options.update({
        "scan_type": "smart",
        "auth_header": "Bearer must-not-enter-queue",
        "skip_global_checks": True,
        "custom_endpoints": ["GET /v1/items"],
        "custom_budget": {
            "request_max": 50,
            "max_urls": 20,
            "browser_max_pages": 0,
            "phase4_max_seconds": 0,
        },
    })

    child, persisted, queued = worker._canonical_shard_job(
        parent,
        child_id="22222222-2222-4222-8222-222222222222",
        child_job_id="child-job",
        child_options=options,
        shard_label="coverage[0]",
        shard_index=0,
        shard_count=2,
    )

    assert CanonicalScanJob.from_queue_payload(queued) == child
    assert queued["type"] == worker.parallel_scan.SHARD_JOB_TYPE
    assert "options" not in queued
    assert "must-not-enter-queue" not in json.dumps(queued)
    assert "scan_type" not in persisted
    assert persisted["canonical_shard_authority"]["sub_budget"]["max_browser_actions"] == 0
    assert persisted["canonical_shard_authority"]["sub_budget"]["max_tcp_ports"] == 0
    action_plan = worker._compile_parallel_child_action_plan(child, persisted)
    # This endpoint shard has no executable family work. Parent finalization is
    # deliberately absent from child plans compiled with include_finalizer=False.
    assert action_plan.actions == ()


def test_parallel_child_manifests_bind_value_free_endpoint_and_candidates():
    from runtime.models import TargetBinding
    from scan.contracts import resolve_scan_contract
    from scan.jobs import CanonicalScanJob

    contract = resolve_scan_contract(budget_profile="balanced")
    parent = CanonicalScanJob.create(
        job_id="parent-job",
        scan_id="parent-scan",
        target=TargetBinding(
            target_id="target-1",
            target_kind="web",
            canonical_host="example.test",
            allowed_origins=("https://example.test",),
            allowed_addresses=("192.0.2.10",),
            allowed_root_domains=("example.test",),
        ),
        execution_plan=contract.execution_plan,
    )
    options, manifests = worker._compile_parallel_child_work_manifests(
        child_scan_id="22222222-2222-4222-8222-222222222223",
        target_url="https://example.test",
        parent_job=parent,
        child_options={"custom_budget": {"request_max": 50, "max_urls": 20}},
        selected_shard=1,
        endpoints=("GET /v1/items?account=must-not-persist",),
    )

    endpoint, candidates, templates = manifests
    assert options["endpoint_manifest_ref"] == endpoint.reference().canonical_dict()
    assert options["candidate_manifest_ref"] == candidates.reference().canonical_dict()
    parameterized = next(
        item for item in endpoint.entries if item["query_parameter_names"]
    )
    assert parameterized["query_parameter_names"] == ("account",)
    assert candidates.entries[0]["parameter_name"] == "account"
    assert options["template_manifest_ref"] == (
        templates.reference().canonical_dict()
    )
    assert all(entry["risk"] == "passive" for entry in templates.entries)
    assert "must-not-persist" not in json.dumps([
        endpoint.canonical_dict(), candidates.canonical_dict(),
    ])


def test_parallel_child_plan_owns_only_its_partitioned_collection_requests():
    from runtime.models import TargetBinding
    from scan.contracts import resolve_scan_contract
    from scan.jobs import CanonicalScanJob
    from scan.work_manifests import build_request_manifest

    child_scan_id = "22222222-2222-4222-8222-222222222225"
    selection_digest = "d" * 64
    contract = resolve_scan_contract(budget_profile="balanced")
    parent = CanonicalScanJob.create(
        job_id="parent-job",
        scan_id="parent-scan",
        target=TargetBinding(
            target_id="target-1",
            target_kind="web",
            canonical_host="example.test",
            allowed_origins=("https://example.test",),
            allowed_addresses=("192.0.2.10",),
            allowed_root_domains=("example.test",),
        ),
        execution_plan=contract.execution_plan,
    )
    request_manifest = build_request_manifest(
        scan_id=child_scan_id,
        target_binding_digest=parent.target.digest,
        source_action_ids=("inputs.collection_00",),
        requests=({
            "request_ref_id": "opaque-request-2",
            "route_id": "e" * 64,
            "method": "GET",
            "auth_lane": "anonymous",
            "selected_shard": 1,
            "safe_method": True,
            "body_schema_digest": None,
        },),
    )
    child_options = {
        **contract.option_metadata(),
        "skip_global_checks": True,
        "custom_budget": {"request_max": 50, "max_urls": 20},
        "request_collections": [{
            "collection_id": "11111111-1111-4111-8111-111111111111",
            "binding_id": "22222222-2222-4222-8222-222222222222",
            "selection_id": "33333333-3333-4333-8333-333333333333",
            "selection_digest": selection_digest,
            "replay_policy": "safe_reads",
            "selected_requests": 3,
            "selector": {"max_requests": 3},
        }],
    }

    options, manifests = worker._compile_parallel_child_work_manifests(
        child_scan_id=child_scan_id,
        target_url="https://example.test",
        parent_job=parent,
        child_options=child_options,
        selected_shard=1,
        endpoints=("GET /v1/items",),
        request_manifests_by_selection={selection_digest: request_manifest},
    )
    child, options, _payload = worker._canonical_shard_job(
        parent,
        child_id=child_scan_id,
        child_job_id="child-job",
        child_options=options,
        shard_label="scope[1]",
        shard_index=1,
        shard_count=2,
    )
    plan = worker._compile_parallel_child_action_plan(child, options)

    assert "finalize.report" not in {action.action_id for action in plan.actions}
    collection = next(
        action for action in plan.actions
        if action.capability_name == "collections.replay_safe"
    )
    assert collection.requested_budget["http_requests"] == 1
    assert options["request_collections"][0]["selected_requests"] == 1
    assert options["request_collections"][0]["selector"]["max_requests"] == 1
    assert options["request_manifest_refs"] == {
        selection_digest: request_manifest.reference().canonical_dict()
    }
    assert request_manifest in manifests
    assert "opaque-request-1" not in json.dumps(options)
    assert "private-body-canary" not in json.dumps(options)


def test_local_continuation_compiles_discovery_receipts_into_appended_actions(monkeypatch):
    import hashlib

    from runtime.models import TargetBinding
    from runtime.observation_manifests import ObservationManifest
    from scan.action_plan import ScanActionPlanCompiler
    from scan.budget_allocator import allocate_scan_action_plan
    from scan.capability_result import (
        CapabilityReceiptReference,
        CapabilityResultReference,
        CapabilityResultStatus,
    )
    from scan.continuation import ScanContinuationAllocation
    from scan.contracts import resolve_scan_contract

    scan_id = "45454545-4545-4545-8545-454545454545"
    target = TargetBinding(
        target_id="target-continuation",
        target_kind="web",
        canonical_host="example.test",
        allowed_origins=("https://example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
    )
    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={"active_testing": True, "include_families": ["xss"]},
    )
    raw_parent = ScanActionPlanCompiler().compile(
        scan_id=scan_id,
        execution_plan=contract.execution_plan,
        target_binding=target,
        defer_manifest_actions=True,
        include_finalizer=False,
    )
    admitted = allocate_scan_action_plan(
        raw_parent,
        contract.budget,
        assign_residual_to_finalizer=False,
        require_finalizer=False,
    )
    parent = admitted.plan
    allocation = ScanContinuationAllocation(
        scan_id=scan_id,
        parent_plan_digest=parent.plan_digest,
        execution_plan_digest=parent.execution_plan_digest,
        target_binding_digest=parent.target_binding_digest,
        parent_action_ids=tuple(action.action_id for action in parent.actions),
        budget_ceiling=admitted.residual_scan_execute_budget,
        max_endpoint_entries=contract.budget.max_endpoints,
        max_candidate_entries=contract.budget.max_http_requests,
        required_capabilities=("xss.verify",),
        allowed_capabilities=("xss.verify",),
    )
    results = {
        action.action_id: CapabilityResultReference(
            action_id=action.action_id,
            action_digest=action.action_digest,
            capability_name=action.capability_name,
            adapter_name=str(action.placement["adapter_name"]),
            adapter_version=str(action.placement["adapter_version"]),
            output_schema=action.output_schema,
            status=CapabilityResultStatus.SUCCESS,
            partial=False,
            timed_out=False,
            reason_code=None,
            receipt_ref=CapabilityReceiptReference(
                receipt_id=str(uuid.uuid5(
                    uuid.NAMESPACE_URL, f"continuation:{action.action_id}",
                )),
                receipt_hash=hashlib.sha256(
                    action.action_id.encode()
                ).hexdigest(),
            ),
            observation_manifest_ref=ObservationManifest(
                manifest_id=str(uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"continuation-manifest:{action.action_id}",
                )),
                owner_id=scan_id,
                action_id=action.action_id,
                capability_name=action.capability_name,
                output_schema=action.output_schema,
                observation_count=0,
                content_sha256=hashlib.sha256(b"").hexdigest(),
                size_bytes=0,
                object_key=f"scans/{scan_id}/{action.action_id}.jsonl",
            ).reference(),
            budget_reserved=action.requested_budget,
            budget_consumed={},
        )
        for action in parent.actions
    }

    class Dispatcher:
        def __init__(self):
            self.scan_id = scan_id
            self.target_url = "https://example.test"
            self.options = {}
            self.execution = types.SimpleNamespace(
                execution_plan=contract.execution_plan,
            )

        @property
        def target(self):
            return target

        async def _observations(self, action_id):
            if action_id == "discover.web_crawl":
                return ({
                    "kind": "discovered_route",
                    "method": "GET",
                    "url": "https://example.test/search?q=hello",
                },)
            return ()

    persisted = []
    amended = []

    class ManifestStore:
        async def persist(self, _conn, *, manifest):
            persisted.append(manifest)

    class ActionStore:
        async def amend_plan(self, _conn, **kwargs):
            amended.append(kwargs)

    conn = _FakePlanConn(scan_id, uuid.uuid4(), uuid.uuid4())
    monkeypatch.setattr(worker, "db_pool", _FakePlanPool(conn))
    monkeypatch.setattr(worker, "PostgresScanManifestStore", ManifestStore)
    monkeypatch.setattr(worker, "PostgresScanActionStore", ActionStore)

    continued, revision = asyncio.run(worker._materialize_local_scan_continuation(
        parent_plan=parent,
        allocation=allocation,
        parent_results=results,
        dispatcher=Dispatcher(),
        execution_plan=contract.execution_plan,
    ))

    assert [manifest.kind.value for manifest in persisted] == [
        "endpoint", "candidate",
    ]
    assert amended[0]["parent_plan"] == parent
    assert amended[0]["amended_plan"] == continued
    assert amended[0]["revision"] == revision
    assert revision.plan_digest == continued.plan_digest
    assert continued.actions[:len(parent.actions)] == parent.actions
    assert continued.actions[-1].action_id == "finalize.report"
    assert any(
        action.capability_name == "xss.verify"
        for action in continued.actions
    )


def test_active_parallel_child_freezes_the_same_nuclei_template_pack():
    from runtime.models import TargetBinding
    from scan.contracts import resolve_scan_contract
    from scan.jobs import CanonicalScanJob

    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={"active_testing": True, "include_families": ["nuclei"]},
        approval_receipt_id="approval-1",
    )
    target = TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="example.test",
        allowed_origins=("https://example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
    )
    parent = CanonicalScanJob.create(
        job_id="parent-job",
        scan_id="parent-scan",
        target=target,
        execution_plan=contract.execution_plan,
    )

    options, manifests = worker._compile_parallel_child_work_manifests(
        child_scan_id="22222222-2222-4222-8222-222222222224",
        target_url="https://example.test",
        parent_job=parent,
        child_options={"custom_budget": {"request_max": 50, "max_urls": 20}},
        selected_shard=0,
        endpoints=("GET /v1/items",),
    )

    template = manifests[-1]
    assert template.kind.value == "template"
    assert options["template_manifest_ref"] == (
        template.reference().canonical_dict()
    )


def test_canonical_scan_plan_persists_and_queues_only_v2_child_jobs(monkeypatch):
    from runtime.models import TargetBinding
    from scan.contracts import resolve_scan_contract
    from scan.jobs import CanonicalScanJob

    parent_id = "51515151-5151-4151-8151-515151515151"
    target_id = uuid.UUID("31313131-3131-4131-8131-313131313131")
    from scan.action_plan import ScanActionPlanCompiler
    from scan.budget_allocator import allocate_scan_action_plan

    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={"exclude_families": ["nuclei"]},
    )
    target = TargetBinding(
        target_id=str(target_id),
        target_kind="web",
        canonical_host="example.test",
        allowed_origins=("https://example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
    )
    parent_job = CanonicalScanJob.create(
        job_id="parent-v2-job",
        scan_id=parent_id,
        target=target,
        execution_plan=contract.execution_plan,
    )
    parent_action_plan = allocate_scan_action_plan(
        ScanActionPlanCompiler().compile(
            scan_id=parent_id,
            execution_plan=contract.execution_plan,
            target_binding=target,
        ),
        contract.budget,
    ).plan
    parent_queue = parent_job.payload()
    parent_queue.update({
        "type": worker.parallel_scan.PLAN_JOB_TYPE,
        "placement": {"node_scope": "local"},
        "attempt": 1,
        "plan_version": worker.parallel_scan.PLAN_VERSION,
        "parallel_worker_count": 2,
    })
    options = contract.option_metadata()
    options.update({
        "scan_type": "deep",
        "active": False,
        "network_discovery": False,
        "subfinder": contract.policy.subdomain_discovery,
        "parallel": True,
        "shard_strategy": "scope",
        "shards": 2,
        "custom_endpoints": [
            "GET /v1/a", "GET /v1/b", "GET /v1/c", "GET /v1/d",
        ],
        "runtime_scope_guard": {
            **parent_job.payload()["target"],
            "requires_runtime_destination_check": True,
            "requires_runtime_dns_check": True,
            "address_binding_source": "submission_dns_snapshot",
        },
    })
    conn = _FakePlanConn(
        parent_id, target_id, uuid.uuid4(), parent_action_plan,
    )
    redis = _FakeJobRedis()
    monkeypatch.setattr(worker, "db_pool", _FakePlanPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)

    asyncio.run(worker.process_scan_plan_job({
        "job_id": parent_job.job_id,
        "scan_id": parent_id,
        "target": "https://example.test",
        "options": options,
        "parallel_worker_count": 2,
        "_canonical_queue_payload": parent_queue,
    }))

    queued = [json.loads(payload) for _, payload in redis.pushed]
    assert len(queued) == 2
    assert all(CanonicalScanJob.from_queue_payload(item).shard for item in queued)
    assert all("options" not in item for item in queued)
    assert all(item["type"] == worker.parallel_scan.SHARD_JOB_TYPE for item in queued)
    assert len(conn.inserted_children) == 2
    assert all(args[9] == "v2" for args in conn.inserted_children)
    assert all(json.loads(args[12])["schema_version"] == "scan-job/v2" for args in conn.inserted_children)
    assert all(len(args[13]) == 64 for args in conn.inserted_children)
    queued_by_scan = {
        item["scan_id"]: CanonicalScanJob.from_queue_payload(item)
        for item in queued
    }
    assert all(
        json.loads(args[11])
        == queued_by_scan[str(args[0])].shard.sub_budget.payload()
        for args in conn.inserted_children
    )
    assert conn.persisted_action_scan_ids == {
        str(uuid.UUID(str(args[0]))) for args in conn.inserted_children
    }
    assert len(conn.persisted_manifest_rows) == 4
    assert {kind for _scan_id, kind in conn.persisted_manifest_rows} == {
        "endpoint", "candidate",
    }
    parent_update = next(
        json.loads(args[2])
        for query, args in conn.executions
        if "UPDATE scans SET current_phase" in query
        and "sharded:" in str(args)
    )
    record = parent_update["parallel_action_partition_record"]
    assert record["partition_digest"] == parent_update[
        "parallel_action_partition_digest"
    ]
    assert [
        child["role"] for child in record["children"]
    ] == ["global", "endpoint"]
    assert all(
        "finalize.report" not in child["expected_action_ids"]
        for child in record["children"]
    )
    assert all(child["work_partition_digest"] for child in record["children"])
    assert all(child["input_binding_digest"] for child in record["children"])


def test_scan_plan_continuation_fans_out_from_durable_discovery_result(monkeypatch):
    parent_id = "52525252-5252-5252-5252-525252525252"
    discovery_id = "62626262-6262-4262-8262-626262626262"
    target_id = uuid.UUID("32323232-3232-4232-8232-323232323232")

    class DiscoveryPlanConn(_FakePlanConn):
        async def fetchrow(self, query, *args):
            if "SELECT id, status, result, error_message" in query:
                return {
                    "id": uuid.UUID(discovery_id),
                    "status": "completed",
                    "result": {
                        "active_checks": {"active_worklist": [
                            "GET /api/a?id=1", "GET /api/b?id=1",
                            "GET /api/c?id=1", "GET /api/d?id=1",
                        ]}
                    },
                    "error_message": None,
                }
            return await super().fetchrow(query, *args)

    parent_job, parent_plan, options, queue_payload = _canonical_parallel_fixture(
        parent_id, target_id,
    )
    options["coverage_per_shard_cap"] = 2
    conn = DiscoveryPlanConn(
        parent_id, target_id, uuid.uuid4(), parent_plan,
    )
    redis = _FakeJobRedis()
    monkeypatch.setattr(worker, "db_pool", _FakePlanPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)

    asyncio.run(worker.process_scan_plan_job({
        "job_id": parent_job.job_id,
        "scan_id": parent_id,
        "target": "https://example.test",
        "plan_stage": "fanout",
        "discovery_scan_id": discovery_id,
        "options": options,
        "_canonical_queue_payload": queue_payload,
    }))

    jobs = [json.loads(payload) for _, payload in redis.pushed]
    assert len(jobs) == 3
    from scan.jobs import CanonicalScanJob
    assert CanonicalScanJob.from_queue_payload(
        jobs[0]
    ).shard.shard_label == "global-backbone"
    assigned = [
        endpoint
        for args in conn.inserted_children[1:]
        for endpoint in json.loads(args[4])["custom_endpoints"]
    ]
    assert sorted(assigned) == sorted([
        "GET /api/a?id=1", "GET /api/b?id=1",
        "GET /api/c?id=1", "GET /api/d?id=1",
    ])


def test_scan_plan_failed_discovery_runs_canonical_backbone_with_partial_coverage(monkeypatch):
    parent_id = "53535353-5353-4353-8353-535353535353"
    discovery_id = "63636363-6363-4363-8363-636363636363"
    target_id = uuid.UUID("33333333-3333-4333-8333-333333333333")

    class FailedDiscoveryPlanConn(_FakePlanConn):
        async def fetchrow(self, query, *args):
            if "SELECT id, status, result, error_message" in query:
                return {
                    "id": uuid.UUID(discovery_id),
                    "status": "failed",
                    "result": {"error": "Exceeded bounded discovery duration"},
                    "error_message": "Exceeded bounded discovery duration",
                }
            return await super().fetchrow(query, *args)

    parent_job, parent_plan, options, queue_payload = _canonical_parallel_fixture(
        parent_id, target_id,
    )
    conn = FailedDiscoveryPlanConn(
        parent_id, target_id, uuid.uuid4(), parent_plan,
    )
    redis = _FakeJobRedis()
    monkeypatch.setattr(worker, "db_pool", _FakePlanPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)

    asyncio.run(worker.process_scan_plan_job({
        "job_id": parent_job.job_id,
        "scan_id": parent_id,
        "target": "https://example.test",
        "plan_stage": "fanout",
        "discovery_scan_id": discovery_id,
        "options": options,
        "_canonical_queue_payload": queue_payload,
    }))

    queued = [json.loads(payload) for _, payload in redis.pushed]
    assert len(queued) == 2
    from scan.jobs import CanonicalScanJob
    assert all(
        CanonicalScanJob.from_queue_payload(item).shard.parent_scan_id == parent_id
        for item in queued
    )
    parent_update = next(
        args for query, args in conn.executions
        if "UPDATE scans SET status='running'" in query and "shard_count" in query
    )
    parent_options = json.loads(parent_update[3])
    assert parent_options["coverage_status"] == "partial"
    assert parent_options["coverage_reasons"] == [
        "Exceeded bounded discovery duration"
    ]


def test_parallel_shard_slots_enforce_parent_concurrency(monkeypatch):
    # Default per-parent shard concurrency now derives from the FLEET active-scan
    # cap (so one parent can fill the fleet); PARALLEL_SHARD_MAX_PER_PARENT is only
    # a floor. The fleet-wide active-scan semaphore still arbitrates across parents.
    monkeypatch.setattr(worker, "PARALLEL_SHARD_MAX_PER_PARENT", 1)
    monkeypatch.setattr(worker, "PARALLEL_SHARD_CONCURRENCY_HARD_MAX", 5)
    monkeypatch.setattr(worker, "_max_active_scans", lambda r: 2)
    r = _FakeSlotRedis()
    parent_id = "parent-1"

    first, limit = worker._try_acquire_parallel_shard_slot(
        r, parent_id, {}, slot_id="job-1"
    )
    retry, _ = worker._try_acquire_parallel_shard_slot(
        r, parent_id, {}, slot_id="job-1"
    )
    second, _ = worker._try_acquire_parallel_shard_slot(
        r, parent_id, {}, slot_id="job-2"
    )
    third, _ = worker._try_acquire_parallel_shard_slot(
        r, parent_id, {}, slot_id="job-3"
    )

    assert first is True
    assert retry is True  # redelivery refreshes the same lease, not a second slot
    assert second is True
    assert third is False  # capped at the fleet cap (2)
    assert limit == 2
    assert r.zcard(worker._parallel_shard_slot_key(parent_id)) == 2

    worker._release_parallel_shard_slot(r, parent_id, "job-1")
    fourth, _ = worker._try_acquire_parallel_shard_slot(
        r, parent_id, {}, slot_id="job-3"
    )
    assert fourth is True
    assert r.zcard(worker._parallel_shard_slot_key(parent_id)) == 2


def test_parallel_shard_slots_reclaim_expired_members(monkeypatch):
    monkeypatch.setattr(worker, "PARALLEL_SHARD_MAX_PER_PARENT", 1)
    monkeypatch.setattr(worker, "_max_active_scans", lambda r: 1)
    r = _FakeSlotRedis()
    parent_id = "parent-expired"
    key = worker._parallel_shard_slot_key(parent_id)
    r.zsets[key] = {"dead-job": 1.0}

    acquired, limit = worker._try_acquire_parallel_shard_slot(
        r, parent_id, {}, slot_id="replacement-job"
    )

    assert acquired is True
    assert limit == 1
    assert set(r.zsets[key]) == {"replacement-job"}


def test_parallel_shard_slots_remove_legacy_integer_key(monkeypatch):
    monkeypatch.setattr(worker, "PARALLEL_SHARD_MAX_PER_PARENT", 1)
    monkeypatch.setattr(worker, "_max_active_scans", lambda r: 1)
    r = _FakeSlotRedis()
    parent_id = "parent-upgrade"
    key = worker._parallel_shard_slot_key(parent_id)
    r.legacy[key] = 4

    acquired, _ = worker._try_acquire_parallel_shard_slot(
        r, parent_id, {}, slot_id="new-job"
    )

    assert acquired is True
    assert key in r.deleted
    assert set(r.zsets[key]) == {"new-job"}


def test_parallel_shard_concurrency_override_is_clamped(monkeypatch):
    monkeypatch.setattr(worker, "PARALLEL_SHARD_MAX_PER_PARENT", 4)
    monkeypatch.setattr(worker, "PARALLEL_SHARD_CONCURRENCY_HARD_MAX", 8)
    monkeypatch.setattr(worker, "_max_active_scans", lambda r: 6)
    sentinel_r = object()  # non-None so the fleet-derived default path runs

    # No explicit override: default to the fleet cap (6), bounded by floor/hard max.
    assert worker._parallel_shard_concurrency_limit(sentinel_r, {}) == 6
    # Explicit override wins and is clamped to the hard max.
    assert worker._parallel_shard_concurrency_limit(sentinel_r, {"shard_concurrency": 6}) == 6
    assert worker._parallel_shard_concurrency_limit(sentinel_r, {"parallel_shard_concurrency": 99}) == 8
    # Override is floored at 1.
    assert worker._parallel_shard_concurrency_limit(sentinel_r, {"shard_concurrency": 0}) == 1
    # When the fleet cap is below the floor, the floor (PARALLEL_SHARD_MAX_PER_PARENT) wins.
    monkeypatch.setattr(worker, "_max_active_scans", lambda r: 1)
    assert worker._parallel_shard_concurrency_limit(sentinel_r, {}) == 4
    # With no redis handle (r=None), fall back to the floor (no fleet info).
    assert worker._parallel_shard_concurrency_limit(None, {}) == 4


class _BrokenAdmissionRedis:
    def get(self, _key):
        return b"2"

    def eval(self, *_args):
        raise ConnectionError("redis unavailable")


def test_active_scan_admission_fails_closed_for_joined_node(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_NODE_ID", "11111111-1111-4111-8111-111111111111")
    with pytest.raises(worker.FleetAdmissionUnavailable):
        worker._take_scan_slot(_BrokenAdmissionRedis(), "slot-1")


def test_active_scan_admission_keeps_standalone_compatibility(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_NODE_ID", raising=False)
    monkeypatch.delenv("SHAKERSCAN_ENFORCE_FLEET_LIMITS", raising=False)
    assert worker._take_scan_slot(_BrokenAdmissionRedis(), "slot-1") is True


def test_fleet_request_budget_defaults_to_enforce_but_explicit_off_wins(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_NODE_ID", "11111111-1111-4111-8111-111111111111")
    assert worker._effective_request_budget_mode({}) == "enforce"
    assert worker._effective_request_budget_mode({"request_budget_mode": "compatibility"}) == "enforce"
    assert worker._effective_request_budget_mode({"request_budget_mode": "off"}) == "off"


def test_fleet_busy_marker_is_atomic_and_content_free(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "RESULTS_DIR", tmp_path)
    monkeypatch.setenv("SHAKERSCAN_NODE_ID", "11111111-1111-4111-8111-111111111111")
    monkeypatch.setenv("HOSTNAME", "abc123def456")
    marker = worker._fleet_busy_marker({"job_id": "job-1", "scan_id": "scan-1", "secret": "nope"})
    assert marker is not None and marker.is_file()
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["container_id"] == "abc123def456"
    assert "secret" not in payload
    assert not list(marker.parent.glob("*.tmp"))
    worker._clear_fleet_busy_marker(marker)
    assert not marker.exists()


def test_domain_endpoint_budget_reservation_accounts_for_db_and_redis_usage():
    target_id = "33333333-3333-3333-3333-333333333333"
    conn = _FakeRateConn(root_domain="example.test", cap=5, used=2)
    redis = _FakeJobRedis()
    redis.values[worker.asm_inventory.domain_rate_key("example.test")] = 1

    granted = asyncio.run(
        worker._reserve_target_domain_endpoint_budget(
            conn,
            redis,
            target_id=target_id,
            amount=2,
            all_or_nothing=True,
        )
    )

    assert granted["granted"] == 2
    assert granted["limited"] is False
    assert granted["used"] == 2
    assert granted["reserved"] == 3


def test_domain_endpoint_budget_reservation_denies_exhausted_db_budget():
    target_id = "33333333-3333-3333-3333-333333333333"
    conn = _FakeRateConn(root_domain="example.test", cap=5, used=5)
    redis = _FakeJobRedis()

    granted = asyncio.run(
        worker._reserve_target_domain_endpoint_budget(
            conn,
            redis,
            target_id=target_id,
            amount=1,
        )
    )

    assert granted["granted"] == 0
    assert granted["limited"] is True
    assert granted["used"] == 5
    assert granted["reserved"] == 0


def test_parallel_shard_waits_when_domain_endpoint_budget_exhausted(monkeypatch):
    redis = _FakeJobRedis()
    conn = _FakeAsmConn()
    called = {"run": 0}

    async def fake_run_scan(*args, **kwargs):
        called["run"] += 1
        raise AssertionError("rate-limited shard must not run")

    async def fake_reserve(*args, **kwargs):
        return {
            "granted": 0,
            "limited": True,
            "requested": 2,
            "root_domain": "example.test",
            "cap": 1,
        }

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "_execute_reserved_deterministic_scan", fake_run_scan)
    monkeypatch.setattr(worker, "DOMAIN_RATE_REQUEUE_DELAY_SECONDS", 0)
    monkeypatch.setattr(worker, "_reserve_target_domain_endpoint_budget", fake_reserve)

    asyncio.run(
        worker.process_scan_shard_job(
            {
                "job_id": "job-rate-shard",
                "scan_id": "22222222-2222-2222-2222-222222222222",
                "parent_scan_id": "55555555-5555-5555-5555-555555555555",
                "target_id": "33333333-3333-3333-3333-333333333333",
                "target": "https://example.test",
                "options": {"scan_type": "smart", "custom_endpoints": ["GET /a?id=1", "GET /b?id=1"]},
                "shard_label": "coverage[0]",
                "shard_index": 0,
                "shard_count": 1,
            }
        )
    )

    assert called["run"] == 0
    assert redis.pushed
    queued = json.loads(redis.pushed[0][1])
    assert queued["domain_rate_wait_cycles"] == 1
    assert redis.hashes[-1][2]["current_phase"] == "waiting_for_domain_rate"
    assert worker._parallel_shard_slot_key("55555555-5555-5555-5555-555555555555") not in redis.values


def test_broker_shard_result_ingest_never_reclaims_execution_slots_or_budget(monkeypatch):
    redis = _FakeJobRedis()

    class BrokerIngestConn(_FakeAsmConn):
        async def fetchval(self, query, *args):
            assert "SELECT created_at FROM broker_job_leases" in query
            return datetime(2026, 7, 6, tzinfo=timezone.utc)

    conn = BrokerIngestConn(child_status="running", parent_status="running")
    calls = {"load": 0, "run": 0, "persist": 0}

    def forbidden_slot(*args, **kwargs):
        raise AssertionError("broker result ingestion must not claim an execution slot")

    async def forbidden_reserve(*args, **kwargs):
        raise AssertionError("broker result ingestion must not reserve request budget")

    async def forbidden_run(*args, **kwargs):
        calls["run"] += 1
        raise AssertionError("broker result ingestion must not execute the scanner")

    async def load_result(job_data, scan_id):
        calls["load"] += 1
        assert job_data["_broker_result_id"] == "77777777-7777-4777-8777-777777777777"
        assert scan_id == "22222222-2222-4222-8222-222222222222"
        return {
            "target": "https://example.test",
            "result": {"score": 100, "grade": "A"},
            "findings": [],
        }

    async def persist_result(*args, **kwargs):
        calls["persist"] += 1
        return "/tmp/broker-result.json"

    async def no_progress(*args, **kwargs):
        return None

    async def no_merge(*args, **kwargs):
        return False

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "_try_acquire_parallel_shard_slot", forbidden_slot)
    monkeypatch.setattr(worker, "_reserve_target_domain_endpoint_budget", forbidden_reserve)
    monkeypatch.setattr(worker, "run_scan", forbidden_run)
    monkeypatch.setattr(worker, "_load_broker_result", load_result)
    monkeypatch.setattr(worker, "persist_result_artifact", persist_result)
    monkeypatch.setattr(worker, "update_scan_progress", no_progress)
    monkeypatch.setattr(worker, "send_heartbeats", lambda *args, **kwargs: None)
    monkeypatch.setattr(worker.parallel_scan, "reconcile_parallel_parent", no_merge)

    asyncio.run(
        worker.process_scan_shard_job(
            {
                "job_id": "job-broker-ingest",
                "scan_id": "22222222-2222-4222-8222-222222222222",
                "parent_scan_id": "55555555-5555-4555-8555-555555555555",
                "target_id": "33333333-3333-4333-8333-333333333333",
                "target": "https://example.test",
                "options": {
                    "scan_type": "smart",
                    "custom_endpoints": ["GET /bounded"],
                    "request_budget_mode": "enforce",
                    "custom_budget": {"request_max": 1},
                },
                "shard_label": "scope[0]",
                "shard_index": 0,
                "shard_count": 1,
                "_broker_result_id": "77777777-7777-4777-8777-777777777777",
                "_broker_lease_id": "88888888-8888-4888-8888-888888888888",
            }
        )
    )

    assert calls == {"load": 1, "run": 0, "persist": 1}
    assert not redis.pushed
    assert worker._parallel_shard_slot_key("55555555-5555-4555-8555-555555555555") not in redis.values
    assert any(mapping.get("status") == "completed" for _key, _args, mapping in redis.hashes)


def test_hydrate_ai_gate_options_loads_secrets_only_in_worker(monkeypatch):
    target_id = "00000000-0000-0000-0000-000000000001"
    profile_id = "00000000-0000-4000-8000-000000000002"
    monkeypatch.setattr(worker, "db_pool", _FakeCredentialPool())
    monkeypatch.setattr(
        worker,
        "_load_runtime_ai_settings",
        lambda: {
            "ai_url": "https://ai.example/v1/chat/completions",
            "ai_api_key": "runtime-ai-key",
            "ai_model": "model-a",
            "ai_model_fallback": "",
        },
    )

    async def validate(*_args, **_kwargs):
        return types.SimpleNamespace()

    class Resolver:
        @asynccontextmanager
        async def resolve(self, *_args, **_kwargs):
            yield types.SimpleNamespace(
                profile=types.SimpleNamespace(
                    profile_id=profile_id,
                    current_version=2,
                    auth_kind="bearer_token",
                    principal_slot="service",
                ),
                immediate_http=lambda: types.SimpleNamespace(
                    secret="runtime-target-secret",
                    username=None,
                    header_name=None,
                    custom_headers={},
                ),
            )

    monkeypatch.setattr(worker, "validate_worker_credential_authority", validate)
    monkeypatch.setattr(worker, "WorkerCredentialResolver", Resolver)

    options = {
        "run_kind": "ai_api",
        "ai_target_id": target_id,
        "ai_target": {
            "id": target_id,
            "endpoint_url": "https://example.test/chat",
            "credential_profile_ref": {
                "profile_id": profile_id,
                "profile_version": 2,
                "auth_kind": "bearer_token",
                "principal_slot": "service",
                "source": "credential_profiles",
            },
        },
        "credential_action_name": "ai_gate.scan",
        "approval_receipt_id": "00000000-0000-4000-8000-000000000003",
        "scope_receipt_id": "scope-1",
        "runtime_scope_guard": {"allowed_root_domains": ["example.test"]},
    }

    retained = None

    async def exercise():
        nonlocal retained
        async with worker._hydrate_ai_gate_options(
            options, "00000000-0000-4000-8000-000000000004"
        ) as hydrated:
            retained = hydrated
            assert hydrated["ai_target"]["credential"]["secret"] == "runtime-target-secret"
            assert "credential_profile_ref" not in hydrated["ai_target"]
            assert hydrated["ai_api_key"] == "runtime-ai-key"

    asyncio.run(exercise())

    assert retained is not None
    assert "credential" not in retained["ai_target"]


def test_hydrate_ai_gate_options_loads_principal_credentials_in_worker(monkeypatch):
    target_id = "00000000-0000-0000-0000-000000000001"
    profile_id = "00000000-0000-4000-8000-000000000010"
    monkeypatch.setattr(worker, "db_pool", _FakeCredentialPool())
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {})

    async def validate(*_args, **_kwargs):
        return types.SimpleNamespace()

    class Resolver:
        @asynccontextmanager
        async def resolve(self, *_args, **_kwargs):
            yield types.SimpleNamespace(
                profile=types.SimpleNamespace(
                    profile_id=profile_id,
                    current_version=4,
                    auth_kind="bearer_token",
                    principal_slot="secondary",
                ),
                immediate_http=lambda: types.SimpleNamespace(
                    secret="principal-runtime-secret",
                    username=None,
                    header_name=None,
                    custom_headers={},
                ),
            )

    monkeypatch.setattr(worker, "validate_worker_credential_authority", validate)
    monkeypatch.setattr(worker, "WorkerCredentialResolver", Resolver)

    options = {
        "run_kind": "ai_rag",
        "ai_target_id": target_id,
        "ai_target": {
            "id": target_id,
            "endpoint_url": "https://example.test/rag",
            "credential_profile_ref": None,
            "principal_refs": [
                {
                    "id": "00000000-0000-0000-0000-000000000010",
                    "label": "tenant-a-user",
                    "role": "attacker",
                    "credential_configured": True,
                    "credential_profile_ref": {
                        "profile_id": profile_id,
                        "profile_version": 4,
                        "auth_kind": "bearer_token",
                        "principal_slot": "secondary",
                        "source": "credential_profiles",
                    },
                }
            ],
        },
        "credential_action_name": "ai_gate.scan",
        "approval_receipt_id": "00000000-0000-4000-8000-000000000003",
        "scope_receipt_id": "scope-1",
        "runtime_scope_guard": {"allowed_root_domains": ["example.test"]},
    }

    async def exercise():
        async with worker._hydrate_ai_gate_options(
            options, "00000000-0000-4000-8000-000000000004"
        ) as hydrated:
            assert hydrated["ai_target"]["principals"][0]["credential"]["secret"] == "principal-runtime-secret"
            assert hydrated["ai_target"]["principals"][0]["role"] == "attacker"
            assert "principal_refs" not in hydrated["ai_target"]

    asyncio.run(exercise())


def test_hydrate_ai_gate_options_rejects_legacy_configured_refs():
    options = {
        "run_kind": "ai_api",
        "ai_target_id": "00000000-0000-0000-0000-000000000001",
        "ai_target": {
            "id": "00000000-0000-0000-0000-000000000001",
            "endpoint_url": "https://example.test/chat",
            "credential_ref": {
                "ai_target_id": "00000000-0000-0000-0000-000000000001",
                "configured": True,
            },
        },
    }

    async def exercise():
        with pytest.raises(
            worker.CredentialResolutionError, match="legacy AI Gate credential"
        ):
            async with worker._hydrate_ai_gate_options(
                options, "00000000-0000-4000-8000-000000000004"
            ):
                pass

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("kind", "expected_kind", "expected"),
    [
        (
            "authorization_header",
            "custom_header",
            {"header_name": "Authorization", "secret": "Bearer opaque"},
        ),
        ("bearer_token", "bearer", {"secret": "opaque"}),
        (
            "api_key_header",
            "api_key_header",
            {"header_name": "X-API-Key", "secret": "opaque"},
        ),
        ("cookie", "cookie", {"secret": "sid=opaque"}),
        ("basic_auth", "basic_auth", {"secret": "analyst:opaque"}),
        (
            "custom_headers",
            "multi_header",
            {"metadata_json": {"headers": [{"name": "X-Key", "value": "opaque"}]}},
        ),
        (
            "query_parameter",
            "query_param",
            {"header_name": "access_key", "secret": "opaque"},
        ),
    ],
)
def test_ai_gate_generic_credential_projection_preserves_legacy_adapter_semantics(
    kind, expected_kind, expected,
):
    material = types.SimpleNamespace(
        secret=(
            "Bearer opaque"
            if kind == "authorization_header"
            else "sid=opaque"
            if kind == "cookie"
            else "opaque"
        ),
        username="analyst" if kind == "basic_auth" else None,
        header_name="X-API-Key" if kind == "api_key_header" else None,
        custom_headers={"X-Key": "opaque"} if kind == "custom_headers" else {},
    )
    resolved = types.SimpleNamespace(
        profile=types.SimpleNamespace(auth_kind=kind),
        immediate_http=lambda: material,
        query_parameter=lambda: types.SimpleNamespace(name="access_key", value="opaque"),
    )

    projected = worker._ai_gate_runtime_credential(resolved)

    assert projected["auth_kind"] == expected_kind
    for key, value in expected.items():
        assert projected[key] == value


def test_finalize_ai_finding_retest_marks_reproduced_finding(monkeypatch):
    pool = _FakeFinalizePool()
    monkeypatch.setattr(worker, "db_pool", pool)
    verification_id = "00000000-0000-0000-0000-000000000002"
    finding_id = "00000000-0000-0000-0000-000000000003"

    asyncio.run(worker.finalize_ai_finding_retest(
        options={
            "ai_finding_retest": {
                "verification_id": verification_id,
                "finding_id": finding_id,
                "mode": "same_probe",
                "probe_id": "smoke.prompt-leakage",
                "probe_family": "prompt_leakage",
            }
        },
        result={
            "findings": [
                {
                    "confidence": 0.93,
                    "evidence": {"probe_id": "smoke.prompt-leakage", "probe_family": "prompt_leakage"},
                }
            ],
            "ai_gate": {"errors": [], "transcripts": [], "decision": {"decision": "block"}},
        },
        scan_id="00000000-0000-0000-0000-000000000004",
        completed_at=datetime.now(timezone.utc),
        error=None,
    ))

    verification_update = pool.conn.executions[0][1]
    finding_update = pool.conn.executions[1][1]
    assert verification_update[0] == "completed"
    assert verification_update[1] == "still_vulnerable"
    assert verification_update[2] == "exploited"
    assert finding_update[1] == "exploited"


def test_run_scan_rejects_monolithic_deterministic_execution():
    with pytest.raises(
        ValueError,
        match="monolithic deterministic Scan execution has been removed",
    ):
        asyncio.run(worker.run_scan("https://example.com", {"scan_type": "standard"}))


def test_agent_scanner_tool_job_rebuilds_argv_and_publishes_settlement(monkeypatch):
    proxy_options = {}

    class _PinnedProxy:
        def __init__(self, **kwargs):
            proxy_options.update(kwargs)
            self.limit_exceeded = asyncio.Event()
            self.connection_attempts = 0
            self.connections_opened = 0
            self.connections_rejected = 0
            self.upstream_connection_attempts = 0
            self.address_attempts = {}
            self.address_connections = {}
            self.bytes_to_target = 0
            self.bytes_from_target = 0

        @property
        def proxy_url(self): return "socks5://127.0.0.1:41000"
        async def start(self): return self
        async def close(self): return None

    monkeypatch.setattr(worker, "PinnedSocksProxy", _PinnedProxy)
    class _Redis:
        def __init__(self):
            self.values = {}
            self.hashes = []

        def exists(self, _key):
            return False

        def set(self, key, value, ex=None):
            self.values[key] = value

        def hset(self, key, mapping=None):
            self.hashes.append((key, dict(mapping or {})))

        def expire(self, _key, _ttl):
            return True

        def delete(self, key):
            self.values.pop(key, None)

    class _Process:
        pid = 12345

        def __init__(self):
            self.returncode = 0
            self.stdout = asyncio.StreamReader()
            self.stderr = asyncio.StreamReader()
            self.stdout.feed_data(json.dumps({
                "url": "https://example.test/admin?token=secret",
                "status_code": 200,
            }).encode())
            self.stdout.feed_eof()
            self.stderr.feed_eof()

        async def wait(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

    redis = _Redis()
    captured = {}

    async def _exec(*cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return _Process()

    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _exec)
    asyncio.run(worker.process_agent_scanner_tool_job({
        "job_id": "agent-job-1",
        "type": "agent_scanner_tool",
        "tool_name": "httpx",
        "registered_target": "https://example.test",
        "execution_target": "https://example.test/admin?token=secret",
        "scanner_options": {},
        "timeout_ms": 30_000,
        "pinned_address": "203.0.113.7",
        "authorized_addresses": ["203.0.113.7"],
        "_reserved_budget": {"http_requests": 1, "tool_wall_seconds": 30},
    }))

    assert captured["cmd"][0] == "httpx"
    assert "-json" in captured["cmd"] and "-silent" in captured["cmd"]
    assert "-no-stdin" in captured["cmd"]
    assert captured["kwargs"]["stdin"] is asyncio.subprocess.DEVNULL
    assert captured["kwargs"]["start_new_session"] is True
    assert "https://example.test/admin?token=secret" in captured["cmd"]
    assert "-http-proxy" in captured["cmd"]
    assert "socks5://127.0.0.1:41000" in captured["cmd"]
    assert proxy_options["pinned_addresses"] == ["203.0.113.7"]
    result = json.loads(redis.values["agent_tool_result:agent-job-1"])
    assert result["network_binding"] == "hostname_preserving_pinned_socks5"
    assert result["status"] == "success"
    assert result["settlement"]["mode"] == "exact"
    assert result["settlement"]["actual"] == 1
    assert "secret" not in json.dumps(result)


def test_ffuf_worker_materializes_exact_owner_only_wordlist(tmp_path, monkeypatch):
    source = tmp_path / "source.txt"
    source.write_text("admin\n# comment\napi\nadmin\nhealth\n", encoding="utf-8")
    monkeypatch.setitem(
        worker.agent_tools._AGENT_FFUF_WORDLISTS, "common", str(source),
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)

    path, count = worker._materialize_bounded_ffuf_wordlist(
        options={"wordlist": "common"},
        reservation={"http_requests": 2},
        scratch_dir=str(scratch),
    )

    materialized = Path(path)
    assert count == 2
    assert materialized.read_text(encoding="utf-8") == "admin\napi\n"
    assert materialized.stat().st_mode & 0o777 == 0o600


def test_nuclei_request_accounting_uses_stderr_stats_without_exposing_them():
    stats = b'noise\n{"duration":"0:01:35","requests":"1369","templates":"1183"}\n'
    settlement = worker._agent_scanner_request_settlement("nuclei", "", stats)
    assert settlement == {
        "mode": "exact",
        "actual": 1369,
        "observed_minimum": 1369,
        "source": "scanner_counter",
    }
    assert worker._agent_scanner_request_settlement("katana", "", stats)["mode"] == "unavailable"


def test_agent_tool_worker_reports_the_complete_isolated_arsenal(monkeypatch):
    monkeypatch.setattr(worker, "AGENT_TOOL_ONLY_WORKER", True)
    monkeypatch.setattr(worker, "DEVICE_ONLY_WORKER", False)
    monkeypatch.setattr(worker.shutil, "which", lambda command: f"/opt/tools/{command}")
    monkeypatch.setattr(worker, "_worker_build_hostname", lambda: "agent-worker")
    monkeypatch.setattr(worker, "_worker_build_fingerprint", lambda: "fingerprint")
    monkeypatch.setattr(worker, "_published_scanner_version", lambda: "build")
    monkeypatch.setattr(worker, "published_scanner_version", lambda value: value)

    hostname, raw = worker._worker_build_report_payload()
    report = json.loads(raw)
    assert hostname == "agent-worker"
    assert report["worker_kind"] == "agent_tool"
    assert set(worker.agent_tools.RUN_TOOL_NAMES).issubset(report["tools"])


def test_agent_scanner_tool_job_refuses_cross_host_without_spawning(monkeypatch):
    class _Redis:
        def __init__(self):
            self.values = {}

        def set(self, key, value, ex=None):
            self.values[key] = value

        def hset(self, *_args, **_kwargs):
            return True

        def expire(self, *_args):
            return True

        def delete(self, *_args):
            return True

    redis = _Redis()

    async def _must_not_spawn(*_args, **_kwargs):
        raise AssertionError("cross-host queue payload must fail before spawn")

    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _must_not_spawn)
    asyncio.run(worker.process_agent_scanner_tool_job({
        "job_id": "agent-job-2",
        "tool_name": "httpx",
        "registered_target": "https://example.test",
        "execution_target": "https://evil.test/",
        "scanner_options": {},
    }))

    result = json.loads(redis.values["agent_tool_result:agent-job-2"])
    assert result["status"] == "failed"
    assert result["settlement"] == {
        "mode": "exact", "actual": 0, "observed_minimum": 0, "source": "not_executed"
    }


def test_agent_scanner_tool_streams_and_fails_closed_at_output_limit(monkeypatch):
    class _PinnedProxy:
        def __init__(self, **_kwargs):
            self.limit_exceeded = asyncio.Event()
            self.connection_attempts = 0
            self.connections_opened = 0
            self.connections_rejected = 0
            self.upstream_connection_attempts = 0
            self.address_attempts = {}
            self.address_connections = {}
            self.bytes_to_target = 0
            self.bytes_from_target = 0

        @property
        def proxy_url(self): return "socks5://127.0.0.1:41000"
        async def start(self): return self
        async def close(self): return None

    monkeypatch.setattr(worker, "PinnedSocksProxy", _PinnedProxy)
    class _Redis:
        def __init__(self):
            self.values = {}

        def exists(self, _key): return False
        def set(self, key, value, ex=None): self.values[key] = value
        def hset(self, *_args, **_kwargs): return True
        def expire(self, *_args): return True
        def delete(self, *_args): return True

    class _Process:
        pid = 12346

        def __init__(self):
            self.returncode = 0
            self.stdout = asyncio.StreamReader()
            self.stderr = asyncio.StreamReader()
            self.stdout.feed_data(b"X" * 4096)
            self.stdout.feed_eof()
            self.stderr.feed_eof()

        async def wait(self): return self.returncode
        def kill(self): self.returncode = -9

    async def _exec(*_cmd, **_kwargs): return _Process()

    redis = _Redis()
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "_AGENT_TOOL_OUTPUT_BYTES", 128)
    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _exec)
    asyncio.run(worker.process_agent_scanner_tool_job({
        "job_id": "agent-job-output-limit",
        "type": "agent_scanner_tool",
        "tool_name": "httpx",
        "registered_target": "https://example.test",
        "execution_target": "https://example.test/",
        "scanner_options": {},
        "timeout_ms": 30_000,
        "pinned_address": "203.0.113.7",
        "authorized_addresses": ["203.0.113.7"],
        "_reserved_budget": {"http_requests": 1, "tool_wall_seconds": 30},
    }))

    result = json.loads(redis.values["agent_tool_result:agent-job-output-limit"])
    assert result["status"] == "failed"
    assert result["error"] == "output_limit_exceeded"
    assert sum(len(line) for line in result["output_lines"]) <= 128


class _CandidateProofConn:
    def __init__(self, locus, contract_id):
        self.locus = locus
        self.contract_id = contract_id

    async def fetchrow(self, _query, *_args):
        return {"canonical_locus": self.locus, "verifier_contract_id": self.contract_id}


class _CandidateProofPool:
    def __init__(self, locus, contract_id):
        self.conn = _CandidateProofConn(locus, contract_id)

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *_args):
        return False


def test_device_service_candidate_requires_open_probe_and_deny_policy(monkeypatch):
    candidate_id = "11111111-1111-4111-8111-111111111110"

    class _ServiceCandidateConn:
        def __init__(self):
            self.calls = 0

        async def fetchrow(self, _query, *_args):
            self.calls += 1
            if self.calls == 1:
                return {
                    "canonical_locus": {"transport": "tcp", "port": 3000},
                    "verifier_contract_id": "device.service_exposure",
                }
            return {
                "state": "open",
                "service_name": "http",
                "product": "",
                "version": "",
                "cpe": None,
                "policy_disposition": "deny",
                "policy_reason": "Test policy denies cleartext management.",
            }

    class _ServiceCandidatePool:
        def __init__(self):
            self.conn = _ServiceCandidateConn()

        def acquire(self):
            return self

        async def __aenter__(self):
            return self.conn

        async def __aexit__(self, *_args):
            return False

    monkeypatch.setattr(worker, "db_pool", _ServiceCandidatePool())
    result = {
        "device_probe": {
            "transport": "tcp",
            "port": 3000,
            "observation": {"state": "open", "complete": True},
            "verification": {"verdict": "satisfied"},
            "safety": {"halted": False},
        },
        "findings": [],
    }
    settlement = asyncio.run(worker.prepare_device_candidate_probe_result(
        result=result,
        options={
            "candidate_id": candidate_id,
            "proof_contract_id": "device.service_exposure",
        },
        device_target_id="22222222-2222-4222-8222-222222222222",
        target="tv.example.test",
    ))

    assert settlement["status"] == "verified"
    assert settlement["proof"]["promotable"] is True
    assert result["findings"][-1]["tool"] == "device_candidate_verifier"
    assert result["findings"][-1]["evidence"]["candidate_id"] == candidate_id


def test_device_tls_candidate_requires_fresh_strict_identity_failure(monkeypatch):
    candidate_id = "11111111-1111-4111-8111-111111111111"
    monkeypatch.setattr(worker, "db_pool", _CandidateProofPool(
        {"scheme": "https", "port": 8443}, "device.tls",
    ))
    result = {
        "device_posture": {
            "web_dast_children": {"children": [{
                "origin": "https://tv.example.test:8443",
                "tls_assessment": {"trusted": False, "verification_error": "unknown CA"},
            }]},
        },
        "findings": [],
    }
    settlement = asyncio.run(worker.prepare_device_candidate_posture_result(
        result=result,
        options={"candidate_id": candidate_id, "proof_contract_id": "device.tls"},
        device_target_id="22222222-2222-4222-8222-222222222222",
        target="tv.example.test",
    ))
    assert settlement["status"] == "verified"
    assert settlement["proof"]["family"] == "device_tls"
    assert result["findings"][-1]["tool"] == "device_candidate_verifier"


def test_device_auth_candidate_requires_bound_negative_control(monkeypatch):
    candidate_id = "11111111-1111-4111-8111-111111111112"
    monkeypatch.setattr(worker, "db_pool", _CandidateProofPool(
        {"collection_id": "collection-1", "request_id": "request-1"},
        "device.auth_bypass",
    ))
    result = {"device_posture": {}, "findings": [{
        "tool": "device_request_dast",
        "url": "https://tv.example.test/api/private",
        "evidence": {
            "collection_id": "collection-1", "request_id": "request-1",
            "authenticated_status": 200, "anonymous_status": 200,
            "response_match": True,
            "authenticated_body_sha256": "a" * 64,
            "anonymous_body_sha256": "a" * 64,
            "negative_control_status": 404,
            "negative_control_differs": True,
            "generic_response_shell": False,
        },
    }]}
    settlement = asyncio.run(worker.prepare_device_candidate_posture_result(
        result=result,
        options={"candidate_id": candidate_id, "proof_contract_id": "device.auth_bypass"},
        device_target_id="22222222-2222-4222-8222-222222222222",
        target="tv.example.test",
    ))
    assert settlement["status"] == "verified"
    assert settlement["proof"]["proof_basis"] == "authenticated_anonymous_negative_control"


def test_device_ssh_candidate_requires_pin_negotiation_and_policy_violation(monkeypatch):
    candidate_id = "11111111-1111-4111-8111-111111111113"
    pinned = "SHA256:" + "a" * 43
    monkeypatch.setattr(worker, "db_pool", _CandidateProofPool(
        {"transport": "tcp", "port": 22}, "device.ssh_posture",
    ))
    result = {"device_posture": {"services": [{
        "transport": "tcp", "port": 22, "policy_disposition": "require",
        "policy_reason": "SSH negotiated a weak cryptographic algorithm.",
        "ssh": {
            "scan_completed": True,
            "host_key": {"fingerprint_sha256": pinned},
            "negotiated_algorithms": {"cipher_in": "3des-cbc"},
            "weak_algorithms": ["cipher:3des-cbc"],
        },
    }]}, "findings": []}
    settlement = asyncio.run(worker.prepare_device_candidate_posture_result(
        result=result,
        options={
            "candidate_id": candidate_id,
            "proof_contract_id": "device.ssh_posture",
            "expected_ssh_host_keys": {"22": pinned},
        },
        device_target_id="22222222-2222-4222-8222-222222222222",
        target="tv.example.test",
    ))
    assert settlement["status"] == "verified"
    assert settlement["proof"]["family"] == "device_ssh_posture"


def test_nonpromoted_device_candidate_settlement_is_durable():
    verification_id = uuid.uuid4()

    class _Conn:
        def __init__(self):
            self.executed = []

        async def fetchval(self, query, *_args):
            assert "INSERT INTO finding_verifications" in query
            return verification_id

        async def execute(self, query, *args):
            self.executed.append((query, args))
            return "OK"

    conn = _Conn()
    proof = {
        "family": "device_tls",
        "contract_id": "device.tls",
        "contract_version": "1.0.0",
        "proof_basis": "strict_tls_handshake",
        "verdict": "refuted",
    }
    result = asyncio.run(worker.persist_device_candidate_settlement(
        conn,
        scan_id="33333333-3333-4333-8333-333333333333",
        device_target_id="22222222-2222-4222-8222-222222222222",
        settlement={
            "candidate_id": "11111111-1111-4111-8111-111111111111",
            "status": "refuted",
            "proof": proof,
            "gate_reason": "strict handshake succeeded",
        },
    ))

    assert result == verification_id
    assert any("INSERT INTO evidence_instances" in query for query, _ in conn.executed)
    assert any("latest_verification_id" in query for query, _ in conn.executed)
    candidate_update = next(args for query, args in conn.executed if "latest_verification_id" in query)
    assert candidate_update[3] == "33333333-3333-4333-8333-333333333333"


def test_promoted_device_candidate_settlement_casts_scan_uuid_before_text_binding():
    class _Conn:
        def __init__(self):
            self.executed = []

        async def execute(self, query, *args):
            self.executed.append((query, args))
            return "OK"

    conn = _Conn()
    result = asyncio.run(worker.persist_device_candidate_settlement(
        conn,
        scan_id="33333333-3333-4333-8333-333333333333",
        device_target_id="22222222-2222-4222-8222-222222222222",
        settlement={
            "candidate_id": "11111111-1111-4111-8111-111111111111",
            "status": "verified",
            "proof": {"contract_id": "device.service_exposure", "verdict": "verified"},
        },
    ))

    assert result is None
    assert conn.executed[0][1][1] == "33333333-3333-4333-8333-333333333333"


def test_device_advisory_lifecycle_resolves_only_an_observed_stale_service(monkeypatch):
    prior_candidate_id = uuid.uuid4()

    class _Conn:
        def __init__(self):
            self.executed = []

        async def fetch(self, query, *_args):
            assert "family='device_firmware_advisory'" in query
            return [{
                "id": prior_candidate_id,
                "canonical_locus": {"transport": "tcp", "port": 443},
            }]

        async def execute(self, query, *args):
            self.executed.append((query, args))
            return "OK"

        async def fetchval(self, query, *_args):
            assert "UPDATE findings" in query
            return 1

    class _Pool:
        def __init__(self):
            self.conn = _Conn()

        def acquire(self):
            return self

        async def __aenter__(self):
            return self.conn

        async def __aexit__(self, *_args):
            return False

    pool = _Pool()
    monkeypatch.setattr(worker, "db_pool", pool)
    monkeypatch.setattr(worker.device_advisories, "load_verified_snapshot", lambda *_args: {
        "status": "available", "snapshot_sha256": "a" * 64,
        "generated_at": "2026-08-16T00:00:00Z", "advisories": [],
    })
    result = {"device_posture": {"services": [{
        "transport": "tcp", "port": 443, "state": "open",
        "service_name": "https", "product": "fixed-product", "version": "2.0",
        "cpe": "cpe:2.3:a:vendor:fixed-product:2.0:*:*:*:*:*:*:*",
    }]}, "findings": []}

    summary = asyncio.run(worker.correlate_device_advisory_lifecycle(
        result=result,
        device_target_id="22222222-2222-4222-8222-222222222222",
    ))

    assert summary["resolved_stale_matches"] == 1
    assert any("status='refuted'" in query for query, _ in pool.conn.executed)


def _advisory_conn_recording():
    class _Conn:
        def __init__(self):
            self.executed = []
            self.candidate_seq = 0

        async def fetch(self, query, *_args):
            return []

        async def fetchrow(self, query, *args):
            self.candidate_seq += 1
            return {"id": uuid.uuid4(), "status": "new",
                    "fingerprint": f"fp{self.candidate_seq}", "inserted": True}

        async def execute(self, query, *args):
            self.executed.append((query, args))
            return "OK"

        async def fetchval(self, query, *_args):
            return 0

    class _Pool:
        def __init__(self):
            self.conn = _Conn()

        def acquire(self):
            return self

        async def __aenter__(self):
            return self.conn

        async def __aexit__(self, *_args):
            return False

    return _Pool()


_HEARTBLEED_SNAPSHOT = {
    "status": "available", "snapshot_sha256": "b" * 64,
    "generated_at": "2026-08-16T00:00:00Z",
    "advisories": [{
        "cve": "CVE-2014-0160", "product": "openssl",
        "cpe": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        "version_end_excluding": "1.0.1g", "severity": "high",
        "title": "OpenSSL Heartbleed", "reference": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
    }],
}


def _openssl_ssh_service(version_line):
    return {
        "transport": "tcp", "port": 22, "state": "open", "service_name": "ssh",
        "product": "openssh", "version": "8.9", "cpe": "",
        "ssh": {"authentication_succeeded": True, "host_review": {
            "status": "ok",
            "bundles": [{"bundle": "software_packages", "stdout": version_line}],
        }},
    }


def test_authenticated_package_inventory_promotes_advisory(monkeypatch):
    monkeypatch.setattr(worker, "db_pool", _advisory_conn_recording())
    monkeypatch.setattr(worker, "_worker_build_fingerprint", lambda: "fingerprint")
    monkeypatch.setattr(worker.device_advisories, "load_verified_snapshot",
                        lambda *_a: dict(_HEARTBLEED_SNAPSHOT))
    result = {"device_posture": {"services": [_openssl_ssh_service("openssl 1.0.1f\n")]}, "findings": []}
    summary = asyncio.run(worker.correlate_device_advisory_lifecycle(
        result=result, device_target_id="33333333-3333-4333-8333-333333333333",
    ))
    assert summary["authenticated_packages_evaluated"] >= 1
    assert summary["exact_matches"] == 1
    findings = result["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["verified"] is True and finding["proof_state"] == "verified"
    assert finding["proof_contract_v2"]["reexecution"]["performed"] is True
    assert "CVE-2014-0160" in finding["title"]


def test_authenticated_package_fixed_version_does_not_promote(monkeypatch):
    monkeypatch.setattr(worker, "db_pool", _advisory_conn_recording())
    monkeypatch.setattr(worker, "_worker_build_fingerprint", lambda: "fingerprint")
    monkeypatch.setattr(worker.device_advisories, "load_verified_snapshot",
                        lambda *_a: dict(_HEARTBLEED_SNAPSHOT))
    # 1.0.1g is the fixed version (end_excluding), so it is NOT affected -> no finding.
    result = {"device_posture": {"services": [_openssl_ssh_service("openssl 1.0.1g\n")]}, "findings": []}
    summary = asyncio.run(worker.correlate_device_advisory_lifecycle(
        result=result, device_target_id="44444444-4444-4444-8444-444444444444",
    ))
    assert summary["exact_matches"] == 0
    assert result["findings"] == []


def test_fingerprint_only_openssl_does_not_promote(monkeypatch):
    monkeypatch.setattr(worker, "db_pool", _advisory_conn_recording())
    monkeypatch.setattr(worker, "_worker_build_fingerprint", lambda: "fingerprint")
    monkeypatch.setattr(worker.device_advisories, "load_verified_snapshot",
                        lambda *_a: dict(_HEARTBLEED_SNAPSHOT))
    # Same vulnerable version but only a network fingerprint (no authenticated inventory).
    result = {"device_posture": {"services": [{
        "transport": "tcp", "port": 443, "state": "open", "service_name": "https",
        "product": "openssl", "version": "1.0.1f",
        "cpe": "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
    }]}, "findings": []}
    summary = asyncio.run(worker.correlate_device_advisory_lifecycle(
        result=result, device_target_id="55555555-5555-4555-8555-555555555555",
    ))
    assert summary["exact_matches"] == 0
    assert result["findings"] == []


def test_device_agent_auto_verify_is_bounded_and_logged_at_run_completion():
    api = (Path(__file__).resolve().parents[1] / "api" / "api.py").read_text()
    reply = api[api.index('@app.post("/device-agent/session/{run_id}/reply")'):]
    reply = reply[:reply.index('@app.post("/device-agent/session/{run_id}/cancel")')]
    helper = api[api.index("async def _device_agent_auto_verify"):]
    helper = helper[:helper.index("async def _record_device_agent_action")]

    assert "_device_agent_auto_verify(" in reply
    assert '"auto_verified"' in reply
    assert "_DEVICE_AGENT_AUTO_VERIFY_LIMIT = 6" in api
    assert "_DEVICE_AGENT_AUTO_VERIFY_CONTRACTS" in api
    for contract in ("device.service_exposure", "device.tls", "device.ssh_posture", "device.auth_bypass"):
        assert contract in helper or contract in api[api.index("_DEVICE_AGENT_AUTO_VERIFY_CONTRACTS"):][:400]
    assert "control_authorization_requires_session_bound_state_changing_request" in helper
    assert "device_intel_" in helper
    assert "fragility_budget_exhausted" in helper
    assert "auto_verify_limit_reached" in helper
    assert "resolve_local_intel" in helper
    assert "_device_verify_candidate_tool(" in helper
    assert "candidate_not_open_for_verification" in helper


def test_device_control_authorization_executor_replaces_the_hard_block():
    api = (Path(__file__).resolve().parents[1] / "api" / "api.py").read_text()
    verifier = api[api.index("async def _device_control_authorization_blocked"):]
    verifier = verifier[:verifier.index("_DEVICE_AGENT_AUTO_VERIFY_LIMIT")]
    dispatch = api[api.index("async def _device_verify_candidate_tool"):]
    dispatch = dispatch[:dispatch.index("async def _device_control_authorization_blocked")]

    assert api.index("async def _verify_device_control_authorization_candidate") < api.index(
        "async def _record_device_agent_action"
    )
    assert "_verify_device_control_authorization_candidate(" in dispatch
    assert "exact_before_after_cleanup_contract_unavailable" not in api

    assert "control_authorization_precondition_gaps" in verifier
    assert "_device_control_authorization_blocked" in verifier
    assert "missing_preconditions" in verifier
    assert '"unauthorized_rejected"' in verifier
    assert '"unauthenticated_control_accepted"' in verifier
    assert "_device_strip_credential_headers" in verifier
    assert "_device_request_pinned_control_http" in verifier
    assert "exact_strict_inverse_cleanup_request_not_bound" in verifier
    assert "cleanup_restored_exact_pre_state" in verifier
    assert "control_state_transition" in verifier
    assert "'CWE-862'" in verifier
    assert "'high'" in verifier
    assert "before" in verifier and '"after_state"' in verifier
    assert '"state_unchanged"' in verifier
    assert "credentials_stripped_for_replay" in verifier


def test_device_http_request_is_pinned_bounded_and_rate_limited():
    api = (Path(__file__).resolve().parents[1] / "api" / "api.py").read_text()
    executor = api[api.index("async def _execute_device_capability_operation"):]
    executor = executor[:executor.index("async def _device_verify_candidate_tool")]
    branch = executor[executor.index('if name == "device_http_request":'):]
    branch = branch[:branch.index('if name == "verify_service_state":')]

    assert "observe_only cannot send device HTTP requests" in branch
    assert "reserve_device_http_attempt" in branch
    assert branch.index("reserve_device_http_attempt") < branch.index("_device_request_pinned_http")
    assert "_device_confirmed_web_origins" in branch
    assert "_device_request_pinned_http" in branch
    assert '"redirects_followed": False' in branch
    assert "body_sha256" in branch and "body_preview" in branch
    assert "_device_public_response_headers" in branch
    assert "_device_agent_add_evidence" in branch


























def test_standalone_scan_rate_reservation_rejects_legacy_authority():
    from scan.worker_contract import WorkerScanContractError

    for legacy_options in (
        {"scan_type": "quick"},
        {"scan_type": "smart", "budget_profile": "thorough"},
        {"scan_type": "smart", "custom_budget": {"active_max_endpoints": 1234}},
        {
            "scan_type": "standard",
            "custom_endpoints": ["GET /a", "POST /b json:{\"x\":1}"],
        },
    ):
        with pytest.raises(
            WorkerScanContractError,
            match="digest-less deterministic Scan execution has been removed",
        ):
            worker._standalone_scan_rate_reservation_amount(legacy_options)


def test_standalone_enforcing_request_budget_requires_canonical_plan():
    from scan.worker_contract import WorkerScanContractError

    with pytest.raises(
        WorkerScanContractError,
        match="digest-less deterministic Scan execution has been removed",
    ):
        worker._standalone_scan_rate_reservation_amount({
            "scan_type": "smart",
            "request_budget_mode": "enforce",
            "custom_budget": {"request_max": 77},
        })


def test_canonical_rate_reservation_uses_immutable_plan_not_legacy_mode(monkeypatch):
    budget = types.SimpleNamespace(max_http_requests=77, max_endpoints=13)
    policy = types.SimpleNamespace(active_testing=True)
    admission = types.SimpleNamespace(canonical=True, plan=types.SimpleNamespace(
        budget=budget,
        policy=policy,
    ))
    monkeypatch.setattr(
        worker,
        "prepare_worker_dispatch",
        lambda options: (dict(options), admission),
    )
    assert worker._standalone_scan_rate_reservation_amount({
        "request_budget_mode": "enforce",
    }) == 77
    assert worker._standalone_scan_rate_reservation_amount({
        "request_budget_mode": "off",
    }) == 13
    assert worker._standalone_scan_rate_reservation_amount({
        "request_budget_mode": "off",
        "custom_endpoints": [f"GET /{index}" for index in range(20)],
    }) == 13


def test_active_endpoint_attempts_from_report_filters_valid_entries():
    attempts = worker._active_endpoint_attempts_from_report(
        {
            "active_checks": {
                "endpoint_attempt_schema_version": "active_endpoint_attempt_v1",
                "endpoint_attempts": [
                    {"custom_endpoint": "GET /a?id=1", "status": "completed"},
                    {"status": "completed"},
                    "not-a-dict",
                ]
            }
        }
    )

    assert len(attempts) == 1
    assert attempts[0]["custom_endpoint"] == "GET /a?id=1"
    assert attempts[0]["schema_version"] == "active_endpoint_attempt_v1"


def test_active_endpoint_telemetry_present_for_empty_attempt_list():
    report = {"active_checks": {
        "endpoint_attempt_schema_version": "active_endpoint_attempt_v1",
        "per_endpoint_telemetry": True,
        "endpoint_attempts": [],
    }}

    assert worker._active_endpoint_telemetry_present(report) is True
    assert worker._active_endpoint_attempts_from_report(report) == []


def test_active_endpoint_telemetry_rejects_unknown_schema():
    report = {"active_checks": {
        "endpoint_attempt_schema_version": "active_endpoint_attempt_v99",
        "per_endpoint_telemetry": True,
        "endpoint_attempts": [{"custom_endpoint": "GET /a", "status": "completed"}],
    }}

    assert worker._active_endpoint_telemetry_present(report) is False
    assert worker._active_endpoint_attempts_from_report(report) == []


def test_ledger_status_from_endpoint_attempt_maps_time_budget_to_timeout():
    status, summary = worker._ledger_status_from_endpoint_attempt(
        {
            "custom_endpoint": "GET /a?id=1",
            "status": "partial",
            "budget_exhausted_reason": "time_budget",
        }
    )

    assert status == "timeout"
    assert summary == "time_budget"


def test_ledger_status_preserves_block_cancel_and_error_outcomes():
    assert worker._ledger_status_from_endpoint_attempt({
        "status": "skipped", "skip_reason": "auth_missing",
    }) == ("auth_missing", "auth_missing")
    assert worker._ledger_status_from_endpoint_attempt({
        "status": "cancelled", "cancelled": True,
    }) == ("partial", "cancelled")
    assert worker._ledger_status_from_endpoint_attempt({
        "status": "failed", "error_summary": "connection reset",
    }) == ("error", "connection reset")


def test_record_endpoint_telemetry_attempts_uses_per_endpoint_counts(monkeypatch):
    calls = {}
    endpoint_id = "11111111-1111-1111-1111-111111111111"

    async def fake_endpoint_ids_for_worklist(conn, target_id, worklist, *, auth_state, limit=20000):
        calls["resolved"] = {
            "target_id": target_id,
            "worklist": worklist,
            "auth_state": auth_state,
        }
        return [endpoint_id]

    async def fake_record_endpoint_attempts(conn, endpoint_ids, **kwargs):
        calls["record"] = {"endpoint_ids": endpoint_ids, **kwargs}
        return len(endpoint_ids)

    monkeypatch.setattr(worker.asm_inventory, "endpoint_ids_for_worklist", fake_endpoint_ids_for_worklist)
    monkeypatch.setattr(worker.asm_inventory, "record_endpoint_attempts", fake_record_endpoint_attempts)

    result = asyncio.run(
        worker._record_endpoint_telemetry_attempts(
            object(),
            target_id="target-1",
            attempts=[
                {
                    "custom_endpoint": "GET /a?id=1",
                    "status": "completed",
                    "attempted_params_count": 1,
                    "completed_params_count": 1,
                }
            ],
            scan_id="scan-1",
            campaign_id="campaign-1",
            auth_state="user1",
            source="test",
        )
    )

    assert result["written"] == 1
    assert result["completed_ids"] == [endpoint_id]
    assert calls["resolved"] == {
        "target_id": "target-1",
        "worklist": ["GET /a?id=1"],
        "auth_state": "user1",
    }
    assert calls["record"]["status"] == "completed"
    assert calls["record"]["attempted_params_count"] == 1
    assert calls["record"]["completed_params_count"] == 1
    assert calls["record"]["scanner_telemetry_json"]["per_endpoint_telemetry"] is True


def test_apply_campaign_coverage_rollup_preserves_assignment_context():
    merged = {
        "smart_coverage": {
            "endpoints": {
                "discovered": 3,
                "tested": 2,
                "coverage": 0.667,
                "basis": "assigned_custom_endpoints",
            },
            "aggregated_from_shards": 2,
        }
    }
    campaign = {
        "total": 3,
        "attempted": 3,
        "completed": 1,
        "tested": 1,
        "untested": 0,
        "partial": 2,
        "auth_blocked": 0,
        "rate_limited": 0,
        "error": 0,
        "coverage": 0.333,
        "basis": "campaign_attempt_ledger",
    }

    assert worker._apply_campaign_coverage_rollup(merged, campaign) is True

    smart = merged["smart_coverage"]
    assert smart["coverage_basis"] == "attempt_ledger"
    assert smart["endpoints"] == campaign
    assert smart["endpoint_assignment_rollup"]["basis"] == "assigned_custom_endpoints"
    assert smart["aggregated_from_shards"] == 2


def test_apply_campaign_coverage_rollup_ignores_empty_attempts():
    merged = {"smart_coverage": {"endpoints": {"basis": "assigned_custom_endpoints"}}}

    assert worker._apply_campaign_coverage_rollup(merged, {"attempted": 0}) is False
    assert merged["smart_coverage"]["endpoints"]["basis"] == "assigned_custom_endpoints"


def test_scan_merge_all_failed_shards_sets_parent_error_message(monkeypatch):
    parent_id = "55555555-5555-5555-5555-555555555555"
    target_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
    now = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)

    class FakeMergeConn:
        def __init__(self):
            self.executions = []

        async def fetchrow(self, query, *args):
            assert args == (uuid.UUID(parent_id),)
            return {
                "target_id": target_id,
                "target_url": "https://example.test",
                "options": {"parallel_strategy": "coverage"},
                "scan_type": "smart",
                "created_at": now,
                "started_at": now,
                "job_id": "parent-job",
                "status": "running",
                "campaign_id": None,
            }

        async def fetch(self, query, *args):
            assert args == (uuid.UUID(parent_id),)
            return [
                {
                    "id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
                    "status": "failed",
                    "result": {
                        "target": "https://example.test",
                        "error": "Scanner produced no output (exit code 0)",
                        "failure_diagnostics": {"scanner_version": "test-build"},
                    },
                    "score": None,
                    "grade": None,
                    "findings_count": 0,
                    "shard_index": 0,
                    "options": {},
                    "started_at": now,
                    "completed_at": now,
                    "campaign_id": None,
                    "error_message": None,
                },
                {
                    "id": uuid.UUID("22222222-2222-2222-2222-222222222222"),
                    "status": "failed",
                    "result": {},
                    "score": None,
                    "grade": None,
                    "findings_count": 0,
                    "shard_index": 1,
                    "options": {},
                    "started_at": now,
                    "completed_at": now,
                    "campaign_id": None,
                    "error_message": "secondary failure",
                },
            ]

        async def execute(self, query, *args):
            self.executions.append((query, args))
            return "UPDATE 1"

    conn = FakeMergeConn()
    redis = _FakeJobRedis()
    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "save_result_file", lambda result, job_id: f"/tmp/{job_id}.json")

    asyncio.run(worker.process_scan_merge_job({"parent_scan_id": parent_id}))

    parent_updates = [
        args for query, args in conn.executions
        if "UPDATE scans SET status = $1" in query and "error_message = $9" in query
    ]
    assert len(parent_updates) == 1
    args = parent_updates[0]
    assert args[0] == "failed"
    assert args[7] == "failed"
    assert args[8] == (
        "All 2 shard(s) failed; merge had no completed shard. "
        "First failure (shard 0): Scanner produced no output (exit code 0)"
    )
    assert redis.hashes[-1][2]["status"] == "failed"
    assert redis.deleted == [worker.parallel_scan.shards_remaining_key(parent_id)]


def test_scan_plan_dynamic_request_uses_self_contained_broker_shards(monkeypatch):
    parent_id = "55555555-5555-5555-5555-555555555555"
    target_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
    campaign_id = uuid.UUID("44444444-4444-4444-4444-444444444444")
    endpoints = (
        "GET /api/a?id=1", "GET /api/b?id=1",
        "GET /api/c?id=1", "GET /api/d?id=1",
    )
    parent_job, parent_plan, options, queue_payload = _canonical_parallel_fixture(
        parent_id, target_id, custom_endpoints=endpoints,
    )
    options.update({
        "coverage_allocation": "dynamic",
        "coverage_dynamic_batch_size": 2,
        "coverage_per_shard_cap": 2,
    })
    conn = _FakePlanConn(parent_id, target_id, campaign_id, parent_plan)
    redis = _FakeJobRedis()

    monkeypatch.setattr(worker, "db_pool", _FakePlanPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)

    asyncio.run(
        worker.process_scan_plan_job(
            {
                "job_id": parent_job.job_id,
                "scan_id": parent_id,
                "target": "https://example.test",
                "options": options,
                "_canonical_queue_payload": queue_payload,
            }
        )
    )

    child_jobs = [json.loads(payload) for _, payload in redis.pushed]
    from scan.jobs import CanonicalScanJob
    canonical_children = [
        CanonicalScanJob.from_queue_payload(job) for job in child_jobs
    ]
    child_options = [json.loads(args[4]) for args in conn.inserted_children]
    assert len(child_jobs) == 3
    assert {job["type"] for job in child_jobs} == {worker.parallel_scan.SHARD_JOB_TYPE}
    assert canonical_children[0].shard.shard_label == "global-backbone"
    assert child_options[0]["parallel_backbone"] is True
    for job, persisted in zip(canonical_children[1:], child_options[1:], strict=True):
        assert job.shard.parent_scan_id == parent_id
        assert job.target.target_id == str(target_id)
        assert persisted["zero_rediscovery"] is True
        assert persisted["custom_budget"]["phase4_max_seconds"] == 0
        assert len(persisted["custom_endpoints"]) == 2
    assert redis.sets[0][0] == worker.parallel_scan.shards_remaining_key(parent_id)
    assert redis.sets[0][1] == 3
    parent_update = [
        args for query, args in conn.executions
        if "UPDATE scans SET status='running'" in query and "shard_count" in query
    ][0]
    parent_options = json.loads(parent_update[3])
    assert parent_options["parallel_strategy"] == "coverage"
    assert parent_options["coverage_allocation"] == "static"
    assert parent_options[worker.parallel_scan.PARALLEL_EXPECTED_SHARDS_KEY] == 3
    request_budgets = [
        job.shard.sub_budget.max_http_requests for job in canonical_children
    ]
    assert parent_options["parallel_planned_request_budget"] == sum(request_budgets)
    assert parent_options["parallel_backbone_request_budget"] == request_budgets[0]


def test_scan_plan_coverage_defaults_to_self_contained_allocation(monkeypatch):
    parent_id = "56565656-5656-5656-5656-565656565656"
    target_id = uuid.UUID("34343434-3434-3434-3434-343434343434")
    campaign_id = uuid.UUID("45454545-4545-4545-4545-454545454545")
    endpoints = (
        "GET /api/a?id=1", "GET /api/b?id=1",
        "GET /api/c?id=1", "GET /api/d?id=1",
    )
    parent_job, parent_plan, options, queue_payload = _canonical_parallel_fixture(
        parent_id, target_id, custom_endpoints=endpoints,
    )
    options.update({
        "coverage_dynamic_batch_size": 2,
        "coverage_per_shard_cap": 2,
    })
    conn = _FakePlanConn(parent_id, target_id, campaign_id, parent_plan)
    redis = _FakeJobRedis()
    monkeypatch.delenv("COVERAGE_ALLOCATION_DEFAULT", raising=False)
    monkeypatch.delenv("FULL_COVERAGE_ALLOCATION_DEFAULT", raising=False)

    monkeypatch.setattr(worker, "db_pool", _FakePlanPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)

    asyncio.run(
        worker.process_scan_plan_job(
            {
                "job_id": parent_job.job_id,
                "scan_id": parent_id,
                "target": "https://example.test",
                "options": options,
                "_canonical_queue_payload": queue_payload,
            }
        )
    )

    child_jobs = [json.loads(payload) for _, payload in redis.pushed]
    assert len(child_jobs) == 3
    assert {job["type"] for job in child_jobs} == {worker.parallel_scan.SHARD_JOB_TYPE}
    assert json.loads(conn.inserted_children[0][4])["parallel_backbone"] is True
    parent_update = [
        args for query, args in conn.executions
        if "UPDATE scans SET status='running'" in query and "shard_count" in query
    ][0]
    parent_options = json.loads(parent_update[3])
    assert parent_options["coverage_allocation"] == "static"


def test_scan_plan_coverage_family_uses_static_family_shards(monkeypatch):
    parent_id = "57575757-5757-5757-5757-575757575757"
    target_id = uuid.UUID("35353535-3535-3535-3535-353535353535")
    campaign_id = uuid.UUID("46464646-4646-4646-4646-464646464646")
    endpoints = (
        "GET /api/a?id=1", "GET /api/b?id=1",
        "GET /api/c?id=1", "GET /api/d?id=1",
    )
    parent_job, parent_plan, options, queue_payload = _canonical_parallel_fixture(
        parent_id,
        target_id,
        policy={
            "active_testing": True,
            "allow_state_changing_http": True,
        },
        strategy="coverage_family",
        custom_endpoints=endpoints,
    )
    options.update({
        "coverage_allocation": "static",
        "coverage_max_shards": 6,
        "coverage_per_shard_cap": 2,
    })
    conn = _FakePlanConn(parent_id, target_id, campaign_id, parent_plan)
    redis = _FakeJobRedis()

    monkeypatch.setattr(worker, "db_pool", _FakePlanPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)

    asyncio.run(
        worker.process_scan_plan_job(
            {
                "job_id": parent_job.job_id,
                "scan_id": parent_id,
                "target": "https://example.test",
                "options": options,
                "_canonical_queue_payload": queue_payload,
            }
        )
    )

    child_jobs = [json.loads(payload) for _, payload in redis.pushed]
    from scan.jobs import CanonicalScanJob
    canonical_children = [
        CanonicalScanJob.from_queue_payload(job) for job in child_jobs
    ]
    child_options = [json.loads(args[4]) for args in conn.inserted_children]
    assert len(child_jobs) == 7
    assert {job["type"] for job in child_jobs} == {worker.parallel_scan.SHARD_JOB_TYPE}
    assert canonical_children[0].shard.shard_label == "global-backbone"
    assert [job.shard.shard_label for job in canonical_children[1:]] == [
        "coverage[0]:broad",
        "coverage[0]:sqli",
        "coverage[0]:xss",
        "coverage[1]:broad",
        "coverage[1]:sqli",
        "coverage[1]:xss",
    ]
    assert child_options[2]["coverage_attempt_family"] == "sqli"
    assert child_options[3]["coverage_attempt_family"] == "xss"
    assert all(item["zero_rediscovery"] is True for item in child_options[1:])
    assert all("asm_check_family" not in item for item in child_options)
    parent_update = [
        args for query, args in conn.executions
        if "UPDATE scans SET status='running'" in query and "shard_count" in query
    ][0]
    parent_options = json.loads(parent_update[3])
    assert parent_options["parallel_strategy"] == "coverage_family"
    assert parent_options["coverage_allocation"] == "static"
    assert "campaign_id" not in parent_options


def test_scan_plan_coverage_family_dynamic_request_uses_self_contained_family_shards(monkeypatch):
    parent_id = "58585858-5858-5858-5858-585858585858"
    target_id = uuid.UUID("36363636-3636-3636-3636-363636363636")
    campaign_id = uuid.UUID("47474747-4747-4747-4747-474747474747")
    endpoints = (
        "GET /api/a?id=1", "GET /api/b?id=1",
        "GET /api/c?id=1", "GET /api/d?id=1",
    )
    parent_job, parent_plan, options, queue_payload = _canonical_parallel_fixture(
        parent_id,
        target_id,
        policy={
            "active_testing": True,
            "allow_state_changing_http": True,
        },
        strategy="coverage_family",
        custom_endpoints=endpoints,
    )
    options.update({
        "coverage_allocation": "dynamic",
        "coverage_dynamic_batch_size": 2,
        "coverage_dynamic_max_batches": 6,
        "coverage_per_shard_cap": 2,
        "coverage_max_shards": 6,
    })
    conn = _FakePlanConn(parent_id, target_id, campaign_id, parent_plan)
    redis = _FakeJobRedis()

    monkeypatch.setattr(worker, "db_pool", _FakePlanPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)

    asyncio.run(
        worker.process_scan_plan_job(
            {
                "job_id": parent_job.job_id,
                "scan_id": parent_id,
                "target": "https://example.test",
                "options": options,
                "_canonical_queue_payload": queue_payload,
            }
        )
    )

    child_jobs = [json.loads(payload) for _, payload in redis.pushed]
    from scan.jobs import CanonicalScanJob
    canonical_children = [
        CanonicalScanJob.from_queue_payload(job) for job in child_jobs
    ]
    child_options = [json.loads(args[4]) for args in conn.inserted_children]
    assert len(child_jobs) == 7
    assert {job["type"] for job in child_jobs} == {worker.parallel_scan.SHARD_JOB_TYPE}
    assert canonical_children[0].shard.shard_label == "global-backbone"
    assert [job.shard.shard_label for job in canonical_children[1:]] == [
        "coverage[0]:broad", "coverage[0]:sqli", "coverage[0]:xss",
        "coverage[1]:broad", "coverage[1]:sqli", "coverage[1]:xss",
    ]
    assert child_options[2]["coverage_attempt_family"] == "sqli"
    assert child_options[3]["coverage_attempt_family"] == "xss"
    assert all("asm_check_family" not in item for item in child_options)
    parent_update = [
        args for query, args in conn.executions
        if "UPDATE scans SET status='running'" in query and "shard_count" in query
    ][0]
    parent_options = json.loads(parent_update[3])
    assert parent_options["parallel_strategy"] == "coverage_family"
    assert parent_options["coverage_allocation"] == "static"
    assert parent_options["coverage_check_families"] == ["all", "sqli", "xss"]
    assert parent_options["coverage_expected_attempts"] == 12


def test_scan_plan_coverage_family_dynamic_respects_explicit_bola_focus(monkeypatch):
    parent_id = "59595959-5959-5959-5959-595959595959"
    target_id = uuid.UUID("37373737-3737-3737-3737-373737373737")
    campaign_id = uuid.UUID("48484848-4848-4848-4848-484848484848")
    endpoints = (
        "GET /api/a?id=1", "GET /api/b?id=1",
        "GET /api/c?id=1", "GET /api/d?id=1",
    )
    parent_job, parent_plan, options, queue_payload = _canonical_parallel_fixture(
        parent_id,
        target_id,
        policy={
            "active_testing": True,
            "allow_state_changing_http": True,
            "include_families": ["bola"],
        },
        strategy="coverage_family",
        custom_endpoints=endpoints,
    )
    options.update({
        "coverage_allocation": "dynamic",
        "coverage_dynamic_batch_size": 2,
        "coverage_dynamic_max_batches": 6,
        "coverage_per_shard_cap": 2,
        "exploit_depth": True,
    })
    conn = _FakePlanConn(parent_id, target_id, campaign_id, parent_plan)
    redis = _FakeJobRedis()

    monkeypatch.setattr(worker, "db_pool", _FakePlanPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)

    asyncio.run(
        worker.process_scan_plan_job(
            {
                "job_id": parent_job.job_id,
                "scan_id": parent_id,
                "target": "https://example.test",
                "options": options,
                "_canonical_queue_payload": queue_payload,
            }
        )
    )

    child_jobs = [json.loads(payload) for _, payload in redis.pushed]
    from scan.jobs import CanonicalScanJob
    canonical_children = [
        CanonicalScanJob.from_queue_payload(job) for job in child_jobs
    ]
    child_options = [json.loads(args[4]) for args in conn.inserted_children]
    assert len(child_jobs) == 3
    assert {job["type"] for job in child_jobs} == {worker.parallel_scan.SHARD_JOB_TYPE}
    assert canonical_children[0].shard.shard_label == "global-backbone"
    assert [job.shard.shard_label for job in canonical_children[1:]] == [
        "coverage[0]:bola", "coverage[1]:bola",
    ]
    assert all(
        item["coverage_attempt_family"] == "bola"
        for item in child_options[1:]
    )
    assert all("auth_header" not in item for item in child_options)
    assert all("user2_header" not in item for item in child_options)
    assert all(
        item["custom_budget"]["phase4_max_seconds"]
        == worker.parallel_scan.BOLA_DYNAMIC_PHASE4_SECONDS
        for item in child_options[1:]
    )
    parent_update = [
        args for query, args in conn.executions
        if "UPDATE scans SET status='running'" in query and "shard_count" in query
    ][0]
    parent_options = json.loads(parent_update[3])
    assert parent_options["parallel_strategy"] == "coverage_family"
    assert parent_options["coverage_allocation"] == "static"
    assert parent_options["coverage_check_families"] == ["bola"]
    assert parent_options["coverage_expected_attempts"] == 4


def test_exploit_batch_without_endpoint_telemetry_marks_partial_not_tested(monkeypatch):
    endpoint_id = "11111111-1111-1111-1111-111111111111"
    calls = {"mark_partial": [], "record": [], "reserved_scan": None}

    async def fake_claim_test_batch(conn, target_id, **kwargs):
        return [
            {
                "id": endpoint_id,
                "method": "GET",
                "path": "/api/users",
                "param_shape": "id",
                "auth_state": "anonymous",
                "param_location": "query",
                "replay_spec": None,
            }
        ]

    async def fake_reserved_scan(target, options, *, scan_id=None, job_id=None):
        calls["reserved_scan"] = {"scan_id": scan_id, "job_id": job_id}
        assert options["custom_endpoints"] == ["GET /api/users?id=1"]
        return {
            "target": target,
            "findings": [],
            "result": {"score": 95, "grade": "A"},
            "active_checks": {},
        }

    async def fake_mark_partial(conn, endpoint_ids, *, verdict):
        calls["mark_partial"].append({"endpoint_ids": endpoint_ids, "verdict": verdict})

    async def fake_mark_tested(*args, **kwargs):
        raise AssertionError("no-telemetry ASM batch must not mark endpoints tested")

    async def fake_record_endpoint_attempts(conn, endpoint_ids, **kwargs):
        calls["record"].append({"endpoint_ids": endpoint_ids, **kwargs})
        return len(endpoint_ids)

    async def fake_finish_campaign(*args, **kwargs):
        return 1

    async def fake_upsert_endpoints(*args, **kwargs):
        return 0

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool())
    monkeypatch.setattr(worker, "get_redis", lambda: _FakeJobRedis())
    monkeypatch.setattr(worker, "save_result_file", lambda result, job_id: f"/tmp/{job_id}.json")
    monkeypatch.setattr(worker, "_execute_reserved_deterministic_scan", fake_reserved_scan)
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", fake_claim_test_batch)
    monkeypatch.setattr(worker.asm_inventory, "mark_partial", fake_mark_partial)
    monkeypatch.setattr(worker.asm_inventory, "mark_tested", fake_mark_tested)
    monkeypatch.setattr(worker.asm_inventory, "record_endpoint_attempts", fake_record_endpoint_attempts)
    monkeypatch.setattr(worker.asm_inventory, "finish_campaign", fake_finish_campaign)
    monkeypatch.setattr(worker.asm_inventory, "upsert_endpoints", fake_upsert_endpoints)

    asyncio.run(
        worker.process_exploit_batch_job(
            {
                "job_id": "job-no-telemetry",
                "scan_id": "22222222-2222-2222-2222-222222222222",
                "target_id": "33333333-3333-3333-3333-333333333333",
                "target": "https://example.test",
                "options": {"scan_type": "smart"},
                "campaign_id": "44444444-4444-4444-4444-444444444444",
                "batch_size": 1,
            }
        )
    )

    assert calls["mark_partial"] == [
        {"endpoint_ids": [endpoint_id], "verdict": "missing_endpoint_telemetry"}
    ]
    assert calls["reserved_scan"] == {
        "scan_id": "22222222-2222-2222-2222-222222222222",
        "job_id": "job-no-telemetry",
    }
    assert len(calls["record"]) == 1
    record = calls["record"][0]
    assert record["endpoint_ids"] == [endpoint_id]
    assert record["check_family"] == "all"
    assert record["status"] == "partial"
    assert record["attempted_params_count"] == 0
    assert record["completed_params_count"] == 0
    assert record["error_summary"] == "completed_without_endpoint_telemetry"
    assert record["scanner_telemetry_json"]["per_endpoint_telemetry"] is False
    assert record["scanner_telemetry_json"]["completed_without_endpoint_telemetry"] is True


def test_dynamic_coverage_batch_records_parent_attempts_and_reconciles(monkeypatch):
    endpoint_id = "11111111-1111-1111-1111-111111111111"
    calls = {"claim": None, "run": None, "record": None, "mark_tested": None, "reconcile": None}
    redis = _FakeJobRedis()

    async def fake_claim_test_batch(conn, target_id, **kwargs):
        calls["claim"] = {"target_id": target_id, **kwargs}
        return [
            {
                "id": endpoint_id,
                "method": "GET",
                "path": "/api/users",
                "param_shape": "id",
                "auth_state": "anonymous",
                "param_location": "query",
                "replay_spec": None,
            }
        ]

    async def fake_run_scan(target, options, *, scan_id=None, job_id=None):
        calls["run"] = dict(options)
        assert options["custom_endpoints"] == ["GET /api/users?id=1"]
        return {
            "target": target,
            "findings": [{"title": "Proof", "severity": "high", "tool": "test"}],
            "result": {"score": 80, "grade": "B"},
            "active_checks": {
                "endpoint_attempt_schema_version": "active_endpoint_attempt_v1",
                "per_endpoint_telemetry": True,
                "endpoint_attempts": [
                    {
                        "custom_endpoint": "GET /api/users?id=1",
                        "status": "completed",
                        "attempted_params_count": 1,
                        "completed_params_count": 1,
                    }
                ],
            },
        }

    async def fake_record_endpoint_telemetry_attempts(conn, **kwargs):
        calls["record"] = kwargs
        return {"written": 1, "completed_ids": [endpoint_id], "partial_ids": [], "error_ids": []}

    async def fake_mark_tested(conn, endpoint_ids, *, verdict):
        calls["mark_tested"] = {"endpoint_ids": endpoint_ids, "verdict": verdict}

    async def fake_reconcile(conn, parent_id, r, queue_name):
        calls["reconcile"] = {"parent_id": parent_id, "queue_name": queue_name}
        return True

    async def fake_upsert_endpoints(*args, **kwargs):
        return 0

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool())
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "save_result_file", lambda result, job_id: f"/tmp/{job_id}.json")
    monkeypatch.setattr(worker, "_execute_reserved_deterministic_scan", fake_run_scan)
    monkeypatch.setattr(worker, "save_findings", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("parent merge owns findings")))
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", fake_claim_test_batch)
    monkeypatch.setattr(worker, "_record_endpoint_telemetry_attempts", fake_record_endpoint_telemetry_attempts)
    monkeypatch.setattr(worker.asm_inventory, "mark_tested", fake_mark_tested)
    monkeypatch.setattr(worker.asm_inventory, "upsert_endpoints", fake_upsert_endpoints)
    monkeypatch.setattr(worker.parallel_scan, "reconcile_parallel_parent", fake_reconcile)

    asyncio.run(
        worker.process_exploit_batch_job(
            {
                "job_id": "job-dynamic-coverage",
                "scan_id": "22222222-2222-2222-2222-222222222222",
                "parent_scan_id": "55555555-5555-5555-5555-555555555555",
                "target_id": "33333333-3333-3333-3333-333333333333",
                "target": "https://example.test",
                "campaign_id": "44444444-4444-4444-4444-444444444444",
                "batch_size": 1,
                "stale_days": 0,
                "campaign_only": True,
                "finish_campaign_on_complete": False,
                "options": {
                    "scan_type": "smart",
                    "coverage_dynamic_worker": True,
                    "coverage_dynamic_campaign_only": True,
                    "coverage_dynamic_batch_size": 1,
                    "coverage_attempt_family": "xss",
                    "asm_check_family": "xss",
                    "xss": True,
                    "sqli": False,
                },
            }
        )
    )

    assert calls["claim"]["campaign_only"] is True
    assert calls["claim"]["check_family"] == "xss"
    assert calls["claim"]["limit"] == 1
    assert calls["claim"]["stale_days"] == 0
    assert calls["run"]["asm_check_family"] == "xss"
    assert calls["run"]["xss"] is True
    assert calls["run"]["sqli"] is False
    assert calls["run"]["zero_rediscovery"] is True
    assert calls["run"]["focused_endpoints_only"] is True
    assert calls["run"]["skip_global_checks"] is True
    assert calls["run"]["custom_budget"]["nuclei_max_targets"] == 0
    assert calls["run"]["custom_budget"]["phase4_max_seconds"] == 0
    assert calls["record"]["parent_scan_id"] == "55555555-5555-5555-5555-555555555555"
    assert calls["record"]["campaign_id"] == "44444444-4444-4444-4444-444444444444"
    assert calls["record"]["check_family"] == "xss"
    assert calls["record"]["source"] == "dynamic_full_coverage_batch"
    assert calls["mark_tested"] == {"endpoint_ids": [endpoint_id], "verdict": "findings"}
    assert calls["reconcile"]["parent_id"] == "55555555-5555-5555-5555-555555555555"
    assert worker._parallel_shard_slot_key("55555555-5555-5555-5555-555555555555") not in redis.values


def test_dynamic_bola_batch_preserves_phase4_budget_and_comparator(monkeypatch):
    endpoint_id = "11111111-1111-1111-1111-111111111111"
    calls = {"claim": None, "run": None, "record": None, "mark_tested": None, "reconcile": None}
    redis = _FakeJobRedis()

    async def fake_claim_test_batch(conn, target_id, **kwargs):
        calls["claim"] = {"target_id": target_id, **kwargs}
        return [
            {
                "id": endpoint_id,
                "method": "GET",
                "path": "/api/orders",
                "param_shape": "id",
                "auth_state": "user1",
                "param_location": "query",
                "replay_spec": None,
            }
        ]

    async def fake_run_scan(target, options, *, scan_id=None, job_id=None):
        calls["run"] = dict(options)
        assert options["custom_endpoints"] == ["GET /api/orders?id=1"]
        return {
            "target": target,
            "findings": [{"title": "BOLA proof", "severity": "critical", "tool": "bola"}],
            "result": {"score": 50, "grade": "F"},
            "active_checks": {
                "endpoint_attempt_schema_version": "active_endpoint_attempt_v1",
                "per_endpoint_telemetry": True,
                "endpoint_attempts": [
                    {
                        "custom_endpoint": "GET /api/orders?id=1",
                        "status": "completed",
                        "attempted_params_count": 1,
                        "completed_params_count": 1,
                    }
                ],
            },
        }

    async def fake_record_endpoint_telemetry_attempts(conn, **kwargs):
        calls["record"] = kwargs
        return {"written": 1, "completed_ids": [endpoint_id], "partial_ids": [], "error_ids": []}

    async def fake_mark_tested(conn, endpoint_ids, *, verdict):
        calls["mark_tested"] = {"endpoint_ids": endpoint_ids, "verdict": verdict}

    async def fake_reconcile(conn, parent_id, r, queue_name):
        calls["reconcile"] = {"parent_id": parent_id, "queue_name": queue_name}
        return True

    async def fake_upsert_endpoints(*args, **kwargs):
        return 0

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool())
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "save_result_file", lambda result, job_id: f"/tmp/{job_id}.json")
    monkeypatch.setattr(worker, "_execute_reserved_deterministic_scan", fake_run_scan)
    monkeypatch.setattr(worker, "save_findings", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("parent merge owns findings")))
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", fake_claim_test_batch)
    monkeypatch.setattr(worker, "_record_endpoint_telemetry_attempts", fake_record_endpoint_telemetry_attempts)
    monkeypatch.setattr(worker.asm_inventory, "mark_tested", fake_mark_tested)
    monkeypatch.setattr(worker.asm_inventory, "upsert_endpoints", fake_upsert_endpoints)
    monkeypatch.setattr(worker.parallel_scan, "reconcile_parallel_parent", fake_reconcile)

    asyncio.run(
        worker.process_exploit_batch_job(
            {
                "job_id": "job-dynamic-bola",
                "scan_id": "22222222-2222-2222-2222-222222222222",
                "parent_scan_id": "55555555-5555-5555-5555-555555555555",
                "target_id": "33333333-3333-3333-3333-333333333333",
                "target": "https://example.test",
                "campaign_id": "44444444-4444-4444-4444-444444444444",
                "batch_size": 1,
                "stale_days": 0,
                "campaign_only": True,
                "finish_campaign_on_complete": False,
                "exploit_depth": True,
                "options": {
                    "scan_type": "smart",
                    "coverage_dynamic_worker": True,
                    "coverage_dynamic_campaign_only": True,
                    "coverage_dynamic_batch_size": 1,
                    "coverage_attempt_family": "bola",
                    "asm_check_family": "bola",
                    "auth_state": "user1",
                    "auth_header": "Bearer user1",
                    "user2_header": "Bearer user2",
                    "xss": False,
                    "sqli": False,
                },
            }
        )
    )

    assert calls["claim"]["check_family"] == "bola"
    assert calls["claim"]["auth_state"] == "user1"
    assert calls["run"]["asm_check_family"] == "bola"
    assert calls["run"]["auth_header"] == "Bearer user1"
    assert calls["run"]["user2_header"] == "Bearer user2"
    assert calls["run"]["custom_budget"]["phase4_max_seconds"] == worker.parallel_scan.BOLA_DYNAMIC_PHASE4_SECONDS
    assert calls["run"]["custom_budget"]["nuclei_max_targets"] == 0
    assert calls["record"]["check_family"] == "bola"
    assert calls["mark_tested"] == {"endpoint_ids": [endpoint_id], "verdict": "findings"}


def test_exploit_batch_partial_domain_rate_grant_releases_ungranted_endpoints(monkeypatch):
    first_id = "11111111-1111-1111-1111-111111111111"
    second_id = "22222222-2222-2222-2222-222222222222"
    conn = _FakeAsmConn()
    calls = {"run": None, "record": None, "mark_tested": None}

    async def fake_claim_test_batch(conn, target_id, **kwargs):
        return [
            {
                "id": first_id,
                "method": "GET",
                "path": "/api/a",
                "param_shape": "id",
                "auth_state": "anonymous",
                "param_location": "query",
                "replay_spec": None,
            },
            {
                "id": second_id,
                "method": "GET",
                "path": "/api/b",
                "param_shape": "id",
                "auth_state": "anonymous",
                "param_location": "query",
                "replay_spec": None,
            },
        ]

    async def fake_reserve(*args, **kwargs):
        return {
            "granted": 1,
            "limited": True,
            "requested": 2,
            "root_domain": "example.test",
            "cap": 1,
        }

    async def fake_run_scan(target, options, *, scan_id=None, job_id=None):
        calls["run"] = dict(options)
        assert options["custom_endpoints"] == ["GET /api/a?id=1"]
        return {
            "target": target,
            "findings": [],
            "result": {"score": 95, "grade": "A"},
            "active_checks": {
                "endpoint_attempt_schema_version": "active_endpoint_attempt_v1",
                "per_endpoint_telemetry": True,
                "endpoint_attempts": [
                    {
                        "custom_endpoint": "GET /api/a?id=1",
                        "status": "completed",
                        "attempted_params_count": 1,
                        "completed_params_count": 1,
                    }
                ],
            },
        }

    async def fake_record_endpoint_telemetry_attempts(conn, **kwargs):
        calls["record"] = kwargs
        return {"written": 1, "completed_ids": [first_id], "partial_ids": [], "error_ids": []}

    async def fake_mark_tested(conn, endpoint_ids, *, verdict):
        calls["mark_tested"] = {"endpoint_ids": endpoint_ids, "verdict": verdict}

    async def fake_upsert_endpoints(*args, **kwargs):
        return 0

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: _FakeJobRedis())
    monkeypatch.setattr(worker, "save_result_file", lambda result, job_id: f"/tmp/{job_id}.json")
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", fake_claim_test_batch)
    monkeypatch.setattr(worker, "_reserve_target_domain_endpoint_budget", fake_reserve)
    monkeypatch.setattr(worker, "_execute_reserved_deterministic_scan", fake_run_scan)
    monkeypatch.setattr(worker, "_record_endpoint_telemetry_attempts", fake_record_endpoint_telemetry_attempts)
    monkeypatch.setattr(worker.asm_inventory, "mark_tested", fake_mark_tested)
    monkeypatch.setattr(worker.asm_inventory, "upsert_endpoints", fake_upsert_endpoints)

    asyncio.run(
        worker.process_exploit_batch_job(
            {
                "job_id": "job-partial-rate",
                "scan_id": "33333333-3333-3333-3333-333333333333",
                "target_id": "44444444-4444-4444-4444-444444444444",
                "target": "https://example.test",
                "campaign_id": "55555555-5555-5555-5555-555555555555",
                "batch_size": 2,
                "options": {"scan_type": "smart", "coverage_dynamic_worker": True},
            }
        )
    )

    assert calls["run"]["custom_endpoints"] == ["GET /api/a?id=1"]
    assert calls["record"]["attempts"][0]["custom_endpoint"] == "GET /api/a?id=1"
    assert calls["mark_tested"] == {"endpoint_ids": [first_id], "verdict": "clean"}
    assert any(
        "last_attempt_status='rate_limited'" in query and args[0] == [second_id]
        for query, args in conn.executions
    )


def test_dynamic_coverage_batch_parent_cancelled_before_claim_does_not_claim(monkeypatch):
    calls = {"claim": 0, "reconcile": None}
    redis = _FakeJobRedis()
    conn = _FakeAsmConn(child_status="pending", parent_status="cancelled")

    async def fake_claim_test_batch(*args, **kwargs):
        calls["claim"] += 1
        return []

    async def fake_reconcile(conn, parent_id, r, queue_name):
        calls["reconcile"] = {"parent_id": parent_id, "queue_name": queue_name}
        return False

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", fake_claim_test_batch)
    monkeypatch.setattr(worker.parallel_scan, "reconcile_parallel_parent", fake_reconcile)

    asyncio.run(
        worker.process_exploit_batch_job(
            {
                "job_id": "job-cancelled-dynamic",
                "scan_id": "22222222-2222-2222-2222-222222222222",
                "parent_scan_id": "55555555-5555-5555-5555-555555555555",
                "target_id": "33333333-3333-3333-3333-333333333333",
                "target": "https://example.test",
                "campaign_id": "44444444-4444-4444-4444-444444444444",
                "batch_size": 1,
                "campaign_only": True,
                "finish_campaign_on_complete": False,
                "options": {"scan_type": "smart", "coverage_dynamic_worker": True},
            }
        )
    )

    assert calls["claim"] == 0
    assert any("Cancelled by parent scan" in query for query, args in conn.executions)
    assert redis.hashes[-1][2]["status"] == "cancelled"
    assert calls["reconcile"]["parent_id"] == "55555555-5555-5555-5555-555555555555"
    assert worker._parallel_shard_slot_key("55555555-5555-5555-5555-555555555555") not in redis.values


def test_dynamic_coverage_batch_claim_is_scoped_to_shard_auth_state(monkeypatch):
    calls = {"claim": None, "reconcile": None}
    redis = _FakeJobRedis()
    conn = _FakeAsmConn(child_status="pending", parent_status="running")

    async def fake_claim_test_batch(conn, target_id, **kwargs):
        calls["claim"] = {"target_id": target_id, **kwargs}
        return []

    async def fake_reconcile(conn, parent_id, r, queue_name):
        calls["reconcile"] = {"parent_id": parent_id, "queue_name": queue_name}
        return False

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", fake_claim_test_batch)
    monkeypatch.setattr(worker.parallel_scan, "reconcile_parallel_parent", fake_reconcile)

    asyncio.run(
        worker.process_exploit_batch_job(
            {
                "job_id": "job-user2-dynamic",
                "scan_id": "22222222-2222-2222-2222-222222222222",
                "parent_scan_id": "55555555-5555-5555-5555-555555555555",
                "target_id": "33333333-3333-3333-3333-333333333333",
                "target": "https://example.test",
                "campaign_id": "44444444-4444-4444-4444-444444444444",
                "batch_size": 10,
                "campaign_only": True,
                "finish_campaign_on_complete": False,
                "options": {
                    "scan_type": "smart",
                    "coverage_dynamic_worker": True,
                    "coverage_dynamic_campaign_only": True,
                    "auth_state": "user2",
                    "auth_header": "Bearer user2",
                },
            }
        )
    )

    assert calls["claim"]["auth_state"] == "user2"
    assert calls["claim"]["campaign_only"] is True
    assert calls["claim"]["check_family"] == "all"
    assert redis.hashes[-1][2]["current_phase"] == "no_untested_endpoints"
    assert calls["reconcile"]["parent_id"] == "55555555-5555-5555-5555-555555555555"


def test_dynamic_coverage_batch_cancelled_after_claim_releases_without_running(monkeypatch):
    endpoint_id = "11111111-1111-1111-1111-111111111111"
    calls = {"claim": None, "run": 0, "reconcile": None}
    redis = _FakeJobRedis()
    conn = _FakeAsmConn(
        child_status="pending",
        parent_status="running",
        running_update_result="UPDATE 0",
    )

    async def fake_claim_test_batch(conn, target_id, **kwargs):
        calls["claim"] = kwargs
        return [
            {
                "id": endpoint_id,
                "method": "GET",
                "path": "/api/users",
                "param_shape": "id",
                "auth_state": "anonymous",
                "param_location": "query",
                "replay_spec": None,
            }
        ]

    async def fake_run_scan(*args, **kwargs):
        calls["run"] += 1
        return {}

    async def fake_reconcile(conn, parent_id, r, queue_name):
        calls["reconcile"] = {"parent_id": parent_id, "queue_name": queue_name}
        return False

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "run_scan", fake_run_scan)
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", fake_claim_test_batch)
    monkeypatch.setattr(worker.parallel_scan, "reconcile_parallel_parent", fake_reconcile)

    asyncio.run(
        worker.process_exploit_batch_job(
            {
                "job_id": "job-cancel-race",
                "scan_id": "22222222-2222-2222-2222-222222222222",
                "parent_scan_id": "55555555-5555-5555-5555-555555555555",
                "target_id": "33333333-3333-3333-3333-333333333333",
                "target": "https://example.test",
                "campaign_id": "44444444-4444-4444-4444-444444444444",
                "batch_size": 1,
                "campaign_only": True,
                "finish_campaign_on_complete": False,
                "options": {"scan_type": "smart", "coverage_dynamic_worker": True},
            }
        )
    )

    assert calls["claim"]["campaign_only"] is True
    assert calls["run"] == 0
    assert any("last_attempt_status='cancelled'" in query for query, args in conn.executions)
    assert redis.hashes[-1][2]["status"] == "cancelled"
    assert calls["reconcile"]["parent_id"] == "55555555-5555-5555-5555-555555555555"
    assert worker._parallel_shard_slot_key("55555555-5555-5555-5555-555555555555") not in redis.values


def test_dynamic_coverage_batch_missing_campaign_id_fails_without_claim(monkeypatch):
    calls = {"claim": 0, "reconcile": None}
    redis = _FakeJobRedis()
    parent_id = "55555555-5555-5555-5555-555555555555"
    redis.values[worker.parallel_scan.shards_remaining_key(parent_id)] = 1
    conn = _FakeAsmConn(child_status="pending", parent_status="running")

    async def fake_claim_test_batch(*args, **kwargs):
        calls["claim"] += 1
        return []

    async def fake_reconcile(conn, parent_id, r, queue_name):
        calls["reconcile"] = {"parent_id": parent_id, "queue_name": queue_name}
        return True

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", fake_claim_test_batch)
    monkeypatch.setattr(worker.parallel_scan, "reconcile_parallel_parent", fake_reconcile)

    asyncio.run(
        worker.process_exploit_batch_job(
            {
                "job_id": "job-corrupt-dynamic",
                "scan_id": "22222222-2222-2222-2222-222222222222",
                "parent_scan_id": parent_id,
                "target_id": "33333333-3333-3333-3333-333333333333",
                "target": "https://example.test",
                "batch_size": 1,
                "campaign_only": True,
                "finish_campaign_on_complete": False,
                "options": {"scan_type": "smart", "coverage_dynamic_worker": True},
            }
        )
    )

    assert calls["claim"] == 0
    assert any("corrupt_shard_context" in query for query, args in conn.executions)
    assert redis.hashes[-1][2]["status"] == "failed"
    assert redis.hashes[-1][2]["current_phase"] == "corrupt_shard_context"
    assert calls["reconcile"]["parent_id"] == parent_id
    assert redis.values[worker.parallel_scan.shards_remaining_key(parent_id)] == 0








def test_focused_parent_result_recomputed_from_merged_bola_findings():
    merged = {
        "result": {
            "score": 100,
            "grade": "A",
            "summary": "Focused BOLA Scan Grade: A (100/100) - 0 in-scope issue(s) found",
            "grade_warning": "Grade may be inaccurate - required scan modules did not complete",
            "coverage_issues": ["Active checks requested but no results or errors recorded"],
            "original_grade": "A",
        }
    }
    findings = [
        {
            "tool": "smart_authz",
            "title": "Broken object authorization: user2 can access user1 object",
            "severity": "high",
            "cvss_score": 8.0,
            "cwe": "CWE-639",
        },
        {
            "tool": "csp_evaluator",
            "title": "CSP header missing",
            "severity": "medium",
        },
    ]

    score, grade = worker._recompute_focused_parent_result(merged, findings, "bola")

    assert score == 90
    assert grade == "C"
    assert merged["result"]["summary"] == "Focused BOLA Scan Grade: C (90/100) - 1 in-scope issue(s) found"
    assert merged["result"]["focused_context_findings"] == 1
    assert merged["result"]["grade_reliable"] is True
    assert "grade_warning" not in merged["result"]
    assert "coverage_issues" not in merged["result"]
    assert "original_grade" not in merged["result"]


def test_parallel_parent_degraded_when_any_shard_fails():
    merged = {
        "result": {"score": 90, "grade": "C", "grade_reliable": True},
        "scan_metadata": {},
        "parallel": {"shards_completed": 2, "shards_failed": 1},
    }

    changed = worker._mark_parallel_parent_degraded(merged, failed_count=1, total_count=3)

    assert changed is True
    assert merged["parallel"]["degraded"] is True
    assert merged["scan_metadata"]["degraded"] is True
    assert merged["scan_metadata"]["grade_reliable"] is False
    assert merged["result"]["grade_reliable"] is False
    assert merged["result"]["degraded"] is True
    assert merged["result"]["grade"] == "C*"
    assert merged["result"]["original_grade"] == "C"
    assert merged["result"]["coverage_issues"]


def test_parent_duplicate_merge_preserves_stronger_proof_and_instances():
    union = {}
    weak = {
        "tool": "smart_sqli",
        "title": "SQL injection suspected",
        "severity": "high",
        "confidence": 0.55,
        "evidence": {"url": "https://example.test/a", "payload": "1"},
    }
    proven = {
        "tool": "browser_replay",
        "title": "SQL injection proven",
        "severity": "high",
        "confidence": 0.95,
        "proof_of_exploitation": True,
        "evidence": {"url": "https://example.test/b", "payload": "' OR 1=1--"},
    }

    worker._add_parent_union_finding(union, "same-finding", weak)
    worker._add_parent_union_finding(union, "same-finding", proven)

    merged = union["same-finding"]
    assert merged["title"] == "SQL injection proven"
    assert merged["evidence"]["duplicate_count"] == 2
    assert set(merged["evidence"]["all_urls"]) == {"https://example.test/a", "https://example.test/b"}
    assert set(merged["evidence"]["all_payloads"]) == {"1", "' OR 1=1--"}
    assert len(merged["evidence"]["merged_instances"]) == 2
    assert merged["deduplication"]["consolidated"] is True
    assert merged["deduplication"]["tools_involved"] == ["browser_replay", "smart_sqli"]


def test_focused_family_from_dynamic_coverage_family_options():
    options = {
        "parallel_strategy": "coverage_family",
        "coverage_check_families": ["bola"],
    }

    assert worker._focused_family_from_parent_options(options) == "bola"


# ----- NUL-byte persistence guard (finalize data-loss regression) -------------
def test_strip_null_bytes_removes_nul_from_nested_finding_strings():
    # A NUL byte in finding evidence (e.g. binary content from the %2500 file-bypass
    # harvest) crashed the Postgres INSERT and stranded scans mid-finalize. The
    # save_findings sanitizer must strip \x00 from every nested string.
    import json as _json
    finding = {
        "title": "Sensitive file\x00 exposed",
        "url": "http://t/ftp/secret.key%2500.md",
        "evidence": {"content_preview": "AES\x00KEY\x00material", "markers": ["a\x00b", "c"]},
        "nested": [{"deep": "x\x00y"}],
        "confidence": 0.9,
    }
    cleaned = worker._strip_null_bytes(finding)
    blob = _json.dumps(cleaned)
    assert "\x00" not in blob and "\\u0000" not in blob
    assert cleaned["title"] == "Sensitive file exposed"
    assert cleaned["evidence"]["content_preview"] == "AESKEYmaterial"
    assert cleaned["evidence"]["markers"] == ["ab", "c"]
    assert cleaned["nested"][0]["deep"] == "xy"
    assert cleaned["confidence"] == 0.9  # non-strings untouched
