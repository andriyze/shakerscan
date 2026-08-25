from __future__ import annotations

from pathlib import Path

from api.runtime.capability_registry import CAPABILITY_REGISTRY


ROOT = Path(__file__).resolve().parents[1]


def _slice(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin:source.index(end, begin)]


def test_auth_and_http_routes_derive_from_the_canonical_registry():
    auth = {spec.name for spec in CAPABILITY_REGISTRY.for_hunt_executor("worker_auth")}
    http = {spec.name for spec in CAPABILITY_REGISTRY.for_hunt_executor("worker_http")}
    assert auth == {
        "auth.session.establish",
        "auth.session.refresh",
        "auth.session.revoke",
    }
    assert http == {"authz.verify", "http.request"}
    assert all(
        CAPABILITY_REGISTRY.require(name).hunt_executor == "worker_auth"
        for name in auth
    )
    assert CAPABILITY_REGISTRY.require("http.request").hunt_executor == "worker_http"


def test_planner_sees_only_opaque_session_and_principal_inputs():
    establish = CAPABILITY_REGISTRY.require(
        "auth.session.establish"
    ).planner_contract()["input_schema"]
    assert set(establish["properties"]) == {"as_principal"}
    for forbidden in (
        "username", "password", "secret", "token", "cookie", "headers",
        "endpoint_url", "auth_kind", "credential_binding_digest",
    ):
        assert forbidden not in establish["properties"]

    request = CAPABILITY_REGISTRY.require("http.request").planner_contract()
    assert "session_ref" in request["input_schema"]["properties"]
    assert request["placement"]["credentials_resolved_server_side"] is True

    authz = CAPABILITY_REGISTRY.require(
        "authz.verify"
    ).planner_contract()["input_schema"]
    assert set(authz["properties"]) == {
        "primary_session_ref", "secondary_session_ref", "routes",
    }
    assert authz["required"] == [
        "primary_session_ref", "secondary_session_ref", "routes",
    ]


def test_control_plane_queue_contains_no_decrypted_session_or_profile_material():
    source = (ROOT / "api/api.py").read_text()
    enqueue = _slice(
        source,
        "async def _enqueue_canonical_http_capability(",
        "\n\nasync def _enqueue_canonical_browser_capability(",
    )
    assert '"type": "canonical_http_capability"' in enqueue
    assert '"capability_input": dict(capability_input)' in enqueue
    for forbidden in (
        "encrypted_headers", "decrypted", "password", "client_secret",
        "authorization_header", "credential_profile_refs", "target_url",
    ):
        assert forbidden not in enqueue


def test_authz_session_use_requires_fresh_credential_approval():
    source = (ROOT / "api/api.py").read_text()
    handler = _slice(
        source,
        "async def execute_hunt_capability(",
        "\n\n@app.post(\"/hunts/{hunt_id}/shell-plans/",
    )
    assert 'name == "authz.verify"' in handler
    assert 'request.input.get("primary_session_ref")' in handler
    assert 'request.input.get("secondary_session_ref")' in handler
    assert (
        'risk_tier="credential" if principal_slot != "anonymous" or uses_session'
        in handler
    )


def test_worker_reloads_every_authority_before_session_or_http_execution():
    source = (ROOT / "api/worker.py").read_text()
    handler = _slice(
        source,
        "async def process_canonical_http_capability_job(",
        "\n\nasync def process_job(",
    )
    for required in (
        "SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE",
        "_revalidate_hunt_action_authority(",
        "validate_worker_credential_authority(",
        "WorkerCredentialResolver().resolve(",
        "session_store.load_for_worker(",
        "authorization proof requires distinct primary and secondary profiles",
        "verify_target_bound_object_authorization(",
        "execute_bound_http_request(",
        "terminalize_hunt_capability(",
        "reservation_store.persist_terminal(",
        "session_store.bind_evidence_receipt(",
        'network_binding": "runtime_target_binding"',
    ):
        assert required in handler
    assert "allow_write=False" in handler
    assert "worker_session.close()" in handler
    assert "secondary_worker_session.close()" in handler
    assert "private_session.close()" in handler
    assert "credential_stack.aclose()" in handler

    authority_helper = _slice(
        source,
        "async def _revalidate_hunt_action_authority(",
        "\n\ndef _worker_hunt_profile_context(",
    )
    assert "revalidate_scan_action_authority(" in authority_helper
    assert "Hunt target is no longer active" in authority_helper
    assert "Hunt target locator changed after admission" in authority_helper


def test_worker_router_accepts_the_opaque_http_job_type():
    source = (ROOT / "api/worker.py").read_text()
    router = source[source.index("async def process_job("):]
    assert "elif job_type == 'canonical_http_capability':" in router
    assert "await process_canonical_http_capability_job(job_data)" in router
