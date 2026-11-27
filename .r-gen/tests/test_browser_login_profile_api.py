"""Public saved-profile API and Scan admission, using the real router and store."""
from __future__ import annotations

import asyncio
import json
from dataclasses import asdict

import pytest
from fastapi import HTTPException

from tests.test_credential_api import client, _create_payload, TARGET_ID
from tests.test_browser_login_action import CONFIG, CAP, ORIGIN, POLICY
from request_models import ScanRequest
from scan.browser_login import admit_scan_browser_login_profiles
from runtime.credential_store import PostgresCredentialProfileStore


def create(http):
    return http.post("/credential-profiles", json=_create_payload(
        target_kind="api", auth_kind="form_login", username="synthetic-user",
        endpoint_url=ORIGIN + "/login", browser_login=CONFIG,
        allowed_capabilities=[CAP],
    ))


def test_saved_workflow_is_encrypted_and_never_echoed_in_metadata(client):
    http, pool = client
    response = create(http)
    assert response.status_code == 201, response.text
    profile = response.json()["profile"]
    assert profile["configuration"]["browser_login_configured"] is True
    assert profile["allowed_capabilities"] == [CAP]
    for value in (ORIGIN, "synthetic-user", "#username", "never-return-this-secret"):
        assert value not in response.text
    fetched = http.get("/credential-profiles/" + profile["id"])
    assert fetched.status_code == 200
    assert "#username" not in fetched.text
    assert len(pool.conn.versions) == 1


def test_rotation_requires_explicit_workflow_preservation_or_removal(client):
    http, _ = client
    profile = create(http).json()["profile"]
    payload = {"expected_record_version": 1, "username": "synthetic-user",
               "secret": "synthetic-rotation", "endpoint_url": ORIGIN + "/login"}
    url = "/credential-profiles/" + profile["id"] + "/rotate"
    assert http.post(url, json=payload).status_code == 422
    saved = http.post(url, json={**payload, "browser_login": CONFIG})
    assert saved.status_code == 200, saved.text
    assert saved.json()["profile"]["configuration"]["browser_login_configured"] is True
    removed = http.post(url, json={**payload, "expected_record_version": 2, "browser_login": None})
    assert removed.status_code == 200, removed.text
    assert not removed.json()["profile"]["configuration"].get("browser_login_configured")


@pytest.mark.parametrize("mutation", ["origin", "script", "too_many_requests", "different_check_origin"])
def test_invalid_saved_workflow_is_rejected_without_plaintext_in_errors(client, mutation):
    http, pool = client
    config = json.loads(json.dumps(CONFIG))
    if mutation == "origin": config["workflow"]["submit_url"] = "https://unapproved.test/login"
    if mutation == "script": config["workflow"]["script"] = "synthetic-private-script"
    if mutation == "too_many_requests": config["workflow"]["max_requests"] = 129
    if mutation == "different_check_origin": config["checks"][0]["url"] = "https://unapproved.test/private"
    result = http.post("/credential-profiles", json=_create_payload(
        auth_kind="form_login", username="synthetic-user", endpoint_url=ORIGIN + "/login",
        browser_login=config, allowed_capabilities=[CAP],
    ))
    assert result.status_code == 422
    assert "synthetic-private-script" not in result.text
    assert "unapproved.test" not in result.text
    assert pool.conn.profile is None


def test_scan_admits_only_exact_active_saved_qa_profiles_without_decryption(client):
    http, pool = client
    profile = create(http).json()["profile"]
    original_fetch = pool.conn.fetch
    async def fetch(query, *args):
        rows = await original_fetch(query, *args)
        return [{**row, "allowed_capabilities": pool.conn.binding["allowed_capabilities"]} for row in rows]
    pool.conn.fetch = fetch
    request = ScanRequest(target=ORIGIN, target_kind="api", browser_login_profile_ids=[profile["id"]])
    async def scenario():
        store = PostgresCredentialProfileStore()
        refs = await admit_scan_browser_login_profiles(pool.conn, store=store, request=request,
                                                        target_id=TARGET_ID, policy=POLICY)
        assert refs == [{"profile_id": profile["id"], "profile_version": 1, "principal_slot": "primary"}]
        pool.conn.binding["allowed_capabilities"] = ["http.request"]
        with pytest.raises(HTTPException):
            await admit_scan_browser_login_profiles(pool.conn, store=store, request=request,
                                                    target_id=TARGET_ID, policy=POLICY)
    asyncio.run(scenario())
