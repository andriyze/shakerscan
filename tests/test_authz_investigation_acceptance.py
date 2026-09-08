"""Acceptance for the assisted authorization investigation, on the EXISTING proof engine.

This runs the shipping cross-principal differential (`authz_resource_replay_test`) against the
seeded fixture. It is the milestone's acceptance test: the vulnerable twin must yield a
reproducible ownership finding, the patched twin must yield none, and the negative controls -- a
public object, an expired session, the attacker's own collection -- must yield none either.

Nothing here builds a parallel engine. The earlier attempt to prove a real-world basket BOLA failed
because that object had no caller-scoped listing, so the victim's id was never absent from the
attacker's own baseline and the differential correctly refused to conclude. A well-formed API has
that listing, and these tests establish that the existing engine is sound when it does.
"""

import asyncio
import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/e2e/fixtures"))
sys.path.insert(0, str(ROOT / "scanner"))

import fixtures_server  # noqa: E402
from scanner_tools.access_control_checks import authz_resource_replay_test  # noqa: E402

USER_A = {"Authorization": "Bearer authz-token-a"}
USER_B = {"Authorization": "Bearer authz-token-b"}
EXPIRED = {"Authorization": "Bearer authz-token-expired"}


@pytest.fixture(scope="module")
def base_url():
    server = fixtures_server.start(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


def _session(headers):
    return SimpleNamespace(config=SimpleNamespace(headers=dict(headers), cookies={}), state=None)


async def _fetch(url, headers=None, timeout=10, **_kwargs):
    request = urllib.request.Request(url)
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {"status_code": response.status, "headers": dict(response.headers),
                    "body": response.read().decode(), "error": None}
    except urllib.error.HTTPError as exc:
        return {"status_code": exc.code, "headers": {}, "body": exc.read().decode(), "error": None}


def run_differential(base, routes, owner=USER_A, attacker=USER_B):
    return asyncio.run(authz_resource_replay_test(
        base, routes, _session(owner), _session(attacker),
        max_producers=5, max_replays=20, timeout=10, max_seconds=30,
        fetcher=_fetch, allow_write_replays=False,
    ))


def test_the_vulnerable_twin_produces_a_cross_principal_finding(base_url):
    """The milestone's positive case: user-b reads an order owned by user-a."""
    result = run_differential(base_url, [
        f"{base_url}/authz/vuln/orders", f"{base_url}/authz/vuln/orders/1001",
    ])
    assert result["vulnerable"] is True
    assert result["cross_principal_violations"] >= 1
    evidence = result["findings"][0]["evidence"]
    assert evidence["proof_type"] == "cross_principal_replay"
    # The soundness the moat requires: the object was absent from the attacker's own listing.
    assert evidence["object_id_absent_from_attacker_listing"] is True
    assert evidence["owner_status"] == 200 and evidence["attacker_status"] == 200


def test_the_patched_twin_produces_no_finding_from_the_same_investigation(base_url):
    """Identical data and routes; only ownership enforcement differs."""
    result = run_differential(base_url, [
        f"{base_url}/authz/safe/orders", f"{base_url}/authz/safe/orders/1001",
    ])
    assert result["vulnerable"] is False
    assert result["cross_principal_violations"] == 0
    assert not result.get("findings")


def test_a_public_object_does_not_produce_proof(base_url):
    """Both principals legitimately read an ownerless object. That is not a bypass."""
    result = run_differential(base_url, [
        f"{base_url}/authz/public/notices", f"{base_url}/authz/public/notices/9001",
    ])
    assert result["vulnerable"] is False
    assert result["cross_principal_violations"] == 0


def test_an_expired_attacker_session_does_not_produce_proof(base_url):
    result = run_differential(base_url, [
        f"{base_url}/authz/vuln/orders", f"{base_url}/authz/vuln/orders/1001",
    ], attacker=EXPIRED)
    assert result["vulnerable"] is False


def test_the_attackers_own_collection_does_not_produce_proof(base_url):
    """user-b reading user-b's order is not a violation, however much it looks like access."""
    result = run_differential(base_url, [
        f"{base_url}/authz/vuln/orders", f"{base_url}/authz/vuln/orders/2001",
    ], owner=USER_B, attacker=USER_B)
    assert result["vulnerable"] is False


def test_the_same_principal_twice_is_refused_as_a_control(base_url):
    """Two identical principals cannot evidence a cross-principal claim."""
    result = run_differential(base_url, [
        f"{base_url}/authz/vuln/orders", f"{base_url}/authz/vuln/orders/1001",
    ], owner=USER_A, attacker=USER_A)
    assert result["vulnerable"] is False
    assert result.get("skipped") is True or result["cross_principal_violations"] == 0


def test_the_finding_is_reproducible_across_runs(base_url):
    """A finding a pentester cannot reproduce is not evidence."""
    first = run_differential(base_url, [
        f"{base_url}/authz/vuln/orders", f"{base_url}/authz/vuln/orders/1001",
    ])
    second = run_differential(base_url, [
        f"{base_url}/authz/vuln/orders", f"{base_url}/authz/vuln/orders/1001",
    ])
    assert first["vulnerable"] is second["vulnerable"] is True
    assert (first["findings"][0]["evidence"]["requested_object_id"]
            == second["findings"][0]["evidence"]["requested_object_id"])


def test_a_shared_object_carrying_identity_data_is_still_not_a_finding(base_url):
    """The strongest negative control: content indistinguishable from a leaked private record.

    The public notices disclose nothing, so on their own they could pass merely by failing the
    disclosure guard rather than by exercising the ownership logic. This object carries an email
    and a postal address, and every principal is entitled to it. A differential that reports it
    is keying on disclosure instead of ownership.
    """
    result = run_differential(base_url, [
        f"{base_url}/authz/public/directory", f"{base_url}/authz/public/directory/7001",
    ])
    assert result["vulnerable"] is False
    assert result["cross_principal_violations"] == 0
