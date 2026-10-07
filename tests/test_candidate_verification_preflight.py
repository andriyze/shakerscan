"""candidate.verify preflight: the route keys the contract advertises are the ones verification uses.

Live soak: a contract-compliant data_exposure candidate ``{"method": "GET", "path": "/ftp/x.md"}``
(SKILL.md: "for a file exposure, its `path`") was refused as ``verification_route_unresolved``,
because the verifier read only ``route`` and ``url``. The refusal also charged the verifier's
whole reservation; tests/test_hunt_authz_verification_limit.py pins that it is now free.
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
import api as api_module  # noqa: E402
import investigation_candidates  # noqa: E402
from hunt import candidate_verification_preflight as preflight  # noqa: E402
from hunt.start_contract import hunt_start_public_contract  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _candidate(locus, family="data_exposure", context=None):
    return {"id": uuid.uuid4(), "plane": "web", "status": "new", "family": family,
            "target_id": uuid.uuid4(), "canonical_locus": locus,
            "verification_context": context or {}, "title": "t", "claimed_severity": "high",
            "verifier_contract_id": None}


@pytest.mark.parametrize("key,value,route", [
    ("route", "/api/users/{id}", "/api/users/{id}"),
    ("url", "https://app.test/ftp/acquisitions.md", "/ftp/acquisitions.md"),
    ("path", "/ftp/acquisitions.md", "/ftp/acquisitions.md"),
])
def test_every_advertised_route_key_resolves_on_its_own(key, value, route):
    assert preflight.verification_route({"method": "GET", key: value}, {}) == route
    assert preflight.web_candidate_preflight(_candidate({"method": "GET", key: value}))[1] == route


def test_route_keys_apply_in_their_published_order():
    locus = {"route": "/r", "url": "https://app.test/u", "path": "/p"}
    assert preflight.verification_route(locus, {"route": "/c"}) == "/r"
    assert preflight.verification_route({"url": locus["url"], "path": "/p"}, {}) == "/u"
    assert preflight.verification_route({"path": "/p"}, {"route": "/c"}) == "/p"
    assert preflight.verification_route({}, {"route": "/c"}) == "/c"


def test_contract_location_keys_match_what_verification_resolves():
    contract = hunt_start_public_contract()["candidates"]
    route_keys = contract["verification_route_keys"]
    identity_only = contract["identity_only_location_keys"]
    # Every advertised request-location key is classified exactly once...
    assert set(route_keys).isdisjoint(identity_only)
    assert set(route_keys) | set(identity_only) == set(investigation_candidates.REQUEST_LOCATION_KEYS)
    assert set(investigation_candidates.REQUEST_LOCATION_KEYS) <= set(contract["locus_keys"])
    # ...the route keys really resolve, and the identity-only keys really do not.
    for key in route_keys:
        assert preflight.verification_route({key: "/ftp/acquisitions.md"}, {}) is not None
    for key in identity_only:
        assert preflight.verification_route({key: ["/a", "/b"]}, {}) is None
        assert "identity only" in contract["locus_keys"][key]
    # The skill's example key for a file exposure is one verification can use.
    skill = (ROOT / "skills/hunt/SKILL.md").read_text(encoding="utf-8")
    example = re.search(r"for a file exposure, its `(\w+)`", skill)
    assert example and example.group(1) in route_keys


class _Conn:
    def __init__(self, candidate):
        self.candidate = candidate

    async def fetchrow(self, sql, *args):
        if "FROM investigation_candidates" in sql:
            return self.candidate
        if "FROM targets" in sql:
            return {"id": self.candidate["target_id"], "url": "https://app.test", "is_active": True}
        raise AssertionError(sql)


class _Pool:
    def __init__(self, candidate):
        self.conn = _Conn(candidate)

    @asynccontextmanager
    async def acquire(self):
        yield self.conn


def _verify(monkeypatch, candidate):
    seen = {}

    async def workflow_for(_conn, _target, family, route, method):
        seen.update(family=family, route=route, method=method)
        raise HTTPException(status_code=418, detail="stop before traffic")

    monkeypatch.setattr(api_module, "db_pool", _Pool(candidate))
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: True)
    monkeypatch.setattr(api_module, "_agent_verification_workflow_for", workflow_for)
    with pytest.raises(HTTPException) as error:
        asyncio.run(api_module._verify_web_candidate_workflow_unlocked(
            candidate["id"], "approval", created_by="test",
        ))
    return error.value, seen


def test_web_verifier_resolves_a_contract_path_locus(monkeypatch):
    error, seen = _verify(monkeypatch, _candidate({"method": "GET", "path": "/ftp/acquisitions.md"}))
    assert error.status_code == 418
    assert seen == {"family": "data_exposure", "route": "/ftp/acquisitions.md", "method": "GET"}


@pytest.mark.parametrize("candidate,status,detail", [
    (_candidate({"route": "/search"}, family="sqli"), 422, "verification bridge supports"),
    (_candidate({"method": "GET"}), 422, "verification_route_unresolved"),
    ({**_candidate({"route": "/a"}), "status": "verified"}, 409, "already verified"),
])
def test_web_verifier_refuses_exactly_as_admission_does(monkeypatch, candidate, status, detail):
    error, seen = _verify(monkeypatch, candidate)
    assert (error.status_code, seen) == (status, {})
    assert detail in str(error.detail)
    with pytest.raises(preflight.CandidateVerificationRefused) as refused:
        preflight.web_candidate_preflight(candidate)
    assert (refused.value.status_code, refused.value.detail) == (status, error.detail)
