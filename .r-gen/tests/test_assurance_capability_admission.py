"""Missing transport/interruption support prevents validation admission."""
import asyncio
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest

from authenticated_assurance import jobs
from authenticated_assurance import router
from authenticated_assurance.models import ValidationRequest
from authenticated_assurance.store import ProfileConflict


@pytest.mark.parametrize("field", ["credential_transport", "credential_interruption"])
def test_unsupported_capability_cannot_reach_database_or_queue(monkeypatch, field):
    spec = replace(jobs.CAPABILITY_REGISTRY.require("http.request"), **{field: "unverified"})
    monkeypatch.setattr(jobs, "CAPABILITY_REGISTRY", SimpleNamespace(require=lambda name: spec))
    monkeypatch.setattr(router, "_engine", {"fixture": True})
    advertised = asyncio.run(router.contract())
    assert advertised["validation_execution"] == "unsupported"
    assert advertised["supported_validation_methods"] == []
    assert advertised["validation_identity_contract"][field] == "unverified"

    async def forbidden(*args, **kwargs):
        raise AssertionError("Unsupported validation must stop before admission side effects")

    conn = SimpleNamespace(fetchrow=forbidden, execute=forbidden)
    with pytest.raises(ProfileConflict, match="validation_not_supported"):
        asyncio.run(jobs.ValidationJobs().prepare(conn, profile_id=uuid4(),
            request=ValidationRequest(expected_revision=1, approval_receipt_id=uuid4(), reviewed=True),
            actor="fixture", generation=uuid4(), expected_build_fingerprint="fixture",
            approve=forbidden, freeze=forbidden))
