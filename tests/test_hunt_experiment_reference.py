"""Real admission-handler retry checks with a database fixture; no execution claims."""

import asyncio
import hashlib
import json
import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from api.hunt import interaction_router as router


@pytest.mark.parametrize("value", ["", "A" * 32, "a" * 31, "a" * 64, "not-a-key"])
def test_experiment_reference_is_a_bounded_identity(value):
    with pytest.raises(ValidationError):
        router.HuntCapabilityRequest(idempotency_key="fixture-key", experiment_key=value)


@pytest.mark.parametrize("old,new", [
    (None, "a" * 32), ("a" * 32, None), ("a" * 32, "b" * 32),
    (None, None), ("a" * 32, "a" * 32),
])
def test_retry_cannot_reassociate_existing_action(monkeypatch, old, new):
    request = router.HuntCapabilityRequest(idempotency_key="fixture-key", experiment_key=new)
    run_id = uuid.uuid4()

    @asynccontextmanager
    async def transaction():
        yield

    class Connection:
        def transaction(self):
            return transaction()

        async def fetchrow(self, sql, *args):
            assert "FROM hunt_actions" in sql
            return {
                "capability_name": "collections.inspect", "status": "completed",
                "result_summary": "{}", "receipt_id": None,
                "input_summary": json.dumps({
                    "input_digest": hashlib.sha256(b"{}").hexdigest(),
                    "idempotency_key_sha256": hashlib.sha256(b"fixture-key").hexdigest(),
                    "experiment_key": old,
                }),
            }

        async def execute(self, *args):
            pytest.fail("conflicting retry must not mutate or dispatch")

    @asynccontextmanager
    async def acquire():
        yield Connection()

    async def load_run(*args, **kwargs):
        return {"id": run_id, "target_kind": "web"}

    monkeypatch.setattr(router, "_pool", lambda: SimpleNamespace(acquire=acquire))
    monkeypatch.setattr(router, "_hunt_run_or_404", load_run)
    lifecycle = SimpleNamespace(
        specification=SimpleNamespace(output_schema="fixture/v1"), placement="api_local",
        mark_replayed=lambda: None,
    )
    if old == new:
        result = asyncio.run(router._execute_hunt_capability_lifecycle(
            str(run_id), "collections.inspect", request, lifecycle,
        ))
        assert result["idempotent_replay"] is True
        return
    with pytest.raises(HTTPException) as exc:
        asyncio.run(router._execute_hunt_capability_lifecycle(
            str(run_id), "collections.inspect", request, lifecycle,
        ))
    assert exc.value.status_code == 409
