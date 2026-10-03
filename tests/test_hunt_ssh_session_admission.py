import json
from uuid import uuid4

import pytest
from fastapi import HTTPException

from api.hunt.ssh_routing import session_key, worker_key, worker_queue
from api.hunt.ssh_stream import require_ssh_session_available
from tests.api_sources import definition_source


class Directory:
    def __init__(self, values):
        self.values = values

    def get(self, key):
        return self.values.get(key)

    def exists(self, key):
        return key in self.values


@pytest.mark.parametrize("state,error", [
    ("closed", "ssh_session_unavailable"),
    ("worker_gone", "ssh_session_worker_unavailable"),
    ("other_hunt", "session_binding_mismatch"),
])
def test_unavailable_session_has_actionable_reconnect_error(state, error):
    hunt, session = str(uuid4()), str(uuid4())
    values = {session_key(session): json.dumps({
        "hunt_id": str(uuid4()) if state == "other_hunt" else hunt,
        "worker_id": "fixture-worker",
    }), worker_key("fixture-worker"): "ready"}
    if state == "closed":
        values.pop(session_key(session))
    if state == "worker_gone":
        values.pop(worker_key("fixture-worker"))
    before = dict(values)
    with pytest.raises(HTTPException) as exc:
        require_ssh_session_available(Directory(values), base_queue="jobs",
                                     hunt_id=hunt, session_id=session)
    assert exc.value.status_code == 409
    assert exc.value.detail.startswith(error + ".")
    assert "without session_id" in exc.value.detail
    assert values == before


def test_live_session_retains_its_owning_worker_without_reconnecting():
    hunt, session = str(uuid4()), str(uuid4())
    directory = Directory({session_key(session): json.dumps({
        "hunt_id": hunt, "worker_id": "fixture-worker",
    }), worker_key("fixture-worker"): "ready"})
    assert require_ssh_session_available(directory, base_queue="jobs",
        hunt_id=hunt, session_id=session) == worker_queue("jobs", "fixture-worker")


def test_session_preflight_precedes_durable_budget_admission():
    handler = definition_source("_execute_hunt_capability_lifecycle")
    assert handler.index("require_ssh_session_available(") < handler.index("create_requested(")
