#!/usr/bin/env python3
"""Align AST admission fixtures with the real helper and required method contract."""
from pathlib import Path
import sys
root = Path(sys.argv[1])

def edit(path, before, after):
    p = root / path
    source = p.read_text()
    if source.count(before) != 1:
        raise ValueError(f'{path}: expected one exact fixture anchor')
    p.write_text(source.replace(before, after, 1))

edit('tests/test_hunt_authz_verification_limit.py',
    'from hunt.device_traffic import reserve_device_traffic\n',
    'from hunt.device_traffic import reserve_device_traffic\nfrom runtime.hunt_http_contract import require_http_request_authority, redact_http_request_body\n')
edit('tests/test_hunt_authz_verification_limit.py',
    '        "reserve_device_traffic": reserve_device_traffic,\n',
    '        "reserve_device_traffic": reserve_device_traffic,\n        "require_http_request_authority": require_http_request_authority,\n')
edit('tests/test_hunt_authz_verification_limit.py',
    '        "_hunt_redacted_capability_input": lambda name, values: dict(values),\n',
    '        "_hunt_redacted_capability_input": lambda name, values: (\n            redact_http_request_body(values) if name == "http.request" else dict(values)),\n')
edit('tests/test_hunt_authz_verification_limit.py',
    '        {"candidate_id": str(uuid.UUID(int=3))} if name == "candidate.verify" else {})\n',
    '        {"candidate_id": str(uuid.UUID(int=3))} if name == "candidate.verify" else\n        {"method": "GET", "path": "/"} if name == "http.request" else {})\n')
edit('tests/test_hunt_device_traffic.py',
    '    fn = admission(store)\n',
    '    values = dict(values or {})\n    if name == "http.request":\n        values.setdefault("method", "GET")\n        values.setdefault("path", "/")\n        values = CAPABILITY_REGISTRY.validate_hunt_input(name, values)\n    fn = admission(store)\n')
edit('tests/test_hunt_replay_worker_lifecycle.py',
    '                    input={"path": "/"}, idempotency_key="after-unaffordable-replay"), life)\n',
    '                    input={"method": "GET", "path": "/"}, idempotency_key="after-unaffordable-replay"), life)\n')
edit('tests/api_import_stubs.py',
    '    if not hasattr(fastapi, "APIRouter"):\n',
    '    if not hasattr(fastapi, "Depends"):\n        # Metadata-only compatibility import; no dependency is executed by the stub.\n        fastapi.Depends = lambda dependency=None, **_kwargs: dependency\n    if not hasattr(fastapi, "APIRouter"):\n')
p = root / 'tests/test_hunt_device_traffic.py'
p.write_text(p.read_text() + '''

def test_authorized_device_put_is_admitted_and_idempotent_without_extra_write_charge():
    async def scenario():
        store = DeviceStore()
        store.run["policy_json"]["allow_state_changing_http"] = True
        store.run["budget_json"]["max_state_changing_requests"] = 5
        values = {"method": "PUT", "path": "/pairing/start", "json_body": {"name": "lab-client"}}
        first = await admit(store, values=values)
        second = await admit(store, values=values)
        assert second["idempotent_replay"] is True
        assert first["action_id"] == second["action_id"]
        assert len(store.actions) == 1
        used = store.run["budget_used_json"]
        assert used["state_changing_requests"] == used["http_requests"] == used["active_actions"] == 1
        summary = next(iter(store.actions.values()))["input_summary"]["input"]
        assert "json_body" not in summary and summary["body_values_visible"] is False
    asyncio.run(scenario())


def test_device_put_missing_write_authority_is_rejected_before_reservation():
    store = DeviceStore()
    with pytest.raises(HTTPException, match="allow_state_changing_http"):
        asyncio.run(admit(store, values={"method": "PUT", "path": "/pairing/start", "json_body": {}}))
    assert not store.actions
    assert store.run["budget_used_json"].get("state_changing_requests", 0) == 0
''')
