"""Execute the worker's real pre-hydration block: a revoked receipt stops queued traffic."""
import ast
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from devices import network_authorization


def dispatch_prefix(globals_):
    source = (Path(__file__).resolve().parents[1]/'api/worker.py').read_text()
    root = ast.parse(source)
    branch = next(node for node in ast.walk(root) if isinstance(node,ast.If)
        and any(isinstance(stmt,ast.Assign) and isinstance(stmt.value,ast.Await)
                and isinstance(stmt.value.value,ast.Call)
                and isinstance(stmt.value.value.func,ast.Name)
                and stmt.value.value.func.id == '_hydrate_generic_scan_credentials'
                for stmt in node.orelse))
    finish = next(i for i,stmt in enumerate(branch.orelse) if isinstance(stmt,ast.If)
                  and isinstance(stmt.test,ast.Call) and isinstance(stmt.test.func,ast.Name)
                  and stmt.test.func.id == 'is_deterministic_dast')
    wrapper = ast.parse('async def dispatch(options, device_target_id, scan_id):\n    pass').body[0]
    wrapper.body = branch.orelse[:finish]
    namespace = dict(globals_)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[wrapper],type_ignores=[])),'worker-preflight','exec'),namespace)
    return namespace['dispatch']


@pytest.mark.parametrize('run_kind',['device_posture','device_probe'])
@pytest.mark.parametrize('revoked',[False,True])
def test_saved_receipt_is_checked_before_any_credential_hydration(monkeypatch,run_kind,revoked):
    events = []
    async def read(_conn,_target):
        events.append('authority')
        return None if revoked else {'standing':True,'approval_receipt_id':'saved','approved_by':'operator'}
    monkeypatch.setattr(network_authorization,'current_target_authorization',read)
    @asynccontextmanager
    async def acquire():
        yield object()
    async def hydrate(options,_scan):
        assert not revoked, 'A revoked scan reached secret hydration'
        events.append('hydrate')
        return options
    dispatch = dispatch_prefix({'db_pool':SimpleNamespace(acquire=acquire),
        '_hydrate_generic_scan_credentials':hydrate,'_hydrate_managed_scan_credentials':hydrate,
        '_hydrate_scan_private_state_key':lambda options: options,
        '_hydrate_device_scan_credentials':hydrate,'_hydrate_device_request_collections':hydrate})
    options = {'run_kind':run_kind,'asset_authorization_receipt_id':'saved'}
    if revoked:
        with pytest.raises(ValueError,match='revoked'):
            asyncio.run(dispatch(options,'target-id','scan-id'))
        assert events == ['authority']
    else:
        asyncio.run(dispatch(options,'target-id','scan-id'))
        assert events[0] == 'authority' and events.count('hydrate') == (4 if run_kind == 'device_posture' else 2)
