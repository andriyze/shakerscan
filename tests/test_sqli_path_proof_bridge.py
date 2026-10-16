"""Path candidates must reach repeated proof through the real Scan dispatcher."""
import asyncio
import uuid
from urllib.parse import unquote, urlsplit

from tests.test_scan_action_adapter import (
    Backend, TARGET, _action, _dispatcher, _lease, _noop,
    action_adapter_module, build_candidate_manifest, build_endpoint_manifest,
    ReplayTransportResult, ScanActionPlan, ScanPolicy,
)


def test_scan_dispatches_a_signalled_path_candidate_to_repeated_proof(monkeypatch):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={'schema_version': 'endpoint-manifest/v2', 'status': 'complete',
            'reason': None, 'endpoints': [{'method': 'GET', 'scheme': 'https',
                'host': 'app.example.test', 'port': 443,
                'normalized_path': '/users/{int}', 'concrete_path': '/users/1',
                'query_keys': [], 'source': 'web.spec_ingest'}]},
        source_action_ids=('discover.spec',))
    candidates = build_candidate_manifest(endpoints, source_action_ids=('discover.spec',), maximum=10)
    assert len(candidates.entries) == 1
    candidate = candidates.entries[0]
    assert candidate['parameter_location'] == 'path'
    dependency = _action('verify.sqli.00000', 'sqli.verify_batch', 0)
    action = _action('prove.sqli.00000', 'sqli.prove_batch', 1,
        dependencies=(dependency.action_id,), capability_args={
            'candidate_manifest_ref': candidates.reference().canonical_dict(),
            'endpoint_manifest_ref': endpoints.reference().canonical_dict(),
            'slice': {'start': 0, 'count': 1}})
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest='a' * 64,
        target_binding_digest=TARGET.digest, actions=(dependency, action))
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates},
        observations={dependency.action_id: ({'kind': 'candidate_attempt',
            'candidate_id': candidate['candidate_id'], 'proof_state': 'suspected'},)})
    requests = []

    class Transport:
        async def send(self, request, **kwargs):
            requests.append(request)
            value = unquote(urlsplit(request.url).path.rsplit('/', 1)[-1])
            return ReplayTransportResult(status_code=200, connected_address='192.0.2.10',
                final_url=request.url, response_headers={'Content-Type': 'application/json'},
                response_body=b'SQLite error: unrecognized token' if value.endswith("'") else b'{"user":1}',
                elapsed_ms=5)

    monkeypatch.setattr(action_adapter_module.DatabaseNeutralScanActionDispatcher,
                        '_scan_replay_transport', lambda *a, **kw: Transport())
    dispatcher = _dispatcher(plan, backend,
        policy=ScanPolicy(active_testing=True, approval_receipt_id='approval-1'))
    result = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    attempts = list(backend.attempts[action.action_id].values())
    assert len(attempts) == 1
    proof = next(o for o in attempts[0]['observations'] if o.get('kind') == 'sqli_proof')
    assert proof['proof_state'] == 'verified'
    assert proof['proof_contract'] == 'sqli_error_differential/v2'
    assert len(requests) == 4
    assert [urlsplit(r.url).path for r in requests] == ['/users/1', '/users/1%27'] * 2
    assert result.budget_consumed['http_requests'] == 4
