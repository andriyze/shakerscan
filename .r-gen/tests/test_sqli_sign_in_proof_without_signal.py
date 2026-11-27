"""A sign-in body candidate reaches the SQLi proof without a sqlmap signal; other bodies do not."""
import asyncio
import json
import uuid

from tests.test_scan_action_adapter import (
    Backend, TARGET, _action, _dispatcher, _lease, _noop,
    action_adapter_module, build_candidate_manifest, build_endpoint_manifest,
    ReplayTransportResult, ScanActionPlan, ScanPolicy,
)


def _run(monkeypatch, path, *, allow_state_changing):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
        surface_manifest={'schema_version': 'endpoint-manifest/v2', 'status': 'complete',
            'reason': None, 'endpoints': [{'method': 'POST', 'scheme': 'https',
                'host': 'app.example.test', 'port': 443, 'normalized_path': path,
                'concrete_path': path, 'query_keys': [], 'content_type': 'application/json',
                'body_field_names': ['email', 'password'], 'source': 'web.browser_crawl'}]},
        source_action_ids=('discover.crawl',))
    candidates = build_candidate_manifest(endpoints, source_action_ids=('discover.crawl',), maximum=10,
                                         allow_state_changing_http=True)
    body = [i for i, c in enumerate(candidates.entries) if c['body_field_names']]
    assert len(body) == 1
    dependency = _action('verify.sqli.00000', 'sqli.verify_batch', 0)
    action = _action('prove.sqli.00000', 'sqli.prove_batch', 1,
        dependencies=(dependency.action_id,), capability_args={
            'candidate_manifest_ref': candidates.reference().canonical_dict(),
            'endpoint_manifest_ref': endpoints.reference().canonical_dict(),
            'slice': {'start': body[0], 'count': 1}})
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest='a' * 64,
        target_binding_digest=TARGET.digest, actions=(dependency, action))
    # The verifier recorded nothing for this candidate: its slice could not fund the body.
    backend = Backend(manifests={endpoints.manifest_id: endpoints, candidates.manifest_id: candidates},
        observations={dependency.action_id: ()})
    requests = []

    class Transport:
        async def send(self, request, **kwargs):
            requests.append(request)
            quoted = any(str(v).endswith("'") for v in json.loads(request.body or b'{}').values())
            body = (b'{"error":"SQLITE_ERROR: unrecognized token"}' if quoted
                    else b'{"error":"Invalid email or password."}')
            return ReplayTransportResult(status_code=500 if quoted else 401,
                connected_address='192.0.2.10', final_url=request.url,
                response_headers={'Content-Type': 'application/json'}, response_body=body, elapsed_ms=5)

    monkeypatch.setattr(action_adapter_module.DatabaseNeutralScanActionDispatcher,
                        '_scan_replay_transport', lambda *a, **kw: Transport())
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy(
        active_testing=True, allow_state_changing_http=allow_state_changing,
        approval_receipt_id='approval-1'))
    result = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    return result, backend.attempts.get(action.action_id, {}), requests


def test_an_unsignalled_sign_in_body_is_proven(monkeypatch):
    result, attempts, requests = _run(monkeypatch, '/rest/user/login', allow_state_changing=True)
    proofs = [o for a in attempts.values() for o in a['observations'] if o.get('kind') == 'sqli_proof']
    assert len(proofs) == 1
    assert proofs[0]['proof_state'] == 'verified'
    assert proofs[0]['proof_contract'] == 'sqli_error_differential/v2'
    assert proofs[0]['request_class'] == 'safe_authentication'
    assert len(requests) == 4


def test_a_sign_in_body_without_state_changing_authority_is_not_replayed(monkeypatch):
    _result, attempts, requests = _run(monkeypatch, '/rest/user/login', allow_state_changing=False)
    assert requests == [] and not attempts


def test_an_unsignalled_body_that_is_not_a_sign_in_still_waits_for_a_signal(monkeypatch):
    result, attempts, requests = _run(monkeypatch, '/api/notes', allow_state_changing=True)
    assert requests == [] and not attempts
    assert 'no_sqli_candidate_observation' in json.dumps(result.public_dict())
