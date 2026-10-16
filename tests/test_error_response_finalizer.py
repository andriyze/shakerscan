"""A diagnostic proof must survive report projection with its exact contract."""
from types import SimpleNamespace

import pytest

from api.capabilities.exposure_probe import classify_exposure
from api.scan.action_adapter import _exposure_observation
from api.scan.action_plan import ScanActionPlan
from api.scan.finalizer import finalize_scan_report
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action


def observation():
    body = (b'Traceback (most recent call last):\n  File "/app/report.py", line 12, in render\n'
            b'    raise ValueError("failed")\nValueError: failed')
    signature = classify_exposure(path='/report', status=500,
        headers={'Content-Type': 'text/plain'}, body=body)
    return _exposure_observation('https://app.example.test/report', 'discovered_endpoint', signature,
        SimpleNamespace(status_code=500, response_headers={'Content-Type': 'text/plain'}, response_body=body))


def report_for(item):
    action = _action('verify.exposure', 0, capability_name='exposure.verify_batch')
    final = _action('finalize.report', 1, dependencies=(action.action_id,))
    plan = ScanActionPlan(scan_id=SCAN_ID, execution_plan_digest='b' * 64,
                         target_binding_digest='a' * 64, actions=(action, final))
    return finalize_scan_report(plan=plan, target_url='https://app.example.test',
        action_results={action.action_id: _result_with_observation_count(action, 1)},
        observations={action.action_id: (item,)})


def test_stack_disclosure_becomes_a_finding_with_its_observed_500_and_v2_contract():
    report = report_for(observation())
    finding, = report['findings']
    assert finding['verified'] is True and finding['severity'] == 'medium'
    assert finding['evidence']['proof_contract'] == 'verbose_error_exposure/v2'
    assert finding['evidence']['response_status'] == 500
    assert 'content withheld' in finding['evidence']['redacted_excerpt']


@pytest.mark.parametrize('changes', [
    {'response_status': 200}, {'response_status': 403},
    {'matched_signature': 'server_error_disclosure'},
    {'exposure_class': 'configuration_secret_file'},
])
def test_a_stored_contract_name_cannot_override_class_signature_or_status(changes):
    assert report_for({**observation(), **changes})['findings'] == []
