"""The real exposure batch preserves 500 diagnostic evidence without leaking it."""
import json

from tests.test_exposure_probe_batch_controls import _run


def test_discovered_500_stack_reaches_scan_evidence_with_its_wire_status(monkeypatch):
    canary = 'unclassified-credential-' + 'q9Wr7vL2xK'
    trace = ('Traceback (most recent call last):\n  File "/app/report.py", line 12, in render\n'
             '    raise ValueError("render failed")\nValueError: render failed\n' + canary).encode()
    receipt, proofs, transport = _run(monkeypatch,
        lambda url: (500, trace) if url.endswith('/report') else (404, b'not found'),
        paths=('/report',))
    assert len(proofs) == 1
    proof = proofs[0]
    assert proof['proof_state'] == 'verified'
    assert proof['proof_contract'] == 'verbose_error_exposure/v2'
    assert proof['response_status'] == 500
    assert proof['response_body_sha256'] is None and proof['response_body_hmac']
    assert canary not in json.dumps(receipt.observations)
    assert '/app/report.py' not in json.dumps(receipt.observations)
    assert all(url.startswith('https://app.example.test/') for url in transport.sent)
