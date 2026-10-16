"""Server failures can disclose runtime internals; status alone proves nothing."""
import json

import pytest

from api.capabilities.exposure_probe import classify_exposure, redacted_exposure_excerpt
from api.proof_contracts import CANONICAL_PROOF_CONTRACTS


TRACES = [
    ('text/plain', 'Traceback (most recent call last):\n  File "/app/service.py", line 12, in lookup\n'
                   '    raise ValueError("failure")\nValueError: failure'),
    ('application/json', json.dumps({'status': 500, 'trace':
        'java.nio.file.NoSuchFileException: /app/reports/missing.pdf\n'
        '\tat com.example.Report.read(Report.java:42)\n'
        '\tat com.example.Controller.get(Controller.java:18)'})),
    ('text/html', '<html><pre>Error: SQLITE_ERROR: near input\n'
                  '    at /app/build/routes/search.js:90:10\n'
                  '    at Layer.handle (/app/node_modules/router/index.js:20:5)</pre></html>'),
    ('text/plain', 'PHP Fatal error: Uncaught RuntimeException: failed in /var/www/app.php on line 23'),
]


@pytest.mark.parametrize('content_type,body', TRACES)
def test_500_with_runtime_stack_has_a_versioned_proof_and_withholds_all_body(content_type, body):
    canary = 'diagnostic-neighbor-' + 'q9Wv7xLk2m'
    data = (body + '\n' + canary).encode() if content_type != 'application/json' else body.encode()
    signature = classify_exposure(path='/report', status=500, headers={'Content-Type': content_type}, body=data)
    assert signature is not None and signature.exposure_class == 'verbose_error_disclosure'
    assert signature.proves_sensitive_exposure and signature.severity == 'medium'
    assert signature.proof_contract == 'verbose_error_exposure/v2'
    assert signature.proof_contract in CANONICAL_PROOF_CONTRACTS
    excerpt = redacted_exposure_excerpt(data, signature)
    assert 'content withheld' in excerpt
    assert canary not in excerpt and '/app/' not in excerpt


@pytest.mark.parametrize('body', [
    'Internal Server Error', 'Error: request failed', 'Traceback (most recent call last)',
    'Fatal error: temporarily unavailable', '{"status":500,"error":"Internal Server Error"}',
    '{"error":"java.lang.RuntimeException: failure"}',
    'A help page says at com.example.Service.handle(Service.java:12).',
    '<!-- Error: failure\n    at /app/index.js:10:2\n    at /app/server.js:20:2 -->',
    '# HELP up 1\n# TYPE up gauge\nup 1\n',
])
def test_status_and_partial_error_keywords_do_not_prove_disclosure(body):
    assert classify_exposure(path='/report', status=500,
        headers={'Content-Type': 'text/html' if body.startswith('<!--') else 'text/plain'},
        body=body.encode()) is None


@pytest.mark.parametrize('status', [301, 400, 401, 403, 404])
def test_denied_redirected_or_missing_resources_keep_the_existing_boundary(status):
    assert classify_exposure(path='/report', status=status, headers={'Content-Type': 'text/plain'},
                             body=TRACES[0][1].encode()) is None
