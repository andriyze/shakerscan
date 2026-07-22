import importlib.util
import os
import sys

_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
_spec = importlib.util.spec_from_file_location(
    "shaker_webhook_checks_under_test",
    os.path.join(_SCANNER_DIR, "scanner_tools", "webhook_checks.py"),
)
_added = _SCANNER_DIR not in sys.path
if _added:
    sys.path.insert(0, _SCANNER_DIR)
try:
    wc = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(wc)
finally:
    if _added:
        sys.path.remove(_SCANNER_DIR)


def test_candidate_webhook_paths_filters_to_webhook_shapes():
    cands = wc._candidate_webhook_paths([
        "POST /api/webhooks/stripe",
        "GET /api/users?id=1",
        "POST /n8n/webhook/abc",
        "POST /api/login",
        "POST /api/webhooks/github",
        {"method": "POST", "url": "/api/webhooks/generic"},
    ])
    assert "/api/webhooks/stripe" in cands
    assert "/n8n/webhook/abc" in cands
    assert "/api/webhooks/github" in cands
    assert "/api/webhooks/generic" in cands
    assert all("login" not in c and "/api/users" not in c for c in cands)


def test_accept_vs_reject_markers():
    # honey's unsigned-webhook acceptance response
    assert wc._ACCEPTED_MARKERS.search(
        '{"processed":true,"event_id":"evt_1","findings":["webhook_signature_bypass"]}'
    )
    # a secure receiver that rejects the unsigned request
    assert wc._REJECTED_MARKERS.search('{"error":"invalid signature"}')
    assert wc._REJECTED_MARKERS.search('{"detail":"signature required"}')
    # benign non-webhook body should not look accepted
    assert not wc._ACCEPTED_MARKERS.search('{"items":[1,2,3]}')
