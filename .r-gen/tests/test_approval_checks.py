import importlib.util
import os
import sys

_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
_spec = importlib.util.spec_from_file_location(
    "shaker_approval_checks_under_test",
    os.path.join(_SCANNER_DIR, "scanner_tools", "approval_checks.py"),
)
_added = _SCANNER_DIR not in sys.path
if _added:
    sys.path.insert(0, _SCANNER_DIR)
try:
    ac = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(ac)
finally:
    if _added:
        sys.path.remove(_SCANNER_DIR)


def test_candidate_paths_filters_to_approval_shapes():
    cands = ac._candidate_paths([
        "POST /api/fintech/wires/approve",
        "POST /api/ecommerce/refunds/approve",
        "POST /api/hris/manager/delegate",
        "POST /api/support/impersonate",
        "POST /api/healthcare/prior-auth",
        "GET /api/users?id=1",
        "POST /api/login",
    ])
    for p in ("/api/fintech/wires/approve", "/api/ecommerce/refunds/approve",
              "/api/hris/manager/delegate", "/api/support/impersonate", "/api/healthcare/prior-auth"):
        assert p in cands
    assert all("login" not in c and "/api/users" not in c for c in cands)


def test_accept_vs_reject_markers():
    assert ac._ACCEPTED_RE.search('{"approved":true,"findings":["fintech_wire_callback_bypass"]}')
    assert ac._ACCEPTED_RE.search('{"approved": true, "approver_role": "support"}')
    assert ac._REJECTED_RE.search('{"detail":"unauthorized"}')
    assert ac._REJECTED_RE.search('{"error":"requires dual approval"}')
    assert not ac._ACCEPTED_RE.search('{"items":[1,2,3]}')
