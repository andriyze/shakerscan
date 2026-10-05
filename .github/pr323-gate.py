"""Keep exact canonical exceptions usable for scan report projections."""
from pathlib import Path
import importlib.util
import subprocess

for name in ('api/api.py', 'tests/test_deployment_gate.py'):
    expected = subprocess.check_output(['git', 'rev-parse', '46b37dd6b73a568c09ba395e32c258c6e6a0bc0a:' + name])
    actual = subprocess.check_output(['git', 'hash-object', name])
    if actual != expected:
        raise RuntimeError('Refusing to overwrite changed source: ' + name)
spec = importlib.util.spec_from_file_location('repair', Path('.github/pr323-repair.py'))
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)
repair.replace('api/api.py', '        if fingerprint and not item.get("finding_id"):\n', '        if fingerprint:\n')
repair.replace('api/api.py',
    '        fingerprints = {str(finding.get("fingerprint") or ""), canonical_finding_fingerprint(finding)}',
    '        fingerprints = {str(finding.get("fingerprint") or canonical_finding_fingerprint(finding))}')
repair.append('tests/test_deployment_gate.py', '''def test_migrated_exact_exception_covers_a_report_without_a_database_row_id():
    finding = {"title": "SQL Injection", "severity": "critical", "tool": "sqlmap", "cwe": "CWE-89",
               "url": "https://app.example.test/search?q=1", "evidence": {"method": "GET", "param": "q"}}
    exception = {"id": "exception", "finding_id": "persisted-row", "status": "active", "approver": "operator",
                 "fingerprint": canonical_finding_fingerprint(finding), "expires_at": "2099-01-01T00:00:00Z"}
    decision = api.build_deployment_decision(_scan([finding]), db_exceptions=[exception])
    assert decision["blocking_findings"] == []
    assert len(decision["applied_exceptions"]) == 1
    assert decision["decision"] == "needs_approval"
    other_service = {**finding, "url": "https://app.example.test:8443/search?q=1"}
    decision = api.build_deployment_decision(_scan([other_service]), db_exceptions=[exception])
    assert len(decision["blocking_findings"]) == 1
    assert decision["applied_exceptions"] == []


def test_a_projected_row_never_gains_a_broader_recomputed_fingerprint():
    full = {"title": "Certificate is untrusted", "severity": "high", "tool": "tls.inspect", "cwe": "CWE-295",
            "url": "https://app.example.test/", "evidence": {"check": "certificate_untrusted"}}
    projected = {k: v for k, v in full.items() if k != "evidence"}
    projected["fingerprint"] = canonical_finding_fingerprint(full)
    broader = canonical_finding_fingerprint(projected)
    assert broader != projected["fingerprint"]
    exception = {"id": "exception", "status": "active", "approver": "operator", "fingerprint": broader,
                 "expires_at": "2099-01-01T00:00:00Z"}
    remaining, applied = api._apply_policy_exceptions([projected], [exception])
    assert remaining == [projected] and applied == []''')
