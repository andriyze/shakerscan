"""The server_injection family: registered, planned, and finalized only from repeated proof."""
from __future__ import annotations

import pytest

from api.check_registry import get_check_family
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.scan.contracts import SCAN_V2_FAMILY_NAMES, public_scan_contract, resolve_scan_contract


def test_server_injection_is_a_registered_canonical_family_and_opt_in():
    assert "server_injection" in SCAN_V2_FAMILY_NAMES
    spec = get_check_family("server_injection")
    assert spec is not None and spec.is_active
    assert get_check_family("ssti").name == "server_injection"
    assert CAPABILITY_REGISTRY.require("injection.verify_batch").output_schema == "injection-verify-batch/v1"
    contract = public_scan_contract()
    family = next(item for item in contract["families"] if item["name"] == "server_injection")
    assert family["capabilities"] == ["injection.verify_batch"]
    assert family["requires_active_testing"] is True
    # In no preset: a Scan runs it only when it is named.
    assert all("server_injection" not in families for families in contract["family_presets"].values())
    with pytest.raises(ValueError, match="active_testing is required"):
        resolve_scan_contract(budget_profile="balanced", policy={
            "preset": "custom", "active_testing": False, "include_families": ["server_injection"],
        })


def test_compiler_emits_a_local_injection_batch_when_the_family_is_named():
    from api.scan.action_plan import ScanActionPlanCompiler
    from tests.test_scan_action_compiler import _execution, _target as _compiler_target

    def capabilities(include, exclude=()):
        plan = ScanActionPlanCompiler().compile(
            scan_id="60000000-0000-4000-8000-000000000001",
            execution_plan=_execution(include=include, exclude=exclude, active=True),
            target_binding=_compiler_target(), action_scope="full",
        )
        return plan, {action.capability_name for action in plan.actions}

    plan, named = capabilities(("server_injection",))
    assert "injection.verify_batch" in named
    action = next(a for a in plan.actions if a.capability_name == "injection.verify_batch")
    assert list(action.placement["eligible_backends"]) == ["local"]
    assert action.action_id.startswith("verify.server_injection")
    # Query candidates are read with GET: no write is reserved for them.
    assert "state_changing_requests" not in action.requested_budget
    _plan, others = capabilities(("xss", "sqli"))
    assert "injection.verify_batch" not in others
    # A plan that names no families (a legacy plan without resolved families enables every family
    # it does not exclude) never runs it: it is opt-in.
    _plan, unnamed = capabilities((), exclude=("nuclei_passive", "nuclei_active"))
    assert "injection.verify_batch" not in unnamed
    assert "nosqli.verify_batch" in unnamed


def _proof(injection_class, contract, **changes):
    return {
        "kind": "injection_proof", "injection_class": injection_class,
        "candidate_id": f"candidate-{injection_class}", "method": "GET", "field_path": "q",
        "canonical_path": "/render", "origin": "https://app.example.test",
        "request_class": "safe_read", "proof_state": "verified", "finding_verdict": "verified",
        "proof_contract": contract, "technique": "arithmetic_double_brace_repeated",
        "payload_shape": "{{<n>*<n>}}", "repetitions": 2,
        "response_pairs": [{"control_status": 200, "payload_status": 200}] * 2,
        **changes,
    }


def test_finalizer_promotes_each_class_only_from_repeated_verified_proof():
    from api.scan.action_plan import ScanActionPlan
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_finalizer import _result_with_observation_count
    from tests.test_scan_orchestrator import SCAN_ID, _action

    verify = _action("verify.server_injection", 0, capability_name="injection.verify_batch")
    final = _action("finalize.report", 1, dependencies=(verify.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(verify, final),
    )
    observations = {verify.action_id: (
        _proof("template_injection", "injection_template_differential/v1"),
        _proof("command_injection", "injection_command_differential/v1"),
        _proof("path_traversal", "injection_path_traversal_differential/v1",
               file_signature="unix_passwd"),
        _proof("xxe", "injection_xxe_differential/v1", file_signature="unix_passwd"),
        _proof("ssrf", "injection_ssrf_differential/v1"),
        # Not proof: one repetition, an unknown class, a contract of another family, not proven.
        _proof("template_injection", "injection_template_differential/v1", repetitions=1,
               candidate_id="once"),
        _proof("made_up", "injection_template_differential/v1", candidate_id="unknown-class"),
        _proof("path_traversal", "nosqli_operator_differential/v1", candidate_id="other-family"),
        _proof("command_injection", None, proof_state="not_proven",
               finding_verdict="not_proven", candidate_id="not-proven"),
    )}
    results = {verify.action_id: _result_with_observation_count(verify, len(observations[verify.action_id]))}

    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations,
    )

    by_cwe = {finding["cwe"]: finding for finding in report["findings"]}
    assert set(by_cwe) == {"CWE-1336", "CWE-78", "CWE-22", "CWE-611", "CWE-918"}
    assert {cwe: finding["severity"] for cwe, finding in by_cwe.items()} == {
        "CWE-1336": "critical", "CWE-78": "critical", "CWE-22": "high", "CWE-611": "high",
        "CWE-918": "high",
    }
    for finding in by_cwe.values():
        assert finding["tool"] == "shakerscan_injection_verify"
        assert finding["verified"] is True and finding["proof_state"] == "verified"
        assert finding["evidence"]["canonical_capability"] == "injection.verify_batch"
    assert by_cwe["CWE-22"]["evidence"]["file_signature"] == "unix_passwd"


def test_the_finding_detail_names_the_class_and_never_a_response_body():
    from api.finding_detail import build_finding_detail as build_detail

    finding = {
        "tool": "shakerscan_injection_verify", "title": "Verified path traversal",
        "severity": "high", "cwe": "CWE-22", "url": "https://app.example.test/download",
        "proof_state": "verified", "verified": True,
        "evidence": {
            "method": "GET", "field_path": "file", "injection_class": "path_traversal",
            "payload_shape": "../../../../../../../../etc/passwd",
            "file_signature": "unix_passwd", "repetitions": 2,
            "technique": "file_signature_dot_dot_slash_repeated",
            "response_pairs": [{"control_status": 404, "payload_status": 200}] * 2,
        },
    }
    detail = build_detail(finding)
    assert detail["class"] == "injection.path_traversal"
    assert detail["class_label"] == "Path traversal"
    assert "root:" not in str(detail)
