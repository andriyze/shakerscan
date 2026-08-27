from __future__ import annotations

from api.capabilities.exposure_probe import (
    SENSITIVE_SEED_PATHS,
    classify_confidential_file,
    classify_exposure,
    directory_listing_links,
    redacted_exposure_excerpt,
)
from api.check_registry import get_check_family
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.scan.action_plan import ScanActionPlan, ScanActionPlanCompiler
from api.scan.contracts import (
    SCAN_MINIMUM_FAMILY_QUOTAS,
    SCAN_V2_FAMILY_NAMES,
    public_scan_contract,
)
from api.scan.finalizer import finalize_scan_report
from tests.test_scan_action_compiler import _execution, _target
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action


def test_secret_material_outranks_structural_disclosure():
    private_key = classify_exposure(
        path="/id_rsa", status=200, headers={"Content-Type": "text/plain"},
        body=b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn...",
    )
    assert private_key is not None
    assert private_key.exposure_class == "private_key_material"
    assert private_key.severity == "critical"

    aws = classify_exposure(
        path="/config", status=200, headers={"Content-Type": "text/plain"},
        body=b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )
    assert aws is not None and aws.severity == "critical"


def test_deterministic_response_signatures_classify_high_exposure():
    cases = {
        "/metrics": (b"# HELP up 1\n# TYPE up gauge\nup 1\n", "metrics_endpoint"),
        "/.env": (b"SECRET_KEY=abc123def456\nDEBUG=true\n", "environment_secret_file"),
        "/.git/config": (b"[core]\n\trepositoryformatversion = 0\n", "version_control_exposure"),
        "/actuator/env": (b'{"activeProfiles":["prod"],"_links":{}}', "actuator_endpoint"),
    }
    for path, (body, expected) in cases.items():
        content_type = "application/json" if expected == "actuator_endpoint" else "text/plain"
        signature = classify_exposure(
            path=path, status=200, headers={"Content-Type": content_type}, body=body,
        )
        assert signature is not None, path
        assert signature.exposure_class == expected
        assert signature.severity == "high"


def test_soft_200_and_denied_responses_are_never_exposures():
    # A SPA shell returned for everything must not inflate exposure coverage.
    assert classify_exposure(
        path="/metrics", status=200, headers={"Content-Type": "text/html"},
        body=b"<!doctype html><html><body>app shell</body></html>",
    ) is None
    for status in (401, 403, 404, 500):
        assert classify_exposure(
            path="/.env", status=status, headers={"Content-Type": "text/plain"},
            body=b"SECRET_KEY=abc123",
        ) is None
    assert classify_exposure(
        path="/.env", status=200, headers={"Content-Type": "text/plain"}, body=b"",
    ) is None


def test_directory_listing_follows_only_bounded_relative_files():
    listing = (
        b"<title>Index of /ftp</title>"
        b'<a href="acquisitions.md">acquisitions.md</a>'
        b'<a href="../">Parent</a>'
        b'<a href="/absolute">abs</a>'
        b'<a href="http://evil.test/x">ext</a>'
        b'<a href="sub/">sub dir</a>'
    )
    assert classify_exposure(
        path="/ftp", status=200, headers={"Content-Type": "text/html"}, body=listing,
    ).exposure_class == "directory_listing"
    assert directory_listing_links(listing) == ("acquisitions.md",)

    confidential = classify_confidential_file(
        status=200, headers={"Content-Type": "text/markdown"},
        body=b"# Internal acquisitions\nConfidential deal terms.",
    )
    assert confidential is not None
    assert confidential.exposure_class == "confidential_file"
    # An HTML page reached from a listing is the app, not a confidential file.
    assert classify_confidential_file(
        status=200, headers={"Content-Type": "text/html"}, body=b"<html>page</html>",
    ) is None


def test_secret_material_excerpt_withholds_content():
    body = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA_secret_bytes\n"
    signature = classify_exposure(
        path="/id_rsa", status=200, headers={"Content-Type": "text/plain"}, body=body,
    )
    excerpt = redacted_exposure_excerpt(body, signature)
    assert "PRIVATE KEY" not in excerpt
    assert "_secret_bytes" not in excerpt
    assert "content withheld" in excerpt


def test_structural_disclosure_excerpt_redacts_inline_secret_values():
    # A verbose error page can echo a secret in key=value form; redact it.
    body = (
        b"Fatal error: connect failed on line 12 "
        b"with password=SuperSecret123! and host=db"
    )
    signature = classify_exposure(
        path="/crash", status=200, headers={"Content-Type": "text/plain"}, body=body,
    )
    assert signature is not None and signature.exposure_class == "verbose_error_disclosure"
    excerpt = redacted_exposure_excerpt(body, signature)
    assert "SuperSecret123!" not in excerpt
    assert "[REDACTED]" in excerpt


def test_sensitive_exposure_is_a_registered_canonical_family():
    assert "sensitive_exposure" in SCAN_V2_FAMILY_NAMES
    assert get_check_family("sensitive_exposure").is_active is True
    assert get_check_family("exposure").name == "sensitive_exposure"  # alias
    spec = CAPABILITY_REGISTRY.require("exposure.verify_batch")
    assert spec.required_approval == "active_testing"
    assert "sensitive_exposure_proof" in spec.evidence_contract
    for profile in ("fast", "balanced", "thorough"):
        assert SCAN_MINIMUM_FAMILY_QUOTAS[profile]["sensitive_exposure"] >= 5
    contract = public_scan_contract()
    families = {item["name"] for item in contract["families"]}
    assert "sensitive_exposure" in families
    assert SENSITIVE_SEED_PATHS  # curated wordlist is non-empty


def test_compiler_emits_exposure_batch_only_when_family_selected():
    target = _target()
    with_family = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("sensitive_exposure",), active=True),
        target_binding=target, action_scope="full",
    )
    caps = {action.capability_name for action in with_family.actions}
    assert "exposure.verify_batch" in caps
    exposure = next(
        action for action in with_family.actions
        if action.capability_name == "exposure.verify_batch"
    )
    # Batch capability: single-worker local adapter only.
    assert list(exposure.placement["eligible_backends"]) == ["local"]

    without_family = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("xss",), active=True),
        target_binding=target, action_scope="full",
    )
    assert "exposure.verify_batch" not in {
        action.capability_name for action in without_family.actions
    }


def test_finalizer_promotes_only_deterministic_sensitive_exposure_proof():
    probe = _action("verify.exposure", 0, capability_name="exposure.verify_batch")
    final = _action("finalize.report", 1, dependencies=(probe.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(probe, final),
    )
    results = {probe.action_id: _result_with_observation_count(probe, 2)}
    observations = {probe.action_id: (
        {
            "kind": "sensitive_exposure_proof",
            "proof_state": "verified", "finding_verdict": "verified",
            "exposure_class": "private_key_material", "severity": "critical",
            "request_url": "https://app.example.test/id_rsa",
            "discovered_via": "seed_path", "response_status": 200,
            "content_type": "text/plain", "response_body_sha256": "c" * 64,
            "matched_signature": "private_key", "redacted_excerpt": "-----BEGIN",
        },
        {
            # A soft-200 non-signature attempt must never promote.
            "kind": "sensitive_exposure_proof",
            "proof_state": "not_proven", "finding_verdict": "not_proven",
            "exposure_class": "", "response_status": 200,
            "response_body_sha256": "d" * 64,
        },
    )}

    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations,
    )

    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["tool"] == "shakerscan_exposure_probe"
    assert finding["severity"] == "critical"
    assert finding["cwe"] == "CWE-538"
    assert finding["verified"] is True
    assert finding["evidence"]["canonical_capability"] == "exposure.verify_batch"
    assert finding["evidence"]["exposure_class"] == "private_key_material"


def test_ordinary_json_apis_are_not_actuator_exposures():
    """``"status"`` is one of the most common keys in any JSON API.

    Matching it bare classified every ordinary REST response as a
    high-severity actuator exposure, so a single application produced a page
    of duplicate false positives -- including endpoints whose 200 body says
    the endpoint is not supported.
    """
    ordinary = (
        b'{"status":"success","data":[{"id":1,"quantity":35}]}',
        b'{"status":"success","data":{"err":"Sorry, this endpoint is not supported."}}',
        b'{"status":"ok"}',
        b'{"status":200,"message":"created"}',
    )
    for body in ordinary:
        assert classify_exposure(
            path="/api/Quantitys", status=200,
            headers={"Content-Type": "application/json"}, body=body,
        ) is None, body


def test_real_actuator_shapes_are_still_detected():
    """Narrowing the pattern must not lose genuine actuator disclosure."""
    for body in (
        b'{"activeProfiles":["prod"],"_links":{}}',
        b'{"status":"UP","components":{"db":{"status":"UP"}}}',
        b'{"diskSpace":{"total":1,"free":1}}',
    ):
        signature = classify_exposure(
            path="/actuator/health", status=200,
            headers={"Content-Type": "application/json"}, body=body,
        )
        assert signature is not None, body
        assert signature.exposure_class == "actuator_endpoint"
        assert signature.severity == "high"
