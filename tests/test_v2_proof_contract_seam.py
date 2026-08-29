"""A satisfied V2 deterministic proof contract must survive the API boundary.

The finalizer stamps a deterministic proof with `proof_contract`, `evidence_type:
deterministic_differential`, `proof_state: verified` and `triage.verified: true` after
re-executing it. `scan_time_verification_fields` recognised only the V1 vocabulary
(`proof_type` in a fixed set, `proof_of_exploitation`, browser proof), which shares no key with
what V2 emits -- so it returned None and the finding persisted as `is_verified: false`,
`proof_state: suspected`.

Live effect on this build: finding 1e9ff7e3 titled "Verified SQL injection", CVSS 9.5, with a
complete `sqli_error_differential/v2` contract and two repetitions, rendered in the UI as
"Suspected", which the legend defines as "a lead, not confirmed". The whole V2 proof chain was
silently demoted, excluded from verified-only filters and from the headline grade.

Two independent audits found this from opposite ends -- the UI showing a contradiction, and the
code showing no overlap between the vocabularies -- and no test spanned the seam.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scanner"))

from scan_verification_state import scan_time_verification_fields  # noqa: E402


def _v2_contract_evidence(**overrides):
    """The exact shape api/scan/finalizer.py emits for a satisfied deterministic contract."""
    evidence = {
        "method": "GET",
        "field_path": "q",
        "technique": "error_based_repeated",
        "repetitions": 2,
        "evidence_type": "deterministic_differential",
        "proof_contract": "sqli_error_differential/v2",
        "proof_state": "verified",
        "triage": {"verified": True, "suspected": False, "needs_verification": False},
    }
    evidence.update(overrides)
    return evidence


def test_a_satisfied_v2_contract_is_recognised_as_proof():
    fields = scan_time_verification_fields(
        {"severity": "critical", "evidence": _v2_contract_evidence()})
    assert fields is not None, "the V2 proof vocabulary must be recognised"
    assert fields["last_verification_verdict"] == "exploited"


def test_the_suspected_shape_is_still_not_proof():
    # What sqlmap's candidate finding actually carries: no contract, triage says unverified.
    suspected = {
        "url": "http://target.test/rest/user/login",
        "param": "JSON email",
        "proof_state": "likely_vulnerable",
        "triage": {"verified": False, "suspected": True, "needs_verification": True},
    }
    fields = scan_time_verification_fields({"severity": "high", "evidence": suspected})
    assert (fields or {}).get("last_verification_verdict") != "exploited"


def test_every_marker_of_the_contract_is_required():
    """The triple is what the finalizer only emits after re-executing a deterministic contract.

    Any one of them alone is a weaker signal that must not promote -- which is the same reason a
    bare `verified: true` is rejected as a generic legacy flag.
    """
    for dropped in ("proof_contract", "proof_state"):
        evidence = _v2_contract_evidence()
        evidence.pop(dropped)
        fields = scan_time_verification_fields({"severity": "critical", "evidence": evidence})
        assert (fields or {}).get("last_verification_verdict") != "exploited", dropped

    unverified_triage = _v2_contract_evidence(
        triage={"verified": False, "suspected": True, "needs_verification": True})
    fields = scan_time_verification_fields(
        {"severity": "critical", "evidence": unverified_triage})
    assert (fields or {}).get("last_verification_verdict") != "exploited"


def test_a_bare_verified_flag_still_does_not_promote():
    # The existing rule this fix must not weaken.
    for finding in ({"severity": "critical", "verified": True},
                    {"severity": "critical", "evidence": {"verified": True}}):
        fields = scan_time_verification_fields(finding)
        assert (fields or {}).get("last_verification_verdict") != "exploited", finding


def test_persisted_retest_verdict_is_not_reinterpreted_as_scan_time_proof():
    fields = scan_time_verification_fields({
        "severity": "critical",
        "last_verification_verdict": "exploited",
    })
    assert fields is None


def test_a_registry_rejected_contract_is_capped_not_promoted():
    # A detector family whose registry contract was judged unmet is capped at likely_vulnerable,
    # and a V2 proof marker must not route around that.
    fields = scan_time_verification_fields({
        "severity": "critical",
        "evidence": _v2_contract_evidence(),
        "registry_contract": {"contract_satisfied": False},
    })
    assert fields["last_verification_verdict"] == "likely_vulnerable"


def test_the_projection_the_ui_reads_agrees():
    """`finding_proof_fields` is what the list and detail render; it must follow the same rule."""
    import importlib.util

    path = Path(__file__).resolve().parents[1] / "api" / "finding_routes" / "router.py"
    source = path.read_text(encoding="utf-8")
    assert "_scan_time_verification_fields(finding)" in source, (
        "the projection must derive from the same recognizer, or the seam reopens"
    )


def test_the_benchmark_reads_the_field_live_rows_actually_carry():
    """`verified` is not a field the API returns; the derived projection is `is_verified`.

    Reading only `verified` made that half of the expression dead, so a proof-projected row could
    only count through the verdict. It survives a fix to the recognizer, so both are fixed together.
    """
    import importlib.util, inspect, sys as _sys

    spec = importlib.util.spec_from_file_location(
        "benchmark_verified_under_test",
        Path(__file__).resolve().parents[1] / "scripts" / "benchmark_targets.py")
    module = importlib.util.module_from_spec(spec)
    _sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    source = inspect.getsource(module)
    assert 'f.get("is_verified")' in source


def test_evidence_is_read_whether_it_is_a_dict_or_json_text():
    """Database rows carry evidence as JSON text.

    The recognizer accepted only a dict, so EVERY evidence-derived signal -- proof_of_exploitation,
    payload_executed, extraction_evidence, and the V2 contract -- was invisible for a persisted
    finding and visible only for one still in memory. That is why the fix above worked in isolation
    and the live endpoint still reported suspected.
    """
    import json as _json

    evidence = _v2_contract_evidence()
    as_dict = scan_time_verification_fields({"severity": "critical", "evidence": evidence})
    as_text = scan_time_verification_fields(
        {"severity": "critical", "evidence": _json.dumps(evidence)})
    assert as_dict == as_text
    assert as_text["last_verification_verdict"] == "exploited"

    # A V1 signal is equally affected and must also survive the round trip.
    v1 = {"proof_of_exploitation": True}
    assert scan_time_verification_fields(
        {"severity": "critical", "evidence": _json.dumps(v1)})["last_verification_verdict"] == "exploited"


def test_unreadable_evidence_is_no_evidence():
    # Unparseable text must never promote, and must not raise either.
    for bad in ("not json", "", b"\xff\xfe", "[1,2,3]", "null"):
        fields = scan_time_verification_fields({"severity": "critical", "evidence": bad})
        assert (fields or {}).get("last_verification_verdict") != "exploited", bad
