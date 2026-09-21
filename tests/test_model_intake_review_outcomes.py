"""The automatic review must name the runner receipt's verdict and failing phase."""

from pathlib import Path
import json
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from model_intake.review_outcomes import (  # noqa: E402
    CALIBRATION_ACCEPTED,
    observed_embedding_digest,
    require_runner_receipt,
    runner_outcome,
)


def _job(status, errors=None, digest=None):
    observations = {"errors": errors or []}
    if digest:
        observations["embedding_output_sha256"] = digest
    return {"result_json": json.dumps({"payload": {"status": status, "observations": observations}})}


def test_runner_outcome_reads_the_verdict_and_first_phase_failure():
    job = _job("FAIL", [
        {"phase": "deserialize_convert", "type": "RuntimeError",
         "message": "Some tensors share memory; safetensors refuses tied tensors"},
        {"phase": "teardown", "type": "ValueError", "message": "later"},
    ])
    status, detail = runner_outcome(job)
    assert status == "FAIL"
    assert detail.startswith("phase deserialize_convert failed with RuntimeError: Some tensors share memory")
    assert runner_outcome(_job("PASS")) == ("PASS", None)
    assert runner_outcome({"result_json": None}) == ("UNKNOWN", None)


def test_conversion_and_runtime_require_a_pass_receipt():
    with pytest.raises(RuntimeError, match=r"controlled conversion did not pass \(runner receipt FAIL\): phase deserialize_convert"):
        require_runner_receipt(_job("FAIL", [{"phase": "deserialize_convert", "type": "RuntimeError", "message": "tied"}]), step="controlled conversion")
    with pytest.raises(RuntimeError, match="see the signed runner receipt"):
        require_runner_receipt(_job("TIMEOUT"), step="runtime verification")
    require_runner_receipt(_job("PASS"), step="runtime verification")


def test_calibration_tolerates_the_expected_fail_but_not_a_run_that_never_finished():
    require_runner_receipt(_job("FAIL"), step="calibration", accepted=CALIBRATION_ACCEPTED)
    with pytest.raises(RuntimeError, match=r"calibration did not complete \(runner receipt CRASHED\)"):
        require_runner_receipt(_job("CRASHED"), step="calibration", accepted=CALIBRATION_ACCEPTED)


def test_observed_embedding_digest_is_validated():
    assert observed_embedding_digest(_job("FAIL", digest="a" * 64)) == "a" * 64
    assert observed_embedding_digest(_job("FAIL", digest="A" * 64)) == "a" * 64
    assert observed_embedding_digest(_job("FAIL", digest="zz")) is None
    assert observed_embedding_digest({"result_json": "not json"}) is None
