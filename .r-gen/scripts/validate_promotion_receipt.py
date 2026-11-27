#!/usr/bin/env python3
"""Validate the per-check acceptance contract of a certified release receipt."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping

try:
    from scripts.certify_release_receipt import (
        CERTIFICATION_CHECK_ACCEPTED_STATES,
        CERTIFICATION_CHECKS_SCHEMA_VERSION,
    )
except ModuleNotFoundError:  # Direct execution: python3 scripts/validate_promotion_receipt.py
    from certify_release_receipt import (  # type: ignore[no-redef]
        CERTIFICATION_CHECK_ACCEPTED_STATES,
        CERTIFICATION_CHECKS_SCHEMA_VERSION,
    )


class PromotionReceiptError(RuntimeError):
    """A certified receipt cannot be promoted under the current contract."""


OPTIONAL_CHECK_TO_EXCLUSION = {
    "real_fleet_parity": "real_fleet_parity",
    "model_intake_physical": "model_intake_physical",
    "device_physical": "device_physical",
}
# Boundaries an authorized declared-debt release may record as waived, by name.
WAIVER_BOUNDARIES = frozenset({
    "complete_dast_quality_bar",
    "installed_stack_e2e_declared_debt",
    "mature_subsystem_preservation_declared_debt",
})


def validate_certification_checks(receipt: Mapping[str, Any]) -> None:
    certification = receipt.get("certification")
    if not isinstance(certification, Mapping) or certification.get("status") != "pass":
        raise PromotionReceiptError("candidate certification status is not pass")
    if certification.get("checks_schema_version") != CERTIFICATION_CHECKS_SCHEMA_VERSION:
        raise PromotionReceiptError("unsupported certification checks schema")
    checks = certification.get("checks")
    if not isinstance(checks, Mapping):
        raise PromotionReceiptError("candidate certification checks are missing")
    expected = set(CERTIFICATION_CHECK_ACCEPTED_STATES)
    actual = set(checks)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise PromotionReceiptError(
            f"certification check set mismatch: missing={missing}, unexpected={unexpected}"
        )
    for name, accepted in CERTIFICATION_CHECK_ACCEPTED_STATES.items():
        state = checks.get(name)
        if state not in accepted:
            raise PromotionReceiptError(
                f"certification check {name} has unaccepted state {state!r}"
            )

    exclusions = certification.get("scope_exclusions")
    if not isinstance(exclusions, list):
        raise PromotionReceiptError("certification scope exclusions must be a list")
    optional_exclusions = sorted(item for item in exclusions if isinstance(item, str))
    waiver_records = [item for item in exclusions if isinstance(item, Mapping)]
    if len(optional_exclusions) + len(waiver_records) != len(exclusions):
        raise PromotionReceiptError("certification scope exclusions must be names or waiver records")
    expected_exclusions = sorted(
        exclusion
        for check, exclusion in OPTIONAL_CHECK_TO_EXCLUSION.items()
        if checks.get(check) == "not_run_optional_boundary"
    )
    if optional_exclusions != expected_exclusions:
        raise PromotionReceiptError(
            "scope exclusions do not match optional checks recorded as not run"
        )
    # Every waiver record must name a known boundary in the waived state, and every waived
    # check must be backed by its record, so a receipt can never carry a silent waiver.
    boundaries: list[str] = []
    for record in waiver_records:
        boundary = str(record.get("boundary") or "")
        if boundary not in WAIVER_BOUNDARIES or record.get("state") != "waived_declared_debt":
            raise PromotionReceiptError(f"unknown or unwaived scope-exclusion record: {boundary!r}")
        boundaries.append(boundary)
    if len(set(boundaries)) != len(boundaries):
        raise PromotionReceiptError("duplicate scope-exclusion records")
    dast_waived = {
        checks.get("complete_dast_quality_bar"), checks.get("dast_release_quality_contract"),
    }
    if dast_waived == {"waived_declared_debt"}:
        if "complete_dast_quality_bar" not in boundaries:
            raise PromotionReceiptError("waived DAST quality bar has no scope-exclusion record")
    elif dast_waived != {"pass"}:
        raise PromotionReceiptError("DAST quality checks must be waived together or pass together")
    elif "complete_dast_quality_bar" in boundaries:
        raise PromotionReceiptError("DAST quality scope-exclusion record without a waived check")


def _read(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PromotionReceiptError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise PromotionReceiptError("release receipt must contain one JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        validate_certification_checks(_read(args.receipt))
    except PromotionReceiptError as exc:
        print(f"release promotion receipt rejected: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
