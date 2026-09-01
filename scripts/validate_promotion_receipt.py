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
    "model_intake_physical": "model_intake_physical",
}


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
    if not isinstance(exclusions, list) or any(not isinstance(item, str) for item in exclusions):
        raise PromotionReceiptError("certification scope exclusions must be a string list")
    expected_exclusions = sorted(
        exclusion
        for check, exclusion in OPTIONAL_CHECK_TO_EXCLUSION.items()
        if checks.get(check) == "not_run_optional_boundary"
    )
    if sorted(exclusions) != expected_exclusions:
        raise PromotionReceiptError(
            "scope exclusions do not match optional checks recorded as not run"
        )


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
