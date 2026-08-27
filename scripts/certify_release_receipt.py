#!/usr/bin/env python3
"""Promote an immutable manifest receipt only after exact-digest acceptance."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")


class CertificationError(RuntimeError):
    """Release evidence is incomplete, inconsistent, or not candidate-bound."""


def _read(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CertificationError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise CertificationError(f"{path.name} must contain one JSON object")
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise CertificationError(f"cannot hash {path.name}: {exc}") from exc
    return digest.hexdigest()


def certify_receipt(
    *,
    candidate: Mapping[str, Any],
    candidate_path: Path,
    upgrade: Mapping[str, Any],
    upgrade_path: Path,
    preservation: Mapping[str, Any],
    preservation_path: Path,
    e2e: Mapping[str, Any],
    e2e_path: Path,
    source_sha: str,
) -> dict[str, Any]:
    if not SOURCE_SHA.fullmatch(source_sha):
        raise CertificationError("source SHA must be a full lowercase commit identity")
    if candidate.get("schema_version") != "shakerscan-release-candidate/v1":
        raise CertificationError("unsupported candidate receipt schema")
    if candidate.get("candidate_sha") != source_sha:
        raise CertificationError("candidate receipt does not bind the requested source SHA")
    images = candidate.get("images")
    if not isinstance(images, Mapping) or set(images) != {"scanner", "api", "ui", "signer"}:
        raise CertificationError("candidate receipt must contain the four release images")
    if not all(SHA256.fullmatch(str(value)) for value in images.values()):
        raise CertificationError("candidate receipt contains a non-exact image digest")
    provenance = candidate.get("provenance")
    if not isinstance(provenance, Mapping) or provenance.get("verified") is not True:
        raise CertificationError("candidate provenance was not verified")

    if upgrade.get("schema_version") != "stateful-upgrade-acceptance/v2":
        raise CertificationError("unsupported upgrade receipt schema")
    if upgrade.get("status") != "pass":
        raise CertificationError("stateful upgrade acceptance did not pass")
    upgrade_candidate = upgrade.get("candidate")
    if not isinstance(upgrade_candidate, Mapping):
        raise CertificationError("upgrade receipt has no candidate identity")
    if upgrade_candidate.get("source_sha") != source_sha:
        raise CertificationError("upgrade receipt source does not match the candidate")
    if upgrade_candidate.get("image_digest") != images["scanner"]:
        raise CertificationError("upgrade receipt did not run the final scanner manifest digest")
    upgrade_checks = upgrade.get("checks")
    if not isinstance(upgrade_checks, Mapping) or not upgrade_checks or any(
        value != "pass" for value in upgrade_checks.values()
    ):
        raise CertificationError("upgrade receipt contains a failed or missing check")

    if preservation.get("schema_version") != "release-preservation-receipt/v1":
        raise CertificationError("unsupported preservation receipt schema")
    if preservation.get("status") != "pass" or preservation.get("source_sha") != source_sha:
        raise CertificationError("mature-subsystem preservation did not pass for this source")
    if preservation.get("images") != dict(sorted(images.items())):
        raise CertificationError("preservation receipt does not bind the final image digests")

    if e2e.get("schema_version") != "shakerscan-e2e-scorecard/v1" or e2e.get("gate") != "pass":
        raise CertificationError("exact-manifest installed-stack E2E did not pass")
    areas = e2e.get("areas")
    if not isinstance(areas, list) or {item.get("area") for item in areas if isinstance(item, Mapping)} != {
        "platform", "model_intake", "ai_gate", "dast", "hunt",
    }:
        raise CertificationError("exact-manifest E2E did not cover every release area")
    if any(
        item.get("gate") != "pass"
        for item in areas
        if isinstance(item, Mapping)
    ):
        raise CertificationError("an exact-manifest E2E area did not pass")
    # The other three receipts each bind the source they ran against; the E2E scorecard did not,
    # so a run that exercised a different deployment could certify this candidate. Require it to
    # name the revision it actually tested, and the images when it recorded them.
    e2e_subject = e2e.get("subject")
    if not isinstance(e2e_subject, Mapping):
        raise CertificationError("E2E scorecard does not identify the deployment it tested")
    if e2e_subject.get("source_revision") != source_sha:
        raise CertificationError("E2E scorecard tested a different source revision")
    e2e_images = e2e_subject.get("images")
    if e2e_images is not None and dict(e2e_images) != dict(sorted(images.items())):
        raise CertificationError("E2E scorecard did not test the final release image digests")

    result = dict(candidate)
    result["schema_version"] = "shakerscan-release-candidate/v2"
    result["certification"] = {
        "status": "pass",
        "source_sha": source_sha,
        "images": dict(sorted(images.items())),
        "checks": {
            "exact_manifest_installed_stack_e2e": "pass",
            "stateful_previous_stable_upgrade": "pass",
            "database_restart_idempotency": "pass",
            "backup_restore_rollback_boundary": "pass",
            "model_intake_and_mature_subsystems": "pass",
            "source_and_image_identity": "pass",
            "e2e_subject_binding": "pass",
        },
        "evidence_sha256": {
            "uncertified_candidate_receipt": _file_sha256(candidate_path),
            "stateful_upgrade_receipt": _file_sha256(upgrade_path),
            "preservation_receipt": _file_sha256(preservation_path),
            "exact_manifest_e2e_scorecard": _file_sha256(e2e_path),
        },
        "rollback_boundary": str(upgrade.get("rollback_boundary") or ""),
    }
    result.pop("receipt_sha256", None)
    result["receipt_sha256"] = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--upgrade", required=True, type=Path)
    parser.add_argument("--preservation", required=True, type=Path)
    parser.add_argument("--e2e-scorecard", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = certify_receipt(
            candidate=_read(args.candidate),
            candidate_path=args.candidate,
            upgrade=_read(args.upgrade),
            upgrade_path=args.upgrade,
            preservation=_read(args.preservation),
            preservation_path=args.preservation,
            e2e=_read(args.e2e_scorecard),
            e2e_path=args.e2e_scorecard,
            source_sha=args.source_sha,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    except CertificationError as exc:
        print(f"release certification failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
