#!/usr/bin/env python3
"""Promote an immutable manifest receipt only after exact-digest acceptance."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

try:
    from release_image_inventory import IMAGE_KEYS
except ModuleNotFoundError:
    from scripts.release_image_inventory import IMAGE_KEYS


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")

CERTIFICATION_CHECKS_SCHEMA_VERSION = "release-certification-checks/v1"
CERTIFICATION_CHECK_ACCEPTED_STATES: dict[str, frozenset[str]] = {
    "exact_manifest_installed_stack_e2e": frozenset({"pass"}),
    "stateful_previous_stable_upgrade": frozenset({"pass"}),
    "database_restart_idempotency": frozenset({"pass"}),
    "backup_restore_rollback_boundary": frozenset({"pass"}),
    "mature_subsystem_preservation": frozenset({"pass"}),
    "model_intake_acceptance": frozenset({"pass"}),
    "source_and_image_identity": frozenset({"pass"}),
    "e2e_subject_binding": frozenset({"pass"}),
    # An authorized declared-debt release records the measured shortfall, never a pass; the
    # promotion validator additionally requires the matching scope-exclusion record.
    "complete_dast_quality_bar": frozenset({"pass", "waived_declared_debt"}),
    "dast_release_quality_contract": frozenset({"pass", "waived_declared_debt"}),
    "fault_cancellation": frozenset({"pass"}),
    "fault_reservation_identity": frozenset({"pass"}),
    "fault_action_resume": frozenset({"pass"}),
    "real_fleet_parity": frozenset({"pass", "not_run_optional_boundary"}),
    "model_intake_physical": frozenset({"pass", "not_run_optional_boundary"}),
    "device_physical": frozenset({"pass", "not_run_optional_boundary"}),
}


class CertificationError(RuntimeError):
    """Release evidence is incomplete, inconsistent, or not candidate-bound."""



def _measured_recall(dast):
    targets = dast.get("targets")
    if not isinstance(targets, list) or not targets or not isinstance(targets[0], dict):
        return None
    for key in ("expected_recall", "recall"):
        value = targets[0].get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value
    return None

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
    upgrade: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    upgrade_path: Path | Sequence[Path],
    preservation: Mapping[str, Any],
    preservation_path: Path,
    e2e: Mapping[str, Any],
    e2e_path: Path,
    source_sha: str,
    waive_dast_quality: bool = False,
    waive_e2e_declared_debt: bool = False,
    external_evidence: Mapping[str, tuple[Mapping[str, Any], Path]] | None = None,
    required_upgrade_baselines: set[str] | None = None,
) -> dict[str, Any]:
    if not SOURCE_SHA.fullmatch(source_sha):
        raise CertificationError("source SHA must be a full lowercase commit identity")
    if candidate.get("schema_version") != "shakerscan-release-candidate/v1":
        raise CertificationError("unsupported candidate receipt schema")
    if candidate.get("candidate_sha") != source_sha:
        raise CertificationError("candidate receipt does not bind the requested source SHA")
    images = candidate.get("images")
    if not isinstance(images, Mapping) or set(images) != set(IMAGE_KEYS):
        raise CertificationError("candidate receipt must contain the five release images")
    if not all(SHA256.fullmatch(str(value)) for value in images.values()):
        raise CertificationError("candidate receipt contains a non-exact image digest")
    provenance = candidate.get("provenance")
    if not isinstance(provenance, Mapping) or provenance.get("verified") is not True:
        raise CertificationError("candidate provenance was not verified")
    # The installer verifies every host-side runtime file against install/MANIFEST.sha256 and the
    # manifest against the published image lock; the lock is written from this field at promotion.
    runtime_manifest = candidate.get("runtime_manifest_sha256")
    if not isinstance(runtime_manifest, str) or not re.fullmatch(r"[0-9a-f]{64}", runtime_manifest):
        raise CertificationError("candidate receipt does not bind the runtime manifest digest")

    upgrades = [upgrade] if isinstance(upgrade, Mapping) else list(upgrade)
    upgrade_paths = [upgrade_path] if isinstance(upgrade_path, Path) else list(upgrade_path)
    if not upgrades or len(upgrades) != len(upgrade_paths):
        raise CertificationError("upgrade receipts and paths must be non-empty and aligned")
    upgrade_versions: set[str] = set()
    upgrade_evidence_paths: dict[str, Path] = {}
    for upgrade_receipt, receipt_path in zip(upgrades, upgrade_paths, strict=True):
        if upgrade_receipt.get("schema_version") != "stateful-upgrade-acceptance/v2":
            raise CertificationError("unsupported upgrade receipt schema")
        if upgrade_receipt.get("status") != "pass":
            raise CertificationError("stateful upgrade acceptance did not pass")
        baseline = upgrade_receipt.get("baseline")
        baseline_version = str(baseline.get("version") or "") if isinstance(baseline, Mapping) else ""
        if not baseline_version or baseline_version in upgrade_versions:
            raise CertificationError("upgrade receipts must identify distinct baseline versions")
        upgrade_versions.add(baseline_version)
        upgrade_evidence_paths[baseline_version] = receipt_path
        upgrade_candidate = upgrade_receipt.get("candidate")
        if not isinstance(upgrade_candidate, Mapping):
            raise CertificationError("upgrade receipt has no candidate identity")
        if upgrade_candidate.get("source_sha") != source_sha:
            raise CertificationError("upgrade receipt source does not match the candidate")
        if upgrade_candidate.get("images") != {
            key: images[key] for key in ("scanner", "api", "ui", "model_intake")
        }:
            raise CertificationError("upgrade receipt did not run all final runtime manifest digests")
        upgrade_checks = upgrade_receipt.get("checks")
        if not isinstance(upgrade_checks, Mapping) or not upgrade_checks or any(
            value != "pass" for value in upgrade_checks.values()
        ):
            raise CertificationError("upgrade receipt contains a failed or missing check")
    if required_upgrade_baselines is not None and upgrade_versions != required_upgrade_baselines:
        raise CertificationError(
            "upgrade receipts must cover exactly these baselines: "
            + ", ".join(sorted(required_upgrade_baselines))
        )

    if preservation.get("schema_version") != "release-preservation-receipt/v1":
        raise CertificationError("unsupported preservation receipt schema")
    if preservation.get("status") != "pass" or preservation.get("source_sha") != source_sha:
        raise CertificationError("mature-subsystem preservation did not pass for this source")
    if preservation.get("images") != dict(sorted(images.items())):
        raise CertificationError("preservation receipt does not bind the final image digests")
    if preservation.get("scope_exclusions") != []:
        raise CertificationError("preservation receipt must include deterministic Model Intake")
    preservation_debt = preservation.get("declared_debt_controls") or []
    if not isinstance(preservation_debt, list):
        raise CertificationError("preservation declared-debt controls must be a list")
    if preservation_debt and not waive_e2e_declared_debt:
        raise CertificationError(
            "preservation receipt records declared-debt controls, but this release did not "
            "authorize installed-stack E2E debt"
        )

    if e2e.get("schema_version") != "shakerscan-e2e-scorecard/v1" or e2e.get("gate") != "pass":
        raise CertificationError("exact-manifest installed-stack E2E did not pass")
    areas = e2e.get("areas")
    if not isinstance(areas, list) or {item.get("area") for item in areas if isinstance(item, Mapping)} != {
        "platform", "ai_gate", "dast", "hunt", "model_intake",
    }:
        raise CertificationError("exact-manifest E2E did not cover every release area")
    if any(
        item.get("gate") != "pass"
        for item in areas
        if isinstance(item, Mapping)
    ):
        raise CertificationError("an exact-manifest E2E area did not pass")
    hunt_area = next(
        item for item in areas
        if isinstance(item, Mapping) and item.get("area") == "hunt"
    )
    hunt_rows = hunt_area.get("rows")
    if not isinstance(hunt_rows, list):
        raise CertificationError("exact-manifest Hunt E2E has no rows")
    h18_rows = [
        row for row in hunt_rows
        if isinstance(row, Mapping) and str(row.get("name") or "").startswith("H-18 ")
    ]
    # A genuine pass is the real proof: passed, not skipped, and NOT a declared-debt
    # xfail. An xfail row also carries passed=True (it does not fail the area gate),
    # so this predicate must reject it explicitly or a debt marker would silently
    # satisfy the Hunt engine's flagship real-target verification requirement.
    h18_genuine = any(
        row.get("passed") is True
        and row.get("skipped") is False
        and not row.get("xfail")
        for row in h18_rows
    )
    h18_debt = any(row.get("xfail") is True for row in h18_rows)
    if not h18_genuine and not (waive_e2e_declared_debt and h18_debt):
        raise CertificationError(
            "exact-manifest Hunt E2E lacks adaptive real-target verified-finding proof"
        )

    # Declared-debt xfails may appear only in an explicitly authorized debt release.
    # Anywhere else they are treated as hard failures: a debt marker can never mask a
    # red check unless this release deliberately accepted that debt.
    declared_debt_rows = [
        {
            "area": str(area.get("area")),
            "check": str(row.get("name")),
            "reason": str(row.get("reason") or ""),
        }
        for area in areas
        if isinstance(area, Mapping)
        for row in (area.get("rows") or [])
        if isinstance(row, Mapping) and row.get("xfail") is True
    ]
    if declared_debt_rows and not waive_e2e_declared_debt:
        raise CertificationError(
            "E2E scorecard carries declared-debt xfails, but this release did not "
            "authorize installed-stack E2E debt"
        )
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

    external = dict(external_evidence or {})
    required_external = {
        "dast_quality", "fault_cancellation", "fault_reservation_identity",
        "fault_action_resume",
    }
    optional_external = {
        "real_fleet_parity", "model_intake_physical", "device_physical",
    }
    if not required_external.issubset(external) or not set(external).issubset(
        required_external | optional_external
    ):
        raise CertificationError("candidate certification is missing required external evidence")
    dast = external["dast_quality"][0]
    # The regression gates (no decay below the shipped floor) and the fact that the
    # complete bar was actually measured (quality_bar_enforced) are required
    # unconditionally -- a waiver may accept a known shortfall, never skip the
    # measurement or let coverage regress.
    if (
        dast.get("regression_gates_passed") is not True
        or dast.get("quality_bar_enforced") is not True
    ):
        raise CertificationError("DAST regression gates or quality-bar enforcement did not hold")
    dast_quality_met = (
        dast.get("passed") is True
        and dast.get("release_quality_contract_passed") is True
        and dast.get("quality_bar_passed") is True
    )
    if not dast_quality_met and not waive_dast_quality:
        raise CertificationError("complete DAST quality bar did not pass")
    dast_quality_waived = not dast_quality_met and waive_dast_quality
    fault_contracts = {
        "fault_cancellation": "scan-cancellation-race-receipt/v1",
        "fault_reservation_identity": "scan-reservation-identity-receipt/v1",
        "fault_action_resume": "scan-action-resume-receipt/v1",
    }
    for key, schema in fault_contracts.items():
        evidence = external[key][0]
        if evidence.get("schema_version") != schema or evidence.get("passed") is not True:
            raise CertificationError(f"{key} did not pass on the final manifest stack")
    if "real_fleet_parity" in external:
        parity = external["real_fleet_parity"][0]
        if (
            parity.get("source_revision") != source_sha
            or parity.get("consistent") is not True
            or parity.get("all_artifacts_truthful") is not True
        ):
            raise CertificationError("real-fleet parity did not pass for this candidate")
    for key in ("model_intake_physical", "device_physical"):
        if key not in external:
            continue
        evidence = external[key][0]
        if evidence.get("candidate_sha") != source_sha or evidence.get("status") != "pass":
            raise CertificationError(f"{key} did not pass for this candidate")

    result = dict(candidate)
    result["schema_version"] = "shakerscan-release-candidate/v2"
    result["certification"] = {
        "status": "pass",
        "checks_schema_version": CERTIFICATION_CHECKS_SCHEMA_VERSION,
        "source_sha": source_sha,
        "images": dict(sorted(images.items())),
        "runtime_manifest_sha256": runtime_manifest,
        "checks": {
            "exact_manifest_installed_stack_e2e": "pass",
            "stateful_previous_stable_upgrade": "pass",
            "database_restart_idempotency": "pass",
            "backup_restore_rollback_boundary": "pass",
            "mature_subsystem_preservation": "pass",
            "model_intake_acceptance": "pass",
            "source_and_image_identity": "pass",
            "e2e_subject_binding": "pass",
            "complete_dast_quality_bar": (
                "waived_declared_debt" if dast_quality_waived else "pass"
            ),
            "dast_release_quality_contract": (
                "waived_declared_debt" if dast_quality_waived else "pass"
            ),
            "fault_cancellation": "pass",
            "fault_reservation_identity": "pass",
            "fault_action_resume": "pass",
            "real_fleet_parity": (
                "pass" if "real_fleet_parity" in external else "not_run_optional_boundary"
            ),
            "model_intake_physical": (
                "pass" if "model_intake_physical" in external else "not_run_optional_boundary"
            ),
            "device_physical": (
                "pass" if "device_physical" in external else "not_run_optional_boundary"
            ),
        },
        "scope_exclusions": [
            *[
            name for name in (
                "real_fleet_parity", "model_intake_physical", "device_physical",
            )
            if name not in external
            ],
            # An explicit, release-owner-authorized acceptance of the measured DAST
            # quality shortfall for this version ("ship what it proves"): the bar was
            # enforced and the regression gates held, but the complete bar was not met
            # and is knowingly waived with the measurement recorded, not hidden.
            *([
                {
                    "boundary": "complete_dast_quality_bar",
                    "state": "waived_declared_debt",
                    # The benchmark scorecard names its recall "expected_recall" (the share of
                    # the fixture's expected findings that were found); "recall" is accepted
                    # for older scorecards. The 2.0.1 receipt recorded None here while the
                    # evidence held 0.44 because only the old key was read.
                    "measured_recall": _measured_recall(dast),
                    "regression_gates_passed": True,
                    "quality_bar_enforced": True,
                    "quality_bar_passed": False,
                }
            ] if dast_quality_waived else []),
            # Named, release-owner-authorized acceptance of specific installed-stack
            # E2E checks that ran and did not pass. Each is recorded by area, check
            # name, and reason -- the measurement is preserved, not hidden, and the
            # rest of every area stayed a hard gate.
            *([
                {
                    "boundary": "installed_stack_e2e_declared_debt",
                    "state": "waived_declared_debt",
                    "checks": declared_debt_rows,
                }
            ] if declared_debt_rows else []),
            # Preservation controls whose only evidence is a declared-debt check, recorded by
            # control so the matrix never silently loses coverage.
            *([
                {
                    "boundary": "mature_subsystem_preservation_declared_debt",
                    "state": "waived_declared_debt",
                    "controls": preservation_debt,
                }
            ] if preservation_debt else []),
        ],
        "evidence_sha256": {
            "uncertified_candidate_receipt": _file_sha256(candidate_path),
            **{
                f"stateful_upgrade_receipt_{version.replace('.', '_')}": _file_sha256(path)
                for version, path in sorted(upgrade_evidence_paths.items())
            },
            "preservation_receipt": _file_sha256(preservation_path),
            "exact_manifest_e2e_scorecard": _file_sha256(e2e_path),
            **{
                key: _file_sha256(path)
                for key, (_value, path) in sorted(external.items())
            },
        },
        "rollback_boundary": "; ".join(sorted({
            str(item.get("rollback_boundary") or "") for item in upgrades
        })),
    }
    result.pop("receipt_sha256", None)
    result["receipt_sha256"] = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--upgrade", required=True, type=Path, action="append")
    parser.add_argument("--preservation", required=True, type=Path)
    parser.add_argument("--e2e-scorecard", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--dast-quality", required=True, type=Path)
    parser.add_argument("--fault-cancellation", required=True, type=Path)
    parser.add_argument("--fault-reservation-identity", required=True, type=Path)
    parser.add_argument("--fault-action-resume", required=True, type=Path)
    parser.add_argument("--real-fleet-parity", type=Path)
    parser.add_argument("--model-intake-physical", type=Path)
    parser.add_argument("--device-physical", type=Path)
    parser.add_argument(
        "--waive-dast-quality-shortfall",
        action="store_true",
        help=(
            "Release-owner acceptance of a measured DAST quality-bar shortfall for "
            "this version. The bar is still enforced and the regression gates must "
            "still hold; the shortfall is recorded as declared debt, never as a pass."
        ),
    )
    parser.add_argument(
        "--waive-e2e-declared-debt",
        action="store_true",
        help=(
            "Release-owner acceptance of the named installed-stack E2E checks that "
            "ran as declared-debt XFAILs in the scorecard. Each is recorded by area, "
            "check, and reason in scope_exclusions; without this flag any XFAIL row "
            "(and any non-genuine H-18 proof) fails certification."
        ),
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = certify_receipt(
            candidate=_read(args.candidate),
            candidate_path=args.candidate,
            upgrade=[_read(path) for path in args.upgrade],
            upgrade_path=args.upgrade,
            preservation=_read(args.preservation),
            preservation_path=args.preservation,
            e2e=_read(args.e2e_scorecard),
            e2e_path=args.e2e_scorecard,
            source_sha=args.source_sha,
            waive_dast_quality=args.waive_dast_quality_shortfall,
            waive_e2e_declared_debt=args.waive_e2e_declared_debt,
            required_upgrade_baselines={
                (Path(__file__).resolve().parents[1] / "install" / name).read_text(encoding="utf-8").strip()
                for name in ("STABLE_VERSION", "OLDEST_SUPPORTED_UPGRADE_BASE")
            },
            external_evidence={
                "dast_quality": (_read(args.dast_quality), args.dast_quality),
                "fault_cancellation": (
                    _read(args.fault_cancellation), args.fault_cancellation,
                ),
                "fault_reservation_identity": (
                    _read(args.fault_reservation_identity), args.fault_reservation_identity,
                ),
                "fault_action_resume": (
                    _read(args.fault_action_resume), args.fault_action_resume,
                ),
                **({
                    "real_fleet_parity": (
                        _read(args.real_fleet_parity), args.real_fleet_parity,
                    )
                } if args.real_fleet_parity else {}),
                **({
                    "model_intake_physical": (
                        _read(args.model_intake_physical), args.model_intake_physical,
                    )
                } if args.model_intake_physical else {}),
                **({
                    "device_physical": (
                        _read(args.device_physical), args.device_physical,
                    )
                } if args.device_physical else {}),
            },
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
