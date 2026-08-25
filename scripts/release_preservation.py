#!/usr/bin/env python3
"""Build a fail-closed, content-free release preservation receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping
import xml.etree.ElementTree as ET


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")


class PreservationError(RuntimeError):
    pass


def _read_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PreservationError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise PreservationError(f"{path.name} must contain one JSON object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise PreservationError(f"cannot hash {path.name}: {exc}") from exc
    return digest.hexdigest()


def _testcases(path: Path) -> list[dict[str, Any]]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise PreservationError(f"cannot read JUnit evidence: {exc}") from exc
    result = []
    for item in root.iter("testcase"):
        result.append({
            "name": str(item.attrib.get("name") or ""),
            "classname": str(item.attrib.get("classname") or ""),
            "file": str(item.attrib.get("file") or ""),
            "failed": item.find("failure") is not None or item.find("error") is not None,
            "skipped": item.find("skipped") is not None,
        })
    if not result:
        raise PreservationError("JUnit evidence contains no test cases")
    return result


def _selector_result(selector: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
    file_name, separator, test_name = str(selector).partition("::")
    if not separator or not file_name.endswith(".py") or not test_name:
        raise PreservationError(f"preservation selector must name one test: {selector}")
    module = Path(file_name).stem
    matches = [
        case for case in cases
        if (
            case["file"].endswith(file_name)
            or module in case["classname"].split(".")
            or case["classname"].endswith(module)
        )
        and (case["name"] == test_name or case["name"].startswith(f"{test_name}["))
    ]
    return {
        "selector": selector,
        "matched": len(matches),
        "passed": bool(matches) and not any(
            case["failed"] or case["skipped"] for case in matches
        ),
    }


def _e2e_result(spec: Mapping[str, Any], scorecard: Mapping[str, Any]) -> dict[str, Any]:
    area_name = str(spec.get("area") or "")
    row_name = str(spec.get("row") or "")
    areas = scorecard.get("areas") or ()
    area = next(
        (item for item in areas if isinstance(item, Mapping) and item.get("area") == area_name),
        None,
    )
    rows = area.get("rows") or () if isinstance(area, Mapping) else ()
    matches = [
        row for row in rows
        if isinstance(row, Mapping) and str(row.get("name") or "") == row_name
    ]
    return {
        "area": area_name,
        "row": row_name,
        "matched": len(matches),
        "passed": bool(matches) and all(
            row.get("passed") is True and row.get("skipped") is not True
            for row in matches
        ),
    }


def build_receipt(
    *,
    matrix: Mapping[str, Any],
    junit_path: Path,
    scorecard_path: Path,
    source_sha: str,
    images: Mapping[str, str],
) -> dict[str, Any]:
    if matrix.get("schema_version") != "release-preservation-matrix/v1":
        raise PreservationError("unsupported preservation matrix schema")
    if not SOURCE_SHA.fullmatch(source_sha):
        raise PreservationError("source SHA must be a full lowercase commit identity")
    required_images = {"scanner", "api", "ui", "signer"}
    if set(images) != required_images or not all(
        SHA256.fullmatch(str(value)) for value in images.values()
    ):
        raise PreservationError(
            "exact scanner, api, ui, and signer sha256 image identities are required"
        )

    cases = _testcases(junit_path)
    scorecard = _read_json(scorecard_path)
    if scorecard.get("schema_version") != "shakerscan-e2e-scorecard/v1":
        raise PreservationError("unsupported E2E scorecard schema")
    if scorecard.get("gate") != "pass":
        raise PreservationError("full E2E scorecard did not pass")

    programs: list[dict[str, Any]] = []
    failed: list[str] = []
    for program_id, program in (matrix.get("programs") or {}).items():
        if not isinstance(program, Mapping):
            raise PreservationError(f"invalid preservation program: {program_id}")
        controls = []
        for control in program.get("controls") or ():
            if not isinstance(control, Mapping) or not control.get("id"):
                raise PreservationError(f"invalid preservation control in {program_id}")
            evidence = []
            if control.get("pytest_selector"):
                evidence.append(_selector_result(str(control["pytest_selector"]), cases))
            if control.get("e2e"):
                if not isinstance(control["e2e"], Mapping):
                    raise PreservationError(f"invalid E2E evidence in {control['id']}")
                evidence.append(_e2e_result(control["e2e"], scorecard))
            passed = bool(evidence) and all(item["passed"] for item in evidence)
            if not passed:
                failed.append(f"{program_id}.{control['id']}")
            controls.append({
                "id": str(control["id"]),
                "label": str(control.get("label") or control["id"]),
                "status": "pass" if passed else "fail",
                "evidence": evidence,
            })
        if not controls:
            raise PreservationError(f"preservation program has no controls: {program_id}")
        programs.append({
            "id": str(program_id),
            "label": str(program.get("label") or program_id),
            "status": "pass" if all(c["status"] == "pass" for c in controls) else "fail",
            "controls": controls,
        })

    receipt: dict[str, Any] = {
        "schema_version": "release-preservation-receipt/v1",
        "source_sha": source_sha,
        "images": dict(sorted(images.items())),
        "matrix_sha256": hashlib.sha256(
            json.dumps(matrix, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "evidence": {
            "junit_sha256": _sha256(junit_path),
            "e2e_scorecard_sha256": _sha256(scorecard_path),
            "junit_test_count": len(cases),
        },
        "status": "pass" if not failed else "fail",
        "failed_controls": failed,
        "programs": programs,
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return receipt


def _images(values: list[str]) -> dict[str, str]:
    images: dict[str, str] = {}
    for value in values:
        name, separator, digest = value.partition("=")
        if not separator or not name or name in images:
            raise PreservationError("--image must use one unique NAME=sha256:DIGEST")
        images[name] = digest
    return images


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--junit", required=True, type=Path)
    parser.add_argument("--e2e-scorecard", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--image", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        receipt = build_receipt(
            matrix=_read_json(args.matrix),
            junit_path=args.junit,
            scorecard_path=args.e2e_scorecard,
            source_sha=args.source_sha,
            images=_images(args.image),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    except (OSError, PreservationError) as exc:
        print(f"release preservation failed: {exc}", file=sys.stderr)
        return 2
    return 0 if receipt["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
