from __future__ import annotations

import json
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from scripts.release_preservation import PreservationError, build_receipt

SOURCE = "a" * 40


ROOT = Path(__file__).resolve().parents[1]
MATRIX = json.loads(
    (ROOT / "tests" / "release_preservation_matrix.json").read_text()
)


def _write_evidence(tmp_path: Path, *, fail_row: str | None = None):
    suite = ET.Element("testsuite")
    areas: dict[str, list[dict]] = {}
    for program in MATRIX["programs"].values():
        for control in program["controls"]:
            selector = control.get("pytest_selector")
            if selector:
                file_name, test_name = selector.split("::", 1)
                ET.SubElement(
                    suite, "testcase", name=test_name,
                    classname=f"tests.{Path(file_name).stem}", file=file_name,
                )
            e2e = control.get("e2e")
            if e2e:
                areas.setdefault(e2e["area"], []).append({
                    "name": e2e["row"],
                    "passed": e2e["row"] != fail_row,
                    "skipped": False,
                    "detail": "",
                })
    junit = tmp_path / "tests.xml"
    ET.ElementTree(suite).write(junit, encoding="utf-8", xml_declaration=True)
    scorecard = tmp_path / "e2e.json"
    scorecard.write_text(json.dumps({
        "schema_version": "shakerscan-e2e-scorecard/v1",
        "gate": "pass" if fail_row is None else "fail",
        "areas": [
            {"area": name, "gate": "pass", "rows": rows}
            for name, rows in areas.items()
        ],
    }))
    playwright = tmp_path / "playwright.json"
    playwright_titles = {
        control["playwright"]["title"]
        for program in MATRIX["programs"].values()
        for control in program["controls"]
        if control.get("playwright")
    }
    playwright.write_text(json.dumps({
        "suites": [{
            "title": "browser",
            "specs": [{
                "title": title,
                "tests": [{
                    "expectedStatus": "passed",
                    "results": [{"status": "passed"}],
                }],
            } for title in sorted(playwright_titles)],
        }],
    }))
    return junit, scorecard, playwright


def _images():
    return {name: f"sha256:{index:064x}" for index, name in enumerate(
        ("scanner", "api", "ui", "signer", "model_intake"), start=1,
    )}


def test_complete_matrix_builds_content_free_candidate_bound_receipt(tmp_path):
    junit, scorecard, playwright = _write_evidence(tmp_path)
    receipt = build_receipt(
        matrix=MATRIX, junit_path=junit, scorecard_path=scorecard,
        playwright_path=playwright,
        source_sha="a" * 40, images=_images(),
    )
    assert receipt["status"] == "pass"
    assert receipt["failed_controls"] == []
    assert {item["id"] for item in receipt["programs"]} == set(MATRIX["programs"])
    assert len(receipt["receipt_sha256"]) == 64
    serialized = json.dumps(receipt).lower()
    for forbidden in ("password", "authorization: bearer", "private key"):
        assert forbidden not in serialized


def test_every_matrix_pytest_selector_names_a_real_test():
    selectors = [
        control["pytest_selector"]
        for program in MATRIX["programs"].values()
        for control in program["controls"]
        if control.get("pytest_selector")
    ]
    assert selectors
    for selector in selectors:
        file_name, test_name = selector.split("::", 1)
        source = (ROOT / file_name).read_text(encoding="utf-8")
        assert f"def {test_name}(" in source, selector


def test_every_matrix_live_evidence_names_a_real_acceptance_check():
    e2e_source = (ROOT / "tests" / "e2e" / "run_e2e.py").read_text(
        encoding="utf-8"
    )
    browser_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "ui" / "tests" / "browser").glob("*.spec.ts"))
    )
    route_manifest = json.loads(
        (ROOT / "ui" / "test-manifests" / "ui-route-action-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    manifested_smoke_routes = {
        route["smokePath"]
        for route in route_manifest["routes"]
        if route.get("smokePath")
    }
    for program in MATRIX["programs"].values():
        for control in program["controls"]:
            if control.get("e2e"):
                row = control["e2e"]["row"]
                assert json.dumps(row) in e2e_source, row
            if control.get("playwright"):
                title = control["playwright"]["title"]
                if title.startswith("/") and title.endswith(
                    " renders without an application exception"
                ):
                    route = title.removesuffix(
                        " renders without an application exception"
                    )
                    assert route in manifested_smoke_routes, title
                    assert "routeManifest.routes.flatMap" in browser_source, title
                else:
                    assert title in browser_source, title


def test_receipt_fails_closed_on_missing_test_or_failed_e2e(tmp_path):
    junit, scorecard, playwright = _write_evidence(tmp_path)
    tree = ET.parse(junit)
    first = next(tree.getroot().iter("testcase"))
    tree.getroot().remove(first)
    tree.write(junit)
    receipt = build_receipt(
        matrix=MATRIX, junit_path=junit, scorecard_path=scorecard,
        playwright_path=playwright,
        source_sha="b" * 40, images=_images(),
    )
    assert receipt["status"] == "fail"
    assert receipt["failed_controls"]

    _, failed_scorecard, failed_playwright = _write_evidence(
        tmp_path, fail_row="MI-2 correct digest verifies",
    )
    with pytest.raises(PreservationError, match="did not pass"):
        build_receipt(
            matrix=MATRIX, junit_path=junit, scorecard_path=failed_scorecard,
            playwright_path=failed_playwright,
            source_sha="b" * 40, images=_images(),
        )


def test_receipt_requires_exact_candidate_image_identities(tmp_path):
    junit, scorecard, playwright = _write_evidence(tmp_path)
    with pytest.raises(PreservationError, match="exact scanner"):
        build_receipt(
            matrix=MATRIX, junit_path=junit, scorecard_path=scorecard,
            playwright_path=playwright,
            source_sha="c" * 40, images={"scanner": "latest"},
        )


def test_receipt_requires_passing_production_browser_evidence(tmp_path):
    junit, scorecard, playwright = _write_evidence(tmp_path)
    with pytest.raises(PreservationError, match="browser acceptance"):
        build_receipt(
            matrix=MATRIX,
            junit_path=junit,
            scorecard_path=scorecard,
            playwright_path=None,
            source_sha="d" * 40,
            images=_images(),
        )

    report = json.loads(playwright.read_text())
    hunt_spec = next(
        item for item in report["suites"][0]["specs"]
        if item["title"] == "production Hunt UI submits canonical passive V2 authority"
    )
    hunt_spec["tests"][0]["results"][0]["status"] = "failed"
    playwright.write_text(json.dumps(report))
    receipt = build_receipt(
        matrix=MATRIX,
        junit_path=junit,
        scorecard_path=scorecard,
        playwright_path=playwright,
        source_sha="d" * 40,
        images=_images(),
    )
    assert receipt["status"] == "fail"
    assert "ui.hunt_start" in receipt["failed_controls"]


def test_release_workflows_require_and_publish_preservation_evidence():
    e2e = (ROOT / ".github" / "workflows" / "e2e.yml").read_text()
    candidate = (
        ROOT / ".github" / "workflows" / "release-candidate.yml"
    ).read_text()
    assert "--scorecard artifacts/e2e-scorecard.json" in e2e
    assert "full-e2e-${{ inputs.candidate_sha }}" in e2e
    for required in (
        "scripts/run_complete_python_suite.py",
        "scripts/release_preservation.py",
        "tests/release_preservation_matrix.json",
        "artifacts/v2-full-python.xml",
        "artifacts/certification/e2e-scorecard.json",
        "artifacts/certification/playwright.json",
        "--playwright-json",
        '--image "scanner=$(jq -r \'.images.scanner\' "$receipt")"',
        '--image "api=$(jq -r \'.images.api\' "$receipt")"',
        '--image "ui=$(jq -r \'.images.ui\' "$receipt")"',
        '--image "signer=$(jq -r \'.images.signer\' "$receipt")"',
        "preservation-receipt.json",
    ):
        assert required in candidate


def _scorecard_with_debt(tmp_path: Path, row: str, area: str):
    """Replace one required row by its declared-debt xfail row, as a debt release records it."""
    junit, scorecard, playwright = _write_evidence(tmp_path)
    card = json.loads(scorecard.read_text())
    check_id = row.split(" ", 1)[0].rstrip("ABCDEFGH")
    for block in card["areas"]:
        if block["area"] != area:
            continue
        block["rows"] = [item for item in block["rows"] if item["name"] != row]
        block["rows"].append({
            "name": f"{check_id} declared-debt lifecycle", "passed": True, "skipped": False,
            "xfail": True, "reason": "preview surface outside the shipping scope",
        })
    scorecard.write_text(json.dumps(card))
    return junit, scorecard, playwright


def test_a_declared_debt_row_is_recorded_as_waived_only_in_an_authorized_debt_release(tmp_path):
    control = next(
        (program_id, control) for program_id, program in MATRIX["programs"].items()
        for control in program["controls"]
        if control.get("e2e") and not control.get("pytest_selector") and not control.get("playwright")
    )
    program_id, spec = control
    junit, scorecard, playwright = _scorecard_with_debt(tmp_path, spec["e2e"]["row"], spec["e2e"]["area"])

    strict = build_receipt(
        matrix=MATRIX, junit_path=junit, scorecard_path=scorecard, playwright_path=playwright,
        source_sha=SOURCE, images=_images(),
    )
    assert strict["status"] == "fail"
    assert f"{program_id}.{spec['id']}" in strict["failed_controls"]
    assert strict["declared_debt_controls"] == []

    debt = build_receipt(
        matrix=MATRIX, junit_path=junit, scorecard_path=scorecard, playwright_path=playwright,
        source_sha=SOURCE, images=_images(), declared_debt=True,
    )
    assert debt["status"] == "pass"
    assert debt["failed_controls"] == []
    assert [item["control"] for item in debt["declared_debt_controls"]] == [f"{program_id}.{spec['id']}"]
    assert debt["declared_debt_controls"][0]["reason"] == "preview surface outside the shipping scope"
    status = {
        c["id"]: c["status"] for p in debt["programs"] if p["id"] == program_id for c in p["controls"]
    }
    assert status[spec["id"]] == "waived_declared_debt"


def test_a_missing_row_without_a_matching_debt_row_still_fails_in_a_debt_release(tmp_path):
    spec = next(
        control for program in MATRIX["programs"].values() for control in program["controls"]
        if control.get("e2e")
    )
    junit, scorecard, playwright = _write_evidence(tmp_path)
    # The row is simply absent: the area gate still passes, but nothing records the check as debt.
    card = json.loads(scorecard.read_text())
    for block in card["areas"]:
        block["rows"] = [item for item in block["rows"] if item["name"] != spec["e2e"]["row"]]
    scorecard.write_text(json.dumps(card))
    receipt = build_receipt(
        matrix=MATRIX, junit_path=junit, scorecard_path=scorecard, playwright_path=playwright,
        source_sha=SOURCE, images=_images(), declared_debt=True,
    )
    assert receipt["status"] == "fail"
    assert receipt["declared_debt_controls"] == []
