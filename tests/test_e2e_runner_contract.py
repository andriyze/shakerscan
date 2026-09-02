from __future__ import annotations

import json
import sys

from tests.e2e import run_e2e


def test_e2e_runner_writes_machine_readable_scorecard(monkeypatch, tmp_path):
    card = run_e2e.H.Scorecard("fixture")
    card.check("deterministic fixture", True)
    output = tmp_path / "scorecard.json"

    monkeypatch.setattr(run_e2e.H, "preflight", lambda: None)
    monkeypatch.setattr(run_e2e.FX, "start", lambda port: None)
    monkeypatch.setattr(run_e2e, "AREAS", {"fixture": lambda: card})
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_e2e.py", "--area", "fixture", "--scorecard", str(output)],
    )

    # A real run reads the deployment it exercised from the live stack; stand that in, because a
    # scorecard that cannot identify its subject is refused (see the test below).
    # H.get returns the response BODY directly (H._req(...)[1]), not a (status, body)
    # tuple; the subject reader must consume it the same way.
    monkeypatch.setattr(
        run_e2e.H, "get",
        lambda path, timeout=60, headers=None: {
            "source_revision": "a" * 40, "build_fingerprint": "abc123",
            "scanner_version": "2.0.0",
        },
    )

    assert run_e2e.main() == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "shakerscan-e2e-scorecard/v1"
    assert payload["gate"] == "pass"
    assert payload["areas"][0]["area"] == "fixture"
    assert payload["areas"][0]["rows"][0]["name"] == "deterministic fixture"
    # The subject binding: a scorecard must say which deployment it exercised, or it can certify a
    # candidate it never tested.
    assert payload["subject"]["source_revision"] == "a" * 40
    assert payload["subject"]["build_fingerprint"] == "abc123"


def test_a_scorecard_whose_subject_is_unknown_cannot_pass(tmp_path, monkeypatch):
    """An unreachable or unidentified stack must not produce a passing scorecard.

    Every area could pass against some deployment; without knowing which, the result cannot
    qualify a release candidate, so the gate fails rather than emitting an unbound pass.
    """
    import sys

    card = run_e2e.H.Scorecard("fixture")
    card.check("deterministic fixture", True, "ok")
    output = tmp_path / "scorecard.json"
    monkeypatch.setattr(run_e2e.H, "preflight", lambda: None)
    monkeypatch.setattr(run_e2e.FX, "start", lambda port: None)
    monkeypatch.setattr(run_e2e, "AREAS", {"fixture": lambda: card})
    monkeypatch.setattr(
        run_e2e.H, "get",
        lambda path, timeout=60, headers=None: (_ for _ in ()).throw(RuntimeError("unreachable")),
    )
    monkeypatch.setattr(
        sys, "argv", ["run_e2e.py", "--area", "fixture", "--scorecard", str(output)],
    )

    assert run_e2e.main() == 1
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["gate"] == "fail"
    assert "source_revision" not in payload["subject"]



def _dast_scan_policies() -> list[dict]:
    """Extract every policy literal the DAST E2E area submits to POST /scans."""
    import ast
    import inspect

    source = inspect.getsource(run_e2e.run_dast)
    tree = ast.parse(source.lstrip())
    policies: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if (
                isinstance(key, ast.Constant)
                and key.value == "policy"
                and isinstance(value, ast.Dict)
            ):
                try:
                    policies.append(ast.literal_eval(value))
                except ValueError:
                    continue
    return policies


def test_named_dast_cases_actually_select_the_family_they_test():
    """A case named for a family must resolve to that family, not to recon.

    The SQLi and XSS cases previously sent only an exclude list, leaving the
    default passive preset in place. Both resolved to families=["recon"], so
    they could pass green while never running the vulnerability family in their
    own name. That is false coverage, which is worse than no coverage.
    """
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
    from scan.contracts import resolve_scan_contract

    approval = "11111111-1111-4111-8111-111111111111"
    resolved_families = []
    for policy in _dast_scan_policies():
        contract = resolve_scan_contract(
            budget_profile="balanced",
            policy=policy,
            approval_receipt_id=approval,
        )
        resolved_families.append(set(contract.policy.include_families))

    assert any("sqli" in families for families in resolved_families), (
        "no DAST E2E case resolves to the sqli family"
    )
    assert any("xss" in families for families in resolved_families), (
        "no DAST E2E case resolves to the xss family"
    )
    for families in resolved_families:
        assert families != {"recon"}, (
            "a DAST E2E case resolves to recon only, which cannot prove any "
            "vulnerability family ran"
        )
