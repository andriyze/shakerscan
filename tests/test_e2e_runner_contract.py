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

    assert run_e2e.main() == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "shakerscan-e2e-scorecard/v1"
    assert payload["gate"] == "pass"
    assert payload["areas"][0]["area"] == "fixture"
    assert payload["areas"][0]["rows"][0]["name"] == "deterministic fixture"

