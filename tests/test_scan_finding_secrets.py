"""Secrets in Scan findings never stay in evidence (api/scan/finding_secrets.py). Without a
database the values are masked; the store and reference path is covered in
tests/test_discovered_secrets_postgres.py. Values are synthetic."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "api"), str(ROOT / "scanner")]

from scan.finding_secrets import PRIVATE_VALUES_KEY, scrub_findings, scrub_report_secrets  # noqa: E402

AWS = "AKIA" + "Q7XK2M4N9P3R8T5W"
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
HANDED = "AIza" + "SyD-synthetic-google-key-1234567"


def _findings():
    return [
        {"id": "f1", "title": "Exposed config", "evidence": {
            "match_snippet": f"aws_access_key_id = {AWS}", "nested": [{"raw": f"key={STRIPE}"}]}},
        {"id": "f2", "title": "Hardcoded Secret in JavaScript", "evidence": {
            "context": "const k = 'AIza...4567';", PRIVATE_VALUES_KEY: [{"value": HANDED, "label": "google_api"}]}},
    ]


def test_without_a_database_every_value_is_masked_and_the_hand_over_removed():
    findings = _findings()
    counts = asyncio.run(scrub_findings(None, target_id=None, scan_id=None, findings=findings))
    text = json.dumps(findings)
    assert counts == {"found": 3, "kept": 0}
    for raw in (AWS, STRIPE, HANDED):
        assert raw not in text
    assert PRIVATE_VALUES_KEY not in text
    assert "[REDACTED:aws_access_key]" in text and "[REDACTED:stripe_key]" in text
    # Idempotent: a second pass finds nothing.
    assert asyncio.run(scrub_findings(None, target_id=None, scan_id=None, findings=findings)) == {
        "found": 0, "kept": 0}


def test_a_report_with_module_findings_is_scrubbed_even_when_the_database_fails():
    class BrokenPool:
        def acquire(self):
            raise RuntimeError("database unavailable")

    report = {"findings": _findings()[:1], "modules": {"js": {"findings": _findings()[1:]}}}
    counts = asyncio.run(scrub_report_secrets(BrokenPool(), scan_id="11111111-1111-4111-8111-111111111111",
                                              result=report))
    text = json.dumps(report)
    assert counts["found"] == 3 and AWS not in text and HANDED not in text


def test_the_javascript_and_data_exposure_checks_keep_values_out_of_their_text():
    source = (ROOT / "scanner" / "scanner_tools" / "client_side.py").read_text()
    assert '"context": context.replace(full_value, masked_value)[:100]' in source
    exposure = (ROOT / "scanner" / "scanner_tools" / "data_exposure.py").read_text()
    assert '.replace(\n                        matched, f"[{family}:{len(matched)} chars]")' in exposure
