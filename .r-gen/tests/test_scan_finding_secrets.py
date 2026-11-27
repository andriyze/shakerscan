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


def test_the_javascript_context_keeps_no_raw_value_or_neighbouring_key():
    from scanner_tools.client_side import _masked_context
    value = "AIza" + "SyD-synthetic-google-key-1234567"
    neighbour = "sk_test_" + "abcdefghijklmnopqrstuvwx"
    before = f'var other="{neighbour[5:]}"; var k = "'
    context = _masked_context(before, value, value, "AIza...4567", '"; init(k)')
    assert value not in context and neighbour[5:] not in context
    assert "AIza...4567" in context and "init(k)" in context


def test_the_data_exposure_snippet_carries_no_response_text():
    source = (ROOT / "scanner" / "scanner_tools" / "data_exposure.py").read_text()
    assert 'snippet = f"[{family}: {len(m.group(0))} characters at offset {m.start()}]"' in source
    assert "_discovered_secret_values" not in source


def test_a_handed_over_value_is_masked_and_not_kept_and_long_strings_are_searched():
    from scan.finding_secrets import mask_payload
    findings = _findings()
    long_text = "x" * 300_000
    findings.append({"evidence": {"blob": AWS + long_text}})
    asyncio.run(scrub_findings(None, target_id=None, scan_id=None, findings=findings))
    text = json.dumps(findings)
    assert HANDED not in text and AWS not in text and PRIVATE_VALUES_KEY not in text
    posted = {"result": {"findings": [{"evidence": {"k": STRIPE}}]}, "note": [STRIPE]}
    masked = mask_payload(posted)
    assert STRIPE not in json.dumps(masked) and STRIPE in json.dumps(posted)  # a copy, not in place
