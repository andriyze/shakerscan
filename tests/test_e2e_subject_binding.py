"""The E2E scorecard must identify the deployment it tested, or it cannot certify.

`_tested_subject` reads the live `/health` and records `source_revision`. It used to
unpack `H.get("/health")` as a `(status, body)` tuple, but `H.get` returns the body
directly, so the unpack raised ValueError, the bare except swallowed it, and the
subject was ALWAYS empty. That stayed invisible only because every prior certify run
failed an area check before the binding had to resolve; once the areas passed under
declared debt, an empty subject failed the whole gate ("the tested deployment could
not be identified"). This is the regression guard for that one-line fix.
"""

import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

run_e2e = importlib.import_module("tests.e2e.run_e2e")


def _with_health(monkeypatch, payload):
    monkeypatch.setattr(run_e2e.H, "get", lambda *a, **k: payload)


def test_subject_records_source_revision_from_a_real_health_body(monkeypatch):
    _with_health(monkeypatch, {
        "source_revision": "A" * 40,
        "build_fingerprint": "abc123",
        "scanner_version": "2.0.0",
        "status": "ok",
        "extra": "many keys, not a two-tuple",
    })
    subject = run_e2e._tested_subject()
    assert subject["source_revision"] == "a" * 40  # normalized lowercase
    assert subject["build_fingerprint"] == "abc123"
    assert subject["scanner_version"] == "2.0.0"


def test_an_unidentified_or_unreachable_stack_yields_no_source_revision(monkeypatch):
    # "unknown" (a runtime that was never image-built) must not look like a subject.
    _with_health(monkeypatch, {"source_revision": "unknown"})
    assert "source_revision" not in run_e2e._tested_subject()

    def _boom(*a, **k):
        raise RuntimeError("unreachable")

    monkeypatch.setattr(run_e2e.H, "get", _boom)
    assert "source_revision" not in run_e2e._tested_subject()
