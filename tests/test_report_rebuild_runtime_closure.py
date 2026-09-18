"""A frozen-source report rebuild must run on the standard library alone.

`report-rebuild --help` is exercised by the installer smoke against an installed tree that
has no third-party packages. The authenticated-assurance preview (gated off by default)
put a pydantic-backed import in the finalizer's module scope, so importing the finalizer --
and therefore running the rebuild script at all -- began to require pydantic. The 2.3.6
candidate build failed on exactly that, two days after 2.3.5 passed the same gate.
"""
from __future__ import annotations

import builtins
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))


@pytest.fixture
def without_pydantic(monkeypatch):
    """Make every pydantic import fail, as a stdlib-only installed tree does."""
    real_import = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name == "pydantic" or name.startswith("pydantic."):
            raise ModuleNotFoundError("No module named 'pydantic'")
        return real_import(name, *args, **kwargs)

    for module in [key for key in sys.modules if key.split(".")[0] in {"pydantic"}]:
        monkeypatch.delitem(sys.modules, module, raising=False)
    for module in [
        key for key in sys.modules
        if key.split(".")[0] in {"scan", "authenticated_assurance"} or key.startswith("api.")
    ]:
        monkeypatch.delitem(sys.modules, module, raising=False)
    monkeypatch.setattr(builtins, "__import__", guarded)
    yield


def test_the_finalizer_imports_without_pydantic(without_pydantic):
    finalizer = importlib.import_module("scan.finalizer")
    assert callable(finalizer.finalize_scan_report)
    assert callable(finalizer.scan_authentication_summary)


def test_the_fallback_summary_claims_nothing(without_pydantic):
    finalizer = importlib.import_module("scan.finalizer")
    summary = finalizer.scan_authentication_summary({"credential_profile_refs": [{"profile_id": "x"}]})
    assert summary["schema_version"] == "authentication-assurance/v1"
    # Nothing may be asserted about the identity when the evaluator is not present.
    assert summary["state"] == "unknown"
    assert summary["coverage"] == "unverified"
    assert summary["continuous_authentication_proven"] is False
    assert summary["profiles"] == []
    assert summary["secret_values_visible"] is False
    # The reason code stays inside the preview's own vocabulary.
    assert summary["reason_code"] in {"legacy_unverified", "not_validated", "authentication_gap"}
    # ...and the absence is stated rather than implied.
    assert any("not available" in str(item) for item in summary["limitations"])


def test_an_interrupted_scan_still_reports_its_gap_without_pydantic(without_pydantic):
    finalizer = importlib.import_module("scan.finalizer")
    summary = finalizer.scan_authentication_summary({}, interrupted_action_count=3)
    assert summary["interrupted_action_count"] == 3
    assert summary["reason_code"] == "authentication_gap"
