import os
import sys

import pytest
from pydantic import ValidationError


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from fastapi import HTTPException

from settings_routes.router import (  # noqa: E402
    AISettingsUpdate,
    _validate_effective_ai_threshold_update,
)


def test_ai_escalation_must_be_within_verification_eligible_severities():
    with pytest.raises(ValidationError) as exc:
        AISettingsUpdate(
            verification_min_severity="high",
            ai_escalation_min_severity="medium",
        )

    assert "cannot be broader" in str(exc.value)


def test_legacy_threshold_aliases_cannot_contradict_canonical_policy():
    with pytest.raises(ValidationError) as exc:
        AISettingsUpdate(
            verification_min_severity="medium",
            auto_retest_min_severity="low",
        )

    assert "must match canonical verification_min_severity" in str(exc.value)


def test_ordered_canonical_threshold_hierarchy_is_valid():
    settings = AISettingsUpdate(
        verification_min_severity="medium",
        ai_escalation_min_severity="high",
    )

    assert settings.verification_min_severity == "medium"
    assert settings.ai_escalation_min_severity == "high"


def test_partial_threshold_patch_is_validated_against_persisted_state():
    request = AISettingsUpdate(ai_escalation_min_severity="medium")

    with pytest.raises(HTTPException) as exc:
        _validate_effective_ai_threshold_update(
            request,
            {"verification_min_severity": "high"},
        )

    assert exc.value.status_code == 422
    assert "effective verification_min_severity" in exc.value.detail


def test_research_ai_provider_loader_imports_importlib_and_returns_the_provider():
    """Regression: `_load_research_ai_provider` uses `importlib`, which this module does not
    import at module scope. Before the fix it raised NameError, the bare except swallowed it, and
    the loader always returned None, so the configured-AI research planner reported "Shared AI
    provider client is unavailable" in every deployment. The loader must import `importlib`
    itself and return the real `scanner_tools.ai_classifier.call_ai_provider`.
    """
    import importlib as _importlib

    import settings_routes.router as router_module

    provider = router_module._load_research_ai_provider()
    assert callable(provider), "the research AI provider loader returned nothing"
    ai_classifier = _importlib.import_module("scanner_tools.ai_classifier")
    assert provider is ai_classifier.call_ai_provider

    # The loader must not depend on a caller or the module having pre-imported `importlib`:
    # remove any module-level binding and confirm it still resolves the provider on its own.
    had = "importlib" in router_module.__dict__
    saved = router_module.__dict__.pop("importlib", None)
    try:
        assert callable(router_module._load_research_ai_provider())
    finally:
        if had:
            router_module.__dict__["importlib"] = saved
