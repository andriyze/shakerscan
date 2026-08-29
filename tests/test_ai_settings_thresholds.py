import os
import sys

import pytest
from pydantic import ValidationError


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from settings_routes.router import AISettingsUpdate  # noqa: E402


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
