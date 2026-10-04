"""Authorization-aware active Nuclei template selection.

The fixtures under ``tests/fixtures/nuclei_templates`` are real templates copied
verbatim from the pinned ProjectDiscovery bundle:

* ``squid-analysis-report-generator`` -- GET only (exposure/high)
* ``django-debug-exposure`` -- ``method: POST`` (exposure/high)
* ``bloofoxcms-default-login`` -- raw-request POST (default-login/high)
* ``put-method-enabled`` -- raw ``PUT``, tagged ``intrusive`` (misconfig/high)
* ``broken-template.yaml`` -- deliberately malformed YAML (parse error)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scan.nuclei_template_index import (
    build_nuclei_method_index,
    clear_index_cache,
    resolve_active_nuclei_selection,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "nuclei_templates"


@pytest.fixture(autouse=True)
def _fresh_index_cache():
    clear_index_cache()
    yield
    clear_index_cache()


def test_index_classifies_methods_and_intrusive_from_real_templates():
    index = build_nuclei_method_index(str(FIXTURES))
    by_id = {record.template_id: record for record in index.templates}
    assert set(by_id) == {
        "squid-analysis-report-generator",
        "django-debug-exposure",
        "bloofoxcms-default-login",
        "put-method-enabled",
    }
    # The malformed template is counted, not silently classified as GET-only.
    assert index.parse_errors >= 1
    assert not by_id["squid-analysis-report-generator"].state_changing
    assert by_id["django-debug-exposure"].state_changing  # method: POST
    assert by_id["bloofoxcms-default-login"].state_changing  # raw-request POST
    assert by_id["put-method-enabled"].intrusive  # raw PUT, tagged intrusive


def test_unauthorized_selection_excludes_post_raw_and_intrusive_templates():
    selection = resolve_active_nuclei_selection(
        str(FIXTURES), allow_state_changing_http=False,
    )
    assert selection.skip is False
    assert selection.template_ids == ("squid-analysis-report-generator",)
    assert selection.includes_state_changing is False
    # Neither the method-POST, the raw-POST, nor the intrusive template may run.
    assert "django-debug-exposure" not in selection.template_ids
    assert "bloofoxcms-default-login" not in selection.template_ids
    assert "put-method-enabled" not in selection.template_ids
    assert selection.intrusive_excluded == 1


def test_authorized_selection_includes_post_but_still_excludes_intrusive():
    selection = resolve_active_nuclei_selection(
        str(FIXTURES), allow_state_changing_http=True,
    )
    assert selection.skip is False
    assert selection.includes_state_changing is True
    assert set(selection.template_ids) == {
        "squid-analysis-report-generator",
        "django-debug-exposure",
        "bloofoxcms-default-login",
    }
    # A destructive template needs more than state-changing permission, which
    # Scan has no tier to grant, so it is excluded even when authorized.
    assert "put-method-enabled" not in selection.template_ids
    assert selection.intrusive_excluded == 1


def test_index_failure_fails_closed(tmp_path):
    # A directory with no http/ subtree cannot be classified: fail closed in both
    # authorization states rather than running an unknown selection.
    for authorized in (False, True):
        selection = resolve_active_nuclei_selection(
            str(tmp_path), allow_state_changing_http=authorized,
        )
        assert selection.skip is True
        assert selection.skip_reason == "nuclei_template_index_unavailable"
        assert selection.template_ids == ()
        assert selection.includes_state_changing is False


def test_severity_filter_narrows_the_selection():
    # Only high/critical fixtures exist; a medium-only filter selects nothing and
    # fails closed (an honest coverage gap, not a clean empty run).
    selection = resolve_active_nuclei_selection(
        str(FIXTURES), severities="medium", allow_state_changing_http=True,
    )
    assert selection.skip is True
    assert selection.skip_reason == "no_eligible_nuclei_templates"
