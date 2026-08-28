"""Coverage must be measured against the work that exists, not the work that was scheduled.

Batch planning cuts the number of slices to what the budget affords, what the batch ceiling allows
and what the action graph can hold. `planned_candidates` was read from each action's `slice.count`,
so manifest entries the planner never scheduled left no trace: attempts matched slices exactly and
the family reported `complete` over a truncated plan. A scan that could afford one batch of a
twelve-batch manifest looked as covered as one that ran all twelve.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from tests.api_sources import definition_source  # noqa: E402


def test_batch_actions_declare_the_manifest_size_they_were_cut_from():
    source = definition_source("compile")
    assert '"manifest_entries": int(entry_count),' in source
    assert '"scheduled_batches": int(count),' in source
    assert '"total_batches": int(total_batches),' in source


def test_the_finalizer_reads_the_declared_manifest_size():
    source = definition_source("finalize_scan_report")
    assert 'action.capability_args.get("manifest_entries")' in source
    # A bool is an int subclass; accepting True as a count would silently mean "one entry".
    assert "not isinstance(declared, bool)" in source


def test_unscheduled_entries_make_a_family_partial():
    source = definition_source("finalize_scan_report")
    assert 'row["unscheduled_candidates"] = sum(' in source
    assert 'row["reason"] = "manifest_entries_unscheduled"' in source
    # It must be checked BEFORE the complete branch, or truncation stays invisible.
    unscheduled = source.index('elif row["unscheduled_candidates"] > 0:')
    complete = source.index('row["coverage_status"] = "complete"')
    assert unscheduled < complete


def test_unscheduled_is_distinct_from_unattempted():
    # An entry that never became a slice cannot appear in unattempted_candidates, which is
    # planned-minus-attempted over slices that DID exist. Conflating them would hide one or the
    # other.
    source = definition_source("finalize_scan_report")
    assert 'row["unattempted_candidates"] = max(' in source
    assert 'row["manifest_candidates"] = sum(' in source


def test_the_scheduled_total_is_summed_per_capability_not_per_family():
    # A family can plan several capabilities with different manifests; summing across them would
    # let a large manifest mask a small one that was fully truncated.
    source = definition_source("finalize_scan_report")
    assert 'row["_scheduled_entries"][action.capability_name]' in source
    assert "for capability, total in manifest_entries.items()" in source


def test_unfinished_required_work_reaches_the_grade():
    """Marking a family partial is not enough on its own.

    `selected_family_gaps` is what carries a family's incompleteness into the top-level coverage
    rollup and `grade_reliable`. The unscheduled and unattempted branches set the family's own
    status but did not append to it, so an external audit reproduced a plan with ten manifest
    candidates and two scheduled that still reported `coverage: complete` and
    `grade_reliable: true`. A required family that did not finish its surface must invalidate the
    grade computed over it.
    """
    source = definition_source("finalize_scan_report")
    for reason in ("manifest_entries_unscheduled", "candidates_unattempted"):
        branch = source.index(f'row["reason"] = "{reason}"')
        nxt = source.find('elif row[', branch)
        tail = source[branch:nxt if nxt > 0 else branch + 400]
        assert 'selected_family_gaps.append(family)' in tail, reason
        assert 'if row["required"]:' in tail, reason


def test_an_optional_family_does_not_invalidate_the_grade():
    # Only a REQUIRED family's shortfall makes the grade unreliable; a supporting family that ran
    # partially is expected and must not degrade the whole report.
    source = definition_source("finalize_scan_report")
    branch = source.index('row["reason"] = "manifest_entries_unscheduled"')
    tail = source[branch:branch + 900]
    assert tail.index('if row["required"]:') < tail.index("selected_family_gaps.append(family)")
