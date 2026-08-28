"""A single serious finding must not leave an A or B grade.

Scoring was purely subtractive from 100 -- critical -20, high -10 -- so a scan that proved one
critical SQL injection scored 80 and graded B, and one high-severity injection scored 90 and graded
A. On a deliberately vulnerable application the scan list showed rows of A*/90 next to a proven
injection, which is what a user noticed. Severity has to cap the grade, not merely dent it: the
worst thing found decides the ceiling, and the count of findings moves the score within it.
"""

from __future__ import annotations

import pytest

from api.scan.finalizer import _score


def _f(severity):
    return {"severity": severity}


def test_one_critical_finding_cannot_grade_above_f():
    score, grade = _score([_f("critical")])
    assert grade == "F", (score, grade)
    assert score < 60


def test_one_high_finding_cannot_grade_above_c():
    score, grade = _score([_f("high")])
    assert grade in {"C", "D", "F"}, (score, grade)
    assert score < 80


def test_one_medium_finding_cannot_grade_above_b():
    score, grade = _score([_f("medium")])
    assert grade in {"B", "C", "D", "F"}, (score, grade)
    assert score < 90


def test_a_clean_scan_still_scores_full_marks():
    assert _score([]) == (100, "A")


def test_informational_findings_do_not_move_the_grade():
    assert _score([_f("info"), _f("info")]) == (100, "A")


def test_a_low_finding_still_permits_a_high_grade():
    # A single low-severity issue is not a reason to fail an application.
    score, grade = _score([_f("low")])
    assert grade == "A"
    assert score < 100, "it should still cost something"


def test_more_findings_eventually_score_worse_than_one():
    """The ceiling sets the band; the count pushes below it.

    Because the ceiling is a floor on how good the score can be, the first few findings of a
    severity all land at the ceiling -- one high and three highs are both C. Once the subtractive
    weight passes the ceiling the count starts to bite, so volume is not ignored.
    """
    one = _score([_f("high")])[0]
    several = _score([_f("high")] * 3)[0]
    many = _score([_f("high")] * 6)[0]
    assert several == one, "the ceiling dominates until the weight exceeds it"
    assert many < one, "volume must eventually matter"
    assert _score([_f("high")] * 6)[1] in {"D", "F"}


def test_the_worst_severity_sets_the_ceiling():
    # A critical alongside anything else is still capped by the critical.
    assert _score([_f("critical"), _f("low")])[1] == "F"
    assert _score([_f("high"), _f("medium"), _f("low")])[1] in {"C", "D", "F"}


def test_an_unknown_severity_is_treated_as_informational_not_ignored_silently():
    # Unrecognised input must not accidentally become the worst or best case.
    assert _score([{"severity": "bogus"}]) == (100, "A")
