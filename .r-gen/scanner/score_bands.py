"""The one grade band table, shared by every scorer in both trees.

`scanner/grading.py` used A>=90/B>=80/C>=70/D>=55 while the canonical finalizer used D>=60,
so a scan scoring 57 rendered D on one path and F on the other. The table lives here, in the
lower tree, because the API tree may import the scanner but not the reverse.
"""

from __future__ import annotations


GRADE_BANDS: tuple[tuple[int, str], ...] = (
    (90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"),
)


def grade_for(score: int) -> str:
    """Return the letter for a 0-100 score."""
    try:
        value = int(score)
    except (TypeError, ValueError):
        return "F"
    for threshold, letter in GRADE_BANDS:
        if value >= threshold:
            return letter
    return "F"


__all__ = ["GRADE_BANDS", "grade_for"]
