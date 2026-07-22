"""Pure adjudication primitives shared by the live refuter/promotion path and any offline recompute.

No engine imports (no db, httpx, fastapi) — pure functions only, so the live scan path and any
re-derivation of the same decision cannot drift. This mirrors T3MP3ST's ``src/mission/adjudicate.ts``
discipline ("must SHARE so the two paths can't drift"), pinned by the ``--self-test`` at the bottom.

Core invariant (the symmetric mirror of "no LLM output can *create* a finding"):

    No refutation may DISMISS a finding/hypothesis unless it is deterministically corroborated.

An uncorroborated ("signal_only") refute vote fail-safe DOWNGRADES to non-refuting — a hallucinated
refutation that buried a real finding would be catastrophic, because dedup then blocks re-finding it.
For ShakerScan the "cited guard" of the source-code world becomes "the claimed mitigation was
actually OBSERVED in a deterministic re-run" (e.g. a real 403 on cross-principal access).
"""

from __future__ import annotations

from typing import Any

ADJUDICATE_VERSION = "adjudicate-2026-07-12.v1"

# Bases that count as deterministic corroboration for a REFUTE. ``signal_only`` is excluded on
# purpose: an LLM/heuristic assertion with no re-executed proof must never terminally dismiss.
DETERMINISTIC_BASES: frozenset[str] = frozenset(
    {"deterministic_replay", "cryptographic", "parser_protocol", "human_approved_review"}
)
ALL_BASES: frozenset[str] = DETERMINISTIC_BASES | frozenset({"signal_only"})
REFUTER_VERDICTS: frozenset[str] = frozenset({"supported", "weakened", "refuted", "inconclusive"})

# Principals that may never be the authority for a dismissal.
FORBIDDEN_REFUTATION_SOURCES: frozenset[str] = frozenset({"llm", "model", "planner", "ai", "prose"})

# Evidence-strength ladder, low -> high. Promotion requires the top rung, freshly re-executed.
EVIDENCE_STRENGTH_ORDER: tuple[str, ...] = ("claimed", "signal", "reproduced", "cross_principal_verified")
_STRENGTH_RANK: dict[str, int] = {name: index for index, name in enumerate(EVIDENCE_STRENGTH_ORDER)}


def evidence_strength_rank(value: Any) -> int:
    """Rank a strength label; unknown/absent -> -1 (below every real rung)."""
    return _STRENGTH_RANK.get(str(value or "").strip().lower(), -1)


def meets_strength(value: Any, minimum: str) -> bool:
    """True iff ``value`` is at least ``minimum`` on the ladder. Unknown ``minimum`` is unreachable."""
    floor = _STRENGTH_RANK.get(str(minimum or "").strip().lower(), len(EVIDENCE_STRENGTH_ORDER))
    return evidence_strength_rank(value) >= floor


def citecheck_vote(vote: dict[str, Any]) -> dict[str, Any]:
    """Apply the deterministic cite-check to one refuter vote.

    A ``refuted`` vote only *counts* as a refute when its basis is deterministic AND it cites a
    mitigation that was actually observed (corroborating tool-receipt / evidence, or an
    ``cite.observed`` re-run signal). Otherwise it fail-safe downgrades to non-refuting.
    ``weakened`` is a partial negative and never terminally dismisses on its own.
    Returns a normalized vote dict; never raises.
    """
    verdict = (str(vote.get("refuter_verdict") or "").strip().lower() or None)
    if verdict not in REFUTER_VERDICTS:
        verdict = None
    basis = str(vote.get("verdict_basis") or "signal_only").strip().lower()
    if basis not in ALL_BASES:
        basis = "signal_only"
    cite = vote.get("cite") if isinstance(vote.get("cite"), dict) else {}
    has_evidence = bool(vote.get("tool_receipt_ids") or vote.get("evidence_object_ids"))
    cite_observed = bool(cite.get("observed"))
    corroborated = (basis in DETERMINISTIC_BASES) and (has_evidence or cite_observed)

    counts_as_refute = False
    downgraded = False
    reason: str | None = None
    if verdict == "refuted":
        if corroborated:
            counts_as_refute = True
        else:
            downgraded = True
            reason = (
                "refute_basis_not_deterministic"
                if basis not in DETERMINISTIC_BASES
                else "refute_missing_corroborating_evidence"
            )
    return {
        "refuter": str(vote.get("refuter") or vote.get("created_by") or "")[:120],
        "verdict": verdict,
        "basis": basis,
        "corroborated": corroborated,
        "counts_as_refute": counts_as_refute,
        "downgraded": downgraded,
        "reason": reason,
        "cite": {"mitigation": str(cite.get("mitigation") or "")[:300], "observed": cite_observed},
    }


def adjudicate_panel(votes: list[dict[str, Any]] | None, *, min_panel: int = 2) -> dict[str, Any]:
    """Deterministic strict-majority adjudication of a refuter panel.

    Each vote passes the cite-check first. A finding is REFUTED only on a strict majority of
    *counted* refutes among the terminal (refuted/supported) votes — ``refuted * 2 > total`` — so
    **ties resolve to SURVIVED**. A panel below ``min_panel`` is INCONCLUSIVE (never refuted).
    ``survives`` is the fail-safe: only a clean majority refute dismisses; anything else stands.
    Pure and deterministic — identical input yields identical output.
    """
    checked = [citecheck_vote(v) for v in (votes or []) if isinstance(v, dict)]
    refute_votes = [c for c in checked if c["counts_as_refute"]]
    support_votes = [c for c in checked if c["verdict"] == "supported"]
    total = len(refute_votes) + len(support_votes)
    refuted_count = len(refute_votes)
    supported_count = len(support_votes)
    downgrades = [c for c in checked if c["downgraded"]]

    # Only terminal votes participate in quorum.  Otherwise a caller could pad a
    # panel with downgraded/inconclusive rows and let one corroborated refute
    # become a "majority" of the single participating vote.
    if total < max(1, int(min_panel)):
        verdict, reason = "inconclusive", "panel_below_min"
    elif total == 0:
        verdict, reason = "inconclusive", "no_terminal_votes"
    elif refuted_count * 2 > total:
        verdict, reason = "refuted", "strict_majority_refute"
    elif supported_count * 2 > total:
        verdict, reason = "supported", "strict_majority_support"
    else:
        verdict, reason = "inconclusive", "no_strict_majority"  # includes ties -> survive

    return {
        "version": ADJUDICATE_VERSION,
        "verdict": verdict,
        "reason": reason,
        "refuted_count": refuted_count,
        "supported_count": supported_count,
        "participating": total,
        "panel_size": len(checked),
        "downgraded_count": len(downgrades),
        "downgrades": [{"refuter": c["refuter"], "reason": c["reason"]} for c in downgrades],
        "cited_mitigations": [c["cite"]["mitigation"] for c in refute_votes if c["cite"]["mitigation"]],
        "survives": verdict != "refuted",
    }


def require_deterministic_refutation(transition: dict[str, Any]) -> tuple[bool, str | None]:
    """Gate a hypothesis->refuted / finding->false_positive transition (the negative gate).

    Returns ``(ok, reason)``. A dismissal is allowed ONLY when it carries a deterministic basis AND
    a concrete ``refuted_by.verification_id`` whose source is
    not an LLM/planner. Fail-closed: anything missing/model-sourced -> ``(False, reason)``.
    """
    basis = str(transition.get("verdict_basis") or transition.get("basis") or "").strip().lower()
    refuted_by = transition.get("refuted_by") or {}
    if isinstance(refuted_by, str):
        refuted_by = {"ref": refuted_by}
    if not isinstance(refuted_by, dict):
        refuted_by = {}
    source = str(refuted_by.get("source") or "").strip().lower()
    ref = str(
        refuted_by.get("verification_id")
        or refuted_by.get("ref")
        or ""
    ).strip()
    if source in FORBIDDEN_REFUTATION_SOURCES:
        return False, "refuted_by_llm_forbidden"
    if basis not in DETERMINISTIC_BASES:
        return False, "refutation_basis_not_deterministic"
    if not ref:
        return False, "refutation_missing_deterministic_reference"
    return True, None


def vote_from_review(review: dict[str, Any]) -> dict[str, Any]:
    """Normalize a refuter-review-shaped dict (see RefuterReviewRequest) into a panel vote."""
    counter = review.get("counterevidence") if isinstance(review.get("counterevidence"), dict) else {}
    cite = review.get("cite") or counter.get("cite") or {}
    return {
        "refuter_verdict": review.get("refuter_verdict"),
        "verdict_basis": review.get("verdict_basis"),
        "tool_receipt_ids": review.get("tool_receipt_ids") or [],
        "evidence_object_ids": review.get("evidence_object_ids") or [],
        "cite": cite if isinstance(cite, dict) else {},
        "refuter": review.get("created_by") or review.get("refuter"),
    }


def _self_test() -> None:
    """Deterministic self-test. Run: ``python api/adjudicate.py`` (exit 0 = green)."""
    det = {"verdict_basis": "deterministic_replay", "cite": {"mitigation": "ownership 403", "observed": True}}

    # A corroborated deterministic refute counts.
    assert citecheck_vote({"refuter_verdict": "refuted", **det})["counts_as_refute"] is True

    # signal_only refute is fail-safe downgraded, not counted.
    ds = citecheck_vote({"refuter_verdict": "refuted", "verdict_basis": "signal_only", "cite": {"observed": True}})
    assert ds["counts_as_refute"] is False and ds["downgraded"] is True
    assert ds["reason"] == "refute_basis_not_deterministic"

    # deterministic basis but NO corroborating observation -> downgraded.
    ne = citecheck_vote({"refuter_verdict": "refuted", "verdict_basis": "deterministic_replay"})
    assert ne["counts_as_refute"] is False and ne["reason"] == "refute_missing_corroborating_evidence"

    # Strict majority refute (2/3) -> refuted, does not survive.
    p = adjudicate_panel([
        {"refuter_verdict": "refuted", **det},
        {"refuter_verdict": "refuted", **det},
        {"refuter_verdict": "supported", "verdict_basis": "deterministic_replay"},
    ])
    assert p["verdict"] == "refuted" and p["survives"] is False and p["refuted_count"] == 2

    # Tie (1 refute / 1 support) -> survives (ties resolve to not-refuted).
    tie = adjudicate_panel([
        {"refuter_verdict": "refuted", **det},
        {"refuter_verdict": "supported", "verdict_basis": "deterministic_replay"},
    ])
    assert tie["verdict"] != "refuted" and tie["survives"] is True

    # A panel of only-downgraded refutes -> no terminal votes -> survives.
    bogus = adjudicate_panel([
        {"refuter_verdict": "refuted", "verdict_basis": "signal_only"},
        {"refuter_verdict": "refuted", "verdict_basis": "signal_only"},
    ])
    assert bogus["verdict"] == "inconclusive" and bogus["survives"] is True and bogus["downgraded_count"] == 2

    # Below min panel -> inconclusive, survives.
    assert adjudicate_panel([{"refuter_verdict": "refuted", **det}])["verdict"] == "inconclusive"

    # Negative gate: deterministic ref allowed; llm/absent/non-det rejected.
    assert require_deterministic_refutation(
        {"verdict_basis": "deterministic_replay", "refuted_by": {"verification_id": "abc"}}
    ) == (True, None)
    assert require_deterministic_refutation(
        {"verdict_basis": "deterministic_replay", "refuted_by": {"ref": "x", "source": "llm"}}
    )[0] is False
    assert require_deterministic_refutation(
        {"verdict_basis": "signal_only", "refuted_by": {"verification_id": "abc"}}
    ) == (False, "refutation_basis_not_deterministic")
    assert require_deterministic_refutation({"verdict_basis": "deterministic_replay"}) == (
        False,
        "refutation_missing_deterministic_reference",
    )

    # Evidence-strength ladder.
    assert meets_strength("cross_principal_verified", "cross_principal_verified") is True
    assert meets_strength("reproduced", "cross_principal_verified") is False
    assert evidence_strength_rank("claimed") < evidence_strength_rank("reproduced")

    print("adjudicate self-test OK")


if __name__ == "__main__":
    _self_test()
