"""The proof projection (``finding_proof_fields``) as one SQL expression, for the proof filter.

``GET /findings?proof_state=...`` used to read every row the other filters left, project each in
Python and refuse past 20,000 rows. This module states the same classification over the columns a
findings row gives the projection, so the filter is a WHERE clause with ordinary LIMIT/OFFSET and
``COUNT(*) OVER()``: no ceiling, and PostgreSQL streams it.

It must answer exactly what ``finding_proof_fields`` answers for a row of the list query; the
real-PostgreSQL parity test (tests/test_findings_proof_sql_postgres.py) holds the two together. A
findings row reaches the projection as ``f.*`` plus the latest retest, and the only inputs it reads
from such a row are ``severity``, ``last_verification_verdict``, the latest retest mode and keys of
``evidence``; every other key it consults (``validation``, ``poe``, ``proof_state``, ...) is not a
findings column. Python's string handling is reproduced exactly rather than approximated:

* ``str.strip()`` removes Python's whitespace set (``PY_WHITESPACE``), not just spaces;
* ``str.lower()`` is compared only against ASCII words, so folding A-Z and the Kelvin sign (the one
  non-ASCII character whose lowercase is ASCII) decides the same equalities;
* evidence arrives as PostgreSQL's JSON text, which Python parses: a number with a decimal point
  becomes a float, so "is it zero" and "is it 0 or 1" follow float rounding.

One input cannot always be decided in SQL: a triage block stored as a JSON *string* that Python's
``json.loads`` accepts but PostgreSQL's jsonb rejects (NaN, Infinity, lone surrogate escapes). Such
rows are "undetermined"; the route then projects in Python with a bounded streaming scan.
"""

from __future__ import annotations

try:
    from ai_verdict_policy import _DETERMINISTIC_PROOF_TYPES
except ImportError:  # host-side tests import api/ without scanner/ on the path
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scanner"))
    from ai_verdict_policy import _DETERMINISTIC_PROOF_TYPES

try:
    from proof_contracts import CANONICAL_PROOF_CONTRACTS
except ModuleNotFoundError:
    from ..proof_contracts import CANONICAL_PROOF_CONTRACTS

# Every character for which str.isspace() is true: what str.strip() with no argument removes.
PY_WHITESPACE = (
    "\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f \x85\xa0 "
    "           "
    "    　"
)
# Characters whose str.lower() is ASCII, and that ASCII.
FOLD_FROM = "ABCDEFGHIJKLMNOPQRSTUVWXYZK"
FOLD_TO = "abcdefghijklmnopqrstuvwxyzk"

CANDIDATE_PROOF_STATES = ("candidate", "suspected", "likely_vulnerable", "needs_review")
BROWSER_EVIDENCE_TYPES = ("dom_execution", "browser_execution")
BROWSER_TECHNIQUE_PREFIX = "headless_xss_"


# Correctly rounded float parsing: |x| <= 2**-1075 reads as 0.0 and 1 - 2**-54 <= x <= 1 + 2**-53
# as 1.0 (ties go to the even neighbour, which is 0.0 and 1.0). Compared after multiplying by an
# exact power of two so the bounds are integers.
_TWO_1075 = str(2 ** 1075)
_TWO_54 = str(2 ** 54)


def _unicode_literal(text: str) -> str:
    return "U&'" + "".join(
        char if char.isascii() and char.isalnum() else f"\\{ord(char):04X}" for char in text
    ) + "'"


def _words(words) -> str:
    return "(" + ", ".join("'" + word.replace("'", "''") + "'" for word in sorted(words)) + ")"


_WHITESPACE = _unicode_literal(PY_WHITESPACE)
_FOLD_FROM = _unicode_literal(FOLD_FROM)


def _strip(text: str) -> str:
    return f"btrim({text}, {_WHITESPACE})"


def _fold(text: str) -> str:
    return f"translate({text}, {_FOLD_FROM}, '{FOLD_TO}')"


def _text(value: str) -> str:
    return f"({value} #>> '{{}}')"


def _number(value: str) -> str:
    return f"{_text(value)}::numeric"


def _is_true(value: str) -> str:
    """``value is True``."""
    return f"COALESCE({value} = 'true'::jsonb, false)"


def _equals_string(value: str, literal: str) -> str:
    """``value == literal`` for a JSON value and a Python str."""
    return f"COALESCE({value} = '{_json_string(literal)}'::jsonb, false)"


def _json_string(literal: str) -> str:
    return '"' + literal.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _truthy(value: str) -> str:
    """``bool(value)`` for a decoded JSON value (missing reads as None)."""
    return f"""(CASE jsonb_typeof({value})
        WHEN 'boolean' THEN {value} = 'true'::jsonb
        WHEN 'number' THEN abs({_number(value)}) * {_TWO_1075} > 1
        WHEN 'string' THEN {_text(value)} <> ''
        WHEN 'array' THEN jsonb_array_length({value}) > 0
        WHEN 'object' THEN {value} <> '{{}}'::jsonb
        ELSE false END)"""


def _flag(value: str) -> str:
    """ai_verdict_policy._truthy: True, or a string that strips and lowers to 1/true/yes/on."""
    return (
        f"({_is_true(value)} OR COALESCE(jsonb_typeof({value}) = 'string'"
        f" AND {_fold(_strip(_text(value)))} IN ('1', 'true', 'yes', 'on'), false))"
    )


def _lower_word_in(value: str, words) -> str:
    """``str(value or "").strip().lower() in words``: only a string can match ASCII words."""
    return f"COALESCE(jsonb_typeof({value}) = 'string' AND {_fold(_strip(_text(value)))} IN {_words(words)}, false)"


def _lower_prefix(value: str, prefix: str) -> str:
    return (
        f"COALESCE(jsonb_typeof({value}) = 'string'"
        f" AND left({_fold(_strip(_text(value)))}, {len(prefix)}) = '{prefix}', false)"
    )


def _nonblank(value: str) -> str:
    """``bool(str(value or "").strip())``."""
    return (
        f"({_truthy(value)} AND COALESCE(jsonb_typeof({value}) <> 'string'"
        f" OR {_strip(_text(value))} <> '', false))"
    )


def _object(value: str) -> str:
    """``value if isinstance(value, dict) else {}``."""
    return f"(CASE WHEN jsonb_typeof({value}) = 'object' THEN {value} ELSE '{{}}'::jsonb END)"


def _zero_or_one(value: str) -> str:
    """``value in {False, True}``: a bool, or a number equal to 0 or 1 (0.0 and 1.0 too)."""
    return f"""(CASE jsonb_typeof({value})
        WHEN 'boolean' THEN true
        WHEN 'number' THEN abs({_number(value)}) * {_TWO_1075} <= 1
            OR {_number(value)} * {_TWO_54} BETWEEN {_TWO_54} - 1 AND {_TWO_54} + 2
        ELSE false END)"""


def _browser_proof(proof: str, *, nested: bool) -> str:
    """ai_verdict_policy._has_browser_execution_proof for one container."""
    parts = [
        _equals_string(f"{proof} -> 'proof_producer'", "shakerscan"),
        _lower_word_in(f"{proof} -> 'evidence_type'", BROWSER_EVIDENCE_TYPES),
        _lower_prefix(f"{proof} -> 'technique'", BROWSER_TECHNIQUE_PREFIX),
        _is_true(f"{proof} -> 'proven'") if nested else _is_true(f"{proof} -> 'dom_marker_executed'"),
    ]
    return "(" + " AND ".join(parts) + ")"


def _proof_contract_v2(contract: str) -> str:
    """ai_verdict_policy._has_verified_proof_contract_v2 for one envelope object."""
    reexecution = _object(f"{contract} -> 'reexecution'")
    predicate = _object(f"{contract} -> 'predicate'")
    required = f"NOT COALESCE({reexecution} -> 'required' = 'false'::jsonb, false)"
    performed = f"{reexecution} -> 'performed'"
    return "(" + " AND ".join([
        _equals_string(f"{contract} -> 'schema_version'", "proof-contract/v2"),
        _nonblank(f"{contract} -> 'contract_id'"),
        _nonblank(f"{contract} -> 'contract_version'"),
        _nonblank(f"{reexecution} -> 'verifier_build'"),
        f"(CASE WHEN {required} THEN {_is_true(performed)} ELSE {_zero_or_one(performed)} END)",
        _equals_string(f"{contract} -> 'verdict'", "verified"),
        _is_true(f"{contract} -> 'promotable'"),
        _is_true(f"{predicate} -> 'satisfied'"),
        f"NOT {_truthy(f'{predicate} -> ' + chr(39) + 'missing' + chr(39))}",
    ]) + ")"


def _decoded_triage(evidence: str) -> str:
    """serialization._json_object(evidence.get("triage")): an object, or a string holding one."""
    raw = f"({evidence} ->> 'triage')"
    stripped = _strip(raw)
    return f"""(CASE
        WHEN jsonb_typeof({evidence} -> 'triage') = 'object' THEN {evidence} -> 'triage'
        WHEN jsonb_typeof({evidence} -> 'triage') = 'string' AND left({stripped}, 1) = '{{'
             AND pg_input_is_valid({stripped}, 'jsonb')
            THEN {_object(f"{stripped}::jsonb")}
        ELSE '{{}}'::jsonb END)"""


def scan_time_proof_sql(evidence: str) -> str:
    """scan_verification_state.scan_time_verification_fields(...) == 'exploited' for a findings row."""
    evidence_object = f"COALESCE(jsonb_typeof({evidence}) = 'object', false)"
    return "(" + " OR ".join([
        _flag(f"{evidence} -> 'proof_of_exploitation'"),
        _flag(f"{evidence} -> 'payload_executed'"),
        _flag(f"{evidence} -> 'executed'"),
        _truthy(f"{evidence} -> 'extraction_evidence'"),
        _truthy(f"{evidence} -> 'extracted_data'"),
        _browser_proof(_object(f"{evidence} -> 'browser_proof'"), nested=True),
        _browser_proof(evidence, nested=False),
        _lower_word_in(f"{evidence} -> 'proof_type'", _DETERMINISTIC_PROOF_TYPES),
        # _has_satisfied_proof_contract: canonical contract, proof_state verified, triage.verified.
        "(" + " AND ".join([
            f"COALESCE(jsonb_typeof({evidence} -> 'proof_contract') = 'string'"
            f" AND {_strip(_text(f'{evidence} -> ' + chr(39) + 'proof_contract' + chr(39)))}"
            f" IN {_words(CANONICAL_PROOF_CONTRACTS)}, false)",
            _lower_word_in(f"{evidence} -> 'proof_state'", ("verified",)),
            _is_true(f"{_object(f'{evidence} -> ' + chr(39) + 'triage' + chr(39))} -> 'verified'"),
        ]) + ")",
        f"({evidence_object} AND {evidence} ? 'proof_contract_v2'"
        f" AND {_proof_contract_v2(_object(f'{evidence} -> ' + chr(39) + 'proof_contract_v2' + chr(39)))})",
    ]) + ")"


def proof_state_sql(*, evidence: str, severity: str, verdict: str, retest_mode: str) -> str:
    """SQL text: 'verified' | 'suspected' | 'unverified', exactly as finding_proof_fields answers."""
    triage = "decoded.triage"
    selected_state = f"""(CASE
        WHEN {_truthy(f"{evidence} -> 'proof_state'")} THEN {evidence} -> 'proof_state'
        WHEN {_truthy(f"{triage} -> 'proof_state'")} THEN {triage} -> 'proof_state'
        END)"""
    verified = (
        f"({scan_time_proof_sql(evidence)} OR ("
        f"{_fold(f'COALESCE({verdict}, {chr(39)}{chr(39)})')} = 'exploited'"
        f" AND {_fold(f'COALESCE({retest_mode}, {chr(39)}{chr(39)})')} = 'deterministic'))"
    )
    suspected = "(" + " OR ".join([
        f"{_fold(f'COALESCE({severity}, {chr(39)}{chr(39)})')} IN ('critical', 'high')",
        _is_true(f"{triage} -> 'suspected'"),
        _is_true(f"{triage} -> 'needs_verification'"),
        _lower_word_in(selected_state, CANDIDATE_PROOF_STATES),
    ]) + ")"
    return (
        f"(SELECT CASE WHEN {verified} THEN 'verified' WHEN {suspected} THEN 'suspected'"
        f" ELSE 'unverified' END FROM (SELECT {_decoded_triage(evidence)} AS triage) AS decoded)"
    )


def undetermined_proof_sql(evidence: str) -> str:
    """True for a row whose triage string Python may decode but PostgreSQL's jsonb cannot."""
    stripped = _strip(f"({evidence} ->> 'triage')")
    return (
        f"COALESCE(jsonb_typeof({evidence} -> 'triage') = 'string' AND left({stripped}, 1) = '{{'"
        f" AND NOT pg_input_is_valid({stripped}, 'jsonb'), false)"
    )


__all__ = [
    "CANDIDATE_PROOF_STATES",
    "FOLD_FROM",
    "FOLD_TO",
    "PY_WHITESPACE",
    "proof_state_sql",
    "scan_time_proof_sql",
    "undetermined_proof_sql",
]
