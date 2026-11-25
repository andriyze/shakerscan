"""What a recorded candidate's answer suggests next: the right verifier, and a second claim.

Two measured gaps between what Hunts saw and what they recorded:

* **The wrong proof path.** A SQL injection or XSS recorded as family ``injection`` (or ``sqli``,
  which is an alias of it) goes to ``candidate.verify``, which proves neither; ``sqli.verify`` and
  ``xss.verify`` do, on the route and parameter. The answer names the verifier and its input.
* **One claim for two issues.** A response that shows another principal's record *and* a password
  hash, or a directory index *and* the files in it, was recorded as one candidate, so the second
  issue was never claimed. When the cited evidence carries sensitive fields (or a directory index)
  that the claim's family does not cover, the answer suggests a separate candidate citing the same
  evidence.

Guidance only: nothing here records, verifies or refuses anything.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
import re
from typing import Any

_SQL = re.compile(r"\bsql\b|sqli|sql.?injection|union\s+select|syntax error|sqlite|mysql|postgres|"
                  r"ora-\d|odbc|boolean.?based|time.?based", re.I)
_XSS = re.compile(r"\bxss\b|cross.?site.?script|<script|onerror=|javascript:|reflected|stored script", re.I)
_SENSITIVE_FIELD = re.compile(
    r"\"?(password_hash|passwordhash|password|passwd|pwd_hash|hashed_password|secret|client_secret|"
    r"api_key|apikey|access_token|refresh_token|private_key|aws_secret_access_key|ssn|"
    r"social_security|card_number|cardnumber|cvv|iban|mfa_secret|totp_secret|otp_secret|salt)\"?\s*[:=]",
    re.I)
_DIRECTORY_INDEX = re.compile(r"index of /|directory listing|<title>\s*index of", re.I)
_EXPOSURE_FAMILIES = frozenset({"data_exposure", "sensitive_data_exposure", "information_disclosure",
                                "secrets", "secret_exposure"})
_INJECTION_FAMILIES = frozenset({"injection", "sqli", "sql_injection", "xss", "cross_site_scripting",
                                 "reflected_xss", "stored_xss", "nosqli", "ssti"})


def _family(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _route(locus: Mapping[str, Any]) -> str | None:
    for key in ("route", "path", "url", "endpoint"):
        if locus.get(key):
            return str(locus[key])
    return None


def _parameter(locus: Mapping[str, Any]) -> str | None:
    for key in ("parameter", "param", "field", "input", "query_parameter", "body_field"):
        if locus.get(key):
            return str(locus[key])
    return None


def guidance(*, family: Any, title: Any, claim: Any, locus: Mapping[str, Any] | None,
             evidence_texts: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Suggestions for one recorded candidate (empty when there is nothing to add)."""
    family_name = _family(family)
    locus = dict(locus or {})
    text = f"{title or ''} {claim or ''}"
    route = _route(locus)
    parameter = _parameter(locus)
    out: list[dict[str, Any]] = []
    if family_name in _INJECTION_FAMILIES or family_name.endswith("injection"):
        sql = family_name in {"sqli", "sql_injection"} or bool(_SQL.search(text))
        xss = family_name in {"xss", "cross_site_scripting", "reflected_xss", "stored_xss"} or bool(_XSS.search(text))
        target = {**({"path": route} if route else {}), **({"parameter": parameter} if parameter else {})}
        if sql:
            out.append({
                "kind": "verify_with",
                "capability": "sqli.verify",
                "input": target,
                "message": ("candidate.verify cannot prove SQL injection; run sqli.verify on this route "
                            "and parameter (for a body field: method, body_field_names and "
                            "injection_field). It proves and records the finding itself."),
            })
        if xss:
            out.append({
                "kind": "verify_with",
                "capability": "xss.verify",
                "input": target,
                "message": ("candidate.verify cannot prove XSS; run xss.verify on this route and "
                            "parameter. It proves and records the finding itself."),
            })
    joined = "\n".join(str(item) for item in evidence_texts)[:200_000]
    fields = sorted({match.group(1).lower() for match in _SENSITIVE_FIELD.finditer(joined)})
    if fields and family_name not in _EXPOSURE_FAMILIES:
        out.append({
            "kind": "second_claim",
            "family": "data_exposure",
            "fields": fields[:8],
            "message": (f"The cited evidence also returns {', '.join(fields[:5])}: that is a separate "
                        "issue from this claim. Record it as its own data_exposure candidate citing "
                        "the same evidence, then candidate.verify it."),
        })
    if _DIRECTORY_INDEX.search(joined) and "directory" not in text.lower() and "listing" not in text.lower():
        out.append({
            "kind": "second_claim",
            "family": "data_exposure",
            "message": ("The cited evidence is a directory index: the listing itself is a separate "
                        "issue (directory listing enabled), and each sensitive file in it is its own "
                        "claim. Record them separately."),
        })
    return out


def evidence_texts_from_rows(rows: Iterable[Mapping[str, Any]]) -> list[str]:
    """Body samples, JSON keys and selected values of the cited actions' observations."""
    texts: list[str] = []
    for row in rows:
        summary = row.get("result_summary")
        if isinstance(summary, str):
            try:
                summary = json.loads(summary)
            except ValueError:
                continue
        if not isinstance(summary, Mapping):
            continue
        for observation in (summary.get("observations") or [])[:10]:
            if not isinstance(observation, Mapping):
                continue
            response = observation.get("response") if isinstance(observation.get("response"), Mapping) else observation
            for key in ("body_sample", "text_sample"):
                if response.get(key):
                    texts.append(str(response[key])[:20_000])
            if response.get("json_keys"):
                texts.append(" ".join(f'"{key}":' for key in response["json_keys"]))
            if response.get("selected_json"):
                texts.append(json.dumps(response["selected_json"], default=str)[:20_000])
    return texts


async def candidate_guidance(conn: Any, *, run: Mapping[str, Any], family: Any, title: Any, claim: Any,
                             locus: Mapping[str, Any] | None, evidence_refs: Iterable[str] | None) -> list[dict[str, Any]]:
    """``guidance`` for a candidate just recorded, reading its cited actions' answers."""
    identifiers = []
    for reference in evidence_refs or ():
        text = str(reference or "")
        match = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text, re.I)
        if match:
            identifiers.append(match.group(0).lower())
    rows: list[Mapping[str, Any]] = []
    if identifiers:
        rows = await conn.fetch(
            """SELECT result_summary FROM hunt_actions
               WHERE hunt_run_id=$1 AND id::text = ANY($2::text[]) LIMIT 20""",
            run["id"], identifiers[:20],
        )
    return guidance(family=family, title=title, claim=claim, locus=locus,
                    evidence_texts=evidence_texts_from_rows([dict(row) for row in rows]))


__all__ = ["candidate_guidance", "evidence_texts_from_rows", "guidance"]
