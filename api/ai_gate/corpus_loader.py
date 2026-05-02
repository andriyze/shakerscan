from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .models import Probe, ProbeTurnTemplate


CORPORA_ROOT = Path(__file__).resolve().parent / "corpora"
VALID_SCAN_PROFILES = {"smoke", "trace", "standard", "deep"}
MAX_INLINE_PROBES = 50
MAX_INLINE_PROMPT_CHARS = 4000
MAX_INLINE_TURNS = 8


@dataclass(frozen=True)
class ProbeLoadResult:
    probes: tuple[Probe, ...]
    errors: tuple[str, ...] = ()


def _read_required_string(entry: dict[str, object], key: str) -> str | None:
    value = entry.get(key)
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _read_optional_string(entry: dict[str, object], key: str) -> str | None:
    value = entry.get(key)
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _read_string_tuple(entry: dict[str, object], key: str) -> tuple[str, ...]:
    value = entry.get(key)
    if not isinstance(value, list):
        return ()
    return tuple(item.strip() for item in value if isinstance(item, str) and item.strip())


def _read_turns(
    entry: dict[str, object],
    *,
    entry_index: int,
    prompt: str,
    errors: list[str],
) -> tuple[ProbeTurnTemplate, ...]:
    raw_turns = entry.get("turns")
    if raw_turns is None:
        return ()
    if not isinstance(raw_turns, list):
        errors.append(
            f"custom_probes[{entry_index}].turns must be an array; using prompt as the only turn"
        )
        return ()

    turns: list[ProbeTurnTemplate] = []
    for turn_index, turn in enumerate(raw_turns[:MAX_INLINE_TURNS]):
        if not isinstance(turn, dict):
            errors.append(f"custom_probes[{entry_index}].turns[{turn_index}] must be an object")
            continue
        message = _read_required_string(turn, "message")
        if message is None:
            errors.append(f"custom_probes[{entry_index}].turns[{turn_index}].message is required")
            continue
        if len(message) > MAX_INLINE_PROMPT_CHARS:
            errors.append(
                f"custom_probes[{entry_index}].turns[{turn_index}].message exceeds {MAX_INLINE_PROMPT_CHARS} chars; truncating"
            )
            message = message[:MAX_INLINE_PROMPT_CHARS]
        turns.append(
            ProbeTurnTemplate(
                message=message,
                role=_read_optional_string(turn, "role") or "attacker",
            )
        )

    if isinstance(raw_turns, list) and len(raw_turns) > MAX_INLINE_TURNS:
        errors.append(
            f"custom_probes[{entry_index}].turns has more than {MAX_INLINE_TURNS} turns; extra turns ignored"
        )
    return tuple(turns) if turns else (ProbeTurnTemplate(message=prompt),)


def _read_max_turns(entry: dict[str, object], turns: tuple[ProbeTurnTemplate, ...]) -> int:
    raw_value = entry.get("max_turns")
    default = max(len(turns), 1)
    if isinstance(raw_value, (int, float)):
        return max(1, min(int(raw_value), MAX_INLINE_TURNS))
    return max(1, min(default, MAX_INLINE_TURNS))


def _load_probe_entries(
    raw_entries: object,
    *,
    source_name: str | None = None,
    source_reference: str | None = None,
) -> tuple[Probe, ...]:
    return _load_probe_entries_with_diagnostics(
        raw_entries,
        source_name=source_name,
        source_reference=source_reference,
    ).probes


def _load_probe_entries_with_diagnostics(
    raw_entries: object,
    *,
    source_name: str | None = None,
    source_reference: str | None = None,
) -> ProbeLoadResult:
    if raw_entries is None:
        return ProbeLoadResult(())
    if not isinstance(raw_entries, list):
        return ProbeLoadResult((), ("custom_probes must be an array",))

    probes: list[Probe] = []
    errors: list[str] = []
    seen_ids: set[str] = set()
    for entry_index, entry in enumerate(raw_entries[:MAX_INLINE_PROBES]):
        if not isinstance(entry, dict):
            errors.append(f"custom_probes[{entry_index}] must be an object")
            continue
        probe_id = _read_required_string(entry, "id")
        family = _read_required_string(entry, "family")
        title = _read_required_string(entry, "title")
        prompt = _read_required_string(entry, "prompt")
        missing = [
            key
            for key, value in (
                ("id", probe_id),
                ("family", family),
                ("title", title),
                ("prompt", prompt),
            )
            if value is None
        ]
        if missing:
            errors.append(f"custom_probes[{entry_index}] missing required fields: {', '.join(missing)}")
            continue
        assert probe_id is not None
        assert family is not None
        assert title is not None
        assert prompt is not None

        if probe_id in seen_ids:
            errors.append(
                f"custom_probes[{entry_index}].id duplicates another custom probe: {probe_id}"
            )
            continue
        seen_ids.add(probe_id)

        if len(prompt) > MAX_INLINE_PROMPT_CHARS:
            errors.append(
                f"custom_probes[{entry_index}].prompt exceeds {MAX_INLINE_PROMPT_CHARS} chars; truncating"
            )
            prompt = prompt[:MAX_INLINE_PROMPT_CHARS]

        minimum_profile = _read_optional_string(entry, "minimum_profile") or "smoke"
        if minimum_profile not in VALID_SCAN_PROFILES:
            errors.append(
                f"custom_probes[{entry_index}].minimum_profile must be one of {', '.join(sorted(VALID_SCAN_PROFILES))}"
            )
            continue

        turns = _read_turns(entry, entry_index=entry_index, prompt=prompt, errors=errors)
        entry_source_name = _read_optional_string(entry, "source_name")
        entry_source_reference = _read_optional_string(entry, "source_reference")
        probes.append(
            Probe(
                id=probe_id,
                family=family,
                title=title,
                prompt=prompt,
                owasp=_read_optional_string(entry, "owasp"),
                minimum_profile=minimum_profile,
                technique=_read_optional_string(entry, "technique"),
                source_name=entry_source_name or source_name,
                source_reference=entry_source_reference or source_reference,
                tactics=_read_string_tuple(entry, "tactics"),
                expected_safe_behavior=_read_optional_string(entry, "expected_safe_behavior"),
                expected_attack_success=_read_optional_string(entry, "expected_attack_success"),
                severity_if_success=_read_optional_string(entry, "severity_if_success"),
                turns=turns,
                max_turns=_read_max_turns(entry, turns),
                requires_state=bool(entry.get("requires_state", bool(turns))),
                requires_fresh_session=bool(entry.get("requires_fresh_session", False)),
                safe_for_production=bool(entry.get("safe_for_production", True)),
            )
        )
    if isinstance(raw_entries, list) and len(raw_entries) > MAX_INLINE_PROBES:
        errors.append(
            f"custom_probes has more than {MAX_INLINE_PROBES} entries; extra probes ignored"
        )
    return ProbeLoadResult(tuple(probes), tuple(errors))


def load_probe_corpus(filename: str) -> tuple[Probe, ...]:
    corpus_path = CORPORA_ROOT / filename
    raw_entries = json.loads(corpus_path.read_text(encoding="utf-8"))
    return _load_probe_entries(raw_entries)


def load_inline_probe_entries(
    raw_entries: object,
    *,
    source_name: str = "customer_pack",
    source_reference: str = "metadata_json.custom_probes",
) -> tuple[Probe, ...]:
    return _load_probe_entries(
        raw_entries,
        source_name=source_name,
        source_reference=source_reference,
    )


def load_inline_probe_entries_with_diagnostics(
    raw_entries: object,
    *,
    source_name: str = "customer_pack",
    source_reference: str = "metadata_json.custom_probes",
) -> ProbeLoadResult:
    return _load_probe_entries_with_diagnostics(
        raw_entries,
        source_name=source_name,
        source_reference=source_reference,
    )
