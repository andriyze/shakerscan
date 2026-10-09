"""Masking an archived body is linear, bounded, and never runs on the API's event loop.

External release audit, 2026-10-09 (R2): the YAML/text pass walked a secret descriptor's whole
item once per descriptor, so an item that repeats ``name: api_key`` was quadratic (4,000 lines,
56 KB, took 2.97 s), and the async archive endpoint built its export on the event loop. A
scanned service chooses its responses, so a body it returned could stall the API at a later
masked archive view or export.

The masking outcome must not change: the reference below is the per-descriptor walk as it was,
and the linear pass must withhold exactly the lines it withheld. The canaries are test
fixtures; no body here came from a live target.
"""

from __future__ import annotations

import random
import sys

import pytest

from api.runtime import archive_body_masking as masking
from api.runtime.archive_body_masking import (
    _DESCRIPTOR_NAME_KEYS,
    _STRUCTURAL_KEYS,
    _masked_line,
    _opens_credential_context,
    _yaml_line,
    is_location_value,
    is_withheld_key,
    mask_body_text,
    mask_credential_shaped,
    mask_yaml_text,
)

CANARY = "YamlCanaryQ7x2Lm9"


def reference_mask_yaml_text(text: str) -> str:
    """``mask_yaml_text`` before R2, kept verbatim as the oracle for the linear pass."""
    lines = text.split("\n")
    parsed = [_yaml_line(line) for line in lines]
    masked = [False] * len(lines)

    scope: int | None = None
    for index, (indent, item, key, value, _offset) in enumerate(parsed):
        if not lines[index].strip():
            continue
        if scope is not None:
            if indent > scope:
                masked[index] = value is not None
                continue
            scope = None
        if key is not None and is_withheld_key(key):
            if value is None or value in {"|", ">", "|-", ">-", "|+", ">+"}:
                scope = indent
            else:
                masked[index] = True

    for index, (indent, item, key, value, _offset) in enumerate(parsed):
        if not (
            key is not None and key.lower() in _DESCRIPTOR_NAME_KEYS and value is not None
            and is_withheld_key(value.strip("\"'"))
        ):
            continue
        start = index
        if not item:
            for previous in range(index - 1, -1, -1):
                if not lines[previous].strip():
                    continue
                if parsed[previous][0] < indent:
                    break
                start = previous
                if parsed[previous][0] == indent and parsed[previous][1]:
                    break
        for position in range(start, len(lines)):
            other_indent, other_item, other_key, other_value, _ = parsed[position]
            if not lines[position].strip():
                continue
            if position > index and (
                other_indent < indent or (other_item and other_indent == indent)
            ):
                break
            if other_value is None:
                continue
            if other_key is None or other_key.lower() not in _STRUCTURAL_KEYS:
                masked[position] = True

    shaped: dict[int, str] = {}
    context: int | None = None
    for index, (indent, item, key, value, offset) in enumerate(parsed):
        if not lines[index].strip() or masked[index]:
            continue
        if context is not None and indent <= context:
            context = None
        opens = key is not None and _opens_credential_context(key)
        if value is not None and (context is not None or opens) and (
            key is None or key.lower() not in masking._CONTEXT_NAME_KEYS
        ):
            rewritten = mask_credential_shaped(lines[index][offset:])
            if rewritten != lines[index][offset:]:
                shaped[index] = lines[index][:offset] + rewritten
        if context is None and opens and value is None:
            context = indent

    if not any(masked) and not shaped:
        return text
    return "\n".join(
        _masked_line(line, parsed[index][4], parsed[index][2])
        if masked[index] and not is_location_value(parsed[index][2], parsed[index][3])
        else shaped.get(index, line)
        for index, line in enumerate(lines)
    )


_KEYS = (
    "name", "key", "header", "param", "in", "type", "value", "example", "default", "api_key",
    "password", "description", "items", "properties", "parameters", "token", "x-secret", "env",
    "token_url", "headers",
)
_VALUES = (
    "api_key", "password", "client_secret", "'api_key'", '"token"', "x", "|", ">-", "query",
    f"{CANARY}", "https://example.test/token", "abcDEF123456789xyzQWE", None,
)


def _random_document(rng: random.Random) -> str:
    lines = []
    for _ in range(rng.randint(1, 40)):
        roll = rng.random()
        if roll < 0.08:
            lines.append("")
            continue
        if roll < 0.12:
            lines.append(rng.choice(("\t", "   ", "# note", "plain prose: here", "---", "- ", "-", "][:")))
            continue
        indent = " " * rng.choice((0, 0, 1, 2, 2, 3, 4, 4, 6, 8))
        dash = "- " if rng.random() < 0.3 else ""
        if rng.random() < 0.1:
            lines.append(indent + dash + rng.choice(_VALUES[:-1]))
            continue
        value = rng.choice(_VALUES)
        lines.append(f"{indent}{dash}{rng.choice(_KEYS)}:" + ("" if value is None else f" {value}"))
    return "\n".join(lines)


def test_the_linear_pass_withholds_exactly_what_the_per_descriptor_walk_withheld():
    rng = random.Random(20261009)
    with_descriptors = 0
    for _ in range(4_000):
        document = _random_document(rng)
        assert mask_yaml_text(document) == reference_mask_yaml_text(document), document
        lines = document.split("\n")
        if masking._descriptor_items(lines, [_yaml_line(line) for line in lines]):
            with_descriptors += 1
    # The comparison is only worth something if the generator exercises descriptors.
    assert with_descriptors > 1_000


@pytest.mark.parametrize("document", [
    # Repeated descriptors at one indentation: one item each, values withheld in each.
    "\n".join(f"- name: api_key\n  in: query\n  example: {CANARY}{index}" for index in range(50)),
    # Repeated descriptors with no list dash, sharing one block.
    "parameters:\n" + "\n".join(f"  name: password\n  default: {CANARY}{index}" for index in range(50)),
    # A descriptor nested inside another item's block.
    f"- in: header\n  schema:\n    name: token\n    example: {CANARY}\n- name: page\n  example: 3",
    # Malformed, non-YAML text the dispatcher still passes through this pass.
    f"name: api_key\n\t- ][: : value: {CANARY}\n  : :\n-\n- name: token\n value: {CANARY}\n}}{{",
])
def test_descriptor_shapes_withhold_every_canary(document):
    masked = mask_body_text(document)
    assert masked == mask_body_text(document)  # deterministic
    assert mask_yaml_text(document) == reference_mask_yaml_text(document)
    assert CANARY not in masked


def test_a_value_outside_the_descriptor_item_is_not_withheld():
    document = f"- name: api_key\n  example: {CANARY}\n- name: page\n  example: visible-page-3"
    masked = mask_yaml_text(document)
    assert CANARY not in masked
    assert "visible-page-3" in masked


def _line_events(function, *args) -> int:
    """Python line events inside the masking module while ``function`` runs: a work count."""
    count = 0
    target = masking.__file__

    def tracer(frame, event, _arg):
        nonlocal count
        if frame.f_code.co_filename != target:
            return None
        if event == "line":
            count += 1
        return tracer

    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        function(*args)
    finally:
        sys.settrace(previous)
    return count


@pytest.mark.parametrize("make", [
    pytest.param(lambda size: "name: api_key\n" * size, id="repeated-descriptors"),
    pytest.param(lambda size: "  name: password\n  example: x\n" * size, id="flat-block"),
    pytest.param(
        lambda size: "".join(
            f"{' ' * (2 * (index % 40))}- name: token\n{' ' * (2 * (index % 40))}  example: v\n"
            for index in range(size)
        ),
        id="nested-blocks",
    ),
    pytest.param(lambda size: "api_key:\n" + "  value: x\n" * size, id="secret-scope"),
])
def test_yaml_masking_work_grows_linearly(make):
    # A quadratic pass does 16x the work at 4x the input; a linear one about 4x.
    small, large = _line_events(mask_yaml_text, make(500)), _line_events(mask_yaml_text, make(2_000))
    assert large <= 6 * small, (small, large)
