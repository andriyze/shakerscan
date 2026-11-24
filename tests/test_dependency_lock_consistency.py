"""Every hash-pinned lock resolves its human-maintained input.

The images install only the locks (`pip install --require-hashes -r ...lock`), so a raised floor or
pin in the input (by hand or by a dependency update PR) has no effect until the lock is recompiled.
A lock that no longer satisfies its input ships the old version silently; this check names it.
"""
import re
from pathlib import Path

import pytest
from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]

_PAIRS = [
    ("scanner/requirements.txt", "scanner/requirements.lock"),
    ("runner/guest/requirements.in", "runner/guest/requirements.lock"),
    ("runner/host/requirements.in", "runner/host/requirements.lock"),
] + [
    (str(source.relative_to(ROOT)), str(source.with_suffix(".lock").relative_to(ROOT)))
    for source in sorted((ROOT / "scanner" / "model_intake_tools").glob("*.in"))
]

_LOCKED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)==([^\s\\;]+)")


def _canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _locked_versions(lock_text):
    versions = {}
    for line in lock_text.splitlines():
        match = _LOCKED.match(line)
        if match:
            versions.setdefault(_canonical(match.group(1)), set()).add(match.group(2))
    return versions


def _requirements(source_text):
    for line in source_text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith("-"):
            yield Requirement(line)


def _unsatisfied(source_text, lock_text):
    locked = _locked_versions(lock_text)
    problems = []
    for requirement in _requirements(source_text):
        if requirement.url:
            continue
        versions = locked.get(_canonical(requirement.name))
        if not versions:
            problems.append(f"{requirement.name} is not in the lock")
            continue
        if not any(requirement.specifier.contains(version, prereleases=True) for version in versions):
            problems.append(f"{requirement} but the lock has {', '.join(sorted(versions))}")
    return problems


def test_the_lock_pairs_exist():
    assert len(_PAIRS) >= 8
    for source, lock in _PAIRS:
        assert (ROOT / source).is_file(), source
        assert (ROOT / lock).is_file(), lock


@pytest.mark.parametrize(("source", "lock"), _PAIRS)
def test_each_lock_satisfies_its_input(source, lock):
    problems = _unsatisfied((ROOT / source).read_text(), (ROOT / lock).read_text())
    assert not problems, f"{lock} is behind {source} (recompile it with the command in its header): {problems}"


def test_a_raised_floor_or_pin_without_a_recompiled_lock_is_named():
    lock = "paramiko==5.0.0 \\\n    --hash=sha256:00\n    # via -r in\nnumpy==2.5.4 ; python_version >= '3.12' \\\n"
    assert _unsatisfied("paramiko>=5.0.0\nnumpy==2.5.4\n", lock) == []
    assert _unsatisfied("paramiko>=5.1.0  # newer\nnumpy==2.5.5\nmissing-dist\n", lock) == [
        "paramiko>=5.1.0 but the lock has 5.0.0",
        "numpy==2.5.5 but the lock has 2.5.4",
        "missing-dist is not in the lock",
    ]
