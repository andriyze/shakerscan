"""CT-discovered names are attributed to the monitored root they actually sit under."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(relative: str):
    spec = importlib.util.spec_from_file_location(f"gungnir_{relative.split('/')[0]}", ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(params=["api/gungnir_worker.py", "scanner/gungnir_worker.py"])
def worker(request, monkeypatch):
    # The worker imports redis/asyncpg for its runtime loop; matching needs neither, and other
    # tests may leave partial stubs of those modules behind.
    monkeypatch.setitem(sys.modules, "redis", types.SimpleNamespace(Redis=object, from_url=lambda *_a, **_k: None))
    monkeypatch.setitem(sys.modules, "asyncpg", types.SimpleNamespace(create_pool=None))
    return _load(request.param)


@pytest.mark.parametrize(
    ("name", "roots", "expected"),
    [
        ("a.example.com", ["le.com", "example.com"], "example.com"),
        ("a.example.com", ["example.com", "le.com"], "example.com"),
        ("api.eu.example.com", ["example.com", "eu.example.com"], "eu.example.com"),
        ("evilexample.com", ["example.com"], None),
        ("example.com", ["example.com"], None),
        ("A.Example.com".lower(), ["Example.COM"], "Example.COM"),
        ("a.example.com", ["example.com."], "example.com."),
        ("a.example.org", ["example.com"], None),
    ],
)
def test_match_root_domain_uses_label_boundaries_and_most_specific_root(worker, name, roots, expected):
    assert worker.match_root_domain(name, roots) == expected
