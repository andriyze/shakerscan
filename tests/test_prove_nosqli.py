"""Regression test for the generic NoSQL operator-injection prover (Verification Depth A)."""
import asyncio
import os
import sys

SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
sys.path.insert(0, SCANNER_DIR)
from scanner_tools import proof_of_exploit as poe  # noqa: E402
sys.path.pop(0)


def _run(mock, url="http://t/api/users?role=user"):
    orig = poe.fetch_with_capture
    poe.fetch_with_capture = mock
    try:
        return asyncio.run(poe.prove_nosqli(url, "role"))
    finally:
        poe.fetch_with_capture = orig


def test_prove_nosqli_proves_operator_bypass():
    # $ne(unlikely) returns materially MORE than $eq(unlikely) and baseline -> bypass proven.
    async def fake(url, timeout=12):
        if "%24ne" in url:
            return {"status_code": 200, "body": "U" * 6000}
        if "%24eq" in url:
            return {"status_code": 200, "body": "U" * 80}
        return {"status_code": 200, "body": "U" * 400}  # baseline
    proof = _run(fake)
    assert proof.proven is True
    assert proof.evidence_type == "nosql_operator_differential"
    assert proof.confidence >= 0.8


def test_prove_nosqli_no_differential_not_proven():
    # Uniform responses (static page) -> no differential -> not proven (no false positive).
    async def flat(url, timeout=12):
        return {"status_code": 200, "body": "U" * 400}
    proof = _run(flat)
    assert proof.proven is False
    assert proof.evidence_type == "not_vulnerable"


def test_prove_nosqli_no_query_param_inconclusive():
    async def fake(url, timeout=12):
        return {"status_code": 200, "body": "x"}
    orig = poe.fetch_with_capture
    poe.fetch_with_capture = fake
    try:
        proof = asyncio.run(poe.prove_nosqli("http://t/api/users", "role"))
    finally:
        poe.fetch_with_capture = orig
    assert proof.proven is False
    assert proof.evidence_type == "inconclusive"
