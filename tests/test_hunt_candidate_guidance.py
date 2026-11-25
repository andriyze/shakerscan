"""Candidate answers name the verifier that proves the family and a second issue the evidence shows."""
from __future__ import annotations

import asyncio
import json

from api.hunt.candidate_guidance import candidate_guidance, evidence_texts_from_rows, guidance
from api.hunt.candidate_verification_preflight import (
    CandidateVerificationRefused,
    web_candidate_preflight,
)

import pytest


def test_injection_candidates_are_steered_to_sqli_and_xss_verify():
    sql = guidance(family="injection", title="Search box SQL injection", claim="a quote breaks the query",
                   locus={"path": "/rest/products/search", "parameter": "q"})
    assert [item["capability"] for item in sql] == ["sqli.verify"]
    assert sql[0]["input"] == {"path": "/rest/products/search", "parameter": "q"}
    xss = guidance(family="xss", title="Reflected script", claim="", locus={"route": "/search"})
    assert [item["capability"] for item in xss] == ["xss.verify"]
    alias = guidance(family="sqli", title="t", claim="c", locus={})
    assert alias and alias[0]["capability"] == "sqli.verify"
    assert guidance(family="bola", title="Another user's order", claim="", locus={"route": "/orders/2"}) == []


def test_a_second_issue_in_the_evidence_is_suggested_as_its_own_claim():
    texts = ['{"id":2,"username":"sam","password_hash":"$2b$12$abc","salary":90000}']
    found = guidance(family="bola", title="Reads other users", claim="", locus={}, evidence_texts=texts)
    assert found[0]["kind"] == "second_claim" and found[0]["family"] == "data_exposure"
    assert "password_hash" in found[0]["fields"]
    # Already an exposure claim: nothing to add for the fields.
    assert guidance(family="data_exposure", title="t", claim="", locus={}, evidence_texts=texts) == []
    listing = guidance(family="data_exposure", title="wp-config backup", claim="", locus={},
                       evidence_texts=["<html><title>Index of /backup</title>"])
    assert listing and "directory index" in listing[0]["message"]


def test_evidence_texts_read_samples_and_json_keys():
    rows = [{"result_summary": json.dumps({"observations": [{"response": {
        "body_sample": "hello", "json_keys": ["id", "password"], "selected_json": {"$.a": 1}}}]})},
            {"result_summary": "not json"}, {"result_summary": {"observations": ["x"]}}]
    texts = evidence_texts_from_rows(rows)
    assert "hello" in texts and '"id": "password":' in texts


def test_candidate_guidance_reads_only_this_hunts_cited_actions():
    action = "6c0ad8b1-4b8e-4c86-9d38-1f0b7d6d8f10"

    class Conn:
        async def fetch(self, query, *args):
            assert "hunt_run_id=$1" in query and args[1] == [action]
            return [{"result_summary": {"observations": [{"response": {"json_keys": ["api_key"]}}]}}]

    found = asyncio.run(candidate_guidance(Conn(), run={"id": "h"}, family="access_control", title="t",
                                           claim="", locus={}, evidence_refs=[f"action:{action}"]))
    assert found[0]["fields"] == ["api_key"]


def test_candidate_verify_refusal_for_injection_names_the_verifiers():
    with pytest.raises(CandidateVerificationRefused) as refused:
        web_candidate_preflight({"family": "sqli", "canonical_locus": {"route": "/search"}})
    assert refused.value.detail.startswith("verification bridge supports")
    assert "sqli.verify" in refused.value.detail and "xss.verify" in refused.value.detail
