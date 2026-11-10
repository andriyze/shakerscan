"""One finding per issue: a Scan must not report the same SQL injection or directory twice."""

from api.scan.finalizer import (
    _fold_directory_listing_slash_twins,
    _fold_sqli_candidates_into_proofs,
)

ORIGIN = "http://10.10.10.100:3000"


def _proof(field="q", method="GET", path="/rest/products/search", candidate="cand-1"):
    return {
        "tool": "shakerscan_sqli_proof", "title": "Verified SQL injection", "cwe": "CWE-89",
        "proof_state": "verified", "url": path,
        "evidence": {"origin": ORIGIN + "/", "method": method, "field_path": field,
                     "candidate_id": candidate},
    }


def _sqlmap(param="q", method="GET", path="/rest/products/search"):
    return {
        "tool": "sqlmap", "title": "Potential SQL injection", "cwe": "CWE-89",
        "proof_state": "likely_vulnerable",
        "url": f"{ORIGIN}{path}?{param}=%3Credacted%3E",
        "evidence": {"method": method, "param": param, "dbms": "SQLite"},
    }


def test_sqlmap_candidate_for_a_proven_input_joins_the_proof():
    proof = _proof()
    kept = _fold_sqli_candidates_into_proofs([proof, _sqlmap()])
    assert kept == [proof]
    assert proof["evidence"]["corroborating_candidates"] == [{
        "tool": "sqlmap", "title": "Potential SQL injection", "input": "q", "dbms": "SQLite",
    }]


def test_request_verifier_candidate_of_the_proven_candidate_joins_the_proof():
    proof = _proof()
    candidate = {
        "tool": "request_sqli_differential", "title": "Potential SQL injection", "cwe": "CWE-89",
        "proof_state": "likely_vulnerable", "url": None,
        "evidence": {"candidate_id": "cand-1", "field_path": "q"},
    }
    assert _fold_sqli_candidates_into_proofs([candidate, proof]) == [proof]


def test_candidates_on_another_input_method_or_route_stay_findings():
    proof = _proof()
    others = [_sqlmap(param="id"), _sqlmap(method="POST"), _sqlmap(path="/rest/basket")]
    assert _fold_sqli_candidates_into_proofs([proof, *others]) == [proof, *others]
    assert "corroborating_candidates" not in proof["evidence"]


def _listing(url):
    return {
        "tool": "shakerscan_exposure_probe", "title": "Sensitive exposure: directory listing",
        "proof_state": "verified", "url": url,
        "evidence": {"exposure_class": "directory_listing"},
    }


def test_a_directory_and_its_slash_form_are_one_listing():
    ftp, ftp_slash, sub = _listing(f"{ORIGIN}/ftp"), _listing(f"{ORIGIN}/ftp/"), _listing(f"{ORIGIN}/ftp/quarantine")
    known, known_slash = _listing(f"{ORIGIN}/.well-known"), _listing(f"{ORIGIN}/.well-known/")
    kept = _fold_directory_listing_slash_twins([ftp, ftp_slash, sub, known_slash, known])
    assert kept == [ftp, sub, known_slash]
    assert ftp["evidence"]["also_listed_at"] == [f"{ORIGIN}/ftp/"]
    assert known_slash["evidence"]["also_listed_at"] == [f"{ORIGIN}/.well-known"]


def test_other_exposures_at_one_path_are_not_folded():
    env = {**_listing(f"{ORIGIN}/backup/"), "evidence": {"exposure_class": "backup_artifact"}}
    listing = _listing(f"{ORIGIN}/backup")
    assert _fold_directory_listing_slash_twins([env, listing]) == [env, listing]
