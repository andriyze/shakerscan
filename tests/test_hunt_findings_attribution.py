"""Execute the production run-scope predicates, including opt-in candidates.

SQLite validates relational behavior locally; PostgreSQL execution is covered
separately in Hunt record CI. Neither is an independent bug-discovery benchmark.
"""
import sqlite3
from pathlib import Path

from api.finding_routes.hunt_scope import candidate_hunt_predicate, finding_hunt_predicate


def database():
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE hunt_runs(id TEXT,target_id TEXT,device_target_id TEXT);
        INSERT INTO hunt_runs VALUES ('hunt-a','target',NULL),('hunt-b','target',NULL),('foreign','other',NULL);
        CREATE TABLE findings(id TEXT,hunt_run_id TEXT,target_id TEXT,device_target_id TEXT);
        INSERT INTO findings VALUES ('direct','hunt-a','target',NULL),('family-proof',NULL,'target',NULL),
          ('reverified','hunt-b','target',NULL),('unrelated',NULL,'target',NULL),('wrong-owner',NULL,'other',NULL);
        CREATE TABLE finding_verifications(finding_id TEXT,requested_by TEXT,status TEXT,verdict TEXT,
          verification_mode TEXT,target_id TEXT,device_target_id TEXT);
        INSERT INTO finding_verifications VALUES
          ('family-proof','hunt_v2:hunt-a','completed','exploited','deterministic','target',NULL),
          ('reverified','hunt_v2:hunt-a','completed','exploited','deterministic','target',NULL),
          ('unrelated','hunt_v2:hunt-a','completed','inconclusive','deterministic','target',NULL),
          ('wrong-owner','hunt_v2:hunt-a','completed','exploited','deterministic','other',NULL);
        CREATE TABLE investigation_candidates(id TEXT,hunt_run_id TEXT);
        INSERT INTO investigation_candidates VALUES ('new','hunt-a'),('seen','hunt-b'),('foreign','hunt-b');
        CREATE TABLE investigation_candidate_observations(candidate_id TEXT,hunt_run_id TEXT);
        INSERT INTO investigation_candidate_observations VALUES ('seen','hunt-a');
    """)
    return db


def matched(db, hunt="hunt-a"):
    return {r[0] for r in db.execute("SELECT f.id FROM findings f WHERE " + finding_hunt_predicate(1), (hunt,))}


def test_null_direct_attribution_and_later_upsert_keep_actual_producing_run_visible():
    db = database()
    assert matched(db) == {"direct", "family-proof", "reverified"}
    assert matched(db, "hunt-b") == {"reverified"}
    assert matched(db, "foreign") == set()


def test_failed_or_nondeterministic_verification_never_supplies_missing_attribution():
    db = database()
    db.execute("UPDATE finding_verifications SET verification_mode='ai_driven'")
    assert matched(db) == {"direct"}
    db.execute("UPDATE finding_verifications SET verification_mode='deterministic',status='failed'")
    assert matched(db) == {"direct"}


def test_opt_in_candidate_union_cannot_escape_hunt_filter():
    db = database()
    ids = {r[0] for r in db.execute("SELECT c.id FROM investigation_candidates c WHERE " + candidate_hunt_predicate(1), ("hunt-a",))}
    assert ids == {"new", "seen"}


def test_route_applies_the_predicates_to_both_queries():
    source = (Path(__file__).resolve().parents[1] / "api/finding_routes/router.py").read_text()
    assert 'query += " AND " + finding_hunt_predicate(param_idx)' in source
    assert 'candidate_query += " AND " + candidate_hunt_predicate(cand_idx)' in source
