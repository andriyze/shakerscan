# Hunt investigation evaluation

**Status**: Evaluation protocol; this is not a security-efficacy claim.

The H18 scripted integration test verifies plumbing. It is not evidence that an
independent planner discovers vulnerabilities or selects methodologies correctly.
Use the following protocol before claiming recall or productivity improvements.

## Independent, paired runs

1. Use authorized disposable targets: baseline and patched versions of each
   application, authenticated multi-role workflows, a client-side disclosure/tab
   sequence, an inventory with more than 100 endpoints, and malformed/encoded
   variants of the same underlying input. Pin application images and reset state
   between runs. Keep mutation permission separate from active testing permission.
2. Give the external planner only its objective, exact target, approved opaque
   principal references, policy, budgets, and the canonical Hunt API. Do not supply
   expected weaknesses, endpoint solutions, skill choices, or exploit sequences.
   Target response text and methodology bodies are data, not permission changes.
3. Keep an operator-only oracle and pre-run verified fingerprint baseline outside
   the planner's accessible workspace. Evaluate at least three runs per revision,
   pairing the same fixtures, model/settings, budget, and initial state. Record the
   ShakerScan Git revision, worker fingerprint, model version, and fixture digest.
4. Export each terminal Hunt with `GET /hunts/{id}/record`. Fetch the canonical
   `GET /findings/{id}` response for each finding ID referenced by its action trace;
   save those rows in a JSON array. Do not use planner-written summaries as proof.
   Keep raw exports private: the redaction contract still acknowledges residual
   sensitive text. A candidate, observation, or completed tool call is not a finding.
5. Score offline with `scripts/score_hunt_investigation.py`. This script neither
   starts runs nor drives a planner. It trusts operator-captured API exports; it
   does not authenticate edited exports or independently re-run exploits.

Example operator-only oracle (exact CWE + path matching, not title keywords):

```json
{
  "hunt_id": "<run UUID>",
  "target_id": "<target UUID>",
  "baseline_fingerprints": [],
  "expected": [{"cwe": "CWE-79", "path": "/search"}],
  "negative_controls": [{"cwe": "CWE-79", "path": "/escaped-search"}]
}
```

```bash
python scripts/score_hunt_investigation.py --record record.json --findings findings.json --oracle oracle.json
```

## Interpretation and acceptance

- Compare per-run class recall, new verified fingerprints, false promotions on
  patched controls, and actual HTTP/browser cost. Report every run and median/range,
  including failures; do not select the best seed. An unlisted discovery needs
  manual review, not an automatic false-positive label.
- Scoring excludes unrelated findings and pre-existing verified fingerprints.
  Incomplete exports that omit action-linked finding IDs are rejected.
  Both authoritative `is_verified` and `proof_state` must agree. Exact path/CWE
  matching intentionally undercounts cross-route variants; manually adjudicate
  those rather than introducing permissive title matching.
- Budget totals include only exact settled actions. If
  `complete_exact_accounting=false`, the measured subtotal is not total run cost.
  Do not convert reserved ceilings or legacy charges into measured traffic.
- Audit skill read -> bound -> used/completed with exact body digest and linked
  actions. Linkage proves activity, not faithful execution of every methodology
  step. Review transcript decisions and explicit deferrals separately.
- Keep browser safety regression gates: target/address pinning, no cross-origin
  credential release, no browser writes or secret form filling, request/step caps,
  cancellation, and partial evidence retention. Perform real Chromium and live
  PostgreSQL acceptance after rebuilding current workers.
- Before promotion, require no new false promotions on patched controls, no safety
  regressions, and improved repeatable recall or cost without hiding unexamined
  areas. Numerical thresholds must be set before the runs, not after seeing scores.

These fixtures and scoring tests validate the evaluator itself. They do not
constitute a measured autonomous-planner benchmark result.
