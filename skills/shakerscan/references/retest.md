# Retest a finding

A retest re-runs the deterministic prover for one finding and records the verdict in its history.
It sends requests to the target, so it is active testing.

1. **Read the finding**: `shakerscan api GET /findings/<finding_id>`: note `target_id`, `status`,
   `proof_state` and the finding type. Device findings are retested by a bounded device scan, AI
   Gate findings by re-running the AI target; the route refuses both and says so.
2. **Check the target's standing authorization**:
   `shakerscan api GET /targets/<target_id>/authorization`. When `authorization` is null, do not
   retest: tell the person to run `shakerscan targets authorize <url-or-id>` in their own terminal,
   and wait. Never authorize it yourself.
3. **Queue it**: `shakerscan api POST /findings/<finding_id>/retest '{}'`. The answer has
   `retest_id`, `status: queued` and the replay commands.
4. **Read the outcome**: `shakerscan api GET /retests/finding/<finding_id>` (newest first) or
   `shakerscan api GET /retests/<retest_id>`: its status, the verdict, `verdict_basis` (a
   deterministic proof, or an AI assessment that alone never concludes) and its evidence.

Several findings at once: `shakerscan api POST /findings/retest '{"finding_ids":[...]}'` (at most 200),
with the same authorization rule for every target involved.
