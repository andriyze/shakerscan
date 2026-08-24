# Deprecated Full command compatibility

`/scan-full` is a temporary compatibility shim. It does not select a separate engine. It translates
to the deterministic Scan with `thorough` ceilings and active-testing permission. Sunset:
**2026-12-31**. Prefer `/scan` with explicit policy and budget.

**Usage**: `/scan-full <target_url>`

## Instructions

1. Confirm that the user owns or is explicitly authorized to actively test the exact target.
2. Use `API_BASE=${SHAKERSCAN_API_BASE:-http://localhost:8080}` and
   `UI_BASE=${SHAKERSCAN_UI_BASE:-http://localhost:3000}`, or the URLs printed by
   `./scanner.sh status`.
3. Submit the canonical translation:

   ```bash
   curl -X POST "$API_BASE/scans" \
     -H "Content-Type: application/json" \
     -H "X-ShakerScan-CLI-Compatibility: scan-full" \
     -d '{
       "target": "$ARGUMENTS",
       "budget_profile": "thorough",
       "policy": {"active_testing": true}
     }'
   ```

4. Report the scan ID and `${UI_BASE}/scans/{scan_id}`, then stop. Do not poll.

The compatibility name is telemetry only: it must never enter the queued job, immutable plan, or
report as execution authority.
