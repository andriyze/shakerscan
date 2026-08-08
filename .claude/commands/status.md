# Scanner Status

Check the status of ShakerScan.

**Usage**: `/status`

## Instructions

Use `API_BASE=${SHAKERSCAN_API_BASE:-http://localhost:8080}` for API calls. Use `UI_BASE=${SHAKERSCAN_UI_BASE:-http://localhost:3000}` for UI links. On a remote VPS, prefer the URLs printed by `./scanner.sh status` after `./scanner.sh start --remote`.

1. Check if scanner is running:
   ```bash
   curl -s "$API_BASE/health" 2>/dev/null
   ```

2. If not running, report:
   ```
   Scanner is not running.
   Start it with: ./scanner.sh start
   For remote VPS over Tailscale: ./scanner.sh start --remote
   ```

3. If running, fetch stats:
   ```bash
   curl -s "$API_BASE/queue/stats"
   curl -s "$API_BASE/dashboard"
   ```

4. Report:
   ```
   ✓ Scanner is running

   Queue:
   - Pending: X
   - Running: X
   - Completed: X

   Stats:
   - Total targets: X
   - Total scans: X
   - Active findings: X (Y critical, Z high)

   Access:
   - UI: ${UI_BASE}
   - API: ${API_BASE}
   ```
