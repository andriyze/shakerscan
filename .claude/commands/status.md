# Scanner Status

Check the status of the Shaker Scan scanner.

**Usage**: `/status`

## Instructions

1. Check if scanner is running:
   ```bash
   curl -s http://localhost:8080/health 2>/dev/null
   ```

2. If not running, report:
   ```
   Scanner is not running.
   Start it with: ./scanner.sh start
   ```

3. If running, fetch stats:
   ```bash
   curl -s http://localhost:8080/queue/stats
   curl -s http://localhost:8080/dashboard
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
   - UI: http://localhost:3000
   - API: http://localhost:8080
   ```
