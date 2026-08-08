# Worker Management

View and scale scanner workers.

**Usage**: `/workers [count]`

## Instructions

Use `API_BASE=${SHAKERSCAN_API_BASE:-http://localhost:8080}` for API calls. On a remote VPS, set it
to the API URL printed by `./scanner.sh status`.

1. Check if scanner is running:
   ```bash
   curl -s "$API_BASE/health"
   ```

2. If no count argument provided, show current worker status:
   ```bash
   # Get worker count via API
   curl -s "$API_BASE/workers"

   # Get queue stats
   curl -s "$API_BASE/queue/stats"
   ```

3. Report current status:
   ```
   Workers: X running
   Queue: Y pending, Z running
   ```

4. If count argument provided (e.g., `/workers 5`):
   - Parse the number from $ARGUMENTS
   - Validate it's between 1-20
   - Scale workers:
     ```bash
     curl -X POST "$API_BASE/workers" \
       -H "Content-Type: application/json" \
       -d '{"count": N}'
     ```
   - If API scaling fails, suggest CLI:
     ```
     ./scanner.sh scale N
     ```

5. After scaling, verify new count:
   ```bash
   curl -s "$API_BASE/workers"
   ```

6. Report result:
   ```
   Scaled to N workers
   - Running: X
   - Pending jobs: Y
   ```
