# Worker Management

View and scale scanner workers.

**Usage**: `/workers [count]`

## Instructions

1. Check if scanner is running:
   ```bash
   curl -s http://localhost:8080/health
   ```

2. If no count argument provided, show current worker status:
   ```bash
   # Get worker count via API
   curl -s http://localhost:8080/workers

   # Get queue stats
   curl -s http://localhost:8080/queue/stats
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
     curl -X POST http://localhost:8080/workers \
       -H "Content-Type: application/json" \
       -d '{"count": N}'
     ```
   - If API scaling fails, suggest CLI:
     ```
     ./scanner.sh scale N
     ```

5. After scaling, verify new count:
   ```bash
   curl -s http://localhost:8080/workers
   ```

6. Report result:
   ```
   Scaled to N workers
   - Running: X
   - Pending jobs: Y
   ```
