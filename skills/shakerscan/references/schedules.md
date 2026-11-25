# Schedules

A schedule runs a Scan (`normal_scan`) or a Continuous ASM improvement (`asm_improve`) for one
target, daily or weekly. The server checks the target and the options exactly as for a Scan.

1. **List**: `shakerscan api GET '/schedules?target_id=<target_id>'` (each with `schedule_health`).
2. **Read one**: `shakerscan api GET /schedules/<schedule_id>`.
3. **Create**:
   `shakerscan api POST /schedules '{"target_id":"<id>","frequency":"weekly","day_of_week":0,"time_of_day":"02:00","timezone":"UTC","scan_options":{"budget_profile":"balanced","policy":{"active_testing":false}}}'`.
   Recurring Scans are passive: the server refuses active testing, credentials, request selections
   and approval receipts in a schedule (submit an explicit Scan for active work, see
   `follow-a-scan.md`). Safe automation defaults are at `GET /settings/automation`.
4. **Change or pause**: `shakerscan api PATCH /schedules/<schedule_id> '{"is_active":false}'`.
5. **Delete** only when the person asks: `shakerscan api DELETE /schedules/<schedule_id>`.

Report the schedule id, when it next runs (`next_run_at`) and its health.
