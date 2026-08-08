---
name: research-agent
description: >-
  Run ShakerScan Deep Hunt: the current coding agent performs free-form, AI-driven exploration and
  bounded active exploitation through /agent/hunt/* while ShakerScan enforces target scope,
  approvals, budgets, evidence provenance, and deterministic finding verification. Use for “deep
  hunt”, “autonomous hunt”, or “investigate autonomously”; do not use for ordinary DAST scans.
---

# Deep Hunt

Deep Hunt is ShakerScan’s autonomous AI investigation workflow. The current Codex, Claude, or
OpenCode session plans each turn; ShakerScan is the only executor.

Keep the user-facing model simple:

- `scan`, `quick scan`, `deep scan`, `smart scan` are Web DAST.
- `deep hunt`, `autonomous hunt`, `investigate autonomously` are this workflow.
- `verify this finding` is the deterministic finding verifier.
- `interactive testing` is the manual browser workbench.

The legacy `/research/*` episode controller remains available for internal guided verification and
compatibility. Do not launch `/research/campaigns/launch` when the user asks for Deep Hunt.

## Authorization and launch

1. Check `GET /health`.
2. Resolve or create the authorized HTTP(S) target and retain its `target_id`.
3. Explain that Deep Hunt performs bounded active testing and confirm that the user owns the target
   or has explicit permission.
4. Create a target-bound scope receipt and an expiring credential-tier approval containing
   `confirm_authorized`.
5. Start:

   ```http
   POST /agent/hunt/{target_id}/session
   Content-Type: application/json

   {
     "objective": "Explore autonomously and verify the highest-value security weaknesses",
     "mode": "deep_hunt",
     "max_iterations": 20,
     "token_budget": 9000,
     "approval_receipt_id": "APPROVAL_UUID"
   }
   ```

Deep Hunt enables bounded active `run_tool` templates and approved proof promotion. Arbitrary
state-changing `POST`/`PUT`/`PATCH`/`DELETE` requests remain blocked in the free-form loop; controlled
mutation belongs to typed server workflows with cleanup and proof contracts.

## Drive the keyless loop

The session returns a `run_id` and a complete transcript. The current coding-agent session is the
planner—no separate AI provider key is required.

1. Read the complete latest transcript.
2. If `status` is `awaiting_planner`, submit one reply to:

   ```http
   POST /agent/hunt/session/{run_id}/reply
   ```

3. Continue with a fenced tool-call block:

   ````text
   ```json
   {"tool_calls":[{"name":"http_request","arguments":{"method":"GET","path":"/api/items","as_principal":"anonymous"}}]}
   ```
   ````

4. Finish with a debrief:

   ```json
   {
     "done": true,
     "findings": [
       {
         "title": "Anonymous access to private records",
         "severity": "high",
         "family": "data_exposure",
         "predicate": "anonymous_sensitive_read",
         "route": "/api/items",
         "method": "GET",
         "evidence_refs": ["resp_1"],
         "remediation": "Require authorization before returning records."
       }
     ],
     "abstained": false
   }
   ```

5. Drive only while the run is `awaiting_planner`. `planning` means a turn is already executing.
   Stop on `completed`, `failed`, or `cancelled`, and surface a non-clean `stop_reason`.

Use:

```http
GET  /agent/hunt/session/{run_id}
POST /agent/hunt/session/{run_id}/cancel
GET  /agent/hunt/runs
GET  /agent/findings/{target_id}
```

## Tool and evidence contract

Callable tools are `http_request`, `query_kb`, `diff`, `note`, and `run_tool`. Follow the tool
schemas embedded in the first transcript exactly.

- All target traffic stays on the selected target host. Scheme and port may change only through an
  explicit concrete origin; never cross to another host.
- Credentials are resolved server-side through managed principal slots and never enter planner
  messages.
- Use different principals and `diff` for access-control hypotheses.
- Each HTTP response produces a `resp_N` reference.
- A finding is persisted only when `evidence_refs` points to actual tool output.
- Planner prose, inline `details`, or a status code alone is not proof.
- Never invent receipt IDs, credentials, target IDs, evidence references, or tool output.

Findings begin in the **Suspected** tier. Supported families may be replayed through the server’s
deterministic two-run proof moat and become **Verified** only when the proof predicate passes.
Never claim that the model verified a vulnerability.

## Authenticated targets

Configure managed credential profiles and bind them to target principal slots before the hunt:

```http
POST /targets/{target_id}/credential-profiles
POST /targets/{target_id}/principals
```

Use `as_principal` values offered by the tool contract, such as `anonymous`, `user1`, or `user2`.
Expired credentials must be rotated server-side. Never ask the model to carry a bearer token,
cookie, password, or approval receipt content.

## Stop conditions

Stop when:

- the objective is answered;
- the evidence falsifies the remaining leads;
- the turn, request, active-action, time, or token ceiling is reached;
- authorization expires or fails revalidation;
- the target is deactivated;
- the user cancels;
- the planner declines or cannot produce a valid turn.

Report the Deep Hunt run ID and UI path `/deep-hunt?run={run_id}`. If a Deep Hunt tool
queues an asynchronous scan or retest, report its ID and stop instead of polling unless the user
explicitly asks to continue later.
