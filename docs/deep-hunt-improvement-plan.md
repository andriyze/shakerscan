# Deep Hunt — Discovery & Loop Improvement Plan

_Grounded in the 2026-07-17 create-based mass-assignment session: the engine was made to find AND
verify a genuinely net-new bug with zero false positives, proven end-to-end through the real dispatch,
then driven through a live gated campaign to the exact blocking gates. This document captures the
data, the experience, and a prioritized plan — with discovery as the binding constraint._

## 1. What is proven (this session's wins)

The autonomous engine now promotes **create-based mass_assignment** (the canonical Juice Shop
admin-registration bug, `POST /api/Users {role:admin}`) end-to-end, with the zero-FP moat intact.

| Layer | Evidence | Commit |
|---|---|---|
| Zero-FP relax (managed body credential + best-effort restoration, server-derived) | 6 regression guards; can't leak to other families or bypass a predicate | `0b25f07` |
| Write-route proof binding (create-MA binds to the POST, not the GET read-back) | a real "plumbed-not-wired" gate the harness missed | `9ad47a9` |
| Server-side materializer + universal field/envelope discovery | probe → materialize; `$.data.id` discovered, not hardcoded | `fc43dc9` |
| Per-run credential injector (fresh creds each of the two runs) | no replay collision on unique-email creates | `b76948d` |
| cleanup_route no longer required (consistency with best-effort restoration) | the create-MA lead can rank/template without a DELETE route | `2d0dde4` |

**Real-dispatch proof** (`scratchpad/real_dispatch.py`): the production `_arsenal_dispatch_workflow`
ran probe → materializer → real auth resolution → two-run with per-run creds → `proof_state: verified`
→ a real `autonomous_workflow` / `high` / `exploited` / CWE-915 finding in the DB. **518 tests green.**

## 2. Live campaign experience (what was driven, and the exact wall)

A real gated `deep_hunt` campaign was launched in `agent` mode and it ran:

- Minted a credential-tier approval receipt (scope `allowed`); campaign **active**, readiness **ready**
  (surface: ~19.7k inventory rows, ~5.2k mutation routes, `mass_assignment` executable).
- The board produced **6 real leads** (5 `mass_assignment`, 1 `data_exposure`) and the episode went
  `awaiting_planner`.
- Submitting an `execute_action` decision for the create-based registration lead was **rejected** with:
  ```
  experiment_hypothesis_not_on_ranked_live_surface
  experiment_step_method_not_on_surface:control_verify:GET:/api/Users/{id}
  experiment_step_method_not_on_surface:verify:GET:/api/Users/{id}
  experiment_step_method_not_on_surface:cleanup_created:DELETE:/api/Users/{id}
  experiment_step_method_not_on_surface:cleanup_control:DELETE:/api/Users/{id}
  ```

**The loop correctly refuses to act off its discovered surface — and discovery doesn't capture the
create-MA object-instance surface.** This is the binding constraint, not the engine.

## 3. Root-cause analysis

`target_endpoints` for the Juice Shop target **has** `POST /api/Users` (create) and `GET /api/Users`,
`GET /api/Users/` — but **not** the object-instance routes `GET /api/Users/{id}` or
`DELETE /api/Users/{id}`. The crawler saw the collection but never a concrete `/api/Users/5`, so it
never inferred the `/{id}` form. Two consequences, both fatal to create-based MA:

1. **The lead can't form.** `_endpoint_inventory_hypothesis_requests` computes
   `object_route = route + "/{id}"` and `readback_route = object_route if "GET" in object_route_methods`.
   With no `GET /api/Users/{id}` on surface, `readback_route = None → create_based = False` → no
   create-based mass_assignment lead is produced (`readback_route_missing`).
2. **A seeded workflow is rejected.** The decision validator canonicalizes each step's route and
   requires `(method, route)` to be on the surface; `GET /api/Users/{id}` and `DELETE /api/Users/{id}`
   are not, so every read-back/cleanup step is rejected (`experiment_step_method_not_on_surface`).

Separately, a **ranking gap**: a high-severity operator-seeded create-MA lead did not surface in the
top-of-board (`experiment_hypothesis_not_on_ranked_live_surface`), crowded out by update-based leads.

## 4. Improvement plan (prioritized)

### P0 — Discovery: capture the object-instance surface (the binding constraint)

- **P0-1 Infer object-instance routes for discovered collections.** When the inventory has
  `POST /collection` and any `GET /collection/<concrete>` or `/collection/`, register the canonical
  `GET /collection/{id}` (and `DELETE /collection/{id}` where a delete is observed or the API is
  RESTful) in `target_endpoints`. This is inventory canonicalization (`asm_inventory.py`
  `normalize_path` / `dedupe_signature`), not new crawling — it lets the read-back/cleanup routes exist
  on the surface. Lowest-risk, highest-leverage.
- **P0-2 Create-surface probe during discovery (authorized/lab).** The materializer already proves the
  probe technique: for a write collection, create one throwaway object with server-generated
  credentials, observe the returned object route + response envelope, register `GET/DELETE
  /collection/{id}`, best-effort delete. Gated to authorized/Lab intent; labeled + cleaned up. Turns
  "invisible registration surface" into first-class inventory.
- **P0-3 Operator endpoint ingestion → surface, not one-off.** `custom_endpoints` / an OpenAPI / a
  registration hint should persist into `target_endpoints` (the surface the loop gates on), so an
  operator who knows the registration endpoint makes it a rankable lead + a valid experiment surface.

### P1 — Surface-gating: allow create-object siblings

- **P1-1 Accept `/collection/{id}` read-back/cleanup when `POST /collection` is on surface.** In the
  decision-validator surface check, treat the object-instance sibling of an on-surface create
  collection as on-surface for a create-based mass_assignment experiment (the family proof gates the
  rest). This makes the create-MA workflow dispatch even before P0-1/P0-2 land, without loosening the
  surface gate for unrelated routes.

### P1 — Ranking: create-based / net-new leads must surface

- **P1-2 Float create-based mass_assignment leads.** They are the net-new family DAST misses; ensure
  the board de-monopolization / family-balance floats them rather than letting update-based MA leads
  (priority 10.5) crowd them out. Diagnose the exact score gap in `hypothesis_scheduler.score_hypothesis`
  (endorsements weighting looked material — real leads carried inventory endorsements, the seed did not).
- **P1-3 Operator-seeded high-severity leads rank.** An operator-supplied lead should reach the board.

### P2 — Autonomy: server-materialize for LLM planners

- **P2-1 Server-materialize create-MA at dispatch (`configured_ai` mode).** Detect a create-based
  mass_assignment hypothesis at dispatch → probe → `_materialize_create_mass_assignment_workflow` →
  inject creds → dispatch. Agent mode already works via the materializer; an LLM planner can't build a
  managed-credential workflow itself, so the server must for full unattended autonomy.

### P3 — Operational frictions observed (fold into runbooks/tests)

- Credential profiles: `auth_kind ∈ {authorization_header, cookie}` (not `bearer`); store
  `"Bearer <token>"` as the secret; `decrypt_secret` passes plaintext through. One active principal per
  `(target_id, auth_state)` — refresh the existing `user1`, don't insert a second.
- Approval receipts: require `confirm_authorized` (and `confirm_scope_reviewed` for `needs_approval`
  scope); the `receipt_id` is a dashless UUID.
- Two Juice Shop targets exist (`localhost:3001`, `host.docker.internal:3001`); workers reach
  `host.docker.internal`. Use that target for worker-executed campaigns.
- Deploy: `./api` is mounted at `/app/_src/api` and copied to `/app` on `restart` — restart api+worker
  to deploy; `/app/_src` can't `import api` (no `scanner_tools` on its path).

## 5. Why the live demo was NOT forced

Hand-seeding the object-instance routes into `target_endpoints` and hand-boosting the lead's rank would
have produced a green "live promotion" while masking exactly the discovery gaps this plan fixes — a
benchmark-fitting move this project explicitly forbids. The engine and the real dispatch are proven;
the honest next step is P0/P1 discovery + surface + ranking, then a live campaign promotes on its own.

## 6. Suggested sequence

1. **P1-1** (surface-gating for create-object siblings) — smallest change, unblocks a live agent-mode
   promotion immediately once a lead exists.
2. **P0-1** (inventory canonicalization of object-instance routes) — makes the create-MA lead form
   naturally from existing inventory.
3. **P1-2/P1-3** (ranking) — the lead reaches the board.
4. Re-run the live `deep_hunt`; it should promote create-based mass_assignment with 0 FP, unattended in
   agent mode.
5. **P0-2** (create-surface probe) and **P2-1** (server-materialize) for breadth and LLM-planner autonomy.
