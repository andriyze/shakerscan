# UI QA Report — click-through audit (2026-06-25)

> **ARCHIVED (2026-07-11).** This report describes a June deployment. The UI contract suite,
> production build, and rebuilt-stack browser QA supersede its live-state claims.

Method: every route was loaded against the running app (`:3000`), the API endpoints
each page calls were probed (`:8080`), and all page/component sources were read. Issues
only — **no fixes applied**. Severity is user-impact, not effort.

Routes audited (all load HTTP 200 except where noted): `/`, `/scans`, `/scans/[id]`,
`/schedules`, `/targets`, `/targets/[id]/graph`, `/findings`, `/findings/[id]`,
`/exposure`, `/asm`, `/interactive`, `/scan/new`, `/settings`, `/settings/ai-gate`,
`/settings/model-intake`, `/settings/policy-profiles`.

---

## HIGH

1. **`/settings/policy-profiles` returns 404 → the "Policy" sidebar link is dead.**
   `ui/src/components/Sidebar.tsx` (Policy → `/settings/policy-profiles`). Confirmed live:
   `curl :3000/settings/policy-profiles` → 404 (every other route → 200). **Root cause:
   stale baked UI image.** The page (plus an enhanced graph page with filters/search and a
   policy-exceptions UI) was added in the latest commit `cc49849`, *after* the last UI image
   rebuild; the running container's `/app/.next/server/app/settings/` contains only
   `ai-gate`/`model-intake`, not `policy-profiles`. Implication: the newest graph page and the
   exceptions UI are **also not deployed** — the running graph page is the older, filter-less
   version. Fix is a UI rebuild (not a source bug), but as shipped the user hits a 404.

---

## MEDIUM

2. **Dashboard "Critical & High Findings" card can show non-crit/high findings.**
   `ui/src/app/page.tsx:~499` renders `data.recent_findings`, but the `/dashboard` query
   (`api/api.py:~7057`) orders by severity **without filtering to critical/high**. Latent today
   (live data is all-critical), but on a DB with no crit/high findings the card would list
   medium/low/info under a header that claims "Critical & High". Misleading.

3. **Exposure attack-path bullets silently dropped (duplicate React keys).**
   `ui/src/app/exposure/AttackPaths.tsx:150` and `:98` use `key={item}` for `remediation` /
   `missing_required` lists. Templated chains repeat strings (e.g. "Apply input validation"),
   so duplicate keys make React drop the repeats — the user sees **fewer remediation /
   missing-requirement items than exist**. Should key by index.

4. **ASM "Improve coverage" can't scope a batch (backend supports it, UI doesn't).**
   `ui/src/app/asm/page.tsx:~697` only ever sends `{ check_family }`. The client
   (`improveAsmTarget`/`testAsmTarget`) and CLAUDE.md support `endpoint_filter` (e.g. `"api"`),
   `batch_size`, `stale_days`, `exploit_depth` — none are exposed, so users can't scope ASM to
   API-like endpoints or run BOLA from the dashboard.

5. **`/interactive` prefills a vendor demo host as the default target.**
   `ui/src/app/interactive/page.tsx:73-81` defaults target to `https://cr.shakerscan.com` and
   endpoint to `/identity/api/v2/user/dashboard`. A user who clicks "Start Session" without
   editing starts a session against a vendor host, not their own target.

6. **`/interactive` unguarded date render.** `interactive/page.tsx:495`
   `new Date(session.last_activity).toLocaleString()` → renders "Invalid Date" if the field is
   missing/malformed. No guard.

7. **Model-Intake saved-profiles load fails silently.**
   `ui/src/app/settings/model-intake/page.tsx:315-325` — `loadPolicyProfiles` swallows the error
   and sets `[]`, so a failed fetch looks identical to "no custom profiles": the user sees only
   builtins with no error indication (cf. `loadScenario`, which surfaces `scenarioError`).

8. **Scan-detail polling relies on a stale-closure interval.**
   `ui/src/app/scans/[id]/page.tsx:~572` — the refetch `setInterval` reads `scan?.status` from a
   captured closure; it only works because the effect re-creates the interval on each status
   change. Fragile across pending→running→completed transitions.

---

## LOW (cosmetic / latent / contract nits)

**Nav / routing**
- Orphaned routes (load 200 but have no sidebar entry): `/interactive`, `/scan/new`, `/settings`
  — discoverable only by URL or a footer icon. `interactive/page.tsx`, `scan/new/page.tsx`.
- `/targets/[id]` has no `page.tsx` (only `/graph`); any link to a bare `/targets/{id}` would 404.
  No current page emits one, but the exposure-graph node `href`s are a footgun if the API returns one.
- App-graph back-link is hardcoded `href="/targets"` (`targets/[id]/graph/page.tsx:134`) — arriving
  from `/asm` or `/exposure` always returns the user to Targets.

**Lists / tables**
- Scans list: "Type" column header renders unconditionally but its cell is `hidden xl:table-cell`
  (`scans/page.tsx:435` vs `:471`) → header over empty space + misaligned columns below `xl`.
- Findings list: `{finding.cvss_score && ...}` (`findings/page.tsx:694`) hides a legitimate CVSS of
  `0.0` (falsy); detail page uses the correct `!== undefined` (`findings/[id]/page.tsx:619`).
- Findings list: checkbox labeled "exploited only" is bound to `verified_only`
  (`findings/page.tsx:545`), while a separate verdict dropdown has an "exploited" option — confusing.
- Exposure `AttackPaths.tsx:283` severity dot only colors critical/high; medium/low/info/unrated all
  share yellow. `:216` filter-chip label uses `items[0]?.name` not the chain type → near-identical chips.
- Exposure `TriageTable.tsx:436` dead ternary `proven{verified === 1 ? '' : ''}` (both empty);
  `:390-395` some recommendation kinds render a non-interactive gray chip that does nothing on click;
  `:1065` "Sort: priority" applies no client sort (relies on server ordering).

**Error handling / states**
- `ai-gate/page.tsx:351-380` empty `catch {}` on inventory/settings/scenario loads → cards silently
  vanish with no error message on fetch failure.
- Targets bulk scan uses `Promise.all` (`targets/page.tsx:208`); one rejected target reports the whole
  batch as "Failed to start scans" even if others queued (exposure page uses `Promise.allSettled`).
- `targets/page.tsx:250` `handleDiscover` clears state via an untracked `setTimeout` → state update on
  unmounted component if navigated away mid-discovery.
- Schedules `formatRelativeTime` (`schedules/page.tsx:24`) reimplements an **unguarded** `new Date(...)`
  (the shared `lib/format.ts` helper guards `isNaN`) → can render "NaNm ago".

**Data / format**
- `ai-gate/page.tsx:781` `Math.round(candidate.confidence * 100)` → `NaN%` if confidence missing.
- `model-intake/page.tsx:1019` "training data" round-trips through comma-split → a value containing a
  comma is silently split into two entries.
- `targets/page.tsx:522,726` `(asm_coverage.coverage*100).toFixed(0)` → "NaN% covered" if `coverage`
  is null while the object is present (typed required, so low risk).

**Dashboard / counts**
- Queue tiles link to `/scans?status=...` but show `/queue/stats` Redis counts (`page.tsx:295`) — a
  different population; tile number can mismatch the linked list.
- Worker scale dropdown source list includes 25/30/40 (`page.tsx:241`) but is capped by the API max
  (16), so those are unreachable; harmless but misleading.

**Accessibility / remote-mode**
- `/interactive` text inputs (token/header/cookies, `:514-533`) use only `placeholder`, no
  `<label>`/`aria-label` — screen readers get no field name.
- AI-gate "Red-Team Resources" links + several pages build URLs from
  `NEXT_PUBLIC_API_URL || 'http://localhost:8080'` (`ai-gate/page.tsx:45`); on a remote/VPS deploy
  without that env set, these point at the user's own `localhost` and fail (known remote-mode pitfall).
- AI-gate production-scan `ConfirmDialog` (`:1336`) has no `busy` guard — double-confirm possible
  while the request is in flight (the disable dialog correctly uses `busy`).

---

## Verified-clean (no issue)
- Model-Intake `buildPayload`, AI-Gate `buildPayload`, and policy-profiles `formToPayload` all match
  their `ui/src/lib/api.ts` request types — no field mismatches.
- Most modals (ConfirmDialog via `useModalA11y`, schedules/scans dropdowns) handle Escape + focus/click-outside.
- `setInterval` calls have matching `clearInterval` cleanups; dashboard uses in-flight guards.
- Finding-detail Durable-Evidence-Objects section handles optional fields safely; retest polling cleans up.

## Top fixes to prioritize (when fixing later)
1. Rebuild the UI image so `cc49849` (policy-profiles route + Policy nav link + enhanced graph) deploys (#1).
2. Add the severity filter to the dashboard "Critical & High" query (#2).
3. Key the AttackPaths remediation/missing lists by index (#3).
4. Expose `endpoint_filter`/`batch_size` on the ASM improve action (#4).
5. Clear the `/interactive` vendor-host default + guard its date render (#5, #6).
