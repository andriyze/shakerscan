# Release Readiness

**Status (2026-07-21):** `0.7.0` candidate in preparation on
`docs/architecture-review-and-crapi-auth-baseline`; `VERSION` is `0.7.0`. The product scope and
stop-ship list are in [`release-must-fix.md`](release-must-fix.md) — a **trusted-operator,
self-hosted scanner**, not a hosted SaaS. This page is the live checklist reconciled to that scope.
It is not a claim that the branch is release-ready: it is release-ready only when every item below is
green on the **frozen candidate SHA**.

Code, migrations, runtime receipts, and tests are authoritative. Historical test results and audit
snapshots may support investigation, but they cannot satisfy a current-release gate — the
authoritative validation is a fresh run on the frozen candidate (VAL-01), not on branch HEAD.

## Product and security items — reconciled to the 0.7.0 scope

The full July UI/UX audit disposition table is at
[`archive/ui-ux-audit-2026-07-16.md`](archive/ui-ux-audit-2026-07-16.md#release-disposition-2026-07-17).
Reconciled against the trusted-operator scope in `release-must-fix.md`:

- **AUD-03 — proof/provenance authority — CLOSED under SCAN-01.** Deterministic evidence controls
  verified status and severity; AI verdicts are downgrade-only and cannot manufacture or upgrade a
  verified/high finding; a registry proof contract that is unmet can no longer persist
  `last_verification_verdict='exploited'` from a raw proof signal (the persisted-surface fix in
  `e35fe24`).
- **AUD-08 — attack-path semantics — CLOSED under SCAN-01.** A chain reaches the proven `chains[]`
  only when it is complete AND every step is reference-backed "observed"; otherwise it routes to
  `partial_chains` with per-step status. Observed/verified/partial/hypothetical cannot appear as one
  fully proven path.
- **AUD-02 — comprehensive nested-evidence secret redaction — DEFERRED to 0.8.0** per the scope
  boundary. Existing safeguards remain and documentation warns that result storage is sensitive; a
  typed redaction pipeline and old-data rewrite are not 0.7.0 gates.
- **AUD-10 — server-authoritative active-scan approval receipts — DEFERRED to 0.8.0** per the scope
  boundary. Under the trusted-operator model, starting a local active scan is the operator's
  authorization; scope and same-origin enforcement still apply and clear active-testing warnings
  remain required. Reusable target-bound approvals return before shared/untrusted control planes exist.
- **AUD-11 — deployment trust boundary — STANDING documented requirement.** Until ShakerScan has
  application authentication, docs and installer defaults bind to localhost and require Tailscale, a
  VPN, firewall, or an authenticated reverse proxy for remote access. Direct public exposure is
  unsupported.

## Known limitations accepted for 0.7.0

Recorded from the release-candidate adversarial audit (2026-07-21, three tracks over SCAN-01..04 /
UPGRADE-01). **None can produce a false-VERIFIED finding or a false "covered" coverage claim**; each
is conservative/fail-closed or latent, and is an owned decision rather than a silent gap:

- Registry `severity_rules` are advisory metadata; runtime severity capping is the wired active-family
  map (`xss`/`sqli`/`bola`/`auth`/`mass_assignment`/`jwt`), which covers the families that emit
  critical/high. No detector emits a name-only high today; a generic rule evaluator is deferred
  (per-predicate evidence mapping carries mis-cap regression risk with no confirmed benefit).
- The attack-chain "observed step" gate accepts a self-attested `evidence_ref`, but the
  `attack_chain_observations` field has no producer today, so every multi-step chain already demotes
  to `partial`. Latent only.
- `partial` is not a top-level registry execution status (it collapses to `failed`, never to
  `completed`); budget-exhausted work is reported honestly via `budget_exhausted_reason` telemetry.
- Non-active scans omit receipts for the active families (absent, not an explicit `skipped`); nothing
  derives "covered/clean" from receipt absence, and the e2e harness cross-checks receipt presence.

## Release-candidate validation

Run these against the exact candidate commit and retain content-free receipts/artifacts. The fast
host-verifiable checks pass on this branch — unit/contract (2344 passed, 7 skipped),
`generate_capability_inventory.py --check`, and all `release_gates.py` gates — but each MUST be
re-confirmed on the frozen candidate SHA; the live-stack and benchmark rows below are freeze-time.

- [ ] Unit and contract suites pass on the candidate.
- [ ] UI production build and targeted browser QA pass at desktop and narrow viewport widths.
- [ ] `python3 scripts/generate_capability_inventory.py --check` passes.
- [ ] Every skill validates with the skill validator.
- [ ] Documentation links and current/archive indexes pass.
- [ ] `make release-gates` passes. (The Release workflow now invokes the gates in the candidate
      scanner image before publish, so a wrong candidate cannot be published green.)
- [ ] `make e2e` passes against a uniform build-current fleet.
- [ ] `make e2e-model-intake` passes the real public-model path, or the offline fixture is explicitly
      recorded as a limited substitute.
- [ ] A single current-fleet Smart Juice Shop scorecard is recorded.
- [ ] A current-fleet authenticated crAPI scorecard is recorded with distinct-principal and
      accepted-auth receipts; seeded detector-isolation evidence must remain labeled as seeded.
- [ ] Open P0/P1 audit items are fixed or explicitly accepted by the release owner with rationale.

The implemented-versus-planned E2E matrix is maintained in [`E2E_TEST_PLAN.md`](E2E_TEST_PLAN.md).
Benchmark reinterpretations and contamination corrections are preserved in the
[`Benchmark Integrity Ledger`](../results/benchmark-runs/INTEGRITY_LEDGER.md).

## Release automation and metadata

Complete these before creating a tag:

- [x] Correct OCI image license labels from MIT to Apache-2.0 in the GitHub release workflow and
      manual image publisher. (`release.yml` + `scripts/publish-images.sh` label Apache-2.0.)
- [x] Replace the hard-coded `0.5.7` GitHub release highlights with version-specific release notes.
      (`docs/releases/0.7.0.md`; the workflow refuses to publish without non-empty version notes.)
- [x] Make the Release workflow run the required documentation, release-gate, and candidate
      validation jobs. (`release.yml` builds the candidate scanner image and runs unit/contract +
      `release_gates.py` + `npm audit --audit-level=high` + inventory `--check` before publish.)
- [x] Restrict manual release dispatch to an approved release commit/branch and verify that the
      requested version matches `VERSION`. (Candidate SHA must equal checked-out HEAD and be an
      ancestor of `origin/main`; the tag must equal `v${VERSION}`.)
- [ ] Decide which slower benchmark/E2E jobs are scheduled and add the schedule before describing
      them as nightly.
- [x] Replace remaining absolute CLI help claims such as Full running “ALL security tests.”
      (User-facing help is clean; internal leftovers in an api.py comment and scanner.py argparse
      help were reworded in the pre-release hygiene sweep.)
- [ ] Use one product name, **ShakerScan**, in release titles and notes.

## Version and provenance

Only after the blocking work and candidate validation are complete:

1. Select the next version and update `VERSION`.
2. Add version-specific release notes.
3. Add a pending row to [`../RELEASES.md`](../RELEASES.md).
4. Merge the exact candidate to `main`.
5. Tag that commit and publish both multi-architecture images.
6. Record the release commit and image digests in `RELEASES.md`.

Do not reuse `0.5.7`; it is already a published release.

## Hosted installer

The hosted bootstrap is a separate deployment artifact. Updating this repository does not deploy
`https://install.shakerscan.com`.

After the release commit is public:

- [ ] Deploy the current `install/index.sh`.
- [ ] Verify the root response is shell content with an appropriate text/shell content type.
- [ ] Confirm the installer fetches `skills/shakerscan`, `skills/research-agent`, and the full
      `.claude/commands/` set (including `research.md` and `deep-hunt.md`).
- [ ] Run a clean install into an empty temporary home.
- [ ] Verify `shakerscan doctor`, `shakerscan status`, agent launch, skill discovery, and one safe
      quick-scan submission.
- [ ] Verify an upgrade preserves `.env`, results, and Docker volumes.
- [ ] Confirm the installed instructions use public documentation links for files that are not part
      of the minimal runtime.

## Documentation sign-off

- [ ] README installation, first scan, UI map, terminology, safety boundary, and upgrade steps match
      the candidate.
- [ ] AGENTS and CLAUDE instructions match the live OpenAPI and installed package layout.
- [ ] The functionality reference generated inventory is current and its curated sections do not
      contradict the generated routes.
- [ ] Only one live roadmap exists; completed plans and point-in-time audits are archived.
- [ ] Walkthrough text matches the current UI. Historical screenshots are not presented as
      release-current.
- [ ] The archived UI/UX audit disposition table is updated with the final release decision.
