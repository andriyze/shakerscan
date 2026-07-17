# Release Readiness

**Status (2026-07-17):** preparation in progress. The repository remains on `0.5.7` intentionally;
do not choose or publish the next version until the open product, security, and validation items
below are resolved. This page is the live release checklist. It is not a claim that the current
branch is release-ready.

Code, migrations, runtime receipts, and tests are authoritative. Historical test results and audit
snapshots may support investigation, but they cannot satisfy a current-release gate.

## Blocking product and security items

The disposition table at
[`archive/ui-ux-audit-2026-07-16.md`](archive/ui-ux-audit-2026-07-16.md#release-disposition-2026-07-17)
tracks the complete July UI/UX audit. The following items still require implementation or explicit
release acceptance:

- **AUD-02 — serialized nested evidence redaction:** structurally parse and redact supported
  serialized JSON/form/cookie evidence before storage and presentation; provide a migration or
  containment plan for existing evidence.
- **AUD-03 — proof/provenance authority:** finish removing caller authority over proof state and
  provenance from public evidence-recording paths. UI badges already consume server-derived proof
  state, but the API boundary still needs a complete contract review.
- **AUD-08 — attack-path semantics:** complete browser/contract acceptance that observed,
  verified, partial, and hypothetical steps cannot be presented as one fully proven path.
- **AUD-10 — active-scan authorization:** add a reusable, server-authoritative acknowledgement for
  Full, Aggressive, and Smart work, including scheduled execution. Plain warning text is not the
  completed gate.
- **AUD-11 — deployment trust boundary:** until application authentication and authorization exist,
  release documentation must continue to limit access to localhost, Tailscale, or an authenticated
  firewall/VPN/reverse-proxy boundary. Direct public exposure is unsupported.

## Release-candidate validation

Run these against the exact candidate commit and retain content-free receipts/artifacts:

- [ ] Unit and contract suites pass on the candidate.
- [ ] UI production build and targeted browser QA pass at desktop and narrow viewport widths.
- [ ] `python3 scripts/generate_capability_inventory.py --check` passes.
- [ ] Every skill validates with the skill validator.
- [ ] Documentation links and current/archive indexes pass.
- [ ] `make release-gates` passes. The named gates exist today, but the GitHub Release workflow does
      not yet invoke them automatically.
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

- [ ] Correct OCI image license labels from MIT to Apache-2.0 in the GitHub release workflow and
      manual image publisher.
- [ ] Replace the hard-coded `0.5.7` GitHub release highlights with version-specific release notes.
- [ ] Make the Release workflow run the required documentation, release-gate, and candidate
      validation jobs, or require a referenced successful workflow run before tag publication.
- [ ] Restrict manual release dispatch to an approved release commit/branch and verify that the
      requested version matches `VERSION`.
- [ ] Decide which slower benchmark/E2E jobs are scheduled and add the schedule before describing
      them as nightly.
- [ ] Replace remaining absolute CLI help claims such as Full running “ALL security tests.” The
      generated functionality inventory intentionally mirrors the current code until that
      user-facing help string is corrected.
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
- [ ] Confirm the installer fetches `skills/shakerscan`, `skills/research-agent`, and the matching
      `.claude/commands/research.md`.
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
