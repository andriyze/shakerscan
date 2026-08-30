# Current roadmap and next validation work

**Status:** future-only roadmap; reconciled 2026-08-29.

Shipped behavior belongs in `functionality-reference.md`; stop-ship and candidate evidence belong in
`release-readiness.md`. The superseded July roadmap is preserved at
[`archive/proposed-next-steps-2026-07.md`](archive/proposed-next-steps-2026-07.md).

## 1. Freeze and qualify 2.0.0

- Freeze one source SHA and produce immutable multi-architecture candidate digests.
- Run exact-SHA CodeQL, contract, migration, upgrade, installer, UI, and release gates.
- Renew the physical outbound-HTTPS broker receipt on the frozen candidate, including worker loss,
  reclaim, duplicate completion, central artifacts, and public data-store isolation.
- Keep WireGuard preview-only until its separate physical acceptance succeeds.
- Publish and promote stable only through the sequence in `release-process.md`.

## 2. Improve DAST evidence quality

- Improve broad authenticated discovery without benchmark-specific routes or detector hints.
- Increase stored/DOM XSS and workflow/write-BOLA recall while retaining deterministic controls.
- Keep auth-challenge, weak-assurance, and “not examined” presentation distinct from clean results.
- Reduce queue, scope re-check, and external-tool failure classes with behavioral regressions.
- Calibrate on current uniform worker builds and preserve contamination/integrity ledgers.

## 3. Complete lifecycle portability

- Add product-aware archive/restore across Scan, Hunt, AI Gate, and Model Intake.
- Design and accept schema-versioned full-system export/import without importing authority, secrets,
  or proof accidentally.
- Add legal/operational holds and storage accounting before considering automatic retention.

## 4. Harden Hunt usability

- Continue compact evidence-led methodology selection without preloading the 31-method catalogue.
- Improve client artifact, authentication, multi-principal, and business-logic workflows through
  canonical capabilities rather than planner commands.
- Keep budget-exhausted debriefs, truthful action accounting, and finding CRUD covered by live E2E.
- Evaluate methodology relevance and context cost without turning selection into authority.

## 5. Qualify specialized product boundaries

- Keep AI Gate preview until policy/exception and deterministic-judge seams have release gates.
- Qualify Model Intake runner/provider combinations separately from static review.
- Add authorized physical connected-device receipts without weakening silence/inconclusive handling.
- Preserve Fleet, device, model, and web namespaces so metrics cannot contaminate one another.

This roadmap is deliberately short. Completed work should be removed rather than accumulated into an
implementation diary; detailed design belongs in an ADR or architecture document.
