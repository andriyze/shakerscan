# Authenticated Scan Profile and Assurance preview

**Status:** Merge-candidate implementation record for PR #137. The OSS authenticated-assurance surface remains gated off by default behind `SHAKERSCAN_AUTHENTICATED_ASSURANCE=1`. This document distinguishes what is implemented in the merge candidate from intentionally deferred product enablement.

## Merge boundary

PR #137 is intended to merge a safe, additive, fail-closed **authenticated-assurance preview** into OSS. Merging the preview does not mean authenticated Scan profile selection is generally available. The default remains off, unsupported execution paths remain disabled, and Enterprise gateway enablement is a separate compatibility/security decision.

The merge candidate is acceptable only when repository-required CI is green, installer integrity is current, and the real disposable PostgreSQL/worker/interruption/dump-restore acceptance workflow passes without skips.

## Implemented in PR #137

### Reviewed profile and credential custody

- Immutable, owner-reviewed assurance profile revisions are attached to the canonical credential ID and immutable credential/record versions.
- Profile edits serialize with credential rotation and revocation and reject stale expected revisions.
- Assurance management never accepts or persists secret material. Existing encrypted credential storage and worker-local resolution remain authoritative.
- Exact target origin, lifecycle, destination, credential activity/expiry, profile revision, credential version and credential-record version are checked fail-closed.
- `ScanProfileSelection`, immutable assessment snapshots, snapshot binding and transactional profile pinning exist. Credential rows are locked before snapshot admission so concurrent rotation cannot silently race snapshot creation.

### Explicit identity validation

- One-shot, read-only validation uses the existing canonical `http.request` execution path.
- Validation requires reviewed configuration, current credential authority, exact-origin transport and an action-bound expiring credential-tier approval.
- Requests are bounded: one GET, no redirect following, no reusable cookie jar/login retry, bounded timeout and a worker-private response capped at 16 KiB plus truncation detection.
- Only deterministic identity/role match facts, states, stable reason codes and receipt references are persisted; response bodies, headers, tokens, cookies and ciphertext are excluded.
- Cancellation, duplicate delivery, stale build, recovery, expiry, revocation, rate limiting and missing-key behavior fail conservatively.
- Starting a new validation immediately makes current assurance uncertain; an older successful observation cannot keep the profile green.

### Runtime authority and interruption

- Canonical credential-using Scan actions recheck credential metadata and target-bound authority before dispatch, including continuation rounds.
- During supported local credential-using execution, authority is sampled repeatedly and loss raises an action-local cooperative stop signal.
- Inline HTTP closes pending work on authority loss. Already collected evidence remains available as partial output while uncertain wire use is settled conservatively.
- `authentication_uncertain` is distinct from corrected-main `dependency_incomplete`; both result reasons are preserved after the current-main reconciliation.
- Cross-origin redirects carrying credentials or newly received cookies are refused even when both origins are otherwise in target scope.

### Health evidence and reporting

- Budgeted authentication-health actions and worker-private health evaluation exist.
- Durable action receipts are projected into a bounded, allowlisted authentication-health timeline.
- Positive assurance requires a recognized `valid` state, `identity_confirmed` reason and an actual identity match. Malformed or contradictory historical receipts can only degrade assurance, never improve it.
- Reports distinguish sampled identity evidence from continuous authentication. Sampling never claims continuous validity.
- Interrupted/uncertain work appears as an authentication gap without discarding earlier findings.
- Historical raw-authentication options remain explicitly `legacy_unverified` rather than being misclassified as unauthenticated.
- `/scans/{id}/authentication-assurance`, coverage metadata and result UI expose redacted assurance information.

### Management UI and history

- Local-preview profile creation/review, lifecycle controls, validation criteria, explicit validation request, cancellation, history and receipt/budget display are implemented.
- Saving/reviewing a profile does not autonomously perform assessment traffic.
- Interactive SSO/MFA is explicitly unsupported.

### Persistence, recovery and compatibility

- Additive database migrations preserve existing encrypted credential and Scan authority models.
- Disposable PostgreSQL fixtures cover atomic edits, history, revocation races, worker execution and secret-redaction boundaries.
- The dedicated GitHub acceptance workflow exercises real database migration, worker execution, interruption and PostgreSQL dump/restore without skips. On the 2026-09-17 merge-prep run those substantive acceptance steps passed; the run failed later at installer-manifest verification after the corrected-main reconciliation changed runtime files. That packaging failure must be cleared before merge.
- PR #137 has been synchronized with corrected `main`, including the ASM dispatch-backoff regression and incomplete-proof semantics.

## Intentionally not enabled by this merge

These are **not claims of PR #137** and must remain disabled/fail-closed after merge:

1. **General authenticated Scan profile selection.** The snapshot/pinning primitives exist, but the public Scan request still uses the existing credential-selection contract. Do not advertise reviewed assurance-profile selection as supported until exact reviewed revision selection is wired atomically into canonical Scan creation and proven by end-to-end consumer-isolation tests.
2. **Assurance guarantees for every scanner capability.** A capability may consume credentials only when its registry contract explicitly proves the required credential transport and cooperative interruption semantics. Unsupported adapters must continue to be rejected rather than inheriting guarantees from `http.request`.
3. **Continuous authentication.** Health checks are samples. Neither a successful setup check nor successful before/after samples prove uninterrupted identity acceptance for an entire Scan.
4. **Interactive SSO/MFA automation.** No reusable controlled interactive sign-in path is certified in this increment.
5. **Hunt, Model Intake or device assurance parity.** These surfaces have independent authority and compatibility requirements.
6. **Enterprise/SaaS enablement.** `shakerscan-saas` must separately implement/review exact route authorization, reader/editor roles, actor propagation, capability negotiation and old/new engine-gateway compatibility before exposing these management routes.
7. **External customer/design-partner acceptance.** The repository acceptance fixtures are synthetic/controlled. No external target or customer acceptance is claimed.

## Post-merge work

The next product increment should wire reviewed profile selection into canonical Scan admission rather than expanding the preview sideways. Acceptance for that increment is:

- submit an exact `{profile_id, revision, reviewed:true}` selection;
- lock the canonical credential row and pin profile revision, credential version/record version, target binding, validation evidence, expiry and process generation in the Scan admission transaction;
- persist the immutable server-created snapshot with Scan authority;
- mutate/rotate/disable the live profile after admission and prove the historical snapshot is preserved while unauthorized subsequent credential use is blocked;
- certify each participating credential-consuming capability independently;
- expose selection in the Scan UI only after those API/runtime tests pass;
- reconstruct the same frozen snapshot and sampled health timeline from durable evidence after restart/restore.

After that OSS contract is stable, Enterprise can negotiate and authorize it explicitly. Hunt/SSO/other surfaces remain separate increments.

## Merge checklist

- [x] Corrected `main` synchronized into PR #137.
- [x] ASM dispatch-backoff regression retained.
- [x] `dependency_incomplete` and `authentication_uncertain` retained as distinct result semantics.
- [x] Real disposable DB/worker/interruption/dump-restore acceptance executes without skips.
- [x] Health receipt projection is bounded, redacted and fail-closed.
- [x] Preview remains off by default and local-management scoped.
- [ ] Regenerate and verify installer manifest against the final reconciled tree.
- [ ] Remove temporary one-shot reconciliation machinery.
- [ ] Complete repository-required Python/E2E/CodeQL/maintenance/hygiene checks on the final head.
- [ ] Merge only after the final required checks are green.

## Operational constraints

Set `SHAKERSCAN_AUTHENTICATED_ASSURANCE=1` only for the explicitly supported local preview. Revoking a credential uses the existing credential control. Disabling or archiving assurance metadata does not erase the underlying credential or historical evidence. Missing encryption keys fail closed. Never infer target authorization or tenant isolation from profile labels.

The preview is additive. Older binaries do not understand the new validation owner kind, so finish/cancel validation work and settle reservations before downgrade. Do not drop additive assurance tables as part of ordinary rollback.
