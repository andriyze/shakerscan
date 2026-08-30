# Release process

**Status:** current immutable-candidate publication process; reconciled 2026-08-29.

ShakerScan releases use one immutable source commit and one set of image digests. Building,
accepting, publishing, and moving the stable channel are separate gates.

## Repository controls

Import `.github/rulesets/main.json` as the active `main` ruleset. Confirm the required check names in
the repository UI after their first run, because GitHub check contexts are repository-specific.
Store Docker Hub credentials as repository secrets.

The committed ruleset requires a PR, resolved conversations, linear history, current required checks,
and no bypass actors. It does not require an approving or independent reviewer. The **Commit policy** check rejects `release:` commits that
also change product, runtime, migration, test, or operational code. Use `fix(scope):`,
`feat(scope):`, `refactor(scope):`, or `test(scope):` for behavioral work; reserve `release:` for
version, notes, and provenance metadata.

## 1. Freeze and build a candidate

Merge the intended commit through protected `main`, obtain successful exact-SHA CodeQL, then run
**Release candidate** with `version`, the exact 40-character SHA, and the CodeQL run ID. Optional
real-fleet Scan parity, Model Intake physical acceptance, and Connected Device physical acceptance
run IDs may be supplied when those support boundaries are being qualified. The workflow verifies
every supplied workflow identity, conclusion, and head SHA, runs the frozen-source gates and native builds,
bakes version plus source revision into `/opt/shakerscan/release-manifest.json`, pushes only
`candidate-<sha>-<run-id>` multi-architecture manifests, and uploads
`release-candidate-receipt.json`. Each platform build publishes BuildKit provenance and an SBOM;
the final multi-architecture scanner, API, UI, and signer digests receive GitHub/Sigstore build
attestations that are verified immediately and recorded in the receipt. The final four manifest
digests are scanned for unwaived high/critical vulnerabilities before certification.

Never deploy by a mutable version or `latest` during acceptance. Use the candidate tag or, for the
strongest binding, the digests in the receipt.

## 2. Optional physical support-boundary acceptance

Operators may qualify Model Intake KVM, an authorized physical Connected Device, or a clean
hosted-installer control plane with multiple broker VPS nodes on the exact candidate digest. These
receipts exercise host-specific support boundaries; they are optional operational evidence, not a
release-promotion requirement. An omitted receipt is recorded as not run, never passed.

Any application-code change creates a new candidate SHA and requires a new candidate build. Do not
patch a live candidate and keep the old build receipt.

## 3. Publish the immutable version

Run **Promote release** with the version, candidate SHA, and candidate workflow run ID. The workflow
verifies that the candidate succeeded for the exact SHA, downloads its receipt, compares every
registry digest, re-verifies every signed provenance attestation, and creates version tags from
those digests. It performs no build. The GitHub
Release records build provenance. `latest` and the installer remain unchanged.

## 4. Public smoke and stable promotion

Test the published version as a new user would. At minimum run
`scripts/public_install_smoke.sh <version>`, which uses the public curl installer in an empty
temporary home and verifies the installed version plus UI, API, and worker identity. Model Intake is
explicitly excluded from this release's public smoke receipt. The smoke passes
`SHAKERSCAN_INSTALL_VERSION` to the public installer so it tests the
published immutable version before the stable channel moves; ordinary installs leave that variable
unset and continue to resolve `install/STABLE_VERSION`. Continue with the stateful upgrade, rollback,
doctor/status, agent/MCP launch, and a bounded scan. Optional Model Intake or remote Fleet checks
belong in their separate support-boundary receipts.
Preserve the generated content-free receipt and hash.

Only then merge a small PR changing `install/STABLE_VERSION`. Run **Promote stable channel** with the
version and smoke receipt. The workflow validates the receipt schema and every required clean-install
check, confirms the public non-draft release and stable-version file, then moves each `latest` alias
to the already-published version digest. It does not rebuild.

## Stop conditions

Stop and cut a new candidate for any identity mismatch, stale fleet, failed or missing coverage,
heartbeat authority loss, migration failure, digest drift, build-receipt mismatch, unaccepted
high/critical dependency finding, or public smoke regression. Roll back by
pinning the previous immutable version/digest; do not overwrite an existing version tag.
