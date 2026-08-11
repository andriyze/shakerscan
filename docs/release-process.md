# Release process

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

Merge the intended commit through protected `main`, run full E2E and CodeQL on that exact commit,
then run **Release candidate** with `version`, the exact 40-character SHA, and both successful run
IDs. The workflow verifies those runs against the same SHA, runs the remaining frozen-source gates and native builds,
bakes version plus source revision into `/opt/shakerscan/release-manifest.json`, pushes only
`candidate-<sha>-<run-id>` multi-architecture manifests, and uploads
`release-candidate-receipt.json`.

Never deploy by a mutable version or `latest` during acceptance. Use the candidate tag or, for the
strongest binding, the digests in the receipt.

## 2. Physical acceptance (optional)

Operators may use a clean hosted-installer control plane and multiple broker VPS nodes on the exact
candidate digest to exercise cross-node placement, worker loss/reclaim, lease isolation, dedupe,
centralized artifacts, and public datastore isolation. This is operational evidence, not a release
promotion requirement, and it may be performed before or after publication.

Any application-code change creates a new candidate SHA and requires a new candidate build. Do not
patch a live candidate and keep the old build receipt.

## 3. Publish the immutable version

Run **Promote release** with the version, candidate SHA, and candidate workflow run ID. The workflow
verifies that the candidate succeeded for the exact SHA, downloads its receipt, compares every
registry digest, and creates version tags from those digests. It performs no build. The GitHub
Release records build provenance. `latest` and the installer remain unchanged.

## 4. Public smoke and stable promotion

Test the published version as a new user would. At minimum run
`scripts/public_install_smoke.sh <version>`, which uses the public curl installer in an empty
temporary home and verifies one UI/API/worker identity, the no-paste local Model Intake session,
the same session through the production browser bundle, and the exact one-command Firecracker
guidance. The smoke passes `SHAKERSCAN_INSTALL_VERSION` to the public installer so it tests the
published immutable version before the stable channel moves; ordinary installs leave that variable
unset and continue to resolve `install/STABLE_VERSION`. Continue with the stateful upgrade, rollback,
doctor/status, agent/MCP launch, a bounded scan, Model Intake readiness, and remote Fleet status.
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
