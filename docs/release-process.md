# Release process

ShakerScan releases use one immutable source commit and one set of image digests. Building,
accepting, publishing, and moving the stable channel are separate gates.

## Repository controls (one-time owner action)

Import `.github/rulesets/main.json` as the active `main` ruleset. Confirm the required check names in
the repository UI after their first run, because GitHub check contexts are repository-specific.
Create protected GitHub environments named `release-promotion` and `stable-promotion`; each must
require an independent reviewer and prevent self-review. Restrict deployment branches to `main`.
Store Docker Hub credentials only in those environments/repository secrets.

The committed ruleset requires a reviewed PR, resolved conversations, linear history, current
required checks, and no bypass actors. The **Commit policy** check rejects `release:` commits that
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

## 2. Physical acceptance

Use a clean hosted-installer control plane and at least two distinct broker VPS nodes on the exact
candidate digest. `shakerscan fleet accept` must cover cross-node placement, an actual worker kill
and bounded reclaim, lease isolation, duplicate-completion refusal, dedupe, centralized artifacts,
and public datastore isolation. Long Model Intake work must demonstrate continuous heartbeat
authority. Preserve the content-free receipt at a durable HTTPS URL and record its SHA-256.

Any code change after this point creates a new candidate SHA and requires a new candidate build and
acceptance. Do not patch a live candidate and keep the old receipt.

## 3. Publish the immutable version

Run **Promote release** with the version, candidate SHA, candidate workflow run ID, physical receipt
URL/hash, and accepted node count. The protected environment verifies that the candidate workflow
succeeded for the exact SHA, downloads its receipt, compares every registry digest, and creates
version tags from those digests. It performs no build. The GitHub Release records both build and
physical-acceptance provenance. `latest` and the installer remain unchanged.

## 4. Public smoke and stable promotion

Test the published version as a new user would: clean hosted install, stateful upgrade, rollback,
doctor/status, UI/API, agent/MCP launch, a bounded scan, Model Intake readiness, and remote Fleet
status. Preserve a content-free smoke receipt and hash.

Only then merge a small PR changing `install/STABLE_VERSION`. Run **Promote stable channel** with the
version and smoke receipt. The protected environment confirms the public non-draft release and
stable-version file, then moves each `latest` alias to the already-published version digest. It does
not rebuild.

## Stop conditions

Stop and cut a new candidate for any identity mismatch, stale fleet, failed or missing coverage,
heartbeat authority loss, migration failure, digest drift, receipt mismatch, fewer than two accepted
broker nodes, unaccepted high/critical dependency finding, or public smoke regression. Roll back by
pinning the previous immutable version/digest; do not overwrite an existing version tag.
