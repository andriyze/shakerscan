# ShakerScan Release Mapping

This file tracks the best-known git commit that produced each published Docker image tag. `pending`
is reserved for a future release row before its final commit exists. `unverified legacy provenance`
means an older image exists but its exact build commit was not preserved; do not replace that label
with a guessed tag commit.

`./scanner.sh start` uses the moving `latest` Docker tag by default. Use
`./scanner.sh start --image-tag <version>` when you need reproducible images. The hosted installer
still downloads runtime docs/scripts from its configured raw source, so an image pin does not by
itself pin those files.

| Version | Git Commit | Scanner/Worker Image | API Image | UI Image | Model Intake Signer Image |
| --- | --- | --- | --- | --- | --- |
| 0.8.0 | pending candidate | `shakerscan/shakerscan-scanner:0.8.0` | `shakerscan/shakerscan-api:0.8.0` | `shakerscan/shakerscan-ui:0.8.0` | `shakerscan/shakerscan-model-intake-signer:0.8.0` |
| 0.5.7 | `f27bbffda3451ce013aedfb250c7b018104f41d5` | `shakerscan/shakerscan-scanner:0.5.7` | not published separately | `shakerscan/shakerscan-ui:0.5.7` | not published separately |
| 0.5.6 | `e7f8dbde13d218d54c195a0be934c6b5bd459b1b` | `shakerscan/shakerscan-scanner:0.5.6` | not published separately | `shakerscan/shakerscan-ui:0.5.6` | not published separately |
| 0.5.5 | `53f3cb47ee88a90de7fc49346ac85497f4a6c1db` | `shakerscan/shakerscan-scanner:0.5.5` | not published separately | `shakerscan/shakerscan-ui:0.5.5` | not published separately |
| 0.4.2 | `5e1f484469cfc3a9aa1c031613df0b8aada65254` | `shakerscan/shakerscan-scanner:0.4.2` | not published separately | `shakerscan/shakerscan-ui:0.4.2` | not published separately |
| 0.4.1 | `65e87ba5a7d7f48982b7f2cb3fb3d9fe4ed53ef1` | `shakerscan/shakerscan-scanner:0.4.1` | not published separately | `shakerscan/shakerscan-ui:0.4.1` | not published separately |
| 0.4.0 | unverified legacy provenance | `shakerscan/shakerscan-scanner:0.4.0` | not published separately | `shakerscan/shakerscan-ui:0.4.0` | not published separately |
| 0.3.1 | `662d2f8e3618c25a1d29e1a1b62b3e740b54d143` | `shakerscan/shakerscan-scanner:0.3.1` | not published separately | `shakerscan/shakerscan-ui:0.3.1` | not published separately |
| 0.3.0 | `e0c100c79f0d8058973906ef082f2c5143c7bca7` | `shakerscan/shakerscan-scanner:0.3.0` | not published separately | `shakerscan/shakerscan-ui:0.3.0` | not published separately |
| 0.2.0 | `8e2d887b03e44921daf2b3ff9b87f4b2bff3ce04` | `shakerscan/shakerscan-scanner:0.2.0` | not published separately | `shakerscan/shakerscan-ui:0.2.0` | not published separately |

Repository tags `v0.5.0` through `v0.5.4` exist, but their published image provenance was not
recorded in this ledger. Verify Docker registry history and build metadata before adding them; a git
tag alone does not prove which commit produced an image.

## Release Workflow

Version 0.8.0 is the current candidate. Complete
[`docs/release-readiness.md`](docs/release-readiness.md), freeze its exact commit, and record its
validation evidence before tagging.

1. Finish and validate changes on a feature branch.
2. Correct release automation/metadata prerequisites, including Apache-2.0 image labels,
   version-specific release notes, and required release gates.
3. Update `VERSION` with the newly selected version.
4. Add a new row to this table. Use `pending` only until the release commit exists.
5. Open and merge the exact candidate to `main`. The merge triggers the E2E workflow, but does not
   publish release images.
6. Wait for required `main` checks to pass, record the exact merge commit, and create the release tag
   on that commit:

   ```bash
   git checkout main
   git pull
   git tag -a "v<next-version>" -m "ShakerScan v<next-version>"
   git push origin "v<next-version>"
   ```

7. The tag push triggers the GitHub `Release` workflow. It validates the tagged commit, builds the
   scanner/worker, API control-plane, UI, and Model Intake signer images for `linux/amd64` and
   `linux/arm64` on native runners, merges those digests into multi-architecture Docker manifests,
   then creates or updates the GitHub Release.
8. After publication, replace `pending candidate` in this ledger with the tagged commit SHA, record
   the published image digests, and merge that provenance-only follow-up.
9. Deploy and smoke-test the hosted installer separately; publishing this repository or the Docker
   images does not update `install.shakerscan.com`.

Manual image publishing is also available from a clean checkout:

```bash
scripts/publish-images.sh --push --latest --platform linux/amd64,linux/arm64
```

Use manual publishing only for emergency rebuilds from a builder configured for the requested platforms. The normal release path is a `v*.*.*` git tag on `main`.
