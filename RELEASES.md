# ShakerScan Release Mapping

This file tracks the best-known git commit that produced each published Docker image tag. `pending`
is reserved for a future release row before its final commit exists. `unverified legacy provenance`
means an older image exists but its exact build commit was not preserved; do not replace that label
with a guessed tag commit.

The hosted installer resolves `install/STABLE_VERSION`, then downloads runtime files from the
matching immutable `v<version>` tag. Advance that channel only after all release manifests exist.
Release notes and image labels record both the candidate source commit and the workflow-definition
commit; these can differ for an explicitly dispatched candidate build.
Installed runtimes default to the immutable image tag recorded in their downloaded `VERSION` file.
Use `./scanner.sh start --image-tag latest` only when you intentionally want the moving tag. The
hosted installer still downloads runtime docs/scripts from its configured raw source, so the
generated launcher also pins `SCANNER_IMAGE_TAG` to the downloaded version by default.

| Version | Git Commit | Scanner/Worker Image | API Image | UI Image | Model Intake Signer Image |
| --- | --- | --- | --- | --- | --- |
| 0.8.2 | `e5e95a5a898bee8d91ded464bc36c0d32ff5e26c` | `shakerscan/shakerscan-scanner:0.8.2` (`sha256:4de99e5349d7f572d05145d5d02a6919cd637a2dd3f5c976d957097ab0e3a838`) | `shakerscan/shakerscan-api:0.8.2` (`sha256:54e50d7bd2b9223a0bccb3eceb96cbe71166589944935cec03c77542d8100475`) | `shakerscan/shakerscan-ui:0.8.2` (`sha256:4a24d4d9965659e2842d94d72606d51c3329195d401e3aa6acf724d3d5b7ff98`) | `shakerscan/shakerscan-model-intake-signer:0.8.2` (`sha256:98600e5337ce739e917b14d994c6ac63ee1399169e09c4c17509bf141887b780`) |
| 0.8.1 | `85cb9410efaf882588db86721bb8d7016d0ae20f` | `shakerscan/shakerscan-scanner:0.8.1` (`sha256:c5902123c036b8dc21cb39d9d3fd6396213d1ea230c20f6133aaadf5e8bfbbef`) | `shakerscan/shakerscan-api:0.8.1` (`sha256:f9cb8e4d24464ae6be77be65e23c4a2913ddc9884d0392129985a0ac1e296dcb`) | `shakerscan/shakerscan-ui:0.8.1` (`sha256:2af58d0ebb391f824ae2c0bdda4357cbe92a50f4cf0f5be65f5b8ae6a3216afb`) | `shakerscan/shakerscan-model-intake-signer:0.8.1` (`sha256:49a42e117c41b5b1c2e4a9af4a45345ba0ee58f3d58bdfba4a2b936b56505f68`) |
| 0.8.0 | `5cbcdb413df523a931775c5665de2d13408588d2` | `shakerscan/shakerscan-scanner:0.8.0` (`sha256:1c46a2985f38dee25a56b36b7bf75e7d8a7efa93e61716160ee22e94266d5102`) | `shakerscan/shakerscan-api:0.8.0` (`sha256:eb89f3eb25b25797d9191670791a572189013816879b955c52070a108171a627`) | `shakerscan/shakerscan-ui:0.8.0` (`sha256:75e4d83dbbfd98aed0644727302aeb8281e73ed6141c20a11af24834a44789a7`) | `shakerscan/shakerscan-model-intake-signer:0.8.0` (`sha256:42b052aeb93ad6fd531f8d52dcb594645866e64188725a6195cbc8fc9f4577af`) |
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

Version 0.8.2 is the current patch candidate. Complete
[`docs/release-readiness.md`](docs/release-readiness.md), freeze the exact commit, and record its
validation evidence before publishing a later release.

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
