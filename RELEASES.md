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
| 2.0.0 | pending candidate | pending | pending | pending | pending |
| 0.8.18 | `9f87f7dbf814fce37a5cda95ff7954e21aaa1dd2` | `shakerscan/shakerscan-scanner:0.8.18` (`sha256:1bfdd22e87bf90cead6a2c38cd98abd94c5a8eadeea9cee351ea9a484bd1d1fd`) | `shakerscan/shakerscan-api:0.8.18` (`sha256:9349c5c0b4dc59c4c43de0583770ed03a996df6601adf49b175d40747a7f4a0a`) | `shakerscan/shakerscan-ui:0.8.18` (`sha256:7811dd9ff647c546fe695cc139171694e90b2bc26a725ec6b0534fe94c8ce7bb`) | `shakerscan/shakerscan-model-intake-signer:0.8.18` (`sha256:5cdeb9d25bc0e8a423b0cf8eb2669fc5558e4e551605a987252b9cbf11d522ab`) |
| 0.8.17 | `9a43ebc445264c3c6a36e14a7685299b6f4b9dab` | `shakerscan/shakerscan-scanner:0.8.17` (`sha256:31289d5b5d0b5c734d5da1d47e16f7df6d94b4218d9d7bcf7a285e8f9789cfa8`) | `shakerscan/shakerscan-api:0.8.17` (`sha256:b8a0ab7ff3a1369f9569fb434a220584d96f50de6ffa658e9922fd314a7d9aea`) | `shakerscan/shakerscan-ui:0.8.17` (`sha256:51081c10ded6c56db74142e2a3a727e68fea2a00ba6f1a130be8b4eb1c4e6e9b`) | `shakerscan/shakerscan-model-intake-signer:0.8.17` (`sha256:1ea012f6f7dacd150a6869ec94633eaf5e0ec1cef7c0babd1c9d444cff69f251`) |
| 0.8.16 | `93f5bb2ad2b469bec979792a5f9213756427b1d3` | `shakerscan/shakerscan-scanner:0.8.16` (`sha256:8b902f9bbf29f0fd6c0740546db8c14754e048afefcd02c30ff1734f25f00790`) | `shakerscan/shakerscan-api:0.8.16` (`sha256:f781a67e570b51ceb7d7ec98b33d3a130f4ebf17bd7b489ba4c00044a8d5c8da`) | `shakerscan/shakerscan-ui:0.8.16` (`sha256:c77eadabac730085c451f9ac1a00327aff7bc5a63637882dfd270fa4548cd884`) | `shakerscan/shakerscan-model-intake-signer:0.8.16` (`sha256:651e843e75aa31c7a92c785e2aac22089ef42902d97fcdf0a6c3f0870b1d0771`) |
| 0.8.15 | `c66b1119cef331175d236788ea59933ac23a0ec4` | `shakerscan/shakerscan-scanner:0.8.15` (`sha256:3344b8c5e3d509852cb4add283083507a89d04c6a42518d86a82d65d0020f54c`) | `shakerscan/shakerscan-api:0.8.15` (`sha256:afbdbe60eb08783861c16919cfcfbd440350ffb8e8ed13c6c9028951bc29a780`) | `shakerscan/shakerscan-ui:0.8.15` (`sha256:62f710774af949697c111ac67681f3099fe4de241c37a63b1a5b617647d4c627`) | `shakerscan/shakerscan-model-intake-signer:0.8.15` (`sha256:8b40783cf6fa88bb009f975404e1d211bd3b29cd32335876e4b44cf540dbb456`) |
| 0.8.14 | `82ecff779b1ad1942ee8603fd43237929f1fa464` (failed validation; not published) | not published | not published | not published | not published |
| 0.8.13 | `171ffb76800dfe329cd7a51edb85e8065b31c702` | `shakerscan/shakerscan-scanner:0.8.13` (`sha256:76a16abf72bd3a082ab4df684f9fc700e773f02ba8d037f1defb33d0ff004d9a`) | `shakerscan/shakerscan-api:0.8.13` (`sha256:997c260427c568fe6d113ff00ce5d518dd658bec94609963d10843703d756663`) | `shakerscan/shakerscan-ui:0.8.13` (`sha256:746c77b98f06d9ee8f48e8eafa5543fb65eeb60ed08b3ab3e9bd25039e55ebda`) | `shakerscan/shakerscan-model-intake-signer:0.8.13` (`sha256:ec3ad09fd2826a2e87806e611abed874c602e9e6554864ba76f94711eab0b923`) |
| 0.8.12 | `fc4f0b8162f0ef1179b7f43d93a5c6c8075d0d80` (failed validation; not published) | not published | not published | not published | not published |
| 0.8.11 | `23faaa7eea2117f40a450bd82377b7725d4feeb7` (cancelled validation; not published) | not published | not published | not published | not published |
| 0.8.10 | `5a240166783ad673d6f375726d505a09ddc210a0` (cancelled validation; not published) | not published | not published | not published | not published |
| 0.8.9 | `edbf513bd5c18e5905704f33e7e14ab3d9094ec9` (published; not promoted after remote-mode audit) | `shakerscan/shakerscan-scanner:0.8.9` (`sha256:98426ae86a576ed25e80c90beea6c90a1a06b1bc401cdc7fe992aa2fbacfcf2b`) | `shakerscan/shakerscan-api:0.8.9` (`sha256:8aff8313f7ad436aaaec923345f630bad3296a9fe5ac934682a0b96f1122e28c`) | `shakerscan/shakerscan-ui:0.8.9` (`sha256:6f1383e2d7bfdc1db618a8aba3b3230778cd1ef4f1fdd0901e90741720d723be`) | `shakerscan/shakerscan-model-intake-signer:0.8.9` (`sha256:ac6c3f9ef1109a10a05ccab66157ebdadd6519f0636ecad1ae5287850abd818e`) |
| 0.8.8 | `0edc1b720dc98a49c90ff12b4fded0e347f7bb66` (failed validation; not published) | not published | not published | not published | not published |
| 0.8.7 | `e21c3ec53041eaa4f2a6b32698a3bc828cc6a0d8` | `shakerscan/shakerscan-scanner:0.8.7` (`sha256:3d321e96a210034f641d1121b36b9da4750db5573f8309c4c1e0df42d207bcd7`) | `shakerscan/shakerscan-api:0.8.7` (`sha256:42e5c431e74d1d68e906f62ba63aec7bb8f763718e218c72115d091fdd9bea69`) | `shakerscan/shakerscan-ui:0.8.7` (`sha256:7df8d44a50092967e958f677d32ddbda50171de84dca2c556dab1bb97c8a995e`) | `shakerscan/shakerscan-model-intake-signer:0.8.7` (`sha256:f791700aaa4984478186d8254618e99a9c71cc2e6464d3f7fec0177d89146cb8`) |
| 0.8.6 | `86ab5ae2c06c47ac92c6fb6c6b4ce4e708f9e382` (failed validation; not published) | not published | not published | not published | not published |
| 0.8.5 | `9c34f18aa35b976f12fa7960563af3bc3b1c69a6` | `shakerscan/shakerscan-scanner:0.8.5` (`sha256:d60310929cf822c41edd2658634b0f142fc05f4d702c700bc72e96cc715cb36f`) | `shakerscan/shakerscan-api:0.8.5` (`sha256:11ebbd820f1a5fae085526331b4014666f756ffa2574005188356052ba4ee9e4`) | `shakerscan/shakerscan-ui:0.8.5` (`sha256:8600ac1dd844661b6a92b1c55649f4dddd90cdf6b735af3ff2efe0c554064719`) | `shakerscan/shakerscan-model-intake-signer:0.8.5` (`sha256:0aa2e1b12787a56d3ba7991d3484ae7d65ab636eefa801807af5008cfc4b8d60`) |
| 0.8.4 | `fe7966ca21038f02c820c0b72f267d4e6a1d459f` | `shakerscan/shakerscan-scanner:0.8.4` (`sha256:7774cfbfc7bf0b98643060a114057e292d5ae0c1e7b5e9a45487b98c06deea35`) | `shakerscan/shakerscan-api:0.8.4` (`sha256:1546a210cdb2b29f7e5851b8642d55fcda3fd7e1c33bb5966c08b081df2a5d66`) | `shakerscan/shakerscan-ui:0.8.4` (`sha256:ef329ecfb00803090a39b0bc5b18a44181fe3f85e0c61bf3375497bf5942633f`) | `shakerscan/shakerscan-model-intake-signer:0.8.4` (`sha256:630cd8a6d00e1fc25fbb614887b92965423e8fb8e1a27cbe1531e7d000b3ba15`) |
| 0.8.3 | `22da7b9f8ff91f31f03fdf9087e977df05f27a1b` | `shakerscan/shakerscan-scanner:0.8.3` (`sha256:e85a57cc29af3390c73e71c800f81d5a9c0f53909c869b59e78b291d11884007`) | `shakerscan/shakerscan-api:0.8.3` (`sha256:c3c42d9a706de9e5888c674ccc1e4dc280b1a5b4ab5b350b1becdfac3524a6e0`) | `shakerscan/shakerscan-ui:0.8.3` (`sha256:74d3f4b011ef9c1148b62d4a268b93de3f72b77661d261e4bfc417208cd979fe`) | `shakerscan/shakerscan-model-intake-signer:0.8.3` (`sha256:14b8541b21e64abfb22d31b29c3cc395e8e27e2347d4bd6fee02a36bdeee8f41`) |
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

Version 2.0.0 is the pending V2 candidate; it has not been published or promoted. Version 0.8.18
remains the current stable installer-hardening release. Version 0.8.9 was published but deliberately not
promoted after the installed-runtime audit found a remote-mode agent/MCP routing defect; 0.8.10 was
cancelled before publication when the same audit found remaining hard-coded loopback guidance;
0.8.11 was cancelled before publication when the final audit found a host-world-writable Model
Intake sandbox evidence queue; 0.8.12 failed its clean Linux/root suite before publication because
the new ownership path called a nonexistent `Path.chown` method. Version 0.8.13 corrected that path,
passed the exact-candidate release gate, and published matching `linux/amd64` and `linux/arm64`
manifests. Its clean fleet conversion then exposed a transient MinIO bucket-readiness race. Version
0.8.14 added a bounded retry around the real artifact write/read/delete probe, but its validation
stopped before publication because a runtime test hardcoded an obsolete stable-channel version.
Version 0.8.15 carries the Fleet fix, makes that test validate the published release ledger
contract instead of a historical number, and published matching `linux/amd64` and `linux/arm64`
manifests for all four images. Clean post-publication acceptance then found three release-truth
defects: broker workers stamped DAST reports as `dev`, ModelScan inspected only the preferred
safetensors artifact instead of co-published serialized alternates, and Model Intake implementation
rows remained in the default DAST scan list. Version 0.8.16 corrected those boundaries, but its
official build workflow omitted the new release-version argument, so a clean broker result still
reported `scanner dev`. Version 0.8.17 supplied and verified that build input and carried the final
clean-acceptance UI/documentation corrections. Complete
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
