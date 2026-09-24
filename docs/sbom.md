# Release SBOMs

**Status:** Implemented release tooling, stages one and two. Coverage remains explicitly partial.
**Updated:** 2026-09-21.

Official publishing pipelines attach artifact-specific inventories and a signed index.
An SBOM is a contents inventory, not a vulnerability scan, certification or assurance
that every statically linked/minified library has been attributed.

## What is published

Engine release bundles retain the ten original BuildKit SPDX catalogs: scanner, API, UI,
Model Intake signer and Model Intake, each for linux/amd64 and linux/arm64. The certified
receipt and `install/release-images.json` select immutable image subjects, not `latest`.

Stage two independently catalogs each of those ten platform manifests with pinned Syft,
and catalogs the checked-in default supporting-service images on both architectures.
The current release Compose has five distinct supporting images: PostgreSQL, Redis,
MinIO, MinIO client and Caddy. The signer database shares the PostgreSQL image, so its
service use is retained without duplicating the catalog. Optional profile names and
image override variables are recorded. Customer environment overrides are never read.

Each independent runtime catalog has SPDX 2.3 and CycloneDX 1.6 representations.
A separate pair describes the exact resolutions in UI, scanner, signer, Model Intake
and guest dependency locks. These are **source/build inputs, not an assertion that all
listed packages execute or ship in the final application**. A lock-file hash identifies
the input file; it is never substituted for a package distribution's hash.

Client releases retain actual wheel and sdist SPDX file inventories and add CycloneDX
representations. The current client has no declared third-party runtime dependencies;
a future nonempty `Requires-Dist` fails generation until dependency resolution is
implemented. The CLI/MCP copies and agent kit are included in archive file inventories.
Python, its standard library, pip/pipx/uv/Homebrew and external agents are not bundled.
The client version and source commit are independent of the engine release.

| File | Purpose |
| --- | --- |
| `*.spdx.json`, `*.cdx.json` | Artifact catalogs, with build inputs distinguished by name and scope. |
| `sbom-index.json` | Artifact identities, source/exporter commits, document hashes, generator identity and coverage. |
| `sbom-source-inputs.json` | Source lock hashes, image inventory and supporting-service defaults/profile mapping. |
| `sbom-coverage.json` | Coverage checks, catalog differences, limitations and validation method. |
| `sbom-SHA256SUMS` | Hashes of catalogs, evidence, README and index. |
| `sbom-index.sigstore.json` | Detached attestation of the final index; not self-included in the checksum list. |
| `sbom-README.md` | Scope and verification instructions carried with downloads. |

## Coverage checks and limitations

The independent runtime scan uses the exact per-platform manifest and verifies the
returned manifest digest, OS and architecture. Images are downloaded for cataloging,
not run or rebuilt. Sequential temporary workspaces are removed after each image.
BuildKit and independent inventories are preserved separately; their package-identity
differences are evidence, not automatically suppressed false positives.

Checks require OS package metadata, scanner/API/signer installed Python versions,
isolated Model Intake tool environments, compiled Go metadata at expected shipped
binary paths, and Next.js/React/React DOM metadata matching the source lock. Source
requirements files inside an image cannot substitute for installed Python metadata.
Universal-lock markers are evaluated against the target Linux/CPython image, not the CI
host. Inapplicable Windows dependencies remain in source-input catalogs and are recorded
as conditional inputs, not required installed packages. Python patch-dependent markers
fail unless their result is invariant across the observed interpreter family.
Go records include the actual compiled dependency versions and toolchain metadata,
which matters because ShakerScan rebuilds upstream tools with dependency adjustments.

Syft is also the family of cataloger used by BuildKit: these are independent catalog
runs against final bytes, **not two unrelated detection engines**. Passing these targeted
checks does not prove completeness for arbitrary native libraries, vendored code or
minified JavaScript. Unattributed UI lock entries are explicitly reported as unresolved;
they can be development-only, platform-conditional or bundled, not necessarily absent.
Templates, wordlists and vulnerability database snapshots can still be under-attributed.
Host software, remote services and customer volumes are outside the public release BOM.

All generated catalog representations pass the official, content-pinned SPDX 2.2/2.3
or CycloneDX 1.6 JSON schemas with offline reference resolution. The separately versioned
license enumeration is pinned to the official SPDX 3.29 list, preserving newer valid
identifiers such as SMAIL-GPL rather than deleting or relabeling license evidence.
Additional semantic
checks reject dangling/duplicate references and conversion loss of package identifiers.
The first-party source image inventory defines completeness: removing an entire image
and both platform catalogs is rejected, not mistaken for a smaller complete release.
Syft's omitted CycloneDX container-root PURL is filled only after matching the SPDX
root name and immutable manifest digest. This explicit mapping is recorded on the
component; missing dependency identities and conflicting roots still fail validation.
Schema validity is not completeness, correctness of an upstream license assertion or
proof of vulnerability applicability. Inventory is never filtered by severity or waiver.

`release_sbom_toolchain.py` pins Syft 1.52.0 Linux archive SHA-256s and official schema
Git blob identities. The bootstrap records resolved binary/schema SHA-256s in the
index. Release-only jsonschema/PyYAML tooling is version-pinned in the composite action;
packaging is pinned for target-environment marker evaluation; its full transitive Python environment is not currently hash-locked or claimed reproducible.
No cataloger is added to normal product runtime images for this release work.

## Locally built Firecracker guest: remaining runtime scope

The guest root filesystem is built locally rather than distributed as a single global
release artifact. Stage two includes its dependency lock as a **source input only**.
It does not publish a runtime guest SBOM or change guest installation. A future guest
inventory must be generated from the actual built filesystem and bound to its ext4
hash, architecture, Docker image ID and kernel/VMM context; rebuilding a similarly named
image is not a valid substitute. This remains an explicit runtime coverage gap.

## Verification

Download catalogs and all `sbom-*` assets of the desired release into one new directory.
Example commands below require a release produced by these workflows; historical
v2.4.0/client-v0.6.0 assets are not silently backfilled by this PR.

```sh
gh release download vX.Y.Z --repo andriyze/shakerscan \
  --pattern '*.spdx.json' --pattern '*.cdx.json' --pattern 'sbom-*' --dir release-sbom

gh attestation verify release-sbom/sbom-index.json --repo andriyze/shakerscan \
  --signer-workflow andriyze/shakerscan/.github/workflows/release.yml \
  --bundle release-sbom/sbom-index.sigstore.json

python3 scripts/release_sbom.py verify --directory release-sbom
```

For a client tag use `client-vX.Y.Z` and signer workflow
`andriyze/shakerscan/.github/workflows/publish-client.yml`; pass `--dist downloaded-dist`
to the integrity verifier to compare actual distribution hashes. Independently check
the desired version, source commit and artifact digest; authenticity alone does not
choose the version you intended. `verify` checks bundle hashes, relationships, coverage
and subjects, **not signatures or a repeat of complete JSON-schema validation**.
A detached bundle may also need a separately trusted Sigstore root for offline use.

## Release integration and local generation

Engine publication re-verifies existing candidate provenance, exports the BuildKit
catalogs, generates stage-two evidence, validates and signs the final index, then publishes
version tags and GitHub assets. Both candidate build paths are covered without rebuilding
images during promotion. A catalog/schema/coverage failure stops publication.

The client build inventories the exact wheel/sdist, validates the expanded bundle and
uploads it separately as `client-sbom`; the publish job verifies artifact hashes and signs
before PyPI publication. Only `dist/` is sent to PyPI. All SBOMs go to GitHub release assets.
Manual non-publishing builds retain unsigned workflow artifacts; use tagged releases for
long-lived public assets. This work does not bump either product version.

To expand an unsigned stage-one bundle using a clean checkout at its exact source commit:

```sh
python3 scripts/release_sbom_toolchain.py --output /tmp/sbom-tools
python3 scripts/release_sbom_stage2.py --directory stage-one-bundle \
  --source-root /path/to/exact-release-checkout --tools /tmp/sbom-tools \
  --output expanded-bundle
python3 scripts/release_sbom.py verify --directory expanded-bundle
```

Install the release-only dependencies shown in `.github/actions/sbom-tools/action.yml`.
Docker Buildx and registry access are needed for engine export. Output directories must
be new; signed or already expanded input bundles are refused. Locally generated results
are unsigned until an authorized publisher attests them. Never substitute a fresh rebuild
for the historical digest or replace previously published SBOMs without an explicit process.

## Tests and remaining work

```sh
python3 -m unittest discover -s tests -p 'test_release_sbom*.py' -v
```

The CI workflow exercises actual client archives, schema validation and a read-only
catalog of the existing v2.4.0 engine/supporting defaults. It retains source/tool inputs
for reproducibility. Registry availability/rate limits can affect the integration gate.
Guest filesystem inventory and KVM boot acceptance remain outside this implementation.

Further work: local guest artifact inventory, exact bundled-JavaScript attribution, comprehensive static/native library
coverage, explicit template/database contents, kernel/VMM inventories, build-environment
attestations and an ongoing advisory/VEX lifecycle. VEX must be a separately reviewed
statement of applicability with justification, scope and review dates, never an excuse to
remove a shipped component. No automatic “not affected” claims are generated here.

## References

- Docker SBOM scope: https://docs.docker.com/build/metadata/attestations/sbom/
- Syft source and formats: https://github.com/anchore/syft
- SPDX 2.3 schema: https://github.com/spdx/spdx-spec/blob/v2.3/schemas/spdx-schema.json
- CycloneDX 1.6 schemas: https://github.com/CycloneDX/specification/tree/1.6/schema
- GitHub verification: https://cli.github.com/manual/gh_attestation_verify

## Exact-content recovery for retired MinIO registry references

Stage-two cataloging first tries the original pinned Compose reference. For the two reviewed MinIO
server/client digests, an unavailable primary registry may be read through the matching
`ghcr.io/teableio/minio` or `ghcr.io/teableio/minio-mc` mirror. The raw index must hash to the **original
SHA-256**, and both architecture-specific catalogs still use the platform digests from that index.
No mutable tag, alternate version, skipped service or unverified index is accepted. An integrity
failure is not retried through a mirror. All prior completeness and coverage checks remain blocking.

The source plan and each affected catalog retain the original `image_reference` and explicitly add
`retrieval_reference`; generated Syft documents describe the actual retrieval source. Offline bundle
validation checks that this is one of the two exact reviewed source/mirror pairs and that plan and
catalog agree. First-party images and other digests receive no mirror exception.

[Independent content verification](https://github.com/andriyze/shakerscan/actions/runs/36032207153)
downloaded both original indexes, the amd64/arm64 manifests, configurations and every image layer,
verifying their sizes and hashes (180,152,816 distinct bytes across the two images). Mirror publication
is documented in [Teable's version manifest](https://github.com/teableio/teable-deployment/blob/main/versions.yaml),
Git blob `749d0038cf6aaf9aa3c4f46f7afe897ef841dc06`. That statement alone was not used as proof of bytes.

This is SBOM retrieval recovery, not a Compose default migration or a new release certification.
Optional artifact-profile deployments using the inaccessible original references remain tracked in
[#218](https://github.com/andriyze/shakerscan/issues/218); existing operator image overrides are unchanged.
