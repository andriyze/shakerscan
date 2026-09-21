# Release SBOMs (stage one)

**Status:** Maintained release guide; stage-one publication is implemented. Historical releases are not automatically backfilled.
**Reconciled:** 2026-09-21

Official engine and client publishing pipelines produce downloadable, artifact-specific
SBOMs. This is a scoped first stage, **not a claim that every library or build input has
been identified**. An SBOM is an inventory, not a vulnerability scan or a security verdict.

## Published files

Engine releases publish one existing BuildKit SPDX catalog per first-party image and
platform. `install/release-images.json` in the certified source tree drives the image list:
scanner, API, UI, Model Intake signer and Model Intake, each for `linux/amd64` and
`linux/arm64` (ten documents). API and scanner are separate artifacts even when components
overlap. No images are rebuilt, executed or pulled into the Docker daemon by the exporter.

Example filename: `shakerscan-2.4.0-scanner-linux-amd64.spdx.json`.

Client releases use the client's independent version. Each exact wheel and source archive
gets an SPDX 2.3 inventory, including SHA-256 file hashes for the packaged CLI/MCP modules
and agent kit. Example filenames:

- `shakerscan-0.6.0-py3-none-any.whl.spdx.json`
- `shakerscan-0.6.0.tar.gz.spdx.json`

Both release types also publish:

| File | Purpose |
| --- | --- |
| `sbom-index.json` | Release version/tag, artifact source commit, exporter source commit, artifact identities, platform/image digests or client archive hashes, SBOM hashes, original generator identities and coverage notes. |
| `sbom-SHA256SUMS` | Checksums of the SPDX documents, scope README and index. |
| `sbom-index.sigstore.json` | Detached GitHub Actions attestation bundle for the index. |
| `sbom-README.md` | Scope and verification reminder, usable without this repository. |

The index's signed hash list connects each SBOM to its subject. The detached signature
bundle is intentionally outside the checksum manifest; it is verified cryptographically.
The signature establishes which workflow published this inventory, not completeness of
component discovery. Original image build provenance remains separately verifiable.

## Coverage and deliberate exclusions

**Engine:** export the existing final-image BuildKit catalogs, preserving package versions,
identifiers, relationships, original generator metadata and unknown versions as reported.
Never filter out packages because of vulnerability waivers, severity or perceived relevance.
The exporter verifies image inventory/receipt correspondence, certified source binding,
both platforms, platform-bound attestation descriptors and release-critical SPDX structure.
This structural validation is not a full validation of every optional SPDX schema field.

Build-stage dependencies, bundled/minified JavaScript, static/native or vendored dependencies,
Nuclei templates, wordlists and vulnerability databases can be incomplete in these catalogs.
Supporting-service images (PostgreSQL, Redis, MinIO and Caddy), the Firecracker guest and
host-installed software are outside stage one. Do not label this the complete deployment SBOM.

**Client:** inventory the actual archives without installing or executing them. Wheel and
sdist packaged modules/kit must match. The current client declares no third-party runtime
dependencies. A future nonempty `Requires-Dist` fails generation rather than publishing a
misleading dependency-free inventory; extend the dependency resolution before that release.
The host's Python requirement is recorded without inventing an exact interpreter version.
Python/stdlib, pip, uv, pipx, Homebrew, Hatchling/build tools and externally invoked agent
programs are not bundled client dependencies. File inventory does not recursively identify
libraries that might later be embedded in copied source.

SBOMs describe shipped artifacts, **not a customer's live environment**. Never generate these
release files from a customer volume or expose an unauthenticated live-dependency endpoint.

## Verify a downloaded release

Download all its SBOM assets into one fresh directory. Use a trusted checkout of this script
and a current GitHub CLI. For an engine release:

```sh
gh release download v2.4.0 --repo andriyze/shakerscan \
  --pattern '*spdx.json' --pattern 'sbom-*' --dir release-sbom

gh attestation verify release-sbom/sbom-index.json \
  --repo andriyze/shakerscan \
  --signer-workflow andriyze/shakerscan/.github/workflows/release.yml \
  --bundle release-sbom/sbom-index.sigstore.json

python3 scripts/release_sbom.py verify --directory release-sbom
```

Use the release you are inspecting; these example versions do not imply that an already
published release has been backfilled. For client releases, use `client-vX.Y.Z` and signer
workflow `andriyze/shakerscan/.github/workflows/publish-client.yml`. Add `--dist path/to/dist`
to `verify` to compare downloaded wheel/sdist hashes against the signed inventory as well.
Check the index's `release_tag`, `source_sha`, and subject digests against the release/artifact
you intended to inspect; authenticity alone does not select the desired version for you.

`verify` checks file hashes against the index, structural SPDX validity, artifact coverage
and checksum-manifest consistency. It does **not** verify signatures by itself. A checksum
manifest downloaded beside a file is not independent proof of authenticity.
For offline verification, also retain a trusted Sigstore root as described by GitHub CLI;
a detached bundle alone does not guarantee verification without network access.

## Release integration

`release.yml` re-verifies candidate image provenance against the certified commit, exports
SBOMs by the immutable receipt digests, signs/verifies the index, and only then promotes
image version tags and creates the GitHub release with all files attached. This handles
both the reusable build-on-main images and the candidate fallback without changing either
build. Missing catalogs fail before version publication; they are never replaced by a
new scan of a rebuilt image with the same tag.

`publish-client.yml` inventories the exact built distributions after smoke tests and keeps
SBOMs in a separate `client-sbom` workflow artifact. The publish job checks distribution
hashes and signs/verifies the index before PyPI publication. Only `dist/` reaches PyPI;
SBOMs and signatures are attached to the GitHub client release. No client or engine
version is bumped by adding this release infrastructure.

A non-publishing manual client build retains its unsigned SBOM workflow artifact. The
existing manual PyPI publish mode still does not create a GitHub release unless triggered
by a client tag; use tagged releases for durable public SBOM downloads.

## Existing releases and local generation

This PR does not modify historical releases. To inventory one, obtain the **existing**
release receipt and image inventory from its exact source commit, independently verify
its build provenance, and run the exporter from a trusted checkout:

```sh
python3 scripts/release_sbom.py engine \
  --receipt release-candidate-receipt.json --inventory released-image-inventory.json \
  --version 2.4.0 --source-sha RELEASE_COMMIT_40_HEX \
  --generator-source-sha "$(git rev-parse HEAD)" --output sbom-backfill

python3 scripts/release_sbom.py client --dist downloaded-client-archives \
  --version 0.6.0 --source-sha CLIENT_RELEASE_COMMIT_40_HEX \
  --generator-source-sha "$(git rev-parse HEAD)" --output client-sbom-backfill
```

The engine command needs Docker Buildx and registry access; it invokes only
`buildx imagetools inspect` and never sources the release `.env` lock. Registry operations
have bounded retries/timeouts. The client command needs only Python 3.10+. Both refuse an
existing output directory. Locally generated results are unsigned; publish them only via
an explicitly approved signing/backfill process, never silently overwrite prior SBOMs.

## Tests and next stage

```sh
python3 -m unittest discover -s tests -p test_release_sbom.py -v
```

`Release SBOM contracts` also builds real client distributions and, on same-repository PRs,
exports the existing v2.4.0 image catalogs in a read-only registry smoke job. It publishes
no release assets and signs nothing. The fixed historical fixture makes format failures
reproducible; registry outages or rate limits can still affect that integration check.

Later stages: supporting services/guest inventory, independent native/Go and bundled UI
coverage checks, separately scoped build-input SBOMs, pinned generator images at build
time, richer schema validation, CycloneDX export and vulnerability/VEX lifecycle management.
Do not extend the completeness claim until those coverage checks exist.

## References

- Docker BuildKit SBOM scope and multi-platform extraction: https://docs.docker.com/build/metadata/attestations/sbom/
- GitHub artifact attestations: https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations
- GitHub CLI verification and offline options: https://cli.github.com/manual/gh_attestation_verify
