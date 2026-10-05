# Third-party software and data

ShakerScan stands on the work of many open-source security projects. This file credits the tools,
data sets and libraries that ShakerScan bundles in its container images, downloads while building
them, or invokes at runtime, together with their authors and licences.

Each component remains under its own licence. Nothing here changes those terms, and ShakerScan's
own [AGPL-3.0 licence](LICENSE) does not apply to them. Where a licence requires it, the full
licence text ships with the component inside the image (for Debian/Ubuntu packages under
`/usr/share/doc/<package>/copyright`, for Python packages in their `*.dist-info` directory, and
for Go tools in the module source recorded in the image SBOM). Release images carry SPDX SBOMs and
build attestations; see [docs/sbom.md](docs/sbom.md).

To obtain the corresponding source for a GPL- or LGPL-licensed component in a published image,
use the upstream URL and exact version pinned in `scanner/Dockerfile`, `scanner/requirements.lock`
or the SBOM, or open an issue and we will provide it.

## Security tools bundled in the scanner image

| Component | Author / maintainer | Upstream | Licence | How ShakerScan uses it |
|---|---|---|---|---|
| nuclei | ProjectDiscovery, Inc. | https://github.com/projectdiscovery/nuclei | MIT | Built from source; template-based checks |
| nuclei-templates | ProjectDiscovery, Inc. and community contributors | https://github.com/projectdiscovery/nuclei-templates | MIT | Pinned snapshot bundled; a few templates copied, with their authors, as test fixtures in `tests/fixtures/nuclei_templates/` |
| httpx | ProjectDiscovery, Inc. | https://github.com/projectdiscovery/httpx | MIT | Built from source; HTTP probing |
| katana | ProjectDiscovery, Inc. | https://github.com/projectdiscovery/katana | MIT | Built from source; crawling |
| subfinder | ProjectDiscovery, Inc. | https://github.com/projectdiscovery/subfinder | MIT | Built from source; passive subdomain discovery |
| naabu | ProjectDiscovery, Inc. | https://github.com/projectdiscovery/naabu | MIT | Built from source; port discovery |
| tlsx | ProjectDiscovery, Inc. | https://github.com/projectdiscovery/tlsx | MIT | Built from source; TLS inspection |
| dalfox | hahwul (HAHWUL) | https://github.com/hahwul/dalfox | MIT | Built from source; XSS analysis |
| ffuf | Joona Hoikkala and contributors | https://github.com/ffuf/ffuf | MIT | Built from source; content discovery |
| meg | Tom Hudson (tomnomnom) | https://github.com/tomnomnom/meg | MIT | Built from source; bulk path fetching |
| gungnir | g0lden (g0ldencybersec) | https://github.com/g0ldencybersec/gungnir | MIT | Built from source; certificate-transparency monitoring |
| Nmap and the Nmap Scripting Engine | Gordon Lyon and the Nmap Project | https://nmap.org | Nmap Public Source License (see `/usr/share/doc/nmap/copyright`) | Ubuntu package; bounded service and NSE checks |
| sqlmap | Bernardo Damele A. G., Miroslav Stampar | https://sqlmap.org | GPL-2.0-or-later with the sqlmap licence clarifications | Python package; SQL injection confirmation |
| testssl.sh | Dirk Wetter and contributors | https://github.com/testssl/testssl.sh | GPL-2.0 | Pinned snapshot bundled; TLS assessment |
| Playwright (Python) and Chromium | Microsoft Corporation; The Chromium Authors | https://playwright.dev | Apache-2.0; Chromium BSD-3-Clause and bundled third-party licences | Base image and browser automation |

## Model Intake scanners (model-intake image)

| Component | Author / maintainer | Upstream | Licence |
|---|---|---|---|
| Trivy | Aqua Security Software Ltd. | https://github.com/aquasecurity/trivy | Apache-2.0 |
| OSV-Scanner | Google LLC | https://github.com/google/osv-scanner | Apache-2.0 |
| Semgrep CLI (custom rules only) | Semgrep, Inc. | https://github.com/semgrep/semgrep | LGPL-2.1 |
| fickling | Trail of Bits | https://github.com/trailofbits/fickling | LGPL-3.0 |
| ModelScan | Protect AI | https://github.com/protectai/modelscan | Apache-2.0 |
| pip-audit | Python Packaging Authority / Trail of Bits | https://github.com/pypa/pip-audit | Apache-2.0 |
| safetensors | Hugging Face | https://github.com/huggingface/safetensors | Apache-2.0 |
| Firecracker (optional host runner, downloaded by the operator) | Amazon Web Services | https://github.com/firecracker-microvm/firecracker | Apache-2.0 |

ShakerScan does not bundle Semgrep Registry rules; they are under the separate Semgrep Rules License.

## Data sets

| Data | Author / maintainer | Upstream | Licence / terms |
|---|---|---|---|
| SecLists `Discovery/Web-Content/common.txt` | Daniel Miessler, Jason Haddix, g0tmi1k and contributors | https://github.com/danielmiessler/SecLists | MIT |
| DirBuster `directory-list-2.3-small.txt` (via SecLists) | James Fisher / OWASP DirBuster project | https://github.com/danielmiessler/SecLists | CC BY-SA 3.0 |
| SQL injection payloads in `scanner/payloads/sqli/` (curated from SecLists) | SecLists contributors | https://github.com/danielmiessler/SecLists | MIT |
| Retire.js vulnerability repository (`jsrepository.json`) | Erlend Oftedal and RetireJS contributors | https://github.com/RetireJS/retire.js | Apache-2.0 |
| OSV vulnerability data, including the PyPA Advisory Database | Google LLC; Python Packaging Authority | https://osv.dev | CC BY 4.0 (PyPA advisories); per-source terms |
| NVD CPE and CVE data in `scanner/data/device_advisories.json` | NIST National Vulnerability Database | https://nvd.nist.gov | Public domain |
| caniuse-lite (UI build dependency) | Ben Briggs, Andrey Sitnik and contributors | https://github.com/browserslist/caniuse-lite | CC BY 4.0 |

This product uses data from the NVD API but is not endorsed or certified by the NVD.

## Runtime services (Docker Compose)

| Service | Upstream | Licence |
|---|---|---|
| PostgreSQL | https://www.postgresql.org | PostgreSQL License |
| Redis 8 | https://redis.io | Tri-licensed RSALv2 / SSPLv1 / AGPL-3.0 (used under AGPL-3.0) |
| MinIO and mc (optional artifacts profile) | https://min.io | AGPL-3.0 |
| Caddy (optional fleet gateway) | https://caddyserver.com | Apache-2.0 |
| Docker CLI (API image) | https://github.com/docker/cli | Apache-2.0 |
| OWASP Juice Shop (development benchmark fixture only) | https://github.com/juice-shop/juice-shop | MIT |

## Libraries

Python dependencies are pinned with hashes in `scanner/requirements.lock` (and the Model Intake
locks under `scanner/model_intake_tools/` and `runner/guest/`). JavaScript dependencies are pinned
in `ui/package-lock.json` and `posture/package-lock.json`. Notable non-permissive licences among
them: paramiko (LGPL-2.1), certifi (MPL-2.0), the UI build tool lightningcss (MPL-2.0, used
through Tailwind CSS at build time only), and the optional `@img/sharp-libvips-*` binaries
used by Next.js image handling (LGPL-3.0-or-later). All other direct dependencies are under MIT,
BSD, ISC or Apache-2.0 licences; the exact set is recorded in each release SBOM.

## External services

ShakerScan never sends callbacks to ProjectDiscovery's public Interactsh servers. Out-of-band
detection is available only against an Interactsh server the operator runs and configures, and
only when OOB interactions are explicitly authorized. The optional AI features send data to the
AI provider the operator configures, under that provider's terms.

If you believe a component is missing or mis-attributed, please open an issue.
