# ShakerScan - Open Source Edition
# Multi-stage build for comprehensive security scanning

# --- Stage 1: Build Go tools ---
# Pin Go to a stable major/minor while meeting current ProjectDiscovery tool requirements.
#
# This stage builds NATIVELY for the current platform. The release workflow
# builds each arch (amd64, arm64) on its own native GitHub runner and merges the
# results into one multi-arch manifest, so there is no QEMU emulation (which is
# what blew past GitHub's 6h job limit on the v0.5.4 build) and katana's CGO
# dependency (go-tree-sitter) compiles cleanly.
FROM golang:1.26.5-bookworm@sha256:6c5605ab3a9a9fb3c4eafe5b3d63cdbf3881caf113262b67862547b54a9db599 AS go-builder

# Naabu supports both SYN and CONNECT discovery, and its Go packet-capture
# dependency is compiled even though ShakerScan deliberately invokes CONNECT
# mode for unprivileged, portable connected-device scans.
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery tools + Gungnir (CT log scanner). Versions remain
# immutable, while bounded retries tolerate transient DNS/module-proxy outages.
# Each command is built from a small wrapper module so minimum-version
# selection can lift security-sensitive transitive dependencies above the
# versions still pinned by otherwise-current upstream releases. This keeps the
# scanner versions stable while lifting compatible network parsers used on
# attacker-controlled responses above their known-vulnerable dependency floors.
# Cache mounts preserve completed downloads and compilations across retries and
# subsequent builds. Compose builds the API, worker, and intake sandbox from
# this Dockerfile concurrently, so the shared Go caches must be locked; an
# unlocked mount can disappear underneath another build during cache cleanup.
# Separate installs are required because Go expects packages in one `go install`
# invocation to share a module version.
ARG GO_INSTALL_ATTEMPTS=4
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    set -eu; \
    mkdir -p /go/pkg/mod/cache /root/.cache/go-build; \
    build_tool() { \
      tool_name="$1"; \
      tool_package="$2"; \
      tool_version="$3"; \
      tool_dir="/tmp/build-${tool_name}"; \
      rm -rf "${tool_dir}"; \
      mkdir -p "${tool_dir}"; \
      cd "${tool_dir}"; \
      go mod init "shakerscan.local/${tool_name}" >/dev/null || return 1; \
      go get "${tool_package}@${tool_version}" || return 1; \
      go get \
        golang.org/x/crypto@v0.53.0 \
        golang.org/x/net@v0.56.0 \
        golang.org/x/text@v0.39.0 \
        github.com/jackc/pgx/v5@v5.9.0 || return 1; \
      go build -mod=mod -trimpath -o "/go/bin/${tool_name}" "${tool_package}" || return 1; \
      cd /; \
      rm -rf "${tool_dir}"; \
    }; \
    install_tools() { \
      build_tool tlsx github.com/projectdiscovery/tlsx/cmd/tlsx v1.3.0 && \
      build_tool httpx github.com/projectdiscovery/httpx/cmd/httpx v1.10.0 && \
      build_tool katana github.com/projectdiscovery/katana/cmd/katana v1.7.0 && \
      build_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder v2.15.0 && \
      build_tool naabu github.com/projectdiscovery/naabu/v2/cmd/naabu v2.3.7 && \
      build_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei v3.11.0 && \
      build_tool dalfox github.com/hahwul/dalfox/v2 v2.13.0 && \
      build_tool ffuf github.com/ffuf/ffuf/v2 v2.2.1 && \
      build_tool meg github.com/tomnomnom/meg v0.3.0 && \
      build_tool gungnir github.com/g0ldencybersec/gungnir/cmd/gungnir v1.4.0; \
    }; \
    attempt=1; \
    until install_tools; do \
      if [ "$attempt" -ge "$GO_INSTALL_ATTEMPTS" ]; then \
        echo "Go tool installation failed after ${GO_INSTALL_ATTEMPTS} attempts" >&2; \
        exit 1; \
      fi; \
      delay=$((attempt * 5)); \
      echo "Go module download failed (attempt ${attempt}/${GO_INSTALL_ATTEMPTS}); retrying in ${delay}s" >&2; \
      sleep "$delay"; \
      attempt=$((attempt + 1)); \
    done

# --- Stage 2: Runtime with Playwright (Chromium) ---
FROM mcr.microsoft.com/playwright/python:v1.62.0-noble@sha256:aa81288e738725378becba5b3e06cb0f3a7f012a610e87e8d767a090ea3f740d

# System deps for network tooling and additional scanners
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl nmap openssl bind9-dnsutils jq git bash make gcc libpcap0.8 \
    iputils-ping dnsutils procps coreutils \
    nikto masscan python3-pip \
    whois netcat-openbsd traceroute \
    dirb gobuster hydra medusa \
    dnsrecon \
    libcurl4-openssl-dev libssl-dev python3-dev python3-venv \
    bsdmainutils \
 && rm -rf /var/lib/apt/lists/*

# Copy Go binaries to /opt/tools
COPY --from=go-builder /go/bin/tlsx /opt/tools/tlsx
COPY --from=go-builder /go/bin/httpx /opt/tools/httpx
COPY --from=go-builder /go/bin/katana /opt/tools/katana
COPY --from=go-builder /go/bin/subfinder /opt/tools/subfinder
COPY --from=go-builder /go/bin/naabu /opt/tools/naabu
COPY --from=go-builder /go/bin/nuclei /opt/tools/nuclei
COPY --from=go-builder /go/bin/dalfox /opt/tools/dalfox
COPY --from=go-builder /go/bin/ffuf /opt/tools/ffuf
COPY --from=go-builder /go/bin/meg /opt/tools/meg
COPY --from=go-builder /go/bin/gungnir /opt/tools/gungnir

# Make all tools executable
RUN chmod +x /opt/tools/*

# ============================================================
# NUCLEI TEMPLATES
# ============================================================
ENV NUCLEI_CONFIG_DIR=/opt/nuclei-config
ENV NUCLEI_TEMPLATES=/opt/nuclei-templates
ARG NUCLEI_TEMPLATES_COMMIT=2935d63aebd1f5f4a3c8e87c6e7f5c47f689b115
ARG NUCLEI_TEMPLATES_SHA256=20aff7085b5c1771a8f7a28624009359a1cedab924c9ad7836078ca07e28de39

RUN set -e && \
    mkdir -p /opt/nuclei-templates /opt/nuclei-config && \
    curl -fsSL \
        "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/${NUCLEI_TEMPLATES_COMMIT}" \
        -o /tmp/nuclei-templates.tar.gz && \
    echo "${NUCLEI_TEMPLATES_SHA256}  /tmp/nuclei-templates.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/nuclei-templates.tar.gz -C /opt/nuclei-templates --strip-components=1 && \
    rm /tmp/nuclei-templates.tar.gz && \
    TEMPLATE_COUNT=$(find /opt/nuclei-templates -name "*.yaml" -type f 2>/dev/null | wc -l) && \
    echo "Templates found: $TEMPLATE_COUNT" && \
    echo '{"nuclei-templates-directory":"/opt/nuclei-templates"}' > /opt/nuclei-config/.templates-config.json && \
    if [ -f /opt/nuclei-templates/.nuclei-ignore ]; then \
        cp /opt/nuclei-templates/.nuclei-ignore /opt/nuclei-config/.nuclei-ignore; \
    fi && \
    chmod -R 755 /opt/nuclei-config /opt/nuclei-templates

# Download immutable, checksum-verified wordlists for deep discovery.
ARG SECLISTS_COMMIT=f0e9596052a4e27c073cfb452c94a0d955cb29be
ARG SECLISTS_COMMON_SHA256=47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a
ARG SECLISTS_DIRECTORY_SMALL_SHA256=77f7aba81570b24c30965bfc4652cf6c99ee4e5ed38f1eab96f2e102981a6d90
RUN mkdir -p /usr/share/wordlists && \
    cd /usr/share/wordlists && \
    curl -fsSL \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_COMMIT}/Discovery/Web-Content/common.txt" \
        -o common.txt && \
    echo "${SECLISTS_COMMON_SHA256}  common.txt" | sha256sum -c - && \
    curl -fsSL \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_COMMIT}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt" \
        -o directory-list-small.txt && \
    echo "${SECLISTS_DIRECTORY_SMALL_SHA256}  directory-list-small.txt" | sha256sum -c -

# Download an immutable, checksum-verified Retire.js vulnerability database.
ARG RETIREJS_COMMIT=24fe8f48b93998bfc78c5c0567877fe689cce44d
ARG RETIREJS_REPOSITORY_SHA256=5fdf3cc5707264de891f3844becea5fbc17377e8a684aecf8d2fca7936afb6da
RUN mkdir -p /app/data && \
    curl -fsSL \
        "https://raw.githubusercontent.com/RetireJS/retire.js/${RETIREJS_COMMIT}/repository/jsrepository.json" \
        -o /app/data/jsrepository.json && \
    echo "${RETIREJS_REPOSITORY_SHA256}  /app/data/jsrepository.json" | sha256sum -c -

# Install an immutable, checksum-verified testssl.sh snapshot.
ARG TESTSSL_COMMIT=5296954a701dd00240bec32feadffaa7eacb2bba
ARG TESTSSL_SHA256=8e650af4f83f8fbe7baed0287db906d885f955141b93b5cbe46421d050703a82
RUN mkdir -p /opt/testssl.sh && \
    curl -fsSL \
        "https://codeload.github.com/testssl/testssl.sh/tar.gz/${TESTSSL_COMMIT}" \
        -o /tmp/testssl.tar.gz && \
    echo "${TESTSSL_SHA256}  /tmp/testssl.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/testssl.tar.gz -C /opt/testssl.sh --strip-components=1 && \
    rm /tmp/testssl.tar.gz && \
    chmod +x /opt/testssl.sh/testssl.sh
ENV TESTSSL_BIN=/opt/testssl.sh/testssl.sh

# App directory
WORKDIR /app

# Python deps for scanner. requirements.txt is the human-maintained input;
# requirements.lock is the reviewed, reproducible release resolution.
COPY scanner/requirements.txt /app/requirements.txt
COPY scanner/requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir --break-system-packages --ignore-installed --require-hashes \
    -r /app/requirements.lock

# Model-intake evidence adapters live in separate, hash-locked virtual
# environments. Their dependency graphs cannot alter the API/worker runtime.
COPY scanner/model_intake_tools /opt/model-intake-locks
COPY runner/guest/requirements.lock /opt/model-intake-locks/firecracker-runtime.lock
COPY runner/guest/guest_worker.py /opt/model-intake-locks/firecracker-guest-worker.py
COPY runner/guest/guest-init /opt/model-intake-locks/firecracker-guest-init
COPY runner/guest/Dockerfile /opt/model-intake-locks/firecracker-guest.Dockerfile
COPY scanner/Dockerfile /opt/build-inputs/scanner.Dockerfile
RUN set -eu; \
    for tool in modelscan fickling semgrep safetensors pip-audit; do \
      python3 -m venv "/opt/model-intake-tools/${tool}"; \
      "/opt/model-intake-tools/${tool}/bin/pip" install \
        --no-cache-dir --require-hashes -r "/opt/model-intake-locks/${tool}.lock"; \
      if [ "${tool}" != "pip-audit" ]; then \
        ln -s "/opt/model-intake-tools/${tool}/bin/${tool}" "/opt/tools/${tool}"; \
      fi; \
    done; \
    install -m 0755 /opt/model-intake-locks/pip_audit_offline.py /opt/tools/pip-audit-offline; \
    mkdir -p /opt/pip-audit-cache; \
    /opt/tools/pip-audit-offline --build-cache \
      --lock /opt/model-intake-locks/firecracker-runtime.lock \
      --pip-audit /opt/model-intake-tools/pip-audit/bin/pip-audit \
      --output /opt/pip-audit-cache/runtime-audit.json \
      --metadata /opt/pip-audit-cache/metadata.json

# Compiler headers are build-only. Keeping them in the scanner runtime both
# enlarges the release image and exposes kernel-header packages that no scan
# path executes.
RUN apt-get purge -y --auto-remove \
      make gcc libcurl4-openssl-dev libssl-dev python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Trivy is a checksum-pinned native adapter. The vulnerability database is
# captured in the image and scanned offline; readiness exposes its metadata.
ARG TARGETARCH
ARG TRIVY_VERSION=0.73.0
ARG TRIVY_AMD64_SHA256=2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b
ARG TRIVY_ARM64_SHA256=13833d97e8a1a5367471c372a173180157f593bece570e20d5d925fef552f5dd
ARG TRIVY_DOWNLOAD_ATTEMPTS=4
# OSV Scanner 2.5 delegates offline matching to OSV-Scalibr, which appends
# osv-scalibr/<ecosystem>/all.zip to the configured base path.
ARG OSV_SCANNER_VERSION=2.5.0
ARG OSV_SCANNER_AMD64_SHA256=edcfc41d257db36148f065055655fe3fcfc434b0b423ea67468a84c207524e0c
ARG OSV_SCANNER_ARM64_SHA256=fe152e1a546af223e6c557cc3111a8bb3e5dc02fcbf7dbe95d26567c0f0041f2
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) trivy_arch="64bit"; trivy_sha="${TRIVY_AMD64_SHA256}"; osv_arch="amd64"; osv_sha="${OSV_SCANNER_AMD64_SHA256}" ;; \
      arm64) trivy_arch="ARM64"; trivy_sha="${TRIVY_ARM64_SHA256}"; osv_arch="arm64"; osv_sha="${OSV_SCANNER_ARM64_SHA256}" ;; \
      *) echo "Unsupported Trivy architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    trivy_archive="trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz"; \
    curl --retry 4 --retry-all-errors --retry-delay 3 --connect-timeout 20 -fsSL \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${trivy_archive}" \
      -o "/tmp/${trivy_archive}"; \
    echo "${trivy_sha}  /tmp/${trivy_archive}" | sha256sum -c -; \
    tar -xzf "/tmp/${trivy_archive}" -C /opt/tools trivy; \
    rm "/tmp/${trivy_archive}"; \
    chmod 755 /opt/tools/trivy; \
    mkdir -p /opt/trivy-cache; \
    download_trivy_data() { \
      /opt/tools/trivy image --download-db-only --cache-dir /opt/trivy-cache && \
      /opt/tools/trivy fs --scanners misconfig --format json \
        --cache-dir /opt/trivy-cache /opt/model-intake-locks >/dev/null; \
    }; \
    attempt=1; \
    until download_trivy_data; do \
      if [ "$attempt" -ge "${TRIVY_DOWNLOAD_ATTEMPTS}" ]; then \
        echo "Trivy database/check bundle download failed after ${TRIVY_DOWNLOAD_ATTEMPTS} attempts" >&2; \
        exit 1; \
      fi; \
      delay=$((attempt * 5)); \
      echo "Trivy data download failed (attempt ${attempt}/${TRIVY_DOWNLOAD_ATTEMPTS}); retrying in ${delay}s" >&2; \
      sleep "$delay"; \
      attempt=$((attempt + 1)); \
    done; \
    osv_archive="osv-scanner_linux_${osv_arch}"; \
    curl --retry 4 --retry-all-errors --retry-delay 3 --connect-timeout 20 -fsSL \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/${osv_archive}" \
      -o "/tmp/${osv_archive}"; \
    echo "${osv_sha}  /tmp/${osv_archive}" | sha256sum -c -; \
    install -m 0755 "/tmp/${osv_archive}" /opt/tools/osv-scanner; \
    rm "/tmp/${osv_archive}"; \
    mkdir -p /opt/osv-cache/osv-scalibr/PyPI; \
    curl --retry 4 --retry-all-errors --retry-delay 3 --connect-timeout 20 -fsSL \
      "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip" \
      -o /opt/osv-cache/osv-scalibr/PyPI/all.zip; \
    osv_db_sha="$(sha256sum /opt/osv-cache/osv-scalibr/PyPI/all.zip | cut -d' ' -f1)"; \
    osv_updated="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
    printf '{"UpdatedAt":"%s","Ecosystem":"PyPI","DatabaseSHA256":"%s"}\n' \
      "$osv_updated" "$osv_db_sha" > /opt/osv-cache/metadata.json

# Playwright browser path
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-cache

# Create symlink for nuclei's headless mode
RUN CHROME_PATH=$(find /ms-playwright -name "chrome" -type f 2>/dev/null | head -1) && \
    if [ -n "$CHROME_PATH" ]; then \
        ln -sf "$CHROME_PATH" /usr/bin/chromium && \
        ln -sf "$CHROME_PATH" /usr/bin/google-chrome; \
    fi

# Copy scanner application files.
# Glob all top-level scanner modules instead of listing them individually: the
# explicit list silently drifted from the real module set (target_context.py is
# imported by grading/reporting but was never copied, so prebuilt images run
# without the dev source bind-mount crashed with ModuleNotFoundError). The glob
# keeps the image in sync with the package automatically.
# (.dockerignore strips __pycache__ / *.pyc so no build cruft is copied.)
COPY scanner/*.py /app/
COPY scanner/scanner_tools /app/scanner_tools
COPY scanner/wordlists /app/wordlists
COPY scanner/payloads /app/payloads
COPY scanner/data /app/data
ENV DEVICE_INTEL_DB_PATH=/app/data/device_advisories.json
ENV DEVICE_INTEL_DB_SHA256=3c9c66b400f2fe2d931066d9f92fd2cbb3de5030e50ec1570eef0fc018cdfb0a

# Copy API/worker files used by prebuilt images.
# Globbed (like the scanner modules above) so the image can't drift from the
# package as new api modules are imported. This COPY runs AFTER scanner/*.py,
# so for the gungnir_worker.py / __init__.py names that exist in both trees the
# api/ version wins — matching the dev bind-mount, where api/gungnir_worker.py
# is the one mounted at /app/gungnir_worker.py.
COPY api/*.py /app/
COPY api/ai_gate /app/ai_gate

# Ensure scanner files are readable
RUN chmod -R 755 /app/scanner_tools /app/wordlists /app/payloads

# The official Rust parser boundary is a release-image gate, not an optional
# test dependency or a monkeypatched unit-test seam.
RUN PYTHONPATH=/app/scanner_tools \
    /opt/model-intake-tools/safetensors/bin/python \
    /app/scanner_tools/model_intake_safetensors_selftest.py

# The adapter harness always drops tool subprocesses to this account, including
# during the image's functional self-test.
RUN useradd --uid 10001 --user-group --create-home scanner

# Fail image builds where the scanner/import graph is inconsistent.
RUN python3 /app/scanner.py --help >/dev/null && \
    python3 -c "from findings import apply_dast_precision_policy; from constants import resolve_scan_budget"

# Add tools to PATH
ENV PATH="/opt/tools:/usr/local/bin:${PATH}"

# Symlink sslyze
RUN SSLYZE_PATH=$(python3 -c "import shutil; print(shutil.which('sslyze') or '')") && \
    if [ -n "$SSLYZE_PATH" ]; then \
        ln -sf "$SSLYZE_PATH" /opt/tools/sslyze; \
    fi

# ============================================================
# TOOL VERIFICATION
# ============================================================
RUN set -e && \
    echo "========================================" && \
    echo "VERIFYING ALL TOOLS" && \
    echo "========================================" && \
    /opt/tools/httpx -version && \
    /opt/tools/katana -version && \
    /opt/tools/subfinder -version && \
    /opt/tools/naabu -version && \
    /opt/tools/nuclei -version && \
    /opt/tools/dalfox version && \
    /opt/tools/modelscan --version && \
    /opt/tools/fickling --version && \
    /opt/tools/semgrep --version && \
    /opt/tools/trivy --version && \
    /opt/tools/osv-scanner --version && \
    /opt/tools/pip-audit-offline --version && \
    /opt/tools/gungnir -h | head -1 && \
    python3 /app/scanner_tools/model_intake_adapter_self_test.py \
      --output /opt/model-intake-tools/self-test.json && \
    echo "ALL TOOLS VERIFIED OK"

# Create config directories
RUN mkdir -p /tmp/.config/subfinder && \
    touch /tmp/.config/subfinder/config.yaml && \
    mkdir -p /tmp/.config/nuclei && \
    cp /opt/nuclei-config/.templates-config.json /tmp/.config/nuclei/ && \
    chmod -R 777 /tmp/.config

ENV HOME=/tmp

# The API stages the Model Intake guest image through the Docker socket it
# already mounts for worker scaling, which needs a client. This is opt-in per
# service on purpose: scan workers and the no-egress Model Intake sandbox handle
# hostile artifacts and must not carry a Docker client, whether or not a socket
# happens to be present.
ARG INSTALL_DOCKER_CLI=0
ARG DOCKER_CLI_VERSION=27.5.1
# Digests observed from download.docker.com for this exact version. A pinned
# version over HTTPS is not enough on its own: without a digest the client that
# builds the measured guest image would itself be unverified.
ARG DOCKER_CLI_SHA256_X86_64=4f798b3ee1e0140eab5bf30b0edc4e84f4cdb53255a429dc3bbae9524845d640
ARG DOCKER_CLI_SHA256_AARCH64=e6b53725a73763ab3f988c73f8772eaed429754c1a579db5ff11f21990fd1817
RUN if [ "$INSTALL_DOCKER_CLI" = "1" ]; then \
        set -eux; \
        case "$(dpkg --print-architecture)" in \
            amd64) docker_arch=x86_64; expected="$DOCKER_CLI_SHA256_X86_64" ;; \
            arm64) docker_arch=aarch64; expected="$DOCKER_CLI_SHA256_AARCH64" ;; \
            *) echo "unsupported architecture for the Docker CLI" >&2; exit 1 ;; \
        esac; \
        curl -fsSLo /tmp/docker.tgz \
            "https://download.docker.com/linux/static/stable/${docker_arch}/docker-${DOCKER_CLI_VERSION}.tgz"; \
        echo "${expected}  /tmp/docker.tgz" | sha256sum -c -; \
        tar -xzf /tmp/docker.tgz -C /tmp docker/docker; \
        install -m 0755 /tmp/docker/docker /usr/local/bin/docker; \
        rm -rf /tmp/docker.tgz /tmp/docker; \
        docker --version; \
    fi

# Bake the human release/build identity into the image itself. Keep this late
# in the Dockerfile: a new source revision must not invalidate OS packages,
# Python dependencies, scanner tools, and vulnerability databases. Standalone
# Compose overrides this at runtime, while broker-fleet workers deliberately
# receive no operator-authored environment file; without the baked default a
# released remote worker stamped every scan as "dev".
ARG SCANNER_VERSION=dev
ARG SCANNER_SOURCE_REVISION=unknown
ENV SCANNER_VERSION=${SCANNER_VERSION}
ENV SHAKERSCAN_BUILD_VERSION=${SCANNER_VERSION}
ENV SHAKERSCAN_SOURCE_REVISION=${SCANNER_SOURCE_REVISION}
RUN mkdir -p /opt/shakerscan && \
    python3 -c 'import json, os, pathlib; p=pathlib.Path("/opt/shakerscan/release-manifest.json"); p.write_text(json.dumps({"schema_version":"shakerscan-release-identity/v1","version":os.environ["SHAKERSCAN_BUILD_VERSION"],"source_revision":os.environ["SHAKERSCAN_SOURCE_REVISION"]},sort_keys=True)+"\n")' && \
    chmod 0444 /opt/shakerscan/release-manifest.json

# Entry point
COPY scanner/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
