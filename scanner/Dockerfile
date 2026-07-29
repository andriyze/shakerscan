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
FROM golang:1.25@sha256:9006890ecba0a168034d99516084099ae3114d9f2b7d6572c77f2dde57ebc980 AS go-builder

# Install ProjectDiscovery tools + Gungnir (CT log scanner). Versions remain
# immutable, while bounded retries tolerate transient DNS/module-proxy outages.
# Cache mounts preserve completed downloads and compilations across retries and
# subsequent builds. Separate installs are required because Go expects packages
# in one `go install` invocation to share a module version.
ARG GO_INSTALL_ATTEMPTS=4
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    install_tools() { \
      go install github.com/projectdiscovery/tlsx/cmd/tlsx@v1.2.2 && \
      go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0 && \
      go install github.com/projectdiscovery/katana/cmd/katana@v1.5.0 && \
      go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.13.0 && \
      go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.8.0 && \
      go install github.com/hahwul/dalfox/v2@v2.12.0 && \
      go install github.com/ffuf/ffuf/v2@v2.1.0 && \
      go install github.com/tomnomnom/meg@v0.3.0 && \
      go install github.com/g0ldencybersec/gungnir/cmd/gungnir@v1.4.0; \
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
FROM mcr.microsoft.com/playwright/python:v1.59.0-noble@sha256:d8d9811a0e7cfac967f0c2f55d12b739087ae4b0808577b794c2a29ed5124938

# System deps for network tooling and additional scanners
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl nmap openssl bind9-dnsutils jq git bash make gcc \
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
RUN set -eu; \
    for tool in modelscan fickling semgrep; do \
      python3 -m venv "/opt/model-intake-tools/${tool}"; \
      "/opt/model-intake-tools/${tool}/bin/pip" install \
        --no-cache-dir --require-hashes -r "/opt/model-intake-locks/${tool}.lock"; \
      ln -s "/opt/model-intake-tools/${tool}/bin/${tool}" "/opt/tools/${tool}"; \
    done

# Trivy is a checksum-pinned native adapter. The vulnerability database is
# captured in the image and scanned offline; readiness exposes its metadata.
ARG TARGETARCH
ARG TRIVY_VERSION=0.72.0
ARG TRIVY_AMD64_SHA256=bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea
ARG TRIVY_ARM64_SHA256=2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) trivy_arch="64bit"; trivy_sha="${TRIVY_AMD64_SHA256}" ;; \
      arm64) trivy_arch="ARM64"; trivy_sha="${TRIVY_ARM64_SHA256}" ;; \
      *) echo "Unsupported Trivy architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    trivy_archive="trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz"; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${trivy_archive}" -o "/tmp/${trivy_archive}"; \
    echo "${trivy_sha}  /tmp/${trivy_archive}" | sha256sum -c -; \
    tar -xzf "/tmp/${trivy_archive}" -C /opt/tools trivy; \
    rm "/tmp/${trivy_archive}"; \
    chmod 755 /opt/tools/trivy; \
    mkdir -p /opt/trivy-cache; \
    /opt/tools/trivy image --download-db-only --cache-dir /opt/trivy-cache; \
    /opt/tools/trivy fs --scanners misconfig --format json \
      --cache-dir /opt/trivy-cache /opt/model-intake-locks >/dev/null

# Playwright browser path
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

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

# Copy API/worker files used by prebuilt images.
# Globbed (like the scanner modules above) so the image can't drift from the
# package as new api modules are imported. This COPY runs AFTER scanner/*.py,
# so for the gungnir_worker.py / __init__.py names that exist in both trees the
# api/ version wins — matching the dev bind-mount, where api/gungnir_worker.py
# is the one mounted at /app/gungnir_worker.py.
COPY api/*.py /app/
COPY api/ai_gate /app/ai_gate

# Ensure scanner files are readable
RUN chmod -R 755 /app/scanner_tools /app/wordlists

# The adapter harness always drops tool subprocesses to this account, including
# during the image's functional self-test.
RUN useradd -m scanner

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
    /opt/tools/nuclei -version && \
    /opt/tools/dalfox version && \
    /opt/tools/modelscan --version && \
    /opt/tools/fickling --version && \
    /opt/tools/semgrep --version && \
    /opt/tools/trivy --version && \
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

# Entry point
COPY scanner/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
