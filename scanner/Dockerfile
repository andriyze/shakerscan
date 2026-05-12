# ShakerScan - Open Source Edition
# Multi-stage build for comprehensive security scanning

# --- Stage 1: Build Go tools ---
# Pin Go to a stable major/minor while meeting current ProjectDiscovery tool requirements.
FROM golang:1.25 AS go-builder

# Install ProjectDiscovery tools + Gungnir (CT log scanner)
RUN go install github.com/projectdiscovery/tlsx/cmd/tlsx@v1.2.2 \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0 \
 && go install github.com/projectdiscovery/katana/cmd/katana@v1.5.0 \
 && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.13.0 \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.8.0 \
 && go install github.com/hahwul/dalfox/v2@v2.12.0 \
 && go install github.com/ffuf/ffuf/v2@v2.1.0 \
 && go install github.com/tomnomnom/meg@v0.3.0 \
 && go install github.com/g0ldencybersec/gungnir/cmd/gungnir@v1.4.0

# --- Stage 2: Runtime with Playwright (Chromium) ---
FROM mcr.microsoft.com/playwright/python:v1.59.0-noble

# System deps for network tooling and additional scanners
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl nmap openssl bind9-dnsutils jq git bash make gcc \
    iputils-ping dnsutils procps coreutils \
    nikto masscan python3-pip \
    whois netcat-openbsd traceroute \
    dirb gobuster hydra medusa \
    dnsrecon \
    libcurl4-openssl-dev libssl-dev python3-dev \
    bsdmainutils \
 && rm -rf /var/lib/apt/lists/*

# Install Python-based security tools
RUN pip3 install --no-cache-dir --break-system-packages \
    sqlmap==1.10.5 \
    sslyze==6.3.1 commix==0.1 XSStrike==3.2.2 \
    certifi cryptography \
    dnspython pyOpenSSL \
    python-whois shodan \
    paramiko

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

RUN set -e && \
    mkdir -p /opt/nuclei-templates /opt/nuclei-config && \
    /opt/tools/nuclei -update-templates -ud /opt/nuclei-templates 2>&1 && \
    TEMPLATE_COUNT=$(find /opt/nuclei-templates -name "*.yaml" -type f 2>/dev/null | wc -l) && \
    echo "Templates found: $TEMPLATE_COUNT" && \
    echo '{"nuclei-templates-directory":"/opt/nuclei-templates"}' > /opt/nuclei-config/.templates-config.json && \
    if [ -f /opt/nuclei-templates/.nuclei-ignore ]; then \
        cp /opt/nuclei-templates/.nuclei-ignore /opt/nuclei-config/.nuclei-ignore; \
    fi && \
    chmod -R 755 /opt/nuclei-config /opt/nuclei-templates

# Download wordlists for deep discovery
RUN mkdir -p /usr/share/wordlists && \
    cd /usr/share/wordlists && \
    curl -L "https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/common.txt" -o common.txt && \
    curl -L "https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/directory-list-2.3-small.txt" -o directory-list-small.txt

# Download Retire.js vulnerability database
RUN mkdir -p /app/data && \
    curl -L "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json" \
    -o /app/data/jsrepository.json

# Install testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
ENV TESTSSL_BIN=/opt/testssl.sh/testssl.sh

# App directory
WORKDIR /app

# Python deps for scanner
COPY scanner/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --break-system-packages -r /app/requirements.txt

# Playwright browser path
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# Create symlink for nuclei's headless mode
RUN CHROME_PATH=$(find /ms-playwright -name "chrome" -type f 2>/dev/null | head -1) && \
    if [ -n "$CHROME_PATH" ]; then \
        ln -sf "$CHROME_PATH" /usr/bin/chromium && \
        ln -sf "$CHROME_PATH" /usr/bin/google-chrome; \
    fi

# Copy scanner application files
COPY scanner/scanner.py /app/scanner.py
COPY scanner/constants.py /app/constants.py
COPY scanner/grading.py /app/grading.py
COPY scanner/findings.py /app/findings.py
COPY scanner/signals.py /app/signals.py
COPY scanner/reporting.py /app/reporting.py
COPY scanner/gungnir_worker.py /app/gungnir_worker.py
COPY scanner/scanner_tools /app/scanner_tools
COPY scanner/wordlists /app/wordlists

# Copy API/worker files used by prebuilt images.
COPY api/api.py /app/api.py
COPY api/worker.py /app/worker.py
COPY api/gungnir_worker.py /app/gungnir_worker.py
COPY api/session_manager.py /app/session_manager.py
COPY api/retest_contract.py /app/retest_contract.py
COPY api/ai_verifier.py /app/ai_verifier.py
COPY api/ai_control_requirements.py /app/ai_control_requirements.py
COPY api/ai_demo_scenarios.py /app/ai_demo_scenarios.py
COPY api/ai_redteam_artifacts.py /app/ai_redteam_artifacts.py
COPY api/ai_gate_scan.py /app/ai_gate_scan.py
COPY api/ai_gate /app/ai_gate

# Ensure scanner files are readable
RUN chmod -R 755 /app/scanner_tools /app/wordlists

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
    /opt/tools/gungnir -h | head -1 && \
    echo "ALL TOOLS VERIFIED OK"

# Create config directories
RUN mkdir -p /tmp/.config/subfinder && \
    touch /tmp/.config/subfinder/config.yaml && \
    mkdir -p /tmp/.config/nuclei && \
    cp /opt/nuclei-config/.templates-config.json /tmp/.config/nuclei/ && \
    chmod -R 777 /tmp/.config

# Non-root user for security
RUN useradd -m scanner
ENV HOME=/tmp

# Entry point
COPY scanner/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
