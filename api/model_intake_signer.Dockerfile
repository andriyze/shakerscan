FROM python:3.15-slim-bookworm@sha256:96599df822d0e1c6bb700014a05c7f3c8cabc6e0f7ff3c4f9f69cee033b4b5d9

# Debian publishes security fixes faster than the pinned base image is rebuilt, and the image
# gate (Trivy, HIGH/CRITICAL with a fix available) fails on any OS package that lags behind.
# Apply the distribution's current fixes at build time so the base digest can stay pinned;
# 2026-09-13: libpcre2-8-0 10.42-1 -> 10.42-1+deb12u1 (CVE-2026-86145, CVE-2026-89161).
# 2026-10-28: libssl3 and openssl 3.0.22-1~deb12u1 -> 3.0.22-1~deb12u2 (CVE-2026-84782). They are
# named so a build cache that still holds an earlier upgrade of this step cannot keep the fix out.
# 2026-11-05: apt and libapt-pkg6.0 2.6.1 -> 2.6.2 (CVE-2026-109518), named for the same reason.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends --only-upgrade libssl3 openssl apt libapt-pkg6.0 \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH

RUN python -m venv /opt/venv
COPY api/model_intake_signer.requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

# pip is a build tool, not a signer runtime capability. Keeping it would also ship pip's vendor
# SBOM, which describes packages such as msgpack and setuptools that are not installed as runtime
# modules; image scanners then report those build-only components as deployed vulnerabilities.
# Remove it from the venv, the system interpreter, and the ensurepip bundle, and prove it is gone.
RUN /opt/venv/bin/python -m pip uninstall -y pip \
    && /usr/local/bin/python3 -m pip uninstall -y --break-system-packages pip \
    && rm -rf /usr/local/lib/python3.14/ensurepip/_bundled \
        /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.14 \
        /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.14 \
    && /usr/local/bin/python3 -c 'import importlib.util; assert importlib.util.find_spec("pip") is None' \
    && /opt/venv/bin/python -c 'import importlib.util; assert importlib.util.find_spec("pip") is None'

RUN groupadd --gid 65532 signer \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin signer

WORKDIR /app
COPY --chown=65532:65532 api/model_intake_control_plane.py api/model_intake_signer_service.py ./

USER 65532:65532
EXPOSE 8091
CMD ["uvicorn", "model_intake_signer_service:app", "--host", "0.0.0.0", "--port", "8091", "--no-access-log"]
