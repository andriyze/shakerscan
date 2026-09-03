FROM python:3.14-slim-bookworm@sha256:416f0db2a2b561945630cef9877a7ea0581b27449eb9fd9df42f03e1b74b5b63

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
