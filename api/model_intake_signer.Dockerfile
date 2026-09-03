FROM python:3.14-slim-bookworm@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH

RUN python -m venv /opt/venv
COPY api/model_intake_signer.requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

RUN groupadd --gid 65532 signer \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin signer

WORKDIR /app
COPY --chown=65532:65532 api/model_intake_control_plane.py api/model_intake_signer_service.py ./

USER 65532:65532
EXPOSE 8091
CMD ["uvicorn", "model_intake_signer_service:app", "--host", "0.0.0.0", "--port", "8091", "--no-access-log"]
