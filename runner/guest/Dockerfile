FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH

RUN apt-get update \
    && apt-get install -y --no-install-recommends busybox-static iproute2 mount procps strace util-linux \
    && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
COPY runner/guest/requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

RUN groupadd --gid 65532 modelrunner \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin modelrunner \
    && mkdir -p /opt/shakerscan /input /output
COPY runner/guest/guest-init runner/guest/guest_worker.py /opt/shakerscan/
RUN chmod 0755 /opt/shakerscan/guest-init /opt/shakerscan/guest_worker.py

ENTRYPOINT ["/opt/shakerscan/guest-init"]
