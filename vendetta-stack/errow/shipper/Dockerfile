# syntax=docker/dockerfile:1.7
# Traces: PROMPT §2.3 (errow-shipper); CONTRACT §2 (paths), §8.4 (streams), §11 (RUNTIME.md), §12 (hygiene), §15 (record shapes).
# Build context: errow/shipper/   (docker build -f errow/shipper/Dockerfile errow/shipper)
# Runs with a read-only rootfs: the only writable paths are the two volumes below (NDJSON out, state).
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

LABEL org.opencontainers.image.title="errow-shipper" \
      org.opencontainers.image.description="Errow run artifacts to NDJSON streams for Fluent Bit" \
      vendetta.component="errow-shipper"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ERROW_RUNS_DIR=/workspace/errow_runs \
    SHIPPER_OUT_DIR=/var/log/errow \
    SHIPPER_STATE_DIR=/var/lib/errow-shipper \
    TZ=UTC

RUN groupadd --gid 10001 errow-shipper \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin errow-shipper \
 && install -d -o 10001 -g 10001 -m 0755 /var/log/errow /var/lib/errow-shipper \
 && install -d -o root -g root -m 0755 /workspace/errow_runs

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY sanitize.py store.py streams.py dockersrc.py shipper.py /app/

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "/app/shipper.py", "--healthcheck"]

ENTRYPOINT ["python", "/app/shipper.py"]
