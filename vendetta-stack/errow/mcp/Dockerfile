# syntax=docker/dockerfile:1.7
# Traces: PROMPT §2.3 (Errow offensive tooling over MCP); CONTRACT §2 (errow-mcp :9103 mTLS), §4.5 (MCP policy), §11 (RUNTIME.md), §12 (hygiene).
# Build context: errow/mcp/   (docker build -f errow/mcp/Dockerfile errow/mcp)
# The bridge talks to the Docker API (errow-dind) only; it needs no Docker CLI and never touches the host socket.
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

LABEL org.opencontainers.image.title="errow-mcp" \
      org.opencontainers.image.description="Policy-gated MCP bridge exposing Errow offensive tooling to the LLM gateway" \
      vendetta.component="errow-mcp"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MCP_POLICY_FILE=/app/policy.yaml \
    MCP_PKI_DIR=/pki \
    MCP_EVENTS_FILE=/var/log/errow/mcp_events.ndjson \
    MCP_LIVE=false

RUN groupadd --gid 10001 errow-mcp \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin errow-mcp \
 && install -d -o 10001 -g 10001 -m 0755 /var/log/errow

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY sanitize.py policy.py executor.py events.py server.py /app/
COPY policy.yaml /app/policy.yaml

USER 10001:10001
EXPOSE 9103

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "/app/server.py", "--healthcheck"]

ENTRYPOINT ["python", "/app/server.py"]
