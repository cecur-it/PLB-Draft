# Traces: PROMPT §1 Tier 4 / §2.3 / §2.5 ; CONTRACT §4.4 (gateway service), §8.7 (pinned deps), §11 (RUNTIME.md), §12 (hygiene)
# Build context: llm-gateway/    Tag: vendetta-stack/llm-gateway:${STACK_VERSION:-1.0.0}
#   docker build -t vendetta-stack/llm-gateway:${STACK_VERSION:-1.0.0} llm-gateway/
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

ARG STACK_VERSION=1.0.0
LABEL org.opencontainers.image.title="vendetta-stack llm-gateway" \
      org.opencontainers.image.description="Guardrailed triage/forensic gateway for the sovereign Ollama tier, with MCP policy enforcement and a hash-chained audit trail" \
      org.opencontainers.image.version="${STACK_VERSION}" \
      org.opencontainers.image.vendor="Cecur / DaScient"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    STACK_VERSION=${STACK_VERSION}

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY *.py mcp_policy.yaml /app/
COPY schemas/ /app/schemas/
COPY tools/ /app/tools/

# The only writable path is the audit spool (mount a volume per replica); everything else stays read-only compatible.
RUN groupadd --system --gid 10001 llmgw \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin llmgw \
 && mkdir -p /var/lib/llm-gateway/spool /etc/llm-gateway /pki \
 && chown -R 10001:10001 /var/lib/llm-gateway \
 && chmod -R a-w /app

USER 10001:10001
EXPOSE 9101
VOLUME ["/var/lib/llm-gateway/spool"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "/app/server.py", "--healthcheck"]

ENTRYPOINT ["python", "/app/server.py"]
