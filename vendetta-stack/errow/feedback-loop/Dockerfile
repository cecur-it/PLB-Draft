# syntax=docker/dockerfile:1.7
# errow-feedback: webhook (POST /errow-finding) + errow-to-vendetta.sh / vendetta-to-errow.sh.
# Traces: CONTRACT §1 (pinned python base), §2 (errow-feedback :9102), §6 (feedback loop), §11 (RUNTIME.md), §12.
# Build : docker build -t vendetta-stack/errow-feedback:${STACK_VERSION:-1.0.0} errow/feedback-loop
# (context = this directory; tests/ and scratch files are excluded by .dockerignore)
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

LABEL org.opencontainers.image.title="vendetta-stack/errow-feedback" \
      org.opencontainers.image.description="Errow <-> Vendetta feedback loop webhook and scripts (dry-run by default)" \
      org.opencontainers.image.source="vendetta-stack/errow/feedback-loop"

# bash + jq + curl run the scripts; util-linux provides flock(1) for the retest queue lock. Python is stdlib-only.
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash jq curl ca-certificates util-linux \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 feedback \
 && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin feedback \
 && install -d -o 10001 -g 10001 -m 0750 /var/log/feedback-loop

WORKDIR /opt/feedback-loop
COPY --chmod=0755 lib.sh errow-to-vendetta.sh vendetta-to-errow.sh approval.py schema-validate.py server.py action_gate.py ./
COPY --chmod=0644 normalize-finding.jq forensic.jq APPROVALS.md ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FEEDBACK_BIND=0.0.0.0 \
    FEEDBACK_PORT=9102 \
    FEEDBACK_DIR=/var/log/feedback-loop \
    FEEDBACK_WEBHOOK_TOKEN_FILE=/run/secrets/feedback_webhook_token \
    ERROW_FEEDBACK_LIVE=false \
    ERROW_FEEDBACK_FORENSIC=true \
    LLM_GATEWAY_URL=https://llm-gateway:9101 \
    LLM_GATEWAY_TOKEN_FILE=/run/secrets/llm_gateway_token \
    ERROW_FEEDBACK_APPROVALS_FILE=/opt/feedback-loop/APPROVALS.md \
    ERROW_FEEDBACK_APPROVAL_KEY_FILE=/run/secrets/feedback_approval_key \
    FL_CA_FILE=/pki/ca.crt

USER 10001:10001
EXPOSE 9102
VOLUME ["/var/log/feedback-loop"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python3", "/opt/feedback-loop/server.py", "--healthcheck"]

ENTRYPOINT ["python3", "/opt/feedback-loop/server.py"]
