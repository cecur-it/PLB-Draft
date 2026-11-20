# Traces: PROMPT §2.5 (mTLS between tiers), CONTRACT §0 (PKI under /pki), §4.4 (GATEWAY_MTLS=required|optional|off).
"""TLS contexts: the listening socket (optional mTLS) and the outbound client (errow-mcp mTLS, optional https Fluent Bit)."""
from __future__ import annotations

import ssl

from config import Config


def server_ssl_context(cfg: Config) -> ssl.SSLContext | None:
    if not cfg.tls:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cfg.tls_cert), str(cfg.tls_key))
    if cfg.mtls == "off":
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.load_verify_locations(cafile=str(cfg.tls_ca))
        ctx.verify_mode = ssl.CERT_REQUIRED if cfg.mtls == "required" else ssl.CERT_OPTIONAL
    return ctx


def client_ssl_context(cfg: Config, *, client_cert: bool = True) -> ssl.SSLContext:
    """Verifies the peer against the stack CA (hostname checked) and presents the gateway's own certificate."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(cfg.tls_ca))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if client_cert:
        ctx.load_cert_chain(str(cfg.tls_cert), str(cfg.tls_key))
    return ctx
