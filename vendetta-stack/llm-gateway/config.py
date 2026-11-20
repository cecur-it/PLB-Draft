# Traces: PROMPT §1 Tier 4 (sovereign LLM tier, fail-closed); CONTRACT §2 (env knobs, FailClosed), §4.4 (OLLAMA_BASE_URL loopback rule).
"""Environment parsing for the llm-gateway. FailClosedError aborts startup before any socket is opened."""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import urlsplit

VERSION_DEFAULT = "1.0.0"
PROFILES = ("cloud", "onprem", "airgap", "edge")
SOVEREIGN_PROFILES = ("onprem", "airgap")
CLOUD_KEY_ENVS = ("GEMINI_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "LLM_API_KEY")
ERROW_ROUTE = "cs3-errow-security"
_MODEL_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$")

# Task classes that own a routing chain. `triage`/`forensic` predate the security tier and keep their env names.
ROLES = ("triage", "forensic", "deep", "security", "errow")
ROLE_LABELS = {
    "triage": "SIEM/XDR triage classification",
    "forensic": "SOAR playbook generation / root-cause synthesis",
    "deep": "Deep reasoning / multimodal evidence analysis",
    "security": "Vulnerability analysis / secure code review",
    "errow": "Errow scan and agent reasoning",
}
# The security classes are tool-calling tiers whose budget belongs to the answer, not a reasoning trace; they never think.
# Everything else is switchable.
THINKING_DEFAULT = {"triage": False, "forensic": True, "deep": True, "security": False, "errow": False}
# Triage keeps a tight cap, but 512 truncates the agentic triage model mid-JSON and forces a schema fallback on most
# records, so the cap is 1024: still bounded, large enough for the answer to close.
MAX_TOKENS_DEFAULT = {"triage": 1024, "forensic": 4096, "deep": 4096, "security": 2048, "errow": 4096}
# Only high-volume, repetition-heavy classification is cached; security findings and Errow runs are target-specific.
CACHE_DEFAULT = {"triage": True, "forensic": False, "deep": False, "security": False, "errow": False}
# A security/Errow turn is one long agentic answer over a big tool+findings context: 60 s is a triage number and timed
# out on real scan loops, which silently pushed every such turn onto the fallback. The agentic roles get their own cap.
TIMEOUT_MS_DEFAULT = {"security": 120_000, "errow": 120_000, "deep": 120_000}

Resolver = Callable[[str], list[str]]


class ConfigError(Exception):
    """Invalid or inconsistent configuration (exit code 2)."""


class FailClosedError(ConfigError):
    """A sovereign profile (onprem/airgap) would reach a non-local model provider (exit code 3)."""


def _system_resolver(host: str) -> list[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})


def _is_loopback_addr(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return (mapped or ip).is_loopback


def host_is_loopback(host: str, resolver: Resolver = _system_resolver) -> bool:
    if _is_loopback_addr(host):
        return True
    if host.lower().rstrip(".") == "localhost":
        return True
    try:
        addrs = resolver(host)
    except OSError:
        return False
    return bool(addrs) and all(_is_loopback_addr(a) for a in addrs)


def _get_str(env: Mapping[str, str], name: str, default: str) -> str:
    value = env.get(name)
    return default if value is None or value.strip() == "" else value.strip()


def _get_int(env: Mapping[str, str], name: str, default: int, lo: int, hi: int) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}, got {value}")
    return value


def _get_float(env: Mapping[str, str], name: str, default: float, lo: float, hi: float) -> float:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}, got {value}")
    return value


def _get_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    lowered = raw.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be a boolean, got {raw!r}")


def _model(env: Mapping[str, str], names: tuple[str, ...], default: str) -> str:
    for name in names:
        value = env.get(name)
        if value and value.strip():
            tag = value.strip()
            if not _MODEL_TAG.match(tag):
                raise ConfigError(f"{name} is not a valid model tag: {tag!r}")
            return tag
    return default


def enforce_fail_closed(env: Mapping[str, str], resolver: Resolver = _system_resolver) -> None:
    """Raise FailClosedError when a sovereign profile is configured with any route to a hosted model."""
    profile = _get_str(env, "CS3_PROFILE", "onprem").lower()
    if profile not in SOVEREIGN_PROFILES:
        return
    leaked = [n for n in CLOUD_KEY_ENVS if (env.get(n) or "").strip() or (env.get(f"{n}_FILE") or "").strip()]
    if leaked:
        raise FailClosedError(
            f"FailClosedError: CS3_PROFILE={profile} forbids hosted-LLM credentials but {', '.join(leaked)} is set; "
            "unset it (sovereign profiles only talk to the local Ollama tier)"
        )
    mode = _get_str(env, "CS3_LLM_MODE", "local").lower()
    if mode != "local":
        raise FailClosedError(f"FailClosedError: CS3_PROFILE={profile} requires CS3_LLM_MODE=local, got {mode!r}")
    base = _get_str(env, "OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1")
    parts = urlsplit(base)
    host = parts.hostname or ""
    if parts.scheme not in ("http", "https") or not host:
        raise ConfigError(f"OLLAMA_BASE_URL is not a valid http(s) URL: {base!r}")
    if not host_is_loopback(host, resolver):
        raise FailClosedError(
            f"FailClosedError: CS3_PROFILE={profile} requires OLLAMA_BASE_URL to resolve to loopback "
            f"(the node-local ollama-lb), but host {host!r} is not loopback"
        )


@dataclass(frozen=True)
class Config:
    profile: str
    llm_mode: str
    ollama_base_url: str
    model_triage: str
    model_forensic: str
    model_deep: str
    model_security: str
    model_errow_security: str
    model_guard: str | None
    role_max_tokens: Mapping[str, int]
    role_thinking: Mapping[str, bool]
    role_cache: Mapping[str, bool]
    role_timeout_s: Mapping[str, float]
    cache_ttl_s: int
    cache_max_entries: int
    retry_attempts: int
    retry_backoff_s: float
    inference_timeout_s: float
    gpu_share: float
    message_max_chars: int
    max_concurrency: int
    max_queue: int
    max_body_bytes: int
    max_records: int
    request_timeout_s: float
    max_tokens: int
    host: str
    port: int
    tls: bool
    mtls: str
    tls_cert: Path
    tls_key: Path
    tls_ca: Path
    token_file: Path
    fluent_bit_url: str
    spool_dir: Path
    spool_max_events: int
    policy_path: Path
    targets_file: Path | None
    errow_mcp_url: str
    mcp_dns_timeout_s: float
    mcp_output_max_chars: int
    models_json_path: Path
    gpu_util_file: Path | None
    maintenance_file: Path
    log_level: str
    version: str
    env: Mapping[str, str] = field(default_factory=dict, repr=False, compare=False)

    @property
    def mcp_live(self) -> bool:
        return self.env.get("MCP_LIVE") == "true"

    @property
    def ollama_root_url(self) -> str:
        base = self.ollama_base_url.rstrip("/")
        return base[:-3] if base.endswith("/v1") else base

    def timeout_s_for(self, role: str) -> float:
        """Per-attempt timeout: the agentic roles get their own cap, everything else the global one."""
        return self.role_timeout_s.get(role, self.inference_timeout_s)

    def chain_for(self, role: str) -> tuple[str, ...]:
        """Ordered model chain for a task class: cheapest adequate model first, declared fallbacks after it."""
        chains = {
            "triage": (self.model_triage, self.model_forensic),
            "forensic": (self.model_forensic, self.model_triage),
            "deep": (self.model_deep, self.model_forensic, self.model_triage),
            "security": (self.model_security, self.model_deep),
            "errow": (self.model_errow_security, self.model_deep),
        }
        chain: list[str] = []
        for model in chains[role]:
            if model not in chain:
                chain.append(model)
        return tuple(chain)

    def max_tokens_for(self, role: str) -> int:
        return self.role_max_tokens[role]

    def thinking_for(self, role: str, model: str) -> bool:
        """The security classes never think; the other models only when the task class asks for depth."""
        if model in (self.model_security, self.model_errow_security):
            return False
        return self.role_thinking[role]

    def caches(self, role: str) -> bool:
        return self.role_cache[role]

    @classmethod
    def from_env(cls, env: Mapping[str, str], resolver: Resolver = _system_resolver) -> "Config":
        profile = _get_str(env, "CS3_PROFILE", "onprem").lower()
        if profile not in PROFILES:
            raise ConfigError(f"CS3_PROFILE must be one of {', '.join(PROFILES)}, got {profile!r}")
        enforce_fail_closed(env, resolver)

        base = _get_str(env, "OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1").rstrip("/")
        parts = urlsplit(base)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise ConfigError(f"OLLAMA_BASE_URL is not a valid credential-free http(s) URL: {base!r}")

        tls = _get_bool(env, "GATEWAY_TLS", True)
        mtls = _get_str(env, "GATEWAY_MTLS", "optional").lower()
        if mtls not in ("required", "optional", "off"):
            raise ConfigError(f"GATEWAY_MTLS must be required|optional|off, got {mtls!r}")
        if not tls and profile in SOVEREIGN_PROFILES:
            raise ConfigError(f"GATEWAY_TLS=off is not permitted when CS3_PROFILE={profile}")
        if not tls and mtls == "required":
            raise ConfigError("GATEWAY_MTLS=required needs GATEWAY_TLS=on")

        pki = Path(_get_str(env, "PKI_DIR", "/pki"))
        mcp_url = _get_str(env, "ERROW_MCP_URL", "https://errow-mcp:9103/mcp")
        mcp_parts = urlsplit(mcp_url)
        if mcp_parts.scheme != "https" or not mcp_parts.hostname:
            raise ConfigError(f"ERROW_MCP_URL must be an https URL, got {mcp_url!r}")
        fb_url = _get_str(env, "FLUENT_BIT_HTTP_URL", "http://fluent-bit:9880").rstrip("/")
        fb_parts = urlsplit(fb_url)
        if fb_parts.scheme not in ("http", "https") or not fb_parts.hostname:
            raise ConfigError(f"FLUENT_BIT_HTTP_URL must be an http(s) URL, got {fb_url!r}")

        max_chars = _get_int(env, "CS3_MESSAGE_MAX_CHARS", 8000, 256, 200_000)
        timeout_ms = _get_int(env, "INFERENCE_TIMEOUT_MS", 60000, 100, 3_600_000)
        guard = (env.get("INFERENCE_MODEL_GUARD") or "").strip() or None
        if guard and not _MODEL_TAG.match(guard):
            raise ConfigError(f"INFERENCE_MODEL_GUARD is not a valid model tag: {guard!r}")
        model_security = _model(env, ("CS3_MODEL_SECURITY", "INFERENCE_MODEL_SECURITY", "OLLAMA_SECURITY_MODEL"), "nemotron-3-nano:30b")
        model_errow = _model(env, ("CS3_MODEL_ERROW_SECURITY", "INFERENCE_MODEL_ERROW_SECURITY", "OLLAMA_ERROW_SECURITY_MODEL"), model_security)
        # CS3_MODEL_ERROW_SECURITY names the ROUTE (cs3-errow-security); the tier still has to dial a real tag.
        if model_errow == ERROW_ROUTE:
            model_errow = model_security
        if guard and guard in (model_security, model_errow):
            raise ConfigError(f"INFERENCE_MODEL_GUARD must differ from the security models ({model_security})")
        targets = (env.get("MCP_TARGETS_FILE") or "").strip()
        gpu_util = (env.get("OLLAMA_GPU_UTIL_FILE") or "").strip()

        return cls(
            profile=profile,
            llm_mode=_get_str(env, "CS3_LLM_MODE", "local").lower(),
            ollama_base_url=base,
            model_triage=_model(env, ("CS3_MODEL_TRIAGE", "INFERENCE_MODEL_TRIAGE", "OLLAMA_PRIMARY_MODEL"), "nemotron-3-nano:30b"),
            model_forensic=_model(env, ("CS3_MODEL_REASONING", "INFERENCE_MODEL_FORENSIC", "OLLAMA_FALLBACK_MODEL"), "gemma4:26b"),
            model_deep=_model(env, ("CS3_MODEL_REASONING_DEEP", "INFERENCE_MODEL_REASONING_DEEP", "OLLAMA_REASONING_DEEP_MODEL"), "gemma4:31b"),
            model_security=model_security,
            model_errow_security=model_errow,
            model_guard=guard,
            role_max_tokens={role: _get_int(env, f"INFERENCE_MAX_TOKENS_{role.upper()}", MAX_TOKENS_DEFAULT[role], 64, 32_768) for role in ROLES},
            role_thinking={role: _get_bool(env, f"INFERENCE_THINKING_{role.upper()}", THINKING_DEFAULT[role]) for role in ROLES},
            role_cache={role: _get_bool(env, f"GATEWAY_CACHE_{role.upper()}", CACHE_DEFAULT[role]) for role in ROLES},
            role_timeout_s={
                role: _get_int(env, f"INFERENCE_TIMEOUT_MS_{role.upper()}", TIMEOUT_MS_DEFAULT.get(role, timeout_ms), 100, 3_600_000) / 1000.0
                for role in ROLES
            },
            cache_ttl_s=_get_int(env, "GATEWAY_CACHE_TTL_S", 3600, 1, 86_400),
            cache_max_entries=_get_int(env, "GATEWAY_CACHE_MAX_ENTRIES", 512, 0, 100_000),
            retry_attempts=_get_int(env, "GATEWAY_MODEL_ATTEMPTS", 2, 1, 5),
            retry_backoff_s=_get_float(env, "GATEWAY_RETRY_BACKOFF_S", 0.25, 0.0, 10.0),
            inference_timeout_s=timeout_ms / 1000.0,
            gpu_share=_get_float(env, "INFERENCE_GPU_SHARE", 1.0, 0.001, 1.0),
            message_max_chars=max_chars,
            max_concurrency=_get_int(env, "GATEWAY_MAX_CONCURRENCY", 4, 1, 256),
            max_queue=_get_int(env, "GATEWAY_MAX_QUEUE", 512, 1, 100_000),
            max_body_bytes=_get_int(env, "GATEWAY_MAX_BODY_BYTES", 1_048_576, 1024, 64 * 1024 * 1024),
            max_records=_get_int(env, "GATEWAY_MAX_RECORDS", 100, 1, 10_000),
            request_timeout_s=_get_float(env, "GATEWAY_REQUEST_TIMEOUT_S", 300.0, 1.0, 3600.0),
            max_tokens=_get_int(env, "GATEWAY_MAX_TOKENS", 1500, 64, 32_768),
            host=_get_str(env, "GATEWAY_HOST", "0.0.0.0"),
            port=_get_int(env, "GATEWAY_PORT", 9101, 1, 65535),
            tls=tls,
            mtls=mtls,
            tls_cert=Path(_get_str(env, "GATEWAY_TLS_CERT", str(pki / "llm-gateway.crt"))),
            tls_key=Path(_get_str(env, "GATEWAY_TLS_KEY", str(pki / "llm-gateway.key"))),
            tls_ca=Path(_get_str(env, "GATEWAY_TLS_CA", str(pki / "ca.crt"))),
            token_file=Path(_get_str(env, "LLM_GATEWAY_TOKEN_FILE", "/run/secrets/llm_gateway_token")),
            fluent_bit_url=fb_url,
            spool_dir=Path(_get_str(env, "GATEWAY_SPOOL_DIR", "/var/lib/llm-gateway/spool")),
            spool_max_events=_get_int(env, "GATEWAY_SPOOL_MAX_EVENTS", 100_000, 10, 10_000_000),
            policy_path=Path(_get_str(env, "MCP_POLICY_PATH", str(Path(__file__).resolve().parent / "mcp_policy.yaml"))),
            targets_file=Path(targets) if targets else None,
            errow_mcp_url=mcp_url,
            mcp_dns_timeout_s=_get_float(env, "MCP_DNS_TIMEOUT_S", 2.0, 0.1, 30.0),
            mcp_output_max_chars=_get_int(env, "MCP_OUTPUT_MAX_CHARS", max_chars, 256, 200_000),
            models_json_path=Path(_get_str(env, "MODELS_JSON_PATH", "/etc/llm-gateway/models.json")),
            gpu_util_file=Path(gpu_util) if gpu_util else None,
            maintenance_file=Path(_get_str(env, "GATEWAY_MAINTENANCE_FILE", "/var/lib/llm-gateway/maintenance")),
            log_level=_get_str(env, "LOG_LEVEL", "INFO").upper(),
            version=_get_str(env, "STACK_VERSION", VERSION_DEFAULT),
            env=dict(env),
        )
