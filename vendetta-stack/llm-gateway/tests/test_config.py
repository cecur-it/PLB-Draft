# Traces: PROMPT §1 Tier 4 (sovereign LLM tier, fail-closed on on-prem/air-gap), §2.5 (no hosted-LLM credentials in sovereign profiles);
#         CONTRACT §2 (CS3_PROFILE, env knobs), §4.4 (OLLAMA_BASE_URL loopback rule, exit codes).
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Mapping

import pytest

from conftest import ROOT
from config import CLOUD_KEY_ENVS, Config, ConfigError, FailClosedError, enforce_fail_closed, host_is_loopback

SOVEREIGN = ["onprem", "airgap"]


def env(**values: str) -> dict[str, str]:
    return {"CS3_PROFILE": "onprem", **values}


def fake_dns(table: Mapping[str, list[str]]):
    def resolve(host: str) -> list[str]:
        if host not in table:
            raise OSError("unknown host")
        return list(table[host])

    return resolve


@pytest.mark.parametrize("profile", SOVEREIGN)
@pytest.mark.parametrize("key", CLOUD_KEY_ENVS)
def test_any_hosted_llm_key_aborts_sovereign_profiles(profile: str, key: str) -> None:
    with pytest.raises(FailClosedError, match=key):
        Config.from_env({"CS3_PROFILE": profile, key: "sk-not-a-real-key"})


@pytest.mark.parametrize("key", CLOUD_KEY_ENVS)
def test_key_file_variants_are_refused_too(key: str) -> None:
    with pytest.raises(FailClosedError, match=key):
        Config.from_env(env(**{f"{key}_FILE": "/run/secrets/key"}))


def test_the_error_names_every_offending_variable_but_never_prints_a_value() -> None:
    with pytest.raises(FailClosedError) as caught:
        Config.from_env(env(OPENAI_API_KEY="sk-super-secret-value", GEMINI_API_KEY="AIza-another-secret"))
    message = str(caught.value)
    assert "OPENAI_API_KEY" in message and "GEMINI_API_KEY" in message and "FailClosedError" in message
    assert "super-secret" not in message and "another-secret" not in message


def test_blank_key_values_do_not_trigger_the_guard() -> None:
    assert Config.from_env(env(OPENAI_API_KEY="", GEMINI_API_KEY="   ", GATEWAY_TLS="on")).profile == "onprem"


@pytest.mark.parametrize("profile", ["cloud", "edge"])
def test_non_sovereign_profiles_do_not_enforce(profile: str) -> None:
    cfg = Config.from_env({"CS3_PROFILE": profile, "OPENAI_API_KEY": "x", "OLLAMA_BASE_URL": "http://gpu-node.example:11434/v1"}, fake_dns({"gpu-node.example": ["10.0.0.5"]}))
    assert cfg.profile == profile and cfg.ollama_base_url == "http://gpu-node.example:11434/v1"


@pytest.mark.parametrize("profile", SOVEREIGN)
@pytest.mark.parametrize(
    "url",
    ["http://ollama.example.com:11434/v1", "http://10.1.2.3:11434/v1", "http://[2001:db8::1]:11434/v1", "http://0.0.0.0:11434/v1", "https://api.openai.com/v1"],
)
def test_non_loopback_ollama_base_url_aborts(profile: str, url: str) -> None:
    resolver = fake_dns({"ollama.example.com": ["203.0.113.7"], "api.openai.com": ["104.18.1.1"]})
    with pytest.raises(FailClosedError, match="not loopback"):
        Config.from_env({"CS3_PROFILE": profile, "OLLAMA_BASE_URL": url}, resolver)


def test_hostname_resolving_to_a_mix_of_loopback_and_remote_is_refused() -> None:
    resolver = fake_dns({"sneaky.example": ["127.0.0.1", "198.51.100.9"], "lb.local": ["127.0.0.1", "::1"]})
    with pytest.raises(FailClosedError):
        Config.from_env(env(OLLAMA_BASE_URL="http://sneaky.example:11434/v1"), resolver)
    assert Config.from_env(env(OLLAMA_BASE_URL="http://lb.local:11434/v1"), resolver).ollama_base_url == "http://lb.local:11434/v1"


def test_unresolvable_ollama_host_is_refused_not_assumed_local() -> None:
    with pytest.raises(FailClosedError):
        Config.from_env(env(OLLAMA_BASE_URL="http://ollama-lb:11434/v1"), fake_dns({}))


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434/v1", "http://localhost:11434/v1", "http://127.8.9.10:11434/v1", "http://[::1]:11434/v1", "http://LOCALHOST.:11434/v1"])
def test_loopback_ollama_base_url_passes(url: str) -> None:
    assert Config.from_env(env(OLLAMA_BASE_URL=url), fake_dns({})).ollama_base_url == url.rstrip("/")


def test_default_base_url_is_the_node_local_lb() -> None:
    cfg = Config.from_env(env())
    assert cfg.ollama_base_url == "http://127.0.0.1:11434/v1" and cfg.ollama_root_url == "http://127.0.0.1:11434"


def test_non_local_llm_mode_aborts_sovereign_profiles() -> None:
    with pytest.raises(FailClosedError, match="CS3_LLM_MODE"):
        Config.from_env(env(CS3_LLM_MODE="cloud"))
    assert Config.from_env(env(CS3_LLM_MODE="local")).llm_mode == "local"


def test_invalid_scheme_is_a_config_error_not_a_pass() -> None:
    with pytest.raises(ConfigError):
        enforce_fail_closed(env(OLLAMA_BASE_URL="file:///etc/passwd"))
    with pytest.raises(ConfigError):
        Config.from_env({"CS3_PROFILE": "edge", "OLLAMA_BASE_URL": "http://user:pw@127.0.0.1:11434/v1"})


def test_fail_closed_is_a_config_error_subclass() -> None:
    assert issubclass(FailClosedError, ConfigError)


def test_defaults_match_the_contract() -> None:
    cfg = Config.from_env(env())
    assert (cfg.port, cfg.tls, cfg.mtls, cfg.model_triage, cfg.model_forensic) == (9101, True, "optional", "nemotron-3-nano:30b", "gemma4:26b")
    assert (cfg.inference_timeout_s, cfg.gpu_share, cfg.message_max_chars, cfg.max_concurrency) == (60.0, 1.0, 8000, 4)
    assert cfg.timeout_s_for("triage") == cfg.inference_timeout_s == 60.0
    assert cfg.timeout_s_for("errow") == cfg.timeout_s_for("security") == cfg.timeout_s_for("deep") == 120.0
    assert str(cfg.token_file) == "/run/secrets/llm_gateway_token" and str(cfg.spool_dir) == "/var/lib/llm-gateway/spool"
    assert str(cfg.tls_cert) == "/pki/llm-gateway.crt" and str(cfg.tls_key) == "/pki/llm-gateway.key" and str(cfg.tls_ca) == "/pki/ca.crt"
    assert cfg.fluent_bit_url == "http://fluent-bit:9880" and cfg.errow_mcp_url == "https://errow-mcp:9103/mcp" and str(cfg.models_json_path) == "/etc/llm-gateway/models.json"
    assert cfg.mcp_live is False and cfg.version == "1.0.0" and cfg.policy_path == ROOT / "mcp_policy.yaml"


def test_environment_overrides_and_legacy_model_names() -> None:
    cfg = Config.from_env(env(INFERENCE_MODEL_TRIAGE="triage:1b", OLLAMA_FALLBACK_MODEL="forensic:2b", INFERENCE_TIMEOUT_MS="2500", INFERENCE_GPU_SHARE="0.25",
                              CS3_MESSAGE_MAX_CHARS="4000", GATEWAY_MAX_CONCURRENCY="2", GATEWAY_MTLS="required", MCP_LIVE="true", STACK_VERSION="1.2.3"))
    assert (cfg.model_triage, cfg.model_forensic, cfg.inference_timeout_s, cfg.gpu_share) == ("triage:1b", "forensic:2b", 2.5, 0.25)
    assert (cfg.message_max_chars, cfg.max_concurrency, cfg.mtls, cfg.mcp_live, cfg.version) == (4000, 2, "required", True, "1.2.3")
    assert cfg.timeout_s_for("errow") == cfg.timeout_s_for("security") == 120.0
    assert Config.from_env(env(INFERENCE_TIMEOUT_MS_ERROW="45000", INFERENCE_MODEL_GUARD="guard:1b")).timeout_s_for("errow") == 45.0
    assert Config.from_env(env(INFERENCE_MODEL_FORENSIC="new:3b", OLLAMA_FALLBACK_MODEL="old:2b")).model_forensic == "new:3b"


@pytest.mark.parametrize(
    "bad",
    [
        {"CS3_PROFILE": "production"},
        {"GATEWAY_MTLS": "maybe"},
        {"GATEWAY_TLS": "off"},
        {"GATEWAY_TLS": "perhaps"},
        {"INFERENCE_TIMEOUT_MS": "ten"},
        {"INFERENCE_TIMEOUT_MS": "5"},
        {"INFERENCE_GPU_SHARE": "0"},
        {"INFERENCE_GPU_SHARE": "2"},
        {"GATEWAY_MAX_CONCURRENCY": "0"},
        {"GATEWAY_PORT": "70000"},
        {"CS3_MESSAGE_MAX_CHARS": "10"},
        {"ERROW_MCP_URL": "http://errow-mcp:9103/mcp"},
        {"FLUENT_BIT_HTTP_URL": "tcp://fluent-bit:24224"},
        {"INFERENCE_MODEL_TRIAGE": "bad model; rm -rf /"},
        {"INFERENCE_MODEL_GUARD": "../../etc"},
    ],
)
def test_invalid_values_are_config_errors(bad: dict[str, str]) -> None:
    with pytest.raises(ConfigError) as caught:
        Config.from_env({"CS3_PROFILE": "onprem", **bad})
    assert not isinstance(caught.value, FailClosedError) or "CS3_PROFILE" not in bad


def test_tls_off_and_required_mtls_are_incompatible_even_on_edge() -> None:
    with pytest.raises(ConfigError):
        Config.from_env({"CS3_PROFILE": "edge", "GATEWAY_TLS": "off", "GATEWAY_MTLS": "required"})
    assert Config.from_env({"CS3_PROFILE": "edge", "GATEWAY_TLS": "off", "GATEWAY_MTLS": "off"}).tls is False


def test_host_is_loopback_helper() -> None:
    assert host_is_loopback("127.0.0.1") and host_is_loopback("::1") and host_is_loopback("::ffff:127.0.0.1") and host_is_loopback("localhost")
    assert not host_is_loopback("192.168.1.1") and not host_is_loopback("example.invalid", fake_dns({}))


def run_server(*args: str, **values: str) -> subprocess.CompletedProcess[str]:
    base = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "VIRTUAL_ENV")}
    return subprocess.run([sys.executable, "-B", str(ROOT / "server.py"), *args], capture_output=True, text=True, env={**base, **values}, timeout=60, check=False, cwd=ROOT)


@pytest.mark.parametrize("key", ["OPENAI_API_KEY", "GEMINI_API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY", "LLM_API_KEY"])
def test_process_exits_3_with_a_clear_message_on_fail_closed(key: str) -> None:
    result = run_server(CS3_PROFILE="onprem", **{key: "sk-test-value"})
    assert result.returncode == 3 and "FailClosedError" in result.stderr + result.stdout and key in result.stderr + result.stdout
    assert "sk-test-value" not in result.stderr + result.stdout


def test_process_exits_3_on_remote_ollama() -> None:
    result = run_server(CS3_PROFILE="airgap", OLLAMA_BASE_URL="http://10.9.8.7:11434/v1")
    assert result.returncode == 3 and "not loopback" in result.stderr + result.stdout


def test_process_exits_2_on_invalid_configuration() -> None:
    result = run_server(CS3_PROFILE="edge", GATEWAY_MTLS="sometimes")
    assert result.returncode == 2 and "GATEWAY_MTLS" in result.stderr + result.stdout


def test_cli_flags(tmp_path: Path) -> None:
    helped = run_server("--help")
    assert helped.returncode == 0 and "--selftest" in helped.stdout and "--healthcheck" in helped.stdout
    assert run_server("--version").returncode == 0
    selftest = run_server("--selftest", CS3_PROFILE="edge")
    assert selftest.returncode == 0, selftest.stdout + selftest.stderr
    unhealthy = run_server("--healthcheck", CS3_PROFILE="edge", GATEWAY_TLS="off", GATEWAY_PORT="1", GATEWAY_HOST="127.0.0.1")
    assert unhealthy.returncode == 1
