#!/usr/bin/env python3
"""stack-config.py - read the stack's Errow YAML configuration for errow-entrypoint.

Traces: CONTRACT §4.4 (gateway-only LLM, model allow-list), §8 (Errow addenda), §11 (RUNTIME.md);
config/errow-config.yaml and config/llm-providers.yaml in this directory tree.

  stack-config.py env       --file errow-config.yaml  --profile PROFILE
        prints NAME=VALUE lines (one per setting) from `env:` overlaid by `profiles.<PROFILE>.env:`.
        Only an explicit allow-list of names is accepted; secrets can never be configured here (use *_FILE secrets).
  stack-config.py check-llm --file llm-providers.yaml --profile PROFILE --model MODEL
        exit 0 when MODEL is an approved model of an enabled gateway provider of PROFILE; exit 1 with the reason otherwise.
        Also exits 1 when a non-cloud profile enables a direct cloud provider (a broken policy file fails closed).

Exit codes: 0 ok, 1 invalid / violation, 2 usage, 3 file unreadable. PyYAML comes from Errow's own dependency set (pyyaml>=6).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only on an interpreter without PyYAML
    print("stack-config.py: PyYAML is required (it ships in Errow's virtualenv)", file=sys.stderr)
    raise SystemExit(3)

PROFILES = ("cloud", "onprem", "airgap", "edge")

ALLOWED_ENV = re.compile(
    r"^(ERROW_(SCAN_MODE|FAIL_ON|INSTRUCTION_FILE|MODE|SANDBOX_IMAGE|SANDBOX_IMAGE_TAR|TELEMETRY|CLOUD_ENABLED|CLOUD_URL"
    r"|ALLOWED_TARGETS|WORKDIR|LOG_DIR|DIND_TIMEOUT|TENANT_ID|VIEWER_(HOST|PORT|FOLLOW|POLL|MIN_RESTART))"
    r"|OLLAMA_(PRIMARY|FALLBACK|SECURITY)_MODEL"
    r"|ERROW_MODEL_DEGRADED"
    r"|LLM_(TIMEOUT|PREFLIGHT_TIMEOUT|STREAM_[A-Z_]+)"
    r"|errow_(REASONING_EFFORT|MAX_CONTEXT_IMAGES|TOOL_OUTPUT_MAX_[A-Z]+|CONTEXT_[A-Z_]+|PROMPT_CACHE|CACHE_BLOCK_TOKENS"
    r"|FORCE_REQUIRED_TOOL_CHOICE|API_TYPE))$"
)


class ConfigError(Exception):
    pass


def load(path: str) -> dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"stack-config.py: cannot read {path}: {exc.strerror}", file=sys.stderr)
        raise SystemExit(3) from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ConfigError(f"{path}: expected a mapping with `version: 1`")
    return data


def scalar(name: str, value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        text = str(value)
        if "\n" in text or "\r" in text or "\x00" in text:
            raise ConfigError(f"{name}: value must be a single line")
        return text
    raise ConfigError(f"{name}: value must be a string, number or boolean")


def env_section(data: dict[str, Any], where: str) -> dict[str, Any]:
    section = data.get("env", {})
    if section is None:
        return {}
    if not isinstance(section, dict):
        raise ConfigError(f"{where}: env must be a mapping")
    return section


def resolve_env(data: dict[str, Any], profile: str) -> dict[str, str]:
    merged: dict[str, Any] = dict(env_section(data, "env"))
    profiles = data.get("profiles", {}) or {}
    if not isinstance(profiles, dict):
        raise ConfigError("profiles must be a mapping")
    unknown = sorted(set(profiles) - set(PROFILES))
    if unknown:
        raise ConfigError(f"unknown profile(s): {', '.join(map(str, unknown))}")
    overlay = profiles.get(profile) or {}
    if not isinstance(overlay, dict):
        raise ConfigError(f"profiles.{profile} must be a mapping")
    merged.update(env_section(overlay, f"profiles.{profile}"))
    out: dict[str, str] = {}
    for name, value in merged.items():
        if not isinstance(name, str) or not ALLOWED_ENV.match(name):
            raise ConfigError(f"{name!r} is not a configurable setting (secrets and gateway wiring are never set here)")
        if value is None:
            continue
        out[name] = scalar(name, value)
    return out


def check_llm(data: dict[str, Any], profile: str, model: str) -> None:
    providers = data.get("providers")
    profiles = data.get("profiles")
    if not isinstance(providers, dict) or not isinstance(profiles, dict) or profile not in profiles:
        raise ConfigError(f"providers/profiles missing or profile {profile!r} undefined")
    enabled = (profiles[profile] or {}).get("providers") or []
    approved: set[str] = set()
    for name in enabled:
        provider = providers.get(name)
        if not isinstance(provider, dict):
            raise ConfigError(f"profile {profile!r} references unknown provider {name!r}")
        if provider.get("kind") == "cloud-direct":
            if profile != "cloud":
                raise ConfigError(f"profile {profile!r} enables cloud provider {name!r}: only profile 'cloud' may")
            continue
        for entry in provider.get("models") or []:
            approved.add(entry["id"] if isinstance(entry, dict) else str(entry))
    if model not in approved:
        raise ConfigError(f"model {model!r} is not approved for profile {profile!r} (approved: {', '.join(sorted(approved)) or 'none'})")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stack-config.py", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("env", "check-llm"):
        p = sub.add_parser(name)
        p.add_argument("--file", required=True)
        p.add_argument("--profile", required=True, choices=PROFILES)
        if name == "check-llm":
            p.add_argument("--model", required=True)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    try:
        data = load(args.file)
        if args.cmd == "env":
            for key, value in resolve_env(data, args.profile).items():
                print(f"{key}={value}")
        else:
            check_llm(data, args.profile, args.model)
    except ConfigError as exc:
        print(f"stack-config.py: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
