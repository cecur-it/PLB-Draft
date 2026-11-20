#!/usr/bin/env python3
"""Unit tests for errow/stack-config.py and the shipped config/*.yaml (run: python3 -m unittest discover -s errow/tests)."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("stack_config", ROOT / "stack-config.py")
assert spec and spec.loader
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)

CONFIG = ROOT / "config" / "errow-config.yaml"
PROVIDERS = ROOT / "config" / "llm-providers.yaml"


class EnvResolution(unittest.TestCase):
    def test_overlay_and_scalar_rendering(self) -> None:
        data = {"version": 1, "env": {"ERROW_SCAN_MODE": "quick", "ERROW_TELEMETRY": False, "ERROW_VIEWER_PORT": 8765},
                "profiles": {"airgap": {"env": {"ERROW_SCAN_MODE": "deep"}}}}
        self.assertEqual(sc.resolve_env(data, "onprem"), {"ERROW_SCAN_MODE": "quick", "ERROW_TELEMETRY": "false", "ERROW_VIEWER_PORT": "8765"})
        self.assertEqual(sc.resolve_env(data, "airgap")["ERROW_SCAN_MODE"], "deep")

    def test_secrets_and_gateway_wiring_are_rejected(self) -> None:
        for name in ("LLM_API_KEY", "OPENAI_API_KEY", "LLM_API_BASE", "errow_LLM", "errow_APP_URL", "errow_IMAGE", "errow_TELEMETRY", "PATH"):
            with self.assertRaises(sc.ConfigError, msg=name):
                sc.resolve_env({"version": 1, "env": {name: "x"}}, "onprem")

    def test_multiline_and_structured_values_are_rejected(self) -> None:
        for value in ("a\nb", ["x"], {"k": "v"}):
            with self.assertRaises(sc.ConfigError):
                sc.resolve_env({"version": 1, "env": {"ERROW_SCAN_MODE": value}}, "onprem")

    def test_unknown_profile_is_rejected(self) -> None:
        with self.assertRaises(sc.ConfigError):
            sc.resolve_env({"version": 1, "profiles": {"moon": {}}}, "onprem")


class LlmPolicy(unittest.TestCase):
    def setUp(self) -> None:
        self.data = yaml.safe_load(PROVIDERS.read_text(encoding="utf-8"))

    def test_approved_models(self) -> None:
        for profile in sc.PROFILES:
            for model in ("nemotron-3-nano:30b", "gemma4:26b", "gemma4:31b", "cs3-errow-security"):
                sc.check_llm(self.data, profile, model)

    def test_eval_model_is_not_in_the_production_policy(self) -> None:
        for profile in sc.PROFILES:
            with self.assertRaises(sc.ConfigError, msg=profile):
                sc.check_llm(self.data, profile, "qwensploit-v2:9b")

    def test_unapproved_model(self) -> None:
        with self.assertRaises(sc.ConfigError):
            sc.check_llm(self.data, "onprem", "llama3:8b")

    def test_cloud_provider_outside_cloud_fails_closed(self) -> None:
        self.data["profiles"]["airgap"]["providers"].append("cloud-direct")
        with self.assertRaises(sc.ConfigError):
            sc.check_llm(self.data, "airgap", "nemotron-3-nano:30b")

    def test_only_the_cloud_profile_lists_the_direct_provider(self) -> None:
        listed = [name for name, p in self.data["profiles"].items() if "cloud-direct" in p["providers"]]
        self.assertEqual(listed, ["cloud"])

    def test_temperature_and_json_defaults(self) -> None:
        self.assertEqual(self.data["defaults"]["temperature"], 0.2)
        self.assertIs(self.data["defaults"]["strict_json"], True)
        self.assertIs(self.data["defaults"]["streaming"], False)

    def test_forbidden_env_matches_the_entrypoint(self) -> None:
        script = (ROOT / "entrypoint.sh").read_text(encoding="utf-8")
        block = re.search(r"CLOUD_KEY_VARS=\((.*?)\n\)", script, re.S)
        self.assertIsNotNone(block)
        self.assertEqual(set(block.group(1).split()), set(self.data["forbidden_env"]))


class ShippedConfig(unittest.TestCase):
    def test_errow_config_is_valid_for_every_profile(self) -> None:
        data = sc.load(str(CONFIG))
        for profile in sc.PROFILES:
            env = sc.resolve_env(data, profile)
            self.assertEqual(env["ERROW_TELEMETRY"], "false", profile)
            self.assertEqual(env["ERROW_CLOUD_ENABLED"], "false", profile)
            self.assertEqual(env["ERROW_VIEWER_PORT"], "8765", profile)

    def test_no_secret_material_in_either_file(self) -> None:
        pattern = re.compile(r"(sk-[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{20,}|-----BEGIN|password\s*:\s*\S+|YOUR_API_KEY|TODO|CHANGEME)")
        for path in (CONFIG, PROVIDERS):
            self.assertIsNone(pattern.search(path.read_text(encoding="utf-8")), path.name)


class Cli(unittest.TestCase):
    def test_exit_codes(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(sc.main(["env", "--file", str(CONFIG), "--profile", "onprem"]), 0)
            self.assertEqual(sc.main(["check-llm", "--file", str(PROVIDERS), "--profile", "onprem", "--model", "x:1b"]), 1)
            self.assertEqual(sc.main(["env", "--profile", "onprem"]), 2)
            self.assertEqual(sc.main(["env", "--file", str(CONFIG), "--profile", "moon"]), 2)
            with self.assertRaises(SystemExit) as ctx:
                sc.main(["env", "--file", str(CONFIG.with_name("absent.yaml")), "--profile", "onprem"])
            self.assertEqual(ctx.exception.code, 3)


if __name__ == "__main__":
    unittest.main()
