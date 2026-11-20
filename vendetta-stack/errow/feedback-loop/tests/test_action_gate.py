#!/usr/bin/env python3
"""Unit tests for action_gate.py: the single approval gate in front of the manager active-response API.

Traces: CONTRACT §6 (G9 offensive safety), `APPROVALS.md`. Run: python3 -m unittest discover -s tests -p 'test_action_gate.py'
or `python3 tests/test_action_gate.py`. Stdlib only, no docker, no manager: the manager is a counting stub.

The invariant under test is that ONLY an explicit live wish, an allow-listed agent and an unexpired signed approval can
produce a manager call; every other path is a refusal with zero calls (fail closed).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOOP = HERE.parent
sys.path.insert(0, str(LOOP))

import action_gate  # noqa: E402
import approval  # noqa: E402

FINGERPRINT = "a" * 64
KEY = "k" * 40


class Manager:
    """Counting manager stub: /security/user/authenticate + /active-response."""

    def __init__(self, response_code: int = 200) -> None:
        self.response_code = response_code
        self.calls: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args) -> None:
                return

            def _reply(self, code: int, body: bytes, ctype: str = "application/json") -> None:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802
                if self.path.startswith("/security/user/authenticate"):
                    self._reply(200, b"stub-jwt", "text/plain")
                else:
                    self._reply(404, b"{}")

            def do_PUT(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                outer.calls.append({"path": self.path, "body": json.loads(self.rfile.read(length) or b"{}"),
                                    "auth": self.headers.get("Authorization", "")})
                self._reply(outer.response_code, b'{"error":0}')

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class GateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.ledger = root / "APPROVALS.md"
        self.ledger.write_text("# test ledger\n", encoding="utf-8")
        self.key_file = root / "approval_key"
        self.key_file.write_text(KEY, encoding="utf-8")
        self.manager = Manager()
        self.lines: list[str] = []
        self.decisions: list[str] = []
        self.env = {
            "ERROW_FEEDBACK_LIVE": "true",
            "ERROW_FEEDBACK_APPROVALS_FILE": str(self.ledger),
            "ERROW_FEEDBACK_APPROVAL_KEY_FILE": str(self.key_file),
            "ERROW_FEEDBACK_APPROVAL_KEYS_DIR": str(Path(self.tmp.name) / "keys"),
            "ERROW_FEEDBACK_APPROVAL_THRESHOLD": "1",
            "ERROW_FEEDBACK_APPROVERS": "",
            "VENDETTA_EXECD_AGENT_REGEX": "^00[1-9]$",
            "ERROW_FEEDBACK_AR_COMMAND": "!host-isolate.sh",
            "VENDETTA_API_URL": self.manager.url,
            "VENDETTA_API_USER": "wazuh-wui",
            "VENDETTA_API_PASSWORD_FILE": str(root / "manager_password"),
            "VENDETTA_API_CA_FILE": str(root / "missing-ca.pem"),
            "VENDETTA_API_TIMEOUT": "5",
        }
        (root / "manager_password").write_text("secret", encoding="utf-8")
        self._saved = {name: os.environ.get(name) for name in self.env}
        os.environ.update(self.env)
        self.gate = action_gate.Gate(log=self.lines.append, metrics=self.decisions.append)

    def tearDown(self) -> None:
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self.manager.stop()
        self.tmp.cleanup()

    def approve(self, fingerprint: str = FINGERPRINT, ttl_hours: int = 1, approver: str = "alice", expires: str = "") -> None:
        argv = [sys.executable, str(LOOP / "approval.py"), "sign", "--fingerprint", fingerprint, "--approver", approver,
                "--key-file", str(self.key_file)]
        argv += ["--expires", expires] if expires else ["--ttl-hours", str(ttl_hours)]
        line = subprocess.run(argv, capture_output=True, text=True, check=True).stdout.strip()
        with open(self.ledger, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def payload(self, **overrides) -> dict:
        body = {"fingerprint": FINGERPRINT, "agent_id": "001", "command": "!host-isolate.sh", "run": "run-1"}
        body.update(overrides)
        return body

    # ------------------------------------------------------------------ allow
    def test_signed_approval_calls_the_manager_once(self) -> None:
        self.approve()
        code, body = self.gate.handle(self.payload())
        self.assertEqual(code, 200)
        self.assertEqual(body["decision"], "live")
        self.assertEqual(len(self.manager.calls), 1)
        call = self.manager.calls[0]
        self.assertEqual(call["path"], "/active-response?agents_list=001")
        self.assertEqual(call["auth"], "Bearer stub-jwt")
        self.assertEqual(call["body"]["command"], "!host-isolate.sh")
        self.assertEqual(call["body"]["alert"]["data"]["errow_fingerprint"], FINGERPRINT)
        self.assertEqual(call["body"]["alert"]["data"]["errow_run"], "run-1")
        self.assertIn("LIVE", " ".join(self.lines))

    # ------------------------------------------------------------------ refusals
    def test_missing_approval_denies_with_zero_calls(self) -> None:
        code, body = self.gate.handle(self.payload())
        self.assertEqual(code, 403)
        self.assertEqual(body["decision"], "denied")
        self.assertEqual(self.manager.calls, [])
        self.assertIn("denied", self.decisions)

    def test_approval_for_another_fingerprint_does_not_authorise(self) -> None:
        self.approve(fingerprint="b" * 64)
        self.assertEqual(self.gate.handle(self.payload())[0], 403)
        self.assertEqual(self.manager.calls, [])

    def test_expired_approval_denies(self) -> None:
        self.approve(expires=(datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.assertEqual(self.gate.handle(self.payload())[0], 403)
        self.assertEqual(self.manager.calls, [])

    def test_agent_outside_the_allow_list_denies(self) -> None:
        self.approve()
        self.assertEqual(self.gate.handle(self.payload(agent_id="042"))[0], 403)
        self.assertEqual(self.manager.calls, [])

    def test_manager_agent_000_is_always_refused(self) -> None:
        os.environ["VENDETTA_EXECD_AGENT_REGEX"] = "^0+$"  # even a regex that would match it
        self.approve()
        self.assertEqual(self.gate.handle(self.payload(agent_id="000"))[0], 403)
        self.assertEqual(self.manager.calls, [])

    def test_unreadable_ledger_is_a_configuration_error(self) -> None:
        self.approve()
        os.environ["ERROW_FEEDBACK_APPROVALS_FILE"] = str(Path(self.tmp.name) / "absent.md")
        self.assertEqual(self.gate.handle(self.payload())[0], 503)
        self.assertEqual(self.manager.calls, [])

    def test_short_key_is_a_configuration_error(self) -> None:
        self.approve()
        self.key_file.write_text("short", encoding="utf-8")
        self.assertEqual(self.gate.handle(self.payload())[0], 503)
        self.assertEqual(self.manager.calls, [])

    def test_missing_manager_ca_is_a_configuration_error(self) -> None:
        self.approve()
        os.environ["VENDETTA_API_URL"] = "https://127.0.0.1:1"
        code, body = self.gate.handle(self.payload())
        self.assertEqual((code, body["decision"]), (503, "error"))
        self.assertIn("CA file missing", body["reason"])
        self.assertEqual(self.manager.calls, [])

    def test_unusable_manager_ca_is_a_configuration_error(self) -> None:
        self.approve()
        os.environ["VENDETTA_API_URL"] = "https://127.0.0.1:1"
        ca = Path(self.tmp.name) / "garbage-ca.pem"
        ca.write_text("not a certificate\n", encoding="utf-8")
        os.environ["VENDETTA_API_CA_FILE"] = str(ca)
        self.assertEqual(self.gate.handle(self.payload())[0], 503)
        self.assertEqual(self.manager.calls, [])

    # ------------------------------------------------------------------ dual control
    def per_approver_key(self, approver: str) -> Path:
        keys = Path(self.tmp.name) / "keys"
        keys.mkdir(exist_ok=True)
        path = keys / f"{approver}.key"
        path.write_text(f"{approver}-key-0123456789abcdef0123456789", encoding="utf-8")
        os.environ["ERROW_FEEDBACK_APPROVAL_KEYS_DIR"] = str(keys)
        os.environ["ERROW_FEEDBACK_APPROVAL_THRESHOLD"] = "2"
        return path

    def sign(self, approver: str, key: Path) -> None:
        argv = [sys.executable, str(LOOP / "approval.py"), "sign", "--fingerprint", FINGERPRINT,
                "--approver", approver, "--ttl-hours", "1", "--key-file", str(key)]
        line = subprocess.run(argv, capture_output=True, text=True, check=True).stdout.strip()
        with open(self.ledger, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def test_one_of_two_required_approvers_denies(self) -> None:
        self.sign("alice", self.per_approver_key("alice"))
        code, body = self.gate.handle(self.payload())
        self.assertEqual((code, body["decision"]), (403, "denied"))
        self.assertIn("1 of 2", body["reason"])
        self.assertEqual(self.manager.calls, [])

    def test_two_approvers_execute(self) -> None:
        self.sign("alice", self.per_approver_key("alice"))
        self.sign("bob", self.per_approver_key("bob"))
        code, _body = self.gate.handle(self.payload())
        self.assertEqual(code, 200)
        self.assertEqual(len(self.manager.calls), 1)

    def test_shared_key_alone_satisfies_a_threshold_of_two(self) -> None:
        os.environ["ERROW_FEEDBACK_APPROVAL_THRESHOLD"] = "2"
        self.approve()
        self.assertEqual(self.gate.handle(self.payload())[0], 200)
        self.assertEqual(len(self.manager.calls), 1)

    # ------------------------------------------------------------------ dry-run
    def test_live_flag_off_is_a_dry_run(self) -> None:
        os.environ["ERROW_FEEDBACK_LIVE"] = "false"
        self.approve()
        code, body = self.gate.handle(self.payload())
        self.assertEqual((code, body["decision"]), (200, "dry-run"))
        self.assertEqual(self.manager.calls, [])

    def test_dry_run_query_beats_a_valid_approval(self) -> None:
        self.approve()
        self.assertEqual(self.gate.handle(self.payload(), dry_run=True)[1]["decision"], "dry-run")
        self.assertEqual(self.manager.calls, [])

    # ------------------------------------------------------------------ transport
    def test_manager_server_error_is_502(self) -> None:
        self.manager.response_code = 500
        self.approve()
        self.assertEqual(self.gate.handle(self.payload())[0], 502)

    def test_unreachable_manager_is_502(self) -> None:
        self.approve()
        port = self.manager.server.server_address[1]
        self.manager.stop()
        os.environ["VENDETTA_API_URL"] = f"http://127.0.0.1:{port}"
        self.assertEqual(self.gate.handle(self.payload())[0], 502)

    # ------------------------------------------------------------------ validation
    def test_malformed_input_is_400_before_any_gate(self) -> None:
        self.approve()
        for bad in ({"agent_id": "001"}, {"fingerprint": "zz" * 32, "agent_id": "001"},
                    {"fingerprint": FINGERPRINT, "agent_id": "001", "command": "host-isolate.sh"}):
            self.assertEqual(self.gate.handle(bad)[0], 400)
        self.assertEqual(self.manager.calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
