"""Tests for server.py (errow-feedback webhook). stdlib unittest; also collected by pytest.

Run: python3 -m unittest discover -s errow/feedback-loop/tests -p 'test_server.py'
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FL = HERE.parent
FIXTURES = FL.parent.parent / "tests" / "synthetic-logs"
TOKEN = "test-webhook-token-0123456789"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.work = HERE / f".work-server-{os.getpid()}"
        cls.work.mkdir()
        (cls.work / "token").write_text(TOKEN + "\n", encoding="utf-8")
        cls.port = free_port()
        cls.env = {
            **os.environ,
            "FEEDBACK_BIND": "127.0.0.1",
            "FEEDBACK_PORT": str(cls.port),
            "FEEDBACK_WEBHOOK_TOKEN_FILE": str(cls.work / "token"),
            "FEEDBACK_MAX_BODY_BYTES": "65536",
            "FEEDBACK_DIR": str(cls.work / "fl"),
            "ERROW_FEEDBACK_LIVE": "false",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        cls.proc = subprocess.Popen([sys.executable, str(FL / "server.py")], env=cls.env, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("server did not start")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proc.terminate()
        cls.proc.wait(timeout=10)
        shutil.rmtree(cls.work, ignore_errors=True)

    def request(self, method: str, path: str, body: bytes | None = None, token: str | None = TOKEN):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, data

    def sarif_body(self) -> bytes:
        return (FIXTURES / "errow-finding.sarif.json").read_bytes()

    def test_health_and_metrics_need_no_token(self) -> None:
        status, data = self.request("GET", "/health", token=None)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data), {"status": "ok", "live": False})
        status, data = self.request("GET", "/metrics", token=None)
        self.assertEqual(status, 200)
        self.assertIn(b"errow_feedback_live_enabled 0", data)

    def test_post_requires_bearer(self) -> None:
        self.assertEqual(self.request("POST", "/errow-finding", b"{}", token=None)[0], 401)
        self.assertEqual(self.request("POST", "/errow-finding", b"{}", token="wrong")[0], 401)

    def test_sarif_runs_dry_run_script(self) -> None:
        status, data = self.request("POST", "/errow-finding", self.sarif_body())
        self.assertEqual(status, 200, data)
        reply = json.loads(data)
        self.assertEqual(reply["exit_code"], 0)
        self.assertFalse(reply["live"])
        joined = "\n".join(reply["lines"])
        self.assertIn("[errow-to-vendetta] DRY-RUN: would isolate host=scan-target.vendetta.lab", joined)
        self.assertIn("DRY-RUN: would open SOAR ticket", joined)

    def test_ndjson_of_shipper_records(self) -> None:
        sarif = json.loads(self.sarif_body())
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        records = []
        for result in sarif["runs"][0]["results"][:2]:
            records.append(json.dumps({**result, "rule": rule, "run": "r1", "stream": "findings", "source": "errow"}))
        status, data = self.request("POST", "/errow-finding", ("\n".join(records) + "\n").encode())
        self.assertEqual(status, 200, data)
        self.assertGreaterEqual(len(json.loads(data)["lines"]), 3)

    def test_invalid_body_is_400(self) -> None:
        status, data = self.request("POST", "/errow-finding", b"{not json")
        self.assertEqual(status, 400, data)
        self.assertEqual(json.loads(data)["exit_code"], 3)

    def test_empty_and_oversized_bodies(self) -> None:
        self.assertEqual(self.request("POST", "/errow-finding", b"")[0], 400)
        status, _ = self.request("POST", "/errow-finding", b"x" * 70000)
        self.assertEqual(status, 413)

    def test_unknown_paths(self) -> None:
        self.assertEqual(self.request("GET", "/nope", token=None)[0], 404)
        self.assertEqual(self.request("POST", "/nope", b"{}")[0], 404)

    def test_request_data_never_reaches_a_shell(self) -> None:
        marker = self.work / "pwned"
        payload = json.dumps({"ruleId": f"$(touch {marker})", "partialFingerprints": {"primaryLocationLineHash": f"`touch {marker}`"}})
        status, _ = self.request("POST", f"/errow-finding?dry_run=1&x=;touch%20{marker}", payload.encode())
        self.assertIn(status, (200, 400))
        self.assertFalse(marker.exists())

    def test_dry_run_query_overrides_live(self) -> None:
        env = {**self.env, "ERROW_FEEDBACK_LIVE": "true", "FEEDBACK_PORT": str(free_port())}
        proc = subprocess.Popen([sys.executable, str(FL / "server.py")], env=env, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", int(env["FEEDBACK_PORT"])), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
            conn = http.client.HTTPConnection("127.0.0.1", int(env["FEEDBACK_PORT"]), timeout=30)
            conn.request("POST", "/errow-finding?dry_run=1", self.sarif_body(), {"Authorization": f"Bearer {TOKEN}"})
            reply = json.loads(conn.getresponse().read())
            conn.close()
            self.assertFalse(reply["live"])
            self.assertIn("DRY-RUN: would", "\n".join(reply["lines"]))
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def test_healthcheck_flag(self) -> None:
        ok = subprocess.run([sys.executable, str(FL / "server.py"), "--healthcheck"], env=self.env, check=False)
        self.assertEqual(ok.returncode, 0)
        down = subprocess.run(
            [sys.executable, str(FL / "server.py"), "--healthcheck"],
            env={**self.env, "FEEDBACK_PORT": str(free_port())},
            check=False,
        )
        self.assertEqual(down.returncode, 1)

    def test_refuses_to_start_without_token(self) -> None:
        env = {**self.env, "FEEDBACK_WEBHOOK_TOKEN_FILE": str(self.work / "missing"), "FEEDBACK_PORT": str(free_port())}
        proc = subprocess.run([sys.executable, str(FL / "server.py")], env=env, capture_output=True, check=False, timeout=20)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"token file unreadable", proc.stderr)


if __name__ == "__main__":
    unittest.main()
