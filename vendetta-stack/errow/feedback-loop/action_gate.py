"""Action gate: the single approval check in front of the Vendetta manager active-response API.

Traces: CONTRACT §6 (G9 offensive safety: live actions need ERROW_FEEDBACK_LIVE=true AND a signed approval line),
`APPROVALS.md`, `approval.py`, `fluentd/optional/vendetta-execd-live.conf`.

Two callers use the same verifier:
  * Fluentd `@VENDETTA_EXECD` -> POST /approved-action (this module, served by server.py)
  * `errow-to-vendetta.sh` -> `approval.py verify` directly

Gates, in order, all fail-closed:
  1. ERROW_FEEDBACK_LIVE=true                (otherwise 200 dry-run, no manager call)
  2. VENDETTA_EXECD_AGENT_REGEX matches the agent id and the id is not the manager `000`
  3. a signed, unexpired approval line for the fingerprint exists in APPROVALS.md

Only then is the manager called. An unreadable ledger/key is a configuration error (503, retryable), never an
allow. The manager password stays in its secret file; only the minted JWT is held, in memory, briefly.

Stdlib only (same constraint as server.py).
"""

from __future__ import annotations

import base64
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent

FP_RE = re.compile(r"^[0-9a-f]{64}$")
AGENT_RE = re.compile(r"^[0-9A-Za-z_-]{1,64}$")
MANAGER_AGENT_RE = re.compile(r"^0+$")
COMMAND_RE = re.compile(r"^![A-Za-z0-9._-]{1,64}$")

JWT_TTL_SECONDS = 480
MAX_REASON_CHARS = 300


class TrustError(Exception):
    """The manager's TLS trust store is missing or unusable — a configuration error, retryable (503)."""


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _one_line(value: str) -> str:
    text = " ".join(value.split())
    return text[:MAX_REASON_CHARS]


class Gate:
    def __init__(self, log=None, metrics=None) -> None:
        self._log = log or (lambda _line: None)
        self._metrics = metrics or (lambda _decision: None)
        self._jwt = ""
        self._jwt_expiry = 0.0
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- configuration (read per request)
    @property
    def live(self) -> bool:
        return os.environ.get("ERROW_FEEDBACK_LIVE", "false") == "true"

    @property
    def approvals_file(self) -> str:
        return os.environ.get("ERROW_FEEDBACK_APPROVALS_FILE", str(HERE / "APPROVALS.md"))

    @property
    def approval_key_file(self) -> str:
        return os.environ.get("ERROW_FEEDBACK_APPROVAL_KEY_FILE", "/run/secrets/feedback_approval_key")

    @property
    def approval_script(self) -> str:
        return os.environ.get("ERROW_FEEDBACK_APPROVAL_SCRIPT", str(HERE / "approval.py"))

    @property
    def approval_keys_dir(self) -> str:
        return os.environ.get("ERROW_FEEDBACK_APPROVAL_KEYS_DIR", str(Path(self.approval_key_file).parent / "keys"))

    @property
    def approval_threshold(self) -> str:
        return os.environ.get("ERROW_FEEDBACK_APPROVAL_THRESHOLD", "")

    @property
    def approvers(self) -> str:
        return os.environ.get("ERROW_FEEDBACK_APPROVERS", "")

    @property
    def agent_regex(self) -> str:
        return os.environ.get("VENDETTA_EXECD_AGENT_REGEX", "^$")

    @property
    def command(self) -> str:
        return os.environ.get("ERROW_FEEDBACK_AR_COMMAND", "!host-isolate.sh")

    @property
    def api_url(self) -> str:
        return os.environ.get("VENDETTA_API_URL", "https://vendetta-manager:55000").rstrip("/")

    @property
    def api_user(self) -> str:
        return os.environ.get("VENDETTA_API_USER", "wazuh-wui")

    @property
    def api_password_file(self) -> str:
        return os.environ.get("VENDETTA_API_PASSWORD_FILE", "/run/secrets/vendetta_api_password")

    @property
    def api_ca_file(self) -> str:
        return os.environ.get("VENDETTA_API_CA_FILE", "/pki/ca.crt")

    # ---------------------------------------------------------------- gates
    def _agent_allowed(self, agent_id: str) -> tuple[bool, str]:
        pattern = self.agent_regex
        try:
            matches = re.search(pattern, agent_id) is not None
        except re.error as exc:
            return False, f"VENDETTA_EXECD_AGENT_REGEX is invalid ({exc})"
        if not matches:
            return False, f"agent id {agent_id} does not match VENDETTA_EXECD_AGENT_REGEX ({pattern})"
        if MANAGER_AGENT_RE.match(agent_id):
            return False, f"agent id {agent_id} is the manager"
        return True, "allowed"

    def _approved(self, fingerprint: str) -> tuple[bool, str, bool]:
        """(approved, reason, configuration_error)"""
        argv = [sys.executable, self.approval_script, "verify", "--fingerprint", fingerprint]
        if self.approvals_file:
            argv += ["--file", self.approvals_file]
        if self.approval_key_file:
            argv += ["--key-file", self.approval_key_file]
        if self.approval_keys_dir:
            argv += ["--keys-dir", self.approval_keys_dir]
        if self.approval_threshold:
            argv += ["--threshold", self.approval_threshold]
        if self.approvers:
            argv += ["--approvers", self.approvers]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=10, check=False)  # noqa: S603 - fixed argv
        except OSError as exc:
            return False, f"cannot run approval verifier: {exc.strerror}", True
        except subprocess.TimeoutExpired:
            return False, "approval verifier timed out", True
        detail = _one_line((proc.stderr or proc.stdout).decode("utf-8", "replace"))
        if proc.returncode == 0:
            return True, detail or "approved", False
        if proc.returncode == 2:
            return False, detail or "approval configuration error", True
        return False, detail or "no signed approval for this fingerprint", False

    # ---------------------------------------------------------------- manager API
    def _ssl_context(self):
        """Verify the manager against VENDETTA_API_CA_FILE. There is no silent fallback to the system trust store: a
        private CA that silently degrades would widen trust scope without anyone noticing."""
        if not self.api_url.startswith("https://"):
            return None
        try:
            return ssl.create_default_context(cafile=self.api_ca_file)
        except (OSError, ssl.SSLError) as exc:
            raise TrustError(f"manager CA file unusable ({self.api_ca_file}): {exc}") from exc

    def _read_password(self) -> str:
        value = Path(self.api_password_file).read_text(encoding="utf-8").strip()
        if not value:
            raise OSError(f"empty secret file {self.api_password_file}")
        return value

    def _mint_jwt(self) -> str:
        user = quote(self.api_user, safe="")
        password = self._read_password()
        credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
        request = urllib.request.Request(  # noqa: S310 - env-configured manager URL
            f"{self.api_url}/security/user/authenticate?raw=true", data=b"", method="POST"
        )
        request.add_header("Authorization", f"Basic {credentials}")
        request.add_header("Accept", "application/json")
        with urllib.request.urlopen(request, timeout=_env_int("VENDETTA_API_TIMEOUT", 10), context=self._ssl_context()) as response:
            body = response.read().decode("utf-8", "replace").strip()
        token = body
        if body.startswith("{"):
            token = (json.loads(body).get("data") or {}).get("token", "")
        if not token or any(ch.isspace() for ch in token):
            raise ValueError("manager returned no usable JWT")
        return token

    def _token(self) -> str:
        with self._lock:
            if self._jwt and time.monotonic() < self._jwt_expiry:
                return self._jwt
            self._jwt = self._mint_jwt()
            self._jwt_expiry = time.monotonic() + JWT_TTL_SECONDS
            return self._jwt

    def _call_manager(self, agent_id: str, body: dict) -> tuple[int, str]:
        """(status, detail) - 200 on success, manager 4xx passed through, 502/504 on transport/server faults."""
        payload = json.dumps(body, separators=(",", ":")).encode()
        for attempt in (1, 2):
            try:
                request = urllib.request.Request(  # noqa: S310
                    f"{self.api_url}/active-response?agents_list={quote(agent_id, safe='')}", data=payload, method="PUT"
                )
                request.add_header("Content-Type", "application/json")
                request.add_header("Accept", "application/json")
                request.add_header("Authorization", f"Bearer {self._token()}")
                with urllib.request.urlopen(request, timeout=_env_int("VENDETTA_API_TIMEOUT", 10), context=self._ssl_context()) as response:
                    raw = response.read().decode("utf-8", "replace")
                    code = response.status
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", "replace")
                code = exc.code
                if code == 401 and attempt == 1:
                    with self._lock:
                        self._jwt = ""
                    continue
            except TimeoutError:
                return 504, "manager timed out"
            except urllib.error.URLError as exc:
                return 502, f"manager unreachable: {exc.reason}"
            except OSError as exc:
                return 502, f"manager call failed: {exc}"
            if 200 <= code < 300:
                try:
                    if json.loads(raw).get("error", 0) not in (0, None):
                        return 502, f"manager rejected the action: {_one_line(raw)}"
                except (ValueError, AttributeError):
                    pass
                return 200, "executed"
            if 400 <= code < 500:
                return code, _one_line(raw) or f"manager HTTP {code}"
            return 502, _one_line(raw) or f"manager HTTP {code}"
        return 502, "manager authentication failed"

    # ---------------------------------------------------------------- entry point
    def handle(self, payload, dry_run: bool = False) -> tuple[int, dict]:
        if not isinstance(payload, dict):
            return self._reply(400, "invalid", "request body must be a JSON object")

        fingerprint = str(payload.get("fingerprint", "")).strip().lower()
        agent_id = str(payload.get("agent_id", "")).strip()
        command = str(payload.get("command") or self.command).strip()
        run = str(payload.get("run", "")).strip()[:128]

        if not FP_RE.match(fingerprint):
            return self._reply(400, "invalid", "fingerprint must be 64 lowercase hex characters")
        if not AGENT_RE.match(agent_id):
            return self._reply(400, "invalid", "agent_id must match [0-9A-Za-z_-]{1,64}")
        if not COMMAND_RE.match(command):
            return self._reply(400, "invalid", "command must look like !script-name")

        context = {"fingerprint": fingerprint, "agent_id": agent_id, "command": command, "run": run}

        if dry_run or not self.live:
            reason = "requested by ?dry_run=1" if dry_run else "ERROW_FEEDBACK_LIVE is not true"
            return self._reply(200, "dry-run", reason, context)

        allowed, reason = self._agent_allowed(agent_id)
        if not allowed:
            return self._reply(403, "denied", reason, context)

        approved, reason, config_error = self._approved(fingerprint)
        if not approved:
            return self._reply(503, "error", reason, context) if config_error else self._reply(403, "denied", reason, context)

        if self.api_url.startswith("https://") and not Path(self.api_ca_file).is_file():
            return self._reply(
                503,
                "error",
                f"manager CA file missing ({self.api_ca_file}): pin the manager certificate (scripts/pin-manager-cert.sh)",
                context,
            )

        try:
            code, detail = self._call_manager(
                agent_id,
                {
                    "command": command,
                    "arguments": ["-"],
                    "alert": {
                        "data": {
                            "action": "isolate",
                            "errow_fingerprint": fingerprint,
                            "errow_run": run,
                            "source": "fluentd-exec-gate",
                        }
                    },
                },
            )
        except TrustError as exc:
            return self._reply(503, "error", str(exc), context)
        if code == 200:
            return self._reply(200, "live", detail, context)
        return self._reply(code, "failed", detail, context)

    def _reply(self, code: int, decision: str, reason: str, context: dict | None = None) -> tuple[int, dict]:
        self._metrics(decision)
        fingerprint = (context or {}).get("fingerprint", "")
        label = "DENIED" if decision == "denied" else "LIVE" if decision == "live" else decision.upper()
        self._log(f"[action-gate] {label} fingerprint={fingerprint[:16]} decision={decision} reason={reason}")
        body = {"status": "error" if code >= 500 else decision, "decision": decision, "reason": reason}
        body.update(context or {})
        return code, body
