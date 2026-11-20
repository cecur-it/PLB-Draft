"""errow-mcp executor — turns an approved policy Decision into an argv plan and (optionally) runs it.

Everything is an argv ARRAY; no shell string is ever built. By default (MCP_LIVE unset/false) the
bridge only returns the plan (argv + sandbox spec) and never touches Docker. With MCP_LIVE=true each
tool runs in an ephemeral container of the Errow sandbox image (env errow_IMAGE) on the dedicated
`offensive` network, reached through DOCKER_HOST (errow-dind) exactly like errow/runtime/docker_connection.py:
cap_drop ALL (+ only the capabilities the sandbox image's file-capability binaries need), read-only
rootfs, no-new-privileges, pids/memory/cpu limits, tmpfs scratch, AutoRemove, timeout kill, and NO host
mounts except MCP_REPOS_SOURCE mounted read-only for trufflehog. Never on the host.

What each tool really does (honest mapping, see RUNTIME.md):
  bbot/nmap/nuclei/gobuster/subfinder/wafw00f/trufflehog/shell  -> the real CLI in the sandbox image.
  agent_browser  -> `agent-browser` CLI (open + snapshot [+ screenshot]) in an ephemeral container; the
                    screenshot lives in tmpfs and is destroyed with the container (hash + size reported).
  proxy          -> read-only Caido GraphQL query (guest login on 127.0.0.1:48080) executed with
                    `docker exec` inside an ALREADY RUNNING Errow run sandbox (label errow-run-id); the
                    bridge never starts Caido and never replays/modifies traffic.
  web_search     -> same Exa/Perplexity HTTPS call Errow's errow/tools/web_search performs, issued by a
                    stdlib script in an ephemeral container; needs MCP_WEB_SEARCH_KEY_FILE, otherwise the
                    call returns status "unconfigured".
  threat_model / coverage -> in-process READERS of <ERROW_RUNS_DIR>/<run>/.state/threat_models.json and
                    <run>/coverage.json (mounted read-only); nothing is executed.

Traces: PROMPT §2.3, §1 Tier 4; CONTRACT §4.5, §8.4; errow/errow/runtime/{docker_connection,docker_client}.py;
errow/containers/Dockerfile (sandbox user pentester, setcap'd nmap, tools in ~/.local/bin and ~/go/bin).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from policy import Decision, Policy
from sanitize import sanitize_text

DEFAULT_NMAP_CAPS = "NET_RAW,NET_ADMIN,NET_BIND_SERVICE"
NETWORK_DENY = re.compile(r"(^|[_-])(host|bridge|default|edge|aggregation|storage|management|inference)$", re.I)
ATTACHED_DENY = re.compile(
    r"(vendetta|wazuh|opensearch|ollama|llm-gateway|fluent|errow-mcp|errow-feedback|errow-shipper)", re.I
)
REPOS_MOUNT = "/workspace/repos"
SANDBOX_HOME = "/home/pentester"
PAYLOAD_KEYS = {"Raw", "RawV2"}

_PROXY_SCRIPT = (
    "import base64,json,os,urllib.request as u\n"
    "B=os.environ.get('CAIDO_URL','http://127.0.0.1:48080/graphql')\n"
    "def g(q,v=None,t=None):\n"
    " h={'Content-Type':'application/json'}\n"
    " if t:h['Authorization']='Bearer '+t\n"
    " r=u.Request(B,json.dumps({'query':q,'variables':v or {}}).encode(),h)\n"
    " return json.load(u.urlopen(r,timeout=10))\n"
    "t=g('mutation{loginAsGuest{token{accessToken}}}')['data']['loginAsGuest']['token']['accessToken']\n"
    "a=os.environ['PROXY_ACTION'];n=int(os.environ['PROXY_LIMIT'])\n"
    "f={'code':'req.host.eq:\"%s\"'%os.environ['PROXY_HOST']}\n"
    "if a=='scope_status':\n"
    " o=g('query{scopes{id name allowlist denylist indexed}}',None,t)\n"
    "else:\n"
    " raw=' raw' if a=='view_request' else ''\n"
    " q='query($n:Int,$f:HTTPQLInput){requests(first:$n,filter:$f){edges{node{id host port method path query isTls "
    "createdAt'+raw+' response{id statusCode length roundtripTime'+raw+'}}}}}'\n"
    " o=g(q,{'n':1 if a=='view_request' else n,'f':f},t)\n"
    " for e in o.get('data',{}).get('requests',{}).get('edges',[]):\n"
    "  for x in (e['node'],e['node'].get('response') or {}):\n"
    "   if x.get('raw'):x['raw']=base64.b64decode(x['raw']).decode('utf-8','replace')[:4000]\n"
    "print(json.dumps(o))\n"
)

_SEARCH_SCRIPT = (
    "import json,os,urllib.request as u\n"
    "q=os.environ['WS_QUERY'];n=int(os.environ['WS_MAX'])\n"
    "if os.environ['WS_PROVIDER']=='perplexity':\n"
    " r=u.Request('https://api.perplexity.ai/chat/completions',json.dumps({'model':'sonar','messages':"
    "[{'role':'user','content':q}]}).encode(),{'Authorization':'Bearer '+os.environ['WS_KEY'],"
    "'Content-Type':'application/json'})\n"
    " print(json.dumps({'answer':json.load(u.urlopen(r,timeout=25))['choices'][0]['message']['content']}))\n"
    "else:\n"
    " r=u.Request('https://api.exa.ai/search',json.dumps({'query':q,'type':'auto','numResults':n,'contents':"
    "{'summary':{'query':q}}}).encode(),{'x-api-key':os.environ['WS_KEY'],'Content-Type':'application/json'})\n"
    " d=json.load(u.urlopen(r,timeout=25))\n"
    " print(json.dumps([{'title':x.get('title'),'url':x.get('url'),'summary':x.get('summary')}"
    " for x in d.get('results',[])]))\n"
)


class ExecError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class ExecConfig:
    image: str | None = None
    network: str = "offensive"
    create_network: bool = True
    user: str = "pentester"
    mem_limit: str = "1g"
    cpus: float = 1.0
    pids_limit: int = 256
    shm_size: str = "64m"
    tmpfs_size: str = "128m"
    extra_tmpfs: list[str] = field(default_factory=list)
    repos_source: str | None = None
    output_max_bytes: int = 1_048_576
    runs_dir: str = "/workspace/errow_runs"
    nmap_caps: list[str] = field(default_factory=lambda: DEFAULT_NMAP_CAPS.split(","))
    proxy_run_id: str | None = None
    search_provider: str = "exa"
    search_key_file: str | None = None
    docker_host: str | None = None

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> ExecConfig:
        e = env if env is not None else os.environ

        def num(name: str, default: float, cast: Callable[[str], Any] = float) -> Any:
            try:
                return cast(e.get(name, "") or default)
            except ValueError:
                return default

        return cls(
            image=e.get("errow_IMAGE") or e.get("ERROW_IMAGE") or None,
            network=e.get("MCP_SANDBOX_NETWORK", "offensive"),
            create_network=e.get("MCP_SANDBOX_NETWORK_CREATE", "true").strip().lower() not in ("0", "false", "no", "off"),
            user=e.get("SANDBOX_USER", "pentester"),
            mem_limit=e.get("MCP_SANDBOX_MEM_LIMIT", "1g"),
            cpus=num("MCP_SANDBOX_CPUS", 1.0),
            pids_limit=num("MCP_SANDBOX_PIDS_LIMIT", 256, int),
            shm_size=e.get("MCP_SANDBOX_SHM_SIZE", "64m"),
            tmpfs_size=e.get("MCP_SANDBOX_TMPFS_SIZE", "128m"),
            extra_tmpfs=[p for p in e.get("SANDBOX_TMPFS", "").split(",") if p.strip()],
            repos_source=e.get("MCP_REPOS_SOURCE") or None,
            output_max_bytes=num("MCP_OUTPUT_MAX_BYTES", 1_048_576, int),
            runs_dir=e.get("ERROW_RUNS_DIR", "/workspace/errow_runs"),
            nmap_caps=[c.strip().upper() for c in e.get("SANDBOX_NMAP_CAPS", DEFAULT_NMAP_CAPS).split(",") if c.strip()],
            proxy_run_id=e.get("MCP_PROXY_RUN_ID") or None,
            search_provider=e.get("MCP_WEB_SEARCH_PROVIDER", "exa").lower(),
            search_key_file=e.get("MCP_WEB_SEARCH_KEY_FILE") or None,
            docker_host=e.get("DOCKER_HOST") or None,
        )

    def validate(self) -> None:
        if NETWORK_DENY.search(self.network or ""):
            raise ExecError("bad_network", f"MCP_SANDBOX_NETWORK {self.network!r} is not an isolated sandbox network")
        if self.search_provider not in ("exa", "perplexity"):
            raise ExecError("bad_config", "MCP_WEB_SEARCH_PROVIDER must be exa or perplexity")
        if self.repos_source is not None and not self.repos_source.startswith("/") and ":" in self.repos_source:
            raise ExecError("bad_config", "MCP_REPOS_SOURCE must be an absolute path or a named volume")


@dataclass
class Plan:
    tool: str
    kind: str
    steps: list[list[str]]
    timeout_s: int
    network: str | None = None
    caps: list[str] = field(default_factory=list)
    tmpfs: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    secret_env: dict[str, str] = field(default_factory=dict)
    mounts: dict[str, dict[str, str]] = field(default_factory=dict)
    extra_hosts: dict[str, str] = field(default_factory=dict)
    shm_size: str | None = None
    notes: list[str] = field(default_factory=list)
    reader: dict[str, Any] | None = None
    post: str | None = None


@dataclass
class ExecResult:
    status: str
    exit_code: int | None = None
    output: str = ""
    stderr: str = ""
    truncated: bool = False
    output_sha256: str | None = None
    output_bytes: int = 0
    duration_s: float = 0.0
    container: str | None = None
    error: str | None = None
    message: str | None = None
    summary: str = ""


def _tmp(cfg: ExecConfig, *extra: str) -> dict[str, str]:
    """tmpfs mounts: /tmp and /run are noexec; tool state dirs are writable scratch that dies with the container."""
    noexec = f"rw,noexec,nosuid,nodev,size={cfg.tmpfs_size}"
    state = f"rw,nosuid,nodev,size={cfg.tmpfs_size}"
    out = {"/tmp": noexec, "/run": noexec}
    for path in (*extra, *cfg.extra_tmpfs):
        out[path.strip()] = state
    return out


def _pin_hosts(decision: Decision) -> dict[str, str]:
    """Pin the DNS answers the policy validated so the sandbox cannot be rebound to a denied address."""
    if decision.target is None or decision.target.kind == "domain":
        return {}
    pins: dict[str, str] = {}
    for host, addrs in decision.resolved.items():
        v4 = [a for a in addrs if ":" not in a]
        pick = (v4 or addrs)[:1]
        if pick and host != pick[0]:
            pins[host] = pick[0]
    return pins


def build_plan(decision: Decision, cfg: ExecConfig) -> Plan:
    """Map an allowed Decision onto argv arrays. Pure function: no I/O, no Docker."""
    tool, a, spec = decision.tool, decision.args, decision.spec or {}
    timeout = int(spec["timeout_s"])
    common = {"HOME": SANDBOX_HOME, "NO_COLOR": "1"}
    pins = _pin_hosts(decision)
    base = Plan(tool=tool, kind="container", steps=[], timeout_s=timeout, network=cfg.network,
                tmpfs=_tmp(cfg), env=dict(common), extra_hosts=pins)

    if tool == "bbot":
        base.steps = [["bbot", "-t", a["target"], "-p", a["preset"], "-f", "passive", "-rf", "passive",
                       "--silent", "--json", "-y", "--no-deps", "-n", "mcp", "-o", "/tmp/bbot"]]
        base.tmpfs = _tmp(cfg, f"{SANDBOX_HOME}/.bbot", f"{SANDBOX_HOME}/.config/bbot")
        base.notes.append("-rf passive is added so ONLY passive-flagged modules can load (-f alone merely enables them).")
    elif tool == "nmap":
        argv = ["nmap", a["scan_type"]]
        if "ports" in a:
            argv += ["-p", a["ports"]]
        if "timing" in a:
            argv.append(a["timing"])
        argv += [a["target"], "-oX", "-"]
        base.steps = [argv]
        base.caps = list(cfg.nmap_caps)
        base.notes.append(
            "nmap in the sandbox image carries file capabilities; exec fails unless the bounding set contains "
            "all of them, so caps are cap_drop ALL + SANDBOX_NMAP_CAPS (default NET_RAW,NET_ADMIN,NET_BIND_SERVICE)."
        )
    elif tool == "nuclei":
        argv = ["nuclei", "-u", a["target"], "-tags", ",".join(a["tags"])]
        if a.get("severity"):
            argv += ["-severity", ",".join(a["severity"])]
        argv += ["-rl", str(a.get("rate_limit", 25)), "-duc", "-ni", "-nc", "-silent", "-jsonl"]
        base.steps = [argv]
    elif tool == "gobuster":
        base.steps = [["gobuster", "dir", "-u", a["target"], "-w", a["wordlist"],
                       "-t", str(a.get("threads", 5)), "-q", "--no-error", "-z"]]
    elif tool == "subfinder":
        base.steps = [["subfinder", "-d", a["target"], "-silent", "-json", "-duc", "-max-time", "4"]]
        base.tmpfs = _tmp(cfg, f"{SANDBOX_HOME}/.config/subfinder")
        base.notes.append("subfinder queries passive sources only unless -all/-recursive/-active (policy-forbidden).")
    elif tool == "wafw00f":
        base.steps = [["wafw00f", "-f", "json", "-o", "-", a["target"]]]
        base.notes.append("wafw00f has no passive-only switch; policy pins the default detection without -a/--findall.")
    elif tool == "trufflehog":
        mode = a.get("mode", "filesystem")
        source = a["repo_path"] if mode == "filesystem" else f"file://{a['repo_path']}"
        base.steps = [["trufflehog", mode, source, "--json", "--no-verification", "--no-update"]]
        base.network = "none"
        base.post = "trufflehog"
        base.notes.append("--no-verification always on (no secret verification traffic); network none; Raw/RawV2 stripped from output.")
        if cfg.repos_source:
            base.mounts = {cfg.repos_source: {"bind": REPOS_MOUNT, "mode": "ro"}}
        else:
            base.notes.append("MCP_REPOS_SOURCE is unset: live execution will fail with repos_not_mounted.")
    elif tool == "shell":
        base.steps = [_shell_argv(a)]
        if a["command"] == "ping -c 3":
            base.caps = ["NET_RAW"]
    elif tool == "agent_browser":
        url = a["url"]
        sess = ["--session", "mcp"]
        steps = [["agent-browser", *sess, "open", url], ["agent-browser", *sess, "snapshot", "-c"]]
        if a.get("screenshot"):
            steps += [["agent-browser", *sess, "screenshot", "/tmp/shots/page.png"],
                      ["sha256sum", "/tmp/shots/page.png"]]
        steps.append(["agent-browser", *sess, "close"])
        base.kind, base.steps, base.shm_size = "container-session", steps, "256m"
        base.env.update({
            "AGENT_BROWSER_ARGS": "--no-sandbox,--disable-dev-shm-usage,--disable-gpu,--no-first-run,--no-default-browser-check",
            "AGENT_BROWSER_SCREENSHOT_DIR": "/tmp/shots",
        })
        base.tmpfs = _tmp(cfg, "/tmp/shots", f"{SANDBOX_HOME}/.agent-browser", f"{SANDBOX_HOME}/.config", f"{SANDBOX_HOME}/.cache")
        base.notes.append(
            "Chromium runs --no-sandbox inside the already isolated container (no user namespaces under the default "
            "seccomp profile); subresource/redirect reach is bounded by the sandbox network, not by the browser. "
            "Screenshots are tmpfs-only "
            f"(retention {a.get('screenshot_retention_days', spec.get('screenshot_retention_days_default', 7))}d is "
            "recorded in the audit event, not persisted)."
        )
    elif tool == "proxy":
        host = (decision.target.host if decision.target else "") or ""
        base.kind = "proxy-exec"
        base.steps = [["python3", "-c", _PROXY_SCRIPT]]
        base.network = None
        base.env = {"PROXY_ACTION": a["action"], "PROXY_HOST": host, "PROXY_LIMIT": str(a.get("limit", 20))}
        base.notes.append("docker exec into a running Errow run sandbox (label errow-run-id); read-only GraphQL queries only.")
    elif tool == "web_search":
        base.steps = [["python3", "-c", _SEARCH_SCRIPT]]
        base.env.update({"WS_QUERY": sanitize_text(a["query"], 200), "WS_MAX": str(a.get("max_results", 5)),
                         "WS_PROVIDER": cfg.search_provider})
        if cfg.search_key_file:
            base.secret_env = {"WS_KEY": cfg.search_key_file}
        base.network = os.environ.get("MCP_WEB_SEARCH_NETWORK") or cfg.network
    elif tool in ("threat_model", "coverage"):
        rel = ".state/threat_models.json" if tool == "threat_model" else "coverage.json"
        base.kind = "reader"
        base.steps = [["read", f"{cfg.runs_dir}/{a['run']}/{rel}"]]
        base.network = None
        base.reader = {"run": a["run"], "file": rel, "format": a.get("format", "summary")}
        base.notes.append("in-process read-only file read (argv 'read' is a pseudo-step, no process is spawned).")
    else:
        raise ExecError("no_mapping", f"no executor mapping for tool {tool!r}")
    return base


def _shell_argv(a: dict[str, Any]) -> list[str]:
    target = a["target"]
    return {
        "curl -sI": ["curl", "-sI", "--max-time", "20", "--proto", "=http,https", "--", target],
        "dig": ["dig", "+time=3", "+tries=1", target],
        "nslookup": ["nslookup", "-timeout=3", target],
        "ping -c 3": ["ping", "-c", "3", "-W", "2", target],
    }[a["command"]]


class Executor:
    def __init__(
        self,
        policy: Policy,
        config: ExecConfig | None = None,
        *,
        docker_factory: Callable[[], Any] | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.policy = policy
        self.cfg = config or ExecConfig.from_env()
        self._factory = docker_factory
        self._client: Any = None
        self._sleep = sleeper
        self._lock = threading.Lock()
        self._running = 0

    @property
    def running(self) -> int:
        return self._running

    def plan(self, decision: Decision) -> Plan:
        self.cfg.validate()
        return build_plan(decision, self.cfg)

    # ------------------------------------------------------------------ dry-run
    def container_kwargs(self, plan: Plan, name: str, labels: dict[str, str] | None = None) -> dict[str, Any]:
        cfg = self.cfg
        main = plan.steps[0]
        kwargs: dict[str, Any] = {
            "image": cfg.image,
            "name": name,
            "user": cfg.user,
            "working_dir": "/tmp",
            "labels": {"vendetta.component": "errow-mcp-exec", "errow-run-type": "mcp", "errow-mcp-tool": plan.tool,
                       **(labels or {})},
            "environment": dict(plan.env),
            "network_mode": plan.network,
            "network_disabled": plan.network == "none",
            "read_only": True,
            "privileged": False,
            "cap_drop": ["ALL"],
            "cap_add": list(plan.caps),
            "security_opt": ["no-new-privileges:true"],
            "pids_limit": cfg.pids_limit,
            "mem_limit": cfg.mem_limit,
            "memswap_limit": cfg.mem_limit,
            "nano_cpus": int(cfg.cpus * 1_000_000_000),
            "shm_size": plan.shm_size or cfg.shm_size,
            "tmpfs": dict(plan.tmpfs),
            "volumes": {k: dict(v) for k, v in plan.mounts.items()},
            "auto_remove": True,
            "init": True,
            "tty": False,
            "stdin_open": False,
        }
        if plan.kind == "container-session":
            kwargs["entrypoint"] = ["sleep"]
            kwargs["command"] = [str(plan.timeout_s + 10)]
        else:
            kwargs["entrypoint"] = [main[0]]
            kwargs["command"] = list(main[1:])
        if plan.extra_hosts:
            kwargs["extra_hosts"] = dict(plan.extra_hosts)
        return kwargs

    def dry_run(self, plan: Plan) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": plan.kind,
            "argv": plan.steps[0],
            "steps": plan.steps,
            "timeout_s": plan.timeout_s,
            "notes": plan.notes,
        }
        if plan.kind in ("container", "container-session"):
            spec = self.container_kwargs(plan, "errow-mcp-dry-run")
            spec["environment"] = {**plan.env, **{k: "<from file>" for k in plan.secret_env}}
            spec["image_configured"] = bool(self.cfg.image)
            out["sandbox"] = spec
        elif plan.kind == "proxy-exec":
            out["sandbox"] = {"exec_in": "running container with label errow-run-id", "user": self.cfg.user,
                              "environment": plan.env}
        else:
            out["sandbox"] = {"in_process": True, "read_only": True, "runs_dir": self.cfg.runs_dir, **(plan.reader or {})}
        return out

    # ------------------------------------------------------------------ live
    def run(self, plan: Plan, *, request_id: str = "") -> ExecResult:
        started = time.monotonic()
        with self._lock:
            self._running += 1
        try:
            if plan.kind == "reader":
                result = self._read(plan)
            else:
                client = self._docker()
                if plan.kind == "proxy-exec":
                    result = self._proxy(client, plan)
                else:
                    result = self._container(client, plan, request_id)
        except ExecError as exc:
            result = ExecResult(status="error", error=exc.code, message=sanitize_text(exc.message, 500))
        except Exception as exc:  # noqa: BLE001 - docker/requests errors must never escape as a crash
            result = ExecResult(status="error", error="executor_failure", message=sanitize_text(f"{type(exc).__name__}: {exc}", 500))
        finally:
            with self._lock:
                self._running -= 1
        result.duration_s = round(time.monotonic() - started, 3)
        result.summary = _summary(plan.tool, result)
        return result

    def _docker(self) -> Any:
        if self._client is not None:
            return self._client
        if self._factory is None and not self.cfg.docker_host:
            raise ExecError("docker_host_unset", "DOCKER_HOST is not set; refusing to use a local docker socket")
        if not self.cfg.image:
            raise ExecError("no_image", "errow_IMAGE is not set")
        if self._factory is not None:
            self._client = self._factory()
        else:
            import docker  # local import keeps dry-run and policy tests dependency-free

            self._client = docker.from_env(timeout=30)
        return self._client

    def _check_network(self, client: Any, name: str) -> None:
        try:
            net = client.networks.get(name)
        except Exception as exc:  # noqa: BLE001
            if not self.cfg.create_network:
                raise ExecError("network_missing", f"sandbox network {name!r} not found: {type(exc).__name__}") from exc
            # The network lives in the Docker daemon behind DOCKER_HOST (errow-dind), so it can only be created here.
            try:
                net = client.networks.create(name, driver="bridge", check_duplicate=True,
                                             labels={"vendetta.component": "errow-mcp-sandbox"})
            except Exception as exc2:  # noqa: BLE001
                raise ExecError("network_missing", f"sandbox network {name!r} not found and not creatable: {type(exc2).__name__}") from exc2
        try:
            net.reload()
        except Exception:  # noqa: BLE001 - reload is best effort
            pass
        attached = (getattr(net, "attrs", {}) or {}).get("Containers") or {}
        for info in attached.values():
            cname = str((info or {}).get("Name", ""))
            if ATTACHED_DENY.search(cname):
                raise ExecError("network_not_isolated", f"network {name!r} has {cname!r} attached")

    def _container(self, client: Any, plan: Plan, request_id: str) -> ExecResult:
        if plan.tool == "trufflehog" and not self.cfg.repos_source:
            raise ExecError("repos_not_mounted", "MCP_REPOS_SOURCE is unset")
        env_secret = {}
        for name, path in plan.secret_env.items():
            try:
                env_secret[name] = Path(path).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ExecError("unconfigured", f"cannot read {name} secret file") from exc
        if plan.tool == "web_search" and not env_secret:
            return ExecResult(status="unconfigured", error="web_search_unconfigured",
                              message="MCP_WEB_SEARCH_KEY_FILE is not configured")
        if plan.network and plan.network != "none":
            self._check_network(client, plan.network)
        name = f"errow-mcp-{plan.tool}-{secrets.token_hex(4)}"
        kwargs = self.container_kwargs(plan, name, {"errow-mcp-request": request_id[:64]})
        kwargs["environment"] = {**kwargs["environment"], **env_secret}
        container = client.containers.create(**kwargs)
        cid = str(getattr(container, "id", name))[:12]
        deadline_hit = threading.Event()
        killer = threading.Timer(plan.timeout_s, lambda: (deadline_hit.set(), _safe(container.kill)))
        killer.daemon = True
        buf = _Capture(self.cfg.output_max_bytes)
        exit_code: int | None = None
        try:
            if plan.kind == "container":
                # attach and wait BEFORE start(): with AutoRemove the container can vanish right after it exits.
                stream = container.attach(stdout=True, stderr=True, stream=True, logs=True, demux=True)
                reader = threading.Thread(target=buf.consume, args=(stream, container), daemon=True)
                reader.start()
                waited: dict[str, Any] = {}
                waiter = threading.Thread(target=self._wait, args=(container, plan, waited), daemon=True)
                waiter.start()
                container.start()
                killer.start()
                waiter.join(timeout=plan.timeout_s + 20)
                reader.join(timeout=10)
                exit_code = waited.get("code")
            else:
                container.start()
                killer.start()
                try:
                    exit_code = self._session(container, plan, buf)
                except Exception:  # noqa: BLE001 - the watchdog kill surfaces as an API error mid-exec
                    if not deadline_hit.is_set():
                        raise
        finally:
            killer.cancel()
            _safe(container.kill)
            _safe(lambda: container.remove(force=True))
        if deadline_hit.is_set():
            return buf.result("error", exit_code, plan, cid, error="timeout", message=f"killed after {plan.timeout_s}s")
        if buf.overflow:
            return buf.result("executed", exit_code, plan, cid, message="output cap reached; container killed")
        return buf.result("executed", exit_code, plan, cid)

    @staticmethod
    def _wait(container: Any, plan: Plan, out: dict[str, Any]) -> None:
        try:
            res = container.wait(timeout=plan.timeout_s + 15, condition="removed")
        except Exception:  # noqa: BLE001 - 404 when AutoRemove won the race; exit code is then unknown
            return
        if isinstance(res, dict) and res.get("StatusCode") is not None:
            out["code"] = int(res["StatusCode"])

    def _session(self, container: Any, plan: Plan, buf: _Capture) -> int | None:
        code: int | None = 0
        for index, step in enumerate(plan.steps):
            res = container.exec_run(step, demux=True, user=self.cfg.user, workdir="/tmp", environment=plan.env)
            out, err = res.output if isinstance(res.output, tuple) else (res.output, None)
            buf.add(out, err)
            code = res.exit_code
            if index == 0 and res.exit_code not in (0, None):
                break
        return code

    def _proxy(self, client: Any, plan: Plan) -> ExecResult:
        filters: dict[str, Any] = {"label": ["errow-run-id"], "status": "running"}
        candidates = [c for c in client.containers.list(filters=filters)
                      if (getattr(c, "labels", {}) or {}).get("vendetta.component") != "errow-mcp-exec"]
        if self.cfg.proxy_run_id:
            candidates = [c for c in candidates if (c.labels or {}).get("errow-run-id") == self.cfg.proxy_run_id]
        if not candidates:
            raise ExecError("no_running_sandbox", "no running Errow run sandbox with Caido is available")
        candidates.sort(key=lambda c: str((getattr(c, "attrs", {}) or {}).get("Created", "")), reverse=True)
        target = candidates[0]
        buf = _Capture(self.cfg.output_max_bytes)
        res = target.exec_run(plan.steps[0], demux=True, user=self.cfg.user, workdir="/tmp", environment=plan.env)
        out, err = res.output if isinstance(res.output, tuple) else (res.output, None)
        buf.add(out, err)
        return buf.result("executed", res.exit_code, plan, str(getattr(target, "id", ""))[:12])

    def _read(self, plan: Plan) -> ExecResult:
        reader = plan.reader or {}
        run = str(reader["run"])
        root = Path(self.cfg.runs_dir).resolve()
        if run in (".", "..") or "/" in run:
            raise ExecError("bad_run", "invalid run name")
        path = (root / run / reader["file"]).resolve()
        if root not in path.parents:
            raise ExecError("bad_run", "run path escapes the runs directory")
        try:
            if path.stat().st_size > 8 * 1024 * 1024:
                raise ExecError("too_large", "artifact exceeds 8 MiB")
            raw = path.read_bytes()
            doc = json.loads(raw)
        except FileNotFoundError as exc:
            raise ExecError("not_found", f"{reader['file']} not found for run") from exc
        except (OSError, ValueError) as exc:
            raise ExecError("unreadable", f"{reader['file']} unreadable: {type(exc).__name__}") from exc
        body = json.dumps(doc if reader["format"] == "full" else _digest(plan.tool, doc), sort_keys=True)
        buf = _Capture(self.cfg.output_max_bytes)
        buf.add(body.encode(), None)
        return buf.result("executed", 0, plan, None)


def _digest(tool: str, doc: Any) -> dict[str, Any]:
    if tool == "threat_model" and isinstance(doc, dict):
        return {"entries": len(doc), "identities": sorted(doc)[:50],
                "targets": sorted({str(v.get("target")) for v in doc.values() if isinstance(v, dict)})[:50]}
    if isinstance(doc, dict):
        return {k: doc[k] for k in ("schema_version", "run_id", "run_name", "scope", "summary", "completeness") if k in doc} | {
            "entries": len(doc.get("entries", [])), "gaps": len(doc.get("gaps", []))}
    return {"type": type(doc).__name__}


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except Exception:  # noqa: BLE001 - kill/remove after exit are expected to fail with NotFound/Conflict
        pass


class _Capture:
    """Bounded stdout/stderr collector; sha256/bytes describe the raw captured stdout."""

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.out = bytearray()
        self.err = bytearray()
        self.total = 0
        self.overflow = False
        self._lock = threading.Lock()

    def add(self, out: bytes | None, err: bytes | None) -> None:
        with self._lock:
            if out:
                self.total += len(out)
                room = self.cap - len(self.out)
                if len(out) > room:
                    self.overflow = True
                self.out += out[: max(room, 0)]
            if err and len(self.err) < 65536:
                self.err += err[: 65536 - len(self.err)]

    def consume(self, stream: Any, container: Any) -> None:
        try:
            for item in stream:
                out, err = item if isinstance(item, tuple) else (item, None)
                self.add(out, err)
                if self.overflow:
                    _safe(container.kill)
                    return
        except Exception:  # noqa: BLE001 - stream ends with an error when the container is removed
            return

    def result(self, status: str, code: int | None, plan: Plan, cid: str | None, *, error: str | None = None,
               message: str | None = None) -> ExecResult:
        raw = bytes(self.out)
        text = raw.decode("utf-8", errors="replace")
        if plan.post == "trufflehog":
            text = _strip_trufflehog(text)
        if plan.tool == "agent_browser":
            text = text.strip()
        clean = sanitize_text(text)
        return ExecResult(
            status=status, exit_code=code, output=clean, stderr=sanitize_text(bytes(self.err[-4000:]).decode("utf-8", "replace"), 2000),
            truncated=self.overflow or clean.endswith("...[truncated]"),
            output_sha256=hashlib.sha256(raw).hexdigest(), output_bytes=self.total, container=cid,
            error=error, message=message,
        )


def _strip_trufflehog(text: str) -> str:
    kept: list[str] = []
    for line in text.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            kept.append(json.dumps({k: v for k, v in obj.items() if k not in PAYLOAD_KEYS}, sort_keys=True))
    return "\n".join(kept)


def _summary(tool: str, res: ExecResult) -> str:
    head = f"{tool} {res.status}" + (f" exit={res.exit_code}" if res.exit_code is not None else "")
    head += f" bytes={res.output_bytes}" + (" truncated" if res.truncated else "")
    if res.error:
        head += f" error={res.error}"
    first = next((ln.strip() for ln in res.output.splitlines() if ln.strip()), "")
    return sanitize_text((head + (" | " + first if first else "")))[:500]


__all__ = ["ExecConfig", "ExecError", "ExecResult", "Executor", "Plan", "build_plan"]
