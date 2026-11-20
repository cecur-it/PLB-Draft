"""errow-mcp policy engine — independent re-implementation of llm-gateway/mcp_policy.yaml.

Evaluation order (header of errow/mcp/policy.yaml), applied to every tools/call:
  1. tool exists and the calling role (triage|forensic) is listed      -> else deny
  2. every arg is declared, typed and inside enum/pattern/max          -> else deny
  3. no forbidden_args / forbidden tag values present                  -> else deny
  4. target matches `denied` (CIDR / hostname / port / DNS answers)    -> deny wins over any allow
  5. target matches the `targets` allow-list (+ MCP_TARGETS_FILE)      -> else deny
  6. rate limits (tenant / cluster / target / tool) + concurrency      -> else rate_limited
  7. execution only when env MCP_LIVE == "true" (caller decides; see Policy.live_enabled)

Defense in depth: this module never trusts the gateway's verdict; the role comes from
`_meta.role`. Violation strings are `<category>:<detail>` (see RUNTIME.md for the list).
MCP_TARGETS_FILE (yaml {hostnames,cidrs,domains,repo_paths}) can only ADD to `targets`.

Traces: PROMPT §2.3, §2.5; CONTRACT §4.5; errow/mcp/policy.yaml header.
"""

from __future__ import annotations

import collections
import concurrent.futures
import fnmatch
import ipaddress
import os
import posixpath
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import yaml

ROLES = ("triage", "forensic")
TARGET_KINDS = ("host", "domain", "url", "repo_path", "none")
ARG_TYPES = ("string", "integer", "boolean", "array")
TARGET_EXT_KEYS = ("hostnames", "cidrs", "domains", "repo_paths")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")

Resolver = Callable[[str], "list[str]"]


class PolicyError(Exception):
    """The policy (or the operator's targets extension) is malformed."""


class RateLimited(Exception):
    def __init__(self, reason: str, retry_after: float) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retry_after = retry_after


@dataclass
class Target:
    kind: str
    raw: str
    host: str | None = None
    port: int | None = None
    network: Any = None
    path: str | None = None
    scheme: str | None = None
    explicit_port: bool = False

    @property
    def key(self) -> str:
        if self.network is not None:
            return str(self.network)
        return self.path or self.host or self.raw


@dataclass
class Decision:
    tool: str
    role: str | None
    allowed: bool = False
    violations: list[str] = field(default_factory=list)
    target: Target | None = None
    args: dict[str, Any] = field(default_factory=dict)
    resolved: dict[str, list[str]] = field(default_factory=dict)
    spec: dict[str, Any] | None = None

    @property
    def target_key(self) -> str | None:
        return self.target.key if self.target else None


class Admission:
    """Concurrency slot returned by Policy.admit(); release() is idempotent."""

    def __init__(self, limiter: RateLimiter) -> None:
        self._limiter = limiter
        self._released = False

    def release(self) -> None:
        if not self._released:
            self._released = True
            self._limiter.release()

    def __enter__(self) -> Admission:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


def system_resolver(host: str, timeout: float = 3.0) -> list[str]:
    """getaddrinfo with a hard wall-clock timeout; raises OSError when nothing resolves."""
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = pool.submit(socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM)
    try:
        infos = future.result(timeout=timeout)
    except concurrent.futures.TimeoutError as exc:
        raise OSError(f"dns timeout for {host}") from exc
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    seen: list[str] = []
    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]
        if addr not in seen:
            seen.append(addr)
    if not seen:
        raise OSError(f"no addresses for {host}")
    return seen


def _embedded_v4(ip: Any) -> list[Any]:
    """IPv4 addresses hidden inside an IPv6 literal (mapped, 6to4, Teredo, NAT64)."""
    if ip.version != 6:
        return []
    found = []
    if ip.ipv4_mapped is not None:
        found.append(ip.ipv4_mapped)
    if ip.sixtofour is not None:
        found.append(ip.sixtofour)
    if ip.teredo is not None:
        found.extend(ip.teredo)
    if ip in _NAT64:
        found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return found


class RateLimiter:
    """Sliding 60 s windows keyed by (scope, key) plus a concurrency cap; clock is injectable."""

    def __init__(self, limits: dict[str, int], clock: Callable[[], float] = time.monotonic) -> None:
        self._limits = limits
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: dict[tuple[str, str], collections.deque[float]] = {}
        self._running = 0

    @property
    def running(self) -> int:
        return self._running

    def _count(self, key: tuple[str, str], now: float) -> tuple[int, float]:
        window = self._hits.get(key)
        if window is None:
            return 0, 0.0
        while window and now - window[0] >= 60.0:
            window.popleft()
        if not window:
            del self._hits[key]
            return 0, 0.0
        return len(window), 60.0 - (now - window[0])

    def admit(self, checks: list[tuple[str, str, int]]) -> Admission:
        now = self._clock()
        with self._lock:
            if self._running >= self._limits["max_concurrent"]:
                raise RateLimited("rate:concurrency", 1.0)
            for scope, key, limit in checks:
                count, retry = self._count((scope, key), now)
                if count >= limit:
                    raise RateLimited(f"rate:{scope}", max(retry, 1.0))
            for scope, key, _limit in checks:
                self._hits.setdefault((scope, key), collections.deque()).append(now)
            self._running += 1
            if len(self._hits) > 4096:
                for key in list(self._hits):
                    self._count(key, now)
        return Admission(self)

    def release(self) -> None:
        with self._lock:
            self._running = max(0, self._running - 1)


def _tokens(value: str) -> list[str]:
    out: list[str] = []
    for tok in value.split():
        out.append(tok)
        if "=" in tok:
            out.append(tok.split("=", 1)[0])
    return out


def _norm_key(name: str) -> str:
    return name.lower().lstrip("-").replace("-", "_")


class Policy:
    def __init__(
        self,
        doc: dict[str, Any],
        *,
        targets_file: str | None = None,
        resolver: Resolver | None = None,
        clock: Callable[[], float] = time.monotonic,
        dns_timeout: float = 3.0,
        max_target_hosts: int = 256,
    ) -> None:
        self.doc = self._validate(doc)
        self.tools: dict[str, dict[str, Any]] = self.doc["tools"]
        self.live_env: str = self.doc.get("live_env", "MCP_LIVE")
        self.limits: dict[str, int] = self.doc["limits"]
        self._resolver = resolver or (lambda host: system_resolver(host, dns_timeout))
        self._max_hosts = max_target_hosts
        self.limiter = RateLimiter(self.limits, clock)
        denied = self.doc["denied"]
        self.denied_nets = [ipaddress.ip_network(c) for c in denied.get("cidrs", [])]
        self.denied_hosts = [h.lower() for h in denied.get("hostnames", [])]
        self.denied_ports = {int(p) for p in denied.get("ports", [])}
        self._base_targets = self.doc.get("targets", {})
        self._targets_file = targets_file
        self._ext_mtime = -1.0
        self._ext: dict[str, list[str]] = {k: [] for k in TARGET_EXT_KEYS}
        self.targets_error: str | None = None
        if targets_file:
            self._load_extension(strict=True)

    @classmethod
    def load(cls, path: str | os.PathLike[str], **kwargs: Any) -> Policy:
        try:
            doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"cannot load policy {path}: {exc}") from exc
        return cls(doc, **kwargs)

    # ------------------------------------------------------------------ loading / validation
    @staticmethod
    def _validate(doc: Any) -> dict[str, Any]:
        if not isinstance(doc, dict):
            raise PolicyError("policy must be a mapping")
        if doc.get("version") != 1:
            raise PolicyError("unsupported policy version (expected 1)")
        if doc.get("default_action") != "deny":
            raise PolicyError("default_action must be deny")
        limits = doc.get("limits")
        keys = ("per_tenant_per_minute", "cluster_per_minute", "per_target_per_minute", "max_concurrent")
        if not isinstance(limits, dict) or any(
            not isinstance(limits.get(k), int) or isinstance(limits.get(k), bool) or limits[k] < 1
            for k in keys
        ):
            raise PolicyError(f"limits must define positive integers: {', '.join(keys)}")
        denied = doc.get("denied")
        if not isinstance(denied, dict):
            raise PolicyError("denied section missing")
        for cidr in denied.get("cidrs", []):
            try:
                ipaddress.ip_network(cidr)
            except ValueError as exc:
                raise PolicyError(f"bad denied cidr {cidr!r}") from exc
        tools = doc.get("tools")
        if not isinstance(tools, dict) or not tools:
            raise PolicyError("tools section missing")
        for name, spec in tools.items():
            if not isinstance(spec, dict):
                raise PolicyError(f"tool {name}: spec must be a mapping")
            if not spec.get("roles") or any(r not in ROLES for r in spec["roles"]):
                raise PolicyError(f"tool {name}: roles must be a subset of {ROLES}")
            if spec.get("target_kind") not in TARGET_KINDS:
                raise PolicyError(f"tool {name}: bad target_kind")
            if not isinstance(spec.get("timeout_s"), int) or spec["timeout_s"] < 1:
                raise PolicyError(f"tool {name}: timeout_s must be a positive integer")
            for arg, aspec in (spec.get("args") or {}).items():
                if not isinstance(aspec, dict) or aspec.get("type") not in ARG_TYPES:
                    raise PolicyError(f"tool {name}.{arg}: bad type")
                if "pattern" in aspec:
                    try:
                        re.compile(aspec["pattern"])
                    except re.error as exc:
                        raise PolicyError(f"tool {name}.{arg}: bad pattern: {exc}") from exc
            if spec["target_kind"] != "none":
                needed = {"repo_path"} if spec["target_kind"] == "repo_path" else {"target", "url"}
                if not needed & set(spec.get("args") or {}):
                    raise PolicyError(f"tool {name}: target_kind {spec['target_kind']} needs one of {sorted(needed)}")
        return doc

    def _load_extension(self, strict: bool) -> None:
        path = Path(self._targets_file or "")
        try:
            mtime = path.stat().st_mtime
            if mtime == self._ext_mtime:
                return
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict) or set(data) - set(TARGET_EXT_KEYS):
                raise PolicyError(f"only {', '.join(TARGET_EXT_KEYS)} are allowed")
            ext: dict[str, list[str]] = {}
            for key in TARGET_EXT_KEYS:
                items = data.get(key) or []
                if not isinstance(items, list) or any(not isinstance(i, str) or not i for i in items):
                    raise PolicyError(f"{key} must be a list of non-empty strings")
                ext[key] = items
            for cidr in ext["cidrs"]:
                ipaddress.ip_network(cidr, strict=False)
            for pat in ext["repo_paths"]:
                if not pat.startswith("/") or ".." in pat.split("/"):
                    raise PolicyError(f"repo_paths entry {pat!r} must be absolute without ..")
        except (OSError, yaml.YAMLError, ValueError, PolicyError) as exc:
            self.targets_error = f"{path}: {exc}"
            if strict:
                raise PolicyError(f"MCP_TARGETS_FILE unusable: {self.targets_error}") from exc
            return
        self._ext, self._ext_mtime, self.targets_error = ext, mtime, None

    # ------------------------------------------------------------------ accessors
    def live_enabled(self, env: dict[str, str] | None = None) -> bool:
        return (env if env is not None else os.environ).get(self.live_env) == "true"

    def allow_lists(self) -> dict[str, list[str]]:
        if self._targets_file:
            self._load_extension(strict=False)
        merged = {}
        for key in TARGET_EXT_KEYS:
            merged[key] = [str(v) for v in (self._base_targets.get(key) or [])] + self._ext[key]
        return merged

    def input_schema(self, tool: str) -> dict[str, Any]:
        props: dict[str, Any] = {}
        required: list[str] = []
        for name, spec in (self.tools[tool].get("args") or {}).items():
            props[name] = _json_schema(spec)
            if spec.get("required"):
                required.append(name)
        schema: dict[str, Any] = {"type": "object", "properties": props, "additionalProperties": False}
        if required:
            schema["required"] = required
        return schema

    # ------------------------------------------------------------------ evaluation
    def evaluate(self, tool: str, args: Any, role: str | None) -> Decision:
        decision = Decision(tool=str(tool), role=role if isinstance(role, str) else None)
        spec = self.tools.get(tool) if isinstance(tool, str) else None
        if spec is None:
            decision.violations.append("tool:unknown")
            return decision
        decision.spec = spec
        if not isinstance(role, str) or not role:
            decision.violations.append("role:missing")
            return decision
        if role not in ROLES:
            decision.violations.append(f"role:invalid:{_short(role)}")
            return decision
        if role not in spec["roles"]:
            decision.violations.append(f"role:not_allowed:{role}")
            return decision
        if not isinstance(args, dict):
            decision.violations.append("args:not_an_object")
            return decision
        decision.args = dict(args)
        decision.violations.extend(self._check_args(spec, args))
        decision.violations.extend(self._check_forbidden(spec, args))
        if decision.violations:
            return decision
        self._check_target(spec, args, decision)
        decision.allowed = not decision.violations
        return decision

    def admit(self, decision: Decision, tenant: str) -> Admission:
        """Step 6. Raises RateLimited; the caller must release() the returned slot."""
        spec = decision.spec or {}
        checks = [
            ("tenant", tenant, self.limits["per_tenant_per_minute"]),
            ("cluster", "*", self.limits["cluster_per_minute"]),
        ]
        key = decision.target_key
        if key:
            checks.append(("target", key, self.limits["per_target_per_minute"]))
            if "rate_per_target_per_minute" in spec:
                checks.append(("tool_target", f"{decision.tool}|{key}", int(spec["rate_per_target_per_minute"])))
        if "rate_per_minute" in spec:
            checks.append(("tool", decision.tool, int(spec["rate_per_minute"])))
        return self.limiter.admit(checks)

    # -- step 2
    def _check_args(self, spec: dict[str, Any], args: dict[str, Any]) -> list[str]:
        out: list[str] = []
        declared = spec.get("args") or {}
        for name in args:
            if name not in declared:
                out.append(f"arg:{_short(name)}:undeclared")
        for name, aspec in declared.items():
            if name not in args:
                if aspec.get("required"):
                    out.append(f"arg:{name}:required")
                continue
            out.extend(_check_value(name, aspec, args[name]))
        return out

    # -- step 3
    def _check_forbidden(self, spec: dict[str, Any], args: dict[str, Any]) -> list[str]:
        out: list[str] = []
        strings = list(_iter_strings(args))
        keys = {_norm_key(str(k)) for k in args}
        for entry in (str(e) for e in spec.get("forbidden_args") or []):
            if not any(c.isalnum() for c in entry):
                if any(entry in s for s in strings):
                    out.append(f"forbidden_arg:{entry}")
                continue
            flag = entry.startswith("-")
            want = entry if flag else entry.lower()
            hit = _norm_key(entry) in keys
            for s in strings:
                if hit:
                    break
                toks = _tokens(s)
                hit = want in (toks if flag else [t.lower() for t in toks])
            if hit:
                out.append(f"forbidden_arg:{entry}")
        banned = {str(v).lower() for v in spec.get("forbidden_tag_values") or []}
        for value in args.values():
            if banned and isinstance(value, list):
                for item in value:
                    for part in re.split(r"[,\s]+", item.lower()) if isinstance(item, str) else []:
                        if part in banned:
                            out.append(f"forbidden_tag:{part}")
        return list(dict.fromkeys(out))

    # -- steps 4 + 5
    def _check_target(self, spec: dict[str, Any], args: dict[str, Any], decision: Decision) -> None:
        kind = spec["target_kind"]
        if kind == "none":
            return
        if kind == "repo_path":
            self._check_repo_path(spec, str(args["repo_path"]), decision)
            return
        raw = str(args.get("url") if kind == "url" and "url" in args else args["target"])
        allow_url = kind == "url" or (decision.tool == "shell" and args.get("command") == "curl -sI")
        allow_cidr = decision.tool == "nmap"
        allow_port = kind == "url" or decision.tool == "proxy" or (
            decision.tool == "shell" and args.get("command") == "curl -sI"
        )
        try:
            target = self._parse_target(kind, raw, allow_url, allow_cidr)
        except ValueError as exc:
            decision.violations.append(f"target:malformed:{exc}")
            return
        decision.target = target
        v = decision.violations
        v.extend(self._denied_by_name(target))
        for port in self._ports_in_play(target, args):
            if port in self.denied_ports:
                v.append(f"target:denied_port:{port}")
        if target.network is not None:
            for net in self.denied_nets:
                if target.network.version == net.version and target.network.overlaps(net):
                    v.append(f"target:denied_cidr:{net}")
        elif target.host and not v:
            v.extend(self._addresses(target, decision)[1])
        if v:
            return
        if target.explicit_port and not allow_port:
            v.append("target:malformed:port_not_accepted")
            return
        if not self._target_allowed(target):
            v.append(f"target:not_allowed:{_short(target.host or target.raw)}")
            return
        own = spec.get("targets")
        if isinstance(own, dict) and not self._target_allowed(target, own):
            v.append(f"target:not_allowed_for_tool:{_short(target.host or target.raw)}")

    def _check_repo_path(self, spec: dict[str, Any], raw: str, decision: Decision) -> None:
        decision.target = Target("repo_path", raw, path=raw)
        parts = raw.split("/")
        if ".." in parts or "" in parts[1:] or "." in parts:
            decision.violations.append("target:malformed:path_traversal")
            return
        norm = posixpath.normpath(raw)
        if norm != raw or not raw.startswith("/"):
            decision.violations.append("target:malformed:path_not_normalised")
            return
        allowed = self.allow_lists()["repo_paths"]
        if not any(fnmatch.fnmatchcase(norm, pat) for pat in allowed):
            decision.violations.append(f"target:not_allowed:{_short(norm)}")
        own = spec.get("targets")
        if isinstance(own, dict) and not any(
            fnmatch.fnmatchcase(norm, str(p)) for p in own.get("repo_paths", [])
        ):
            decision.violations.append(f"target:not_allowed_for_tool:{_short(norm)}")

    def _parse_target(self, kind: str, raw: str, allow_url: bool, allow_cidr: bool) -> Target:
        if _CONTROL.search(raw) or raw != raw.strip():
            raise ValueError("control_chars")
        if "://" in raw:
            if not allow_url:
                raise ValueError("url_not_accepted")
            parts = urlsplit(raw)
            if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
                raise ValueError("bad_scheme")
            if "@" in parts.netloc or "%" in parts.netloc:
                raise ValueError("bad_authority")
            try:
                port = parts.port
            except ValueError as exc:
                raise ValueError("bad_port") from exc
            host = self._valid_host(parts.hostname or "")
            scheme = parts.scheme.lower()
            return Target(kind, raw, host=host, port=port or (443 if scheme == "https" else 80),
                          scheme=scheme, explicit_port=port is not None)
        if kind == "url" or allow_url:
            host, port = self._split_host_port(raw.partition("/")[0])
            return Target(kind, raw, host=self._valid_host(host), port=port, scheme="http",
                          explicit_port=port is not None)
        if "/" in raw:
            if not allow_cidr:
                raise ValueError("path_not_accepted")
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError as exc:
                raise ValueError("bad_cidr") from exc
            if net.num_addresses > self._max_hosts:
                raise ValueError("range_too_large")
            return Target(kind, raw, network=net)
        host, port = self._split_host_port(raw)
        return Target(kind, raw, host=self._valid_host(host), port=port, explicit_port=port is not None)

    @staticmethod
    def _split_host_port(raw: str) -> tuple[str, int | None]:
        try:
            ipaddress.ip_address(raw)
            return raw, None
        except ValueError:
            pass
        if raw.count(":") == 1:
            host, _, port = raw.partition(":")
            if not port.isdigit() or not 0 < int(port) < 65536:
                raise ValueError("bad_port")
            return host, int(port)
        if ":" in raw:
            raise ValueError("bad_host")
        return raw, None

    @staticmethod
    def _valid_host(host: str) -> str:
        host = host.lower().rstrip(".")
        if not host:
            raise ValueError("empty_host")
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        labels = host.split(".")
        if any(not _LABEL.match(label) for label in labels):
            raise ValueError("bad_host")
        last = labels[-1]
        if last.isdigit() or last.startswith("0x"):
            raise ValueError("numeric_host_form")
        return host

    def _ports_in_play(self, target: Target, args: dict[str, Any]) -> set[int]:
        ports: set[int] = set()
        if target.port:
            ports.add(target.port)
        spec = args.get("ports")
        if isinstance(spec, str):
            for chunk in spec.split(","):
                lo, _, hi = chunk.partition("-")
                if lo.isdigit() and (not hi or hi.isdigit()):
                    start, end = int(lo), int(hi or lo)
                    ports.update(p for p in self.denied_ports if start <= p <= end)
        return ports

    def _denied_by_name(self, target: Target) -> list[str]:
        out: list[str] = []
        host = target.host
        if host is None:
            return out
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            for pat in self.denied_hosts:
                if fnmatch.fnmatchcase(host, pat):
                    out.append(f"target:denied_host:{pat}")
            return out
        out.extend(self._denied_ip(ip))
        return out

    def _denied_ip(self, ip: Any) -> list[str]:
        out = []
        candidates = [ip, *_embedded_v4(ip)]
        for cand in candidates:
            if cand.is_unspecified or cand.is_multicast:
                out.append(f"target:denied_cidr:{cand}")
                continue
            for net in self.denied_nets:
                if cand.version == net.version and cand in net:
                    out.append(f"target:denied_cidr:{net}")
        return list(dict.fromkeys(out))

    def _addresses(self, target: Target, decision: Decision) -> tuple[list[str], list[str]]:
        host = target.host or ""
        try:
            ip = ipaddress.ip_address(host)
            decision.resolved[host] = [str(ip)]
            return [str(ip)], []
        except ValueError:
            pass
        try:
            addrs = self._resolver(host)
        except OSError:
            if target.kind == "domain":
                return [], []
            return [], [f"target:unresolvable:{_short(host)}"]
        decision.resolved[host] = list(addrs)
        problems: list[str] = []
        for addr in addrs:
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                problems.append(f"target:unresolvable:{_short(host)}")
                continue
            problems.extend(self._denied_ip(ip))
        return list(addrs), list(dict.fromkeys(problems))

    def _target_allowed(self, target: Target, lists: dict[str, Any] | None = None) -> bool:
        lists = lists or self.allow_lists()
        hostnames = [str(h).lower() for h in lists.get("hostnames", [])]
        domains = [str(d).lower().strip(".") for d in lists.get("domains", [])]
        cidrs = [ipaddress.ip_network(str(c), strict=False) for c in lists.get("cidrs", [])]
        if target.network is not None:
            return any(
                target.network.version == c.version and target.network.subnet_of(c) for c in cidrs
            )
        host = target.host or ""
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return host in hostnames or any(host == d or host.endswith("." + d) for d in domains)
        return host in hostnames or any(ip.version == c.version and ip in c for c in cidrs)


def _short(value: Any, limit: int = 64) -> str:
    text = _CONTROL.sub("?", str(value))
    return text if len(text) <= limit else text[:limit] + "…"


def _iter_strings(value: Any) -> Any:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _iter_strings(v)


def _check_value(name: str, spec: dict[str, Any], value: Any) -> list[str]:
    kind = spec["type"]
    if kind == "string":
        if not isinstance(value, str):
            return [f"arg:{name}:type"]
        return _check_string(name, spec, value)
    if kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            return [f"arg:{name}:type"]
        if value < int(spec.get("min", 0)):
            return [f"arg:{name}:min"]
        if "max" in spec and value > int(spec["max"]):
            return [f"arg:{name}:max"]
        if "enum" in spec and value not in spec["enum"]:
            return [f"arg:{name}:enum"]
        return []
    if kind == "boolean":
        if not isinstance(value, bool):
            return [f"arg:{name}:type"]
        if "enum" in spec and value not in spec["enum"]:
            return [f"arg:{name}:enum"]
        return []
    if not isinstance(value, list):
        return [f"arg:{name}:type"]
    out: list[str] = []
    if "max" in spec and len(value) > int(spec["max"]):
        out.append(f"arg:{name}:max")
    if spec.get("required") and not value:
        out.append(f"arg:{name}:required")
    items = spec.get("items") or {"type": "string"}
    for item in value:
        out.extend(c.replace(f"arg:{name}:", f"arg:{name}:item_", 1) for c in _check_value(name, items, item))
    return list(dict.fromkeys(out))


def _check_string(name: str, spec: dict[str, Any], value: str) -> list[str]:
    out: list[str] = []
    if _CONTROL.search(value):
        out.append(f"arg:{name}:control_chars")
    if "max" in spec and len(value) > int(spec["max"]):
        out.append(f"arg:{name}:max")
    if "enum" in spec and value not in spec["enum"]:
        out.append(f"arg:{name}:enum")
    if "pattern" in spec and re.fullmatch(spec["pattern"], value) is None:
        out.append(f"arg:{name}:pattern")
    return out


def _json_schema(spec: dict[str, Any]) -> dict[str, Any]:
    kind = spec["type"]
    schema: dict[str, Any] = {"type": kind}
    if kind == "string":
        if "enum" in spec:
            schema["enum"] = list(spec["enum"])
        if "pattern" in spec:
            schema["pattern"] = spec["pattern"]
        if "max" in spec:
            schema["maxLength"] = int(spec["max"])
    elif kind == "integer":
        schema["minimum"] = int(spec.get("min", 0))
        if "max" in spec:
            schema["maximum"] = int(spec["max"])
    elif kind == "boolean":
        if "enum" in spec:
            schema["enum"] = list(spec["enum"])
    else:
        schema["items"] = _json_schema(spec.get("items") or {"type": "string"})
        if "max" in spec:
            schema["maxItems"] = int(spec["max"])
    return schema
