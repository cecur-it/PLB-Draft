# Traces: PROMPT §2.3 (Errow as MCP server: tool allow-lists), §2.5 (guardrails column: MCP policy stage); CONTRACT §4.5 (mcp_policy.yaml),
#         §4.4 (rate budget: 10/min per tenant, 100/min per replica, 4 concurrent).
"""Loads mcp_policy.yaml exactly as written and evaluates tool calls in the order documented in its header:
tool/role -> args (declared, typed, enum/pattern/max) -> forbidden args -> denied CIDR/host/port -> allow-list -> (rate limits live in RateLimiter).

Default deny. `denied` always wins. MCP_TARGETS_FILE can only ADD allow-list entries. Extra fail-safe rules beyond the YAML:
loopback/unspecified/link-local/multicast addresses are always denied, '..' path segments are refused, and hostnames that
resolve to ANY denied address are refused (unresolvable names are not a violation; allow-listing stays by name/CIDR).
"""
from __future__ import annotations

import asyncio
import ipaddress
import math
import posixpath
import re
import socket
import time
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterator, Mapping
from urllib.parse import urlsplit

import yaml

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], Awaitable[list[str]]]

TARGET_KINDS = ("host", "domain", "url", "repo_path", "none")
ARG_TYPES = ("string", "integer", "number", "boolean", "array", "object")
ROLES = ("triage", "forensic")
EXTENSION_KEYS = ("hostnames", "cidrs", "domains", "repo_paths")
DEFAULT_STRING_MAX = 2048
MAX_FILE_BYTES = 256 * 1024
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_HOSTNAME = re.compile(r"^[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9_])?$")
_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.I)


class PolicyError(Exception):
    """mcp_policy.yaml or MCP_TARGETS_FILE is malformed; the gateway refuses to start."""


@dataclass(frozen=True)
class ArgSpec:
    name: str
    type: str
    required: bool = False
    enum: tuple[Any, ...] | None = None
    pattern: re.Pattern[str] | None = None
    max: float | None = None
    min: float | None = None
    items: "ArgSpec | None" = None


@dataclass(frozen=True)
class TargetSet:
    hostnames: tuple[str, ...] = ()
    cidrs: tuple[IPNetwork, ...] = ()
    domains: tuple[str, ...] = ()
    repo_paths: tuple[str, ...] = ()

    def extended(self, other: "TargetSet") -> "TargetSet":
        return TargetSet(
            hostnames=self.hostnames + tuple(h for h in other.hostnames if h not in self.hostnames),
            cidrs=self.cidrs + tuple(c for c in other.cidrs if c not in self.cidrs),
            domains=self.domains + tuple(d for d in other.domains if d not in self.domains),
            repo_paths=self.repo_paths + tuple(p for p in other.repo_paths if p not in self.repo_paths),
        )


@dataclass(frozen=True)
class ToolSpec:
    name: str
    roles: tuple[str, ...]
    sandbox: str
    target_kind: str
    timeout_s: int
    args: Mapping[str, ArgSpec]
    forbidden_args: tuple[str, ...] = ()
    forbidden_tag_values: tuple[str, ...] = ()
    rate_per_target_per_minute: int | None = None
    rate_per_minute: int | None = None
    screenshot_retention_days_default: int | None = None
    targets: TargetSet | None = None


@dataclass(frozen=True)
class Limits:
    per_tenant_per_minute: int
    cluster_per_minute: int
    per_target_per_minute: int
    max_concurrent: int


@dataclass(frozen=True)
class Denied:
    cidrs: tuple[IPNetwork, ...]
    hostnames: tuple[str, ...]
    ports: frozenset[int]


@dataclass(frozen=True)
class ParsedTarget:
    raw: str
    host: str | None = None
    ip: IPAddress | None = None
    network: IPNetwork | None = None
    port: int | None = None
    path: str | None = None

    @property
    def key(self) -> str:
        if self.network is not None:
            return str(self.network)
        if self.ip is not None:
            return str(self.ip)
        return self.host or self.path or self.raw


@dataclass
class Decision:
    violations: list[str] = field(default_factory=list)
    tool: ToolSpec | None = None
    target: ParsedTarget | None = None
    args: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return not self.violations


def _safe(text: object, limit: int = 48) -> str:
    return re.sub(r"[^A-Za-z0-9_.:/=@*-]", "?", str(text))[:limit]


def _as_list(value: Any, what: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PolicyError(f"{what} must be a list")
    return value


def _as_int(value: Any, what: str, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise PolicyError(f"{what} must be an integer >= {minimum}")
    return value


def _network(text: Any, what: str) -> IPNetwork:
    try:
        return ipaddress.ip_network(str(text), strict=False)
    except ValueError as exc:
        raise PolicyError(f"{what}: invalid CIDR {text!r}") from exc


def _arg_spec(name: str, raw: Any, tool: str) -> ArgSpec:
    if not isinstance(raw, dict):
        raise PolicyError(f"tool {tool} arg {name}: spec must be a mapping")
    arg_type = raw.get("type")
    if arg_type not in ARG_TYPES:
        raise PolicyError(f"tool {tool} arg {name}: type must be one of {', '.join(ARG_TYPES)}")
    pattern = None
    if "pattern" in raw:
        try:
            pattern = re.compile(str(raw["pattern"]))
        except re.error as exc:
            raise PolicyError(f"tool {tool} arg {name}: invalid pattern: {exc}") from exc
    enum = tuple(raw["enum"]) if isinstance(raw.get("enum"), list) else None
    items = _arg_spec(f"{name}[]", raw["items"], tool) if isinstance(raw.get("items"), dict) else None
    limit = raw.get("max")
    lower = raw.get("min")
    for label, value in (("max", limit), ("min", lower)):
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)):
            raise PolicyError(f"tool {tool} arg {name}: {label} must be a number")
    return ArgSpec(name=name, type=arg_type, required=raw.get("required") is True, enum=enum, pattern=pattern, max=limit, min=lower, items=items)


def _target_set(raw: Any, what: str, *, strict_keys: bool) -> TargetSet:
    if raw is None:
        return TargetSet()
    if not isinstance(raw, dict):
        raise PolicyError(f"{what} must be a mapping")
    unknown = set(raw) - set(EXTENSION_KEYS)
    if unknown and strict_keys:
        raise PolicyError(f"{what}: unknown keys {sorted(map(str, unknown))}; allowed: {', '.join(EXTENSION_KEYS)}")
    hostnames = []
    for item in _as_list(raw.get("hostnames"), f"{what}.hostnames"):
        text = str(item).strip().lower()
        if not text or text in ("*", "*.*") or not re.fullmatch(r"[a-z0-9_*?.\[\]-]+", text):
            raise PolicyError(f"{what}.hostnames: invalid or too broad entry {item!r}")
        hostnames.append(text)
    cidrs = []
    for item in _as_list(raw.get("cidrs"), f"{what}.cidrs"):
        net = _network(item, f"{what}.cidrs")
        if net.prefixlen == 0:
            raise PolicyError(f"{what}.cidrs: {item!r} is too broad")
        cidrs.append(net)
    domains = []
    for item in _as_list(raw.get("domains"), f"{what}.domains"):
        text = str(item).strip().lower().strip(".")
        if not re.fullmatch(r"[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?", text) or "." not in text:
            raise PolicyError(f"{what}.domains: invalid entry {item!r}")
        domains.append(text)
    repo_paths = []
    for item in _as_list(raw.get("repo_paths"), f"{what}.repo_paths"):
        text = str(item).strip()
        if not text.startswith("/") or text in ("/", "/*") or ".." in text.split("/"):
            raise PolicyError(f"{what}.repo_paths: invalid or too broad entry {item!r}")
        repo_paths.append(text)
    return TargetSet(tuple(hostnames), tuple(cidrs), tuple(domains), tuple(repo_paths))


def _read_yaml(path: Path, what: str) -> Any:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise PolicyError(f"{what} {path} is larger than {MAX_FILE_BYTES} bytes")
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    except OSError as exc:
        raise PolicyError(f"cannot read {what} {path}: {exc.strerror or exc}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"{what} {path} is not valid YAML: {exc}") from exc


class Policy:
    def __init__(self, *, live_env: str, limits: Limits, denied: Denied, targets: TargetSet, tools: Mapping[str, ToolSpec]) -> None:
        self.live_env = live_env
        self.limits = limits
        self.denied = denied
        self.targets = targets
        self.tools = dict(tools)

    @classmethod
    def load(cls, path: Path, targets_file: Path | None = None) -> "Policy":
        doc = _read_yaml(path, "MCP policy")
        if not isinstance(doc, dict):
            raise PolicyError("MCP policy must be a YAML mapping")
        if doc.get("version") != 1:
            raise PolicyError(f"unsupported MCP policy version {doc.get('version')!r}")
        if doc.get("default_action") != "deny":
            raise PolicyError("MCP policy default_action must be 'deny'")
        live_env = doc.get("live_env", "MCP_LIVE")
        if not isinstance(live_env, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", live_env):
            raise PolicyError("MCP policy live_env must be an environment variable name")

        raw_limits = doc.get("limits") or {}
        limits = Limits(
            per_tenant_per_minute=_as_int(raw_limits.get("per_tenant_per_minute", 10), "limits.per_tenant_per_minute"),
            cluster_per_minute=_as_int(raw_limits.get("cluster_per_minute", 100), "limits.cluster_per_minute"),
            per_target_per_minute=_as_int(raw_limits.get("per_target_per_minute", 6), "limits.per_target_per_minute"),
            max_concurrent=_as_int(raw_limits.get("max_concurrent", 4), "limits.max_concurrent"),
        )
        raw_denied = doc.get("denied") or {}
        denied = Denied(
            cidrs=tuple(_network(c, "denied.cidrs") for c in _as_list(raw_denied.get("cidrs"), "denied.cidrs")),
            hostnames=tuple(str(h).strip().lower() for h in _as_list(raw_denied.get("hostnames"), "denied.hostnames")),
            ports=frozenset(_as_int(p, "denied.ports", 1) for p in _as_list(raw_denied.get("ports"), "denied.ports")),
        )
        targets = _target_set(doc.get("targets"), "targets", strict_keys=False)
        if targets_file is not None:
            extension = _read_yaml(targets_file, "MCP_TARGETS_FILE")
            if extension is not None:
                targets = targets.extended(_target_set(extension, "MCP_TARGETS_FILE", strict_keys=True))

        raw_tools = doc.get("tools")
        if not isinstance(raw_tools, dict) or not raw_tools:
            raise PolicyError("MCP policy defines no tools")
        tools: dict[str, ToolSpec] = {}
        for name, raw in raw_tools.items():
            tools[str(name)] = cls._tool(str(name), raw)
        return cls(live_env=live_env, limits=limits, denied=denied, targets=targets, tools=tools)

    @staticmethod
    def _tool(name: str, raw: Any) -> ToolSpec:
        if not isinstance(raw, dict):
            raise PolicyError(f"tool {name} must be a mapping")
        roles = tuple(str(r) for r in _as_list(raw.get("roles"), f"tool {name}.roles"))
        if not roles or any(r not in ROLES for r in roles):
            raise PolicyError(f"tool {name}: roles must be a non-empty subset of {ROLES}")
        kind = raw.get("target_kind")
        if kind not in TARGET_KINDS:
            raise PolicyError(f"tool {name}: target_kind must be one of {TARGET_KINDS}")
        args = {str(k): _arg_spec(str(k), v, name) for k, v in (raw.get("args") or {}).items()}

        def optional_int(key: str) -> int | None:
            return _as_int(raw[key], f"tool {name}.{key}") if raw.get(key) is not None else None

        tool_targets = _target_set(raw["targets"], f"tool {name}.targets", strict_keys=False) if raw.get("targets") is not None else None
        return ToolSpec(
            name=name,
            roles=roles,
            sandbox=str(raw.get("sandbox", "errow-sandbox")),
            target_kind=kind,
            timeout_s=_as_int(raw.get("timeout_s", 60), f"tool {name}.timeout_s"),
            args=args,
            forbidden_args=tuple(str(a) for a in _as_list(raw.get("forbidden_args"), f"tool {name}.forbidden_args")),
            forbidden_tag_values=tuple(str(a).lower() for a in _as_list(raw.get("forbidden_tag_values"), f"tool {name}.forbidden_tag_values")),
            rate_per_target_per_minute=optional_int("rate_per_target_per_minute"),
            rate_per_minute=optional_int("rate_per_minute"),
            screenshot_retention_days_default=optional_int("screenshot_retention_days_default"),
            targets=tool_targets,
        )

    async def evaluate(self, role: Any, tool: Any, args: Any, resolver: Resolver) -> Decision:
        spec = self.tools.get(tool) if isinstance(tool, str) else None
        if spec is None:
            return Decision(violations=["tool:unknown"])
        if not isinstance(role, str) or role not in spec.roles:
            return Decision(violations=[f"role:{_safe(role)}_not_permitted_for_{spec.name}"], tool=spec)
        if not isinstance(args, dict):
            return Decision(violations=["args:not_an_object"], tool=spec)

        violations: list[str] = []
        violations += self._check_args(spec, args)
        violations += self._check_forbidden(spec, args)
        raw_target, target_violations = self._extract_target(spec, args)
        violations += target_violations
        parsed = parse_target(raw_target, spec.target_kind) if raw_target is not None else None
        if raw_target is not None and parsed is None:
            violations.append("target:unparseable")
        violations += self._check_ports(parsed, args)
        if parsed is not None:
            violations += self._check_denied(parsed)
            violations += self._check_allowed(spec, parsed)
            if not violations and parsed.ip is None and parsed.network is None and parsed.host and spec.target_kind != "repo_path":
                violations += await self._check_resolution(parsed.host, resolver)

        decision = Decision(violations=violations, tool=spec, target=parsed)
        if not violations:
            decision.args = self._normalise_args(spec, args)
        return decision

    def _check_args(self, spec: ToolSpec, args: Mapping[str, Any]) -> list[str]:
        found: list[str] = []
        for key in args:
            if not isinstance(key, str) or key not in spec.args:
                found.append(f"args:{_safe(key)}:undeclared")
        for name, arg in spec.args.items():
            if name not in args:
                if arg.required:
                    found.append(f"args:{name}:required")
                continue
            found += [f"args:{name}:{code}" for code in _validate_value(arg, args[name])]
        return found

    def _check_forbidden(self, spec: ToolSpec, args: Mapping[str, Any]) -> list[str]:
        found: list[str] = []
        keys = [str(k) for k in _walk_keys(args)]
        values = list(_walk_strings(args))
        folded_keys = {k.casefold().split("=", 1)[0] for k in keys}
        norm_keys = {k.replace("-", "_") for k in folded_keys}
        tokens: set[str] = set()
        for value in values:
            for token in value.split():
                tokens.add(token.casefold())
                if "=" in token:
                    tokens.add(token.split("=", 1)[0].casefold())
        for entry in spec.forbidden_args:
            folded = entry.casefold()
            if folded.startswith("-"):
                hit = folded in folded_keys or folded in tokens
            elif not any(ch.isalnum() for ch in folded):
                hit = any(entry in value for value in values) or any(entry in key for key in keys)
            else:
                hit = folded.replace("-", "_") in norm_keys
            if hit:
                found.append(f"forbidden_arg:{entry[:24]}")
        if spec.forbidden_tag_values:
            tags = set()
            for name in ("tags", "tag"):
                value = args.get(name)
                for item in value if isinstance(value, list) else [value]:
                    if isinstance(item, str):
                        tags.update(t.strip().casefold() for t in item.split(","))
            for hit in sorted(tags & set(spec.forbidden_tag_values)):
                found.append(f"forbidden_tag:{_safe(hit, 24)}")
        return found

    @staticmethod
    def _extract_target(spec: ToolSpec, args: Mapping[str, Any]) -> tuple[str | None, list[str]]:
        kind = spec.target_kind
        if kind == "none":
            return None, []
        names = {"host": ("target",), "domain": ("target",), "url": ("target", "url"), "repo_path": ("repo_path",)}[kind]
        for name in names:
            value = args.get(name)
            if isinstance(value, str) and value.strip():
                return value, []
        return None, ["target:missing"]

    def _check_ports(self, parsed: ParsedTarget | None, args: Mapping[str, Any]) -> list[str]:
        ranges: list[tuple[int, int]] = []
        if parsed is not None and parsed.port is not None:
            ranges.append((parsed.port, parsed.port))
        for name in ("port", "ports"):
            ranges += _port_ranges(args.get(name))
        hits = sorted({p for lo, hi in ranges for p in self.denied.ports if lo <= p <= hi})
        return [f"target:denied_port:{p}" for p in hits]

    def _check_denied(self, target: ParsedTarget) -> list[str]:
        found: list[str] = []
        if target.host:
            for pattern in self.denied.hostnames:
                if fnmatchcase(target.host, pattern):
                    found.append(f"target:denied_hostname:{_safe(pattern)}")
        if target.ip is not None:
            found += self._denied_ip(target.ip)
        if target.network is not None:
            for net in self.denied.cidrs:
                if net.version == target.network.version and net.overlaps(target.network):
                    found.append(f"target:denied_cidr:{net}")
            if target.network.is_loopback or target.network.is_link_local or target.network.is_multicast or target.network.is_unspecified:
                found.append("target:denied_cidr:builtin")
        return found

    def _denied_ip(self, ip: IPAddress) -> list[str]:
        found = [f"target:denied_cidr:{net}" for net in self.denied.cidrs if net.version == ip.version and ip in net]
        if not found and (ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast):
            found.append("target:denied_cidr:builtin")
        return found

    def _check_allowed(self, spec: ToolSpec, target: ParsedTarget) -> list[str]:
        if not _in_targets(target, self.targets, spec.target_kind):
            return ["target:not_allowlisted"]
        if spec.targets is not None and not _in_targets(target, spec.targets, spec.target_kind):
            return ["target:not_allowlisted_for_tool"]
        return []

    async def _check_resolution(self, host: str, resolver: Resolver) -> list[str]:
        found: list[str] = []
        try:
            addresses = await resolver(host)
        except Exception:  # noqa: BLE001 - an unresolvable lab name is judged by name/CIDR allow-listing alone
            addresses = []
        for text in addresses:
            try:
                ip = ipaddress.ip_address(text.split("%", 1)[0])
            except ValueError:
                continue
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
                ip = ip.ipv4_mapped
            if self._denied_ip(ip):
                found.append(f"target:resolves_to_denied:{ip}")
        return sorted(set(found))

    @staticmethod
    def _normalise_args(spec: ToolSpec, args: Mapping[str, Any]) -> dict[str, Any]:
        out = dict(args)
        if spec.screenshot_retention_days_default is not None and args.get("screenshot") is True and "screenshot_retention_days" not in out:
            out["screenshot_retention_days"] = spec.screenshot_retention_days_default
        return out


def _walk_keys(value: Any) -> Iterator[Any]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def _walk_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)


def _enum_contains(enum: tuple[Any, ...], value: Any) -> bool:
    return any(type(candidate) is type(value) and candidate == value for candidate in enum)


def _validate_value(spec: ArgSpec, value: Any, depth: int = 0) -> list[str]:
    kind = spec.type
    if kind == "string":
        valid = isinstance(value, str)
    elif kind == "integer":
        valid = isinstance(value, int) and not isinstance(value, bool)
    elif kind == "number":
        valid = isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    elif kind == "boolean":
        valid = isinstance(value, bool)
    elif kind == "array":
        valid = isinstance(value, list)
    else:
        valid = isinstance(value, dict)
    if not valid:
        return [f"type_{kind}"]
    found: list[str] = []
    if spec.enum is not None and not _enum_contains(spec.enum, value):
        found.append("not_in_enum")
    if kind == "string":
        if _CTRL.search(value):
            found.append("control_chars")
        if len(value) > (spec.max if spec.max is not None else DEFAULT_STRING_MAX):
            found.append("too_long")
        if spec.pattern is not None and not spec.pattern.fullmatch(value):
            found.append("pattern_mismatch")
    elif kind in ("integer", "number"):
        if spec.max is not None and value > spec.max:
            found.append("above_max")
        if value < (spec.min if spec.min is not None else 0):
            found.append("below_min")
    elif kind == "array":
        if spec.max is not None and len(value) > spec.max:
            found.append("too_many_items")
        if spec.items is not None and depth < 3:
            for index, item in enumerate(value):
                found += [f"item{index}_{code}" for code in _validate_value(spec.items, item, depth + 1)]
    return found


def _port_ranges(value: Any) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    if isinstance(value, bool):
        return out
    if isinstance(value, int):
        return [(value, value)]
    items = value if isinstance(value, list) else [value]
    for item in items:
        if isinstance(item, int) and not isinstance(item, bool):
            out.append((item, item))
        elif isinstance(item, str):
            for part in item.split(","):
                match = re.fullmatch(r"\s*(\d{1,5})\s*(?:-\s*(\d{1,5})\s*)?", part)
                if match:
                    lo = int(match.group(1))
                    hi = int(match.group(2) or lo)
                    out.append((min(lo, hi), max(lo, hi)))
    return out


def _unmap(ip: IPAddress) -> IPAddress:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _host_or_ip(text: str) -> tuple[str | None, IPAddress | None]:
    host = (text.split("%", 1)[0] if ":" in text else text).strip().casefold().rstrip(".")
    if not host:
        return None, None
    try:
        return None, _unmap(ipaddress.ip_address(host))
    except ValueError:
        pass
    if _NUMERIC_HOST.match(host):
        try:
            return None, ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None, None
    if ".." in host or not _HOSTNAME.match(host) or any(len(label) > 63 for label in host.split(".")):
        return None, None
    return host, None


def parse_target(raw: str, kind: str) -> ParsedTarget | None:
    """Parses a tool target into host/ip/network/port/path. Returns None when it cannot be interpreted safely."""
    text = raw.strip()
    if not text or len(text) > 2048 or _CTRL.search(text) or any(ch.isspace() for ch in text):
        return None
    if kind == "repo_path":
        if not text.startswith("/") or "//" in text or ".." in text.split("/") or "." in text.split("/"):
            return None
        return ParsedTarget(raw=text, path=posixpath.normpath(text))

    port: int | None = None
    path: str | None = None
    if "://" in text:
        try:
            parts = urlsplit(text)
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError:
            return None
        if parts.scheme not in ("http", "https") or "@" in parts.netloc or not parts.hostname:
            return None
        host_text, path = parts.hostname, parts.path or "/"
    else:
        head, sep, tail = text.partition("/")
        if sep and kind != "url":
            try:
                net = ipaddress.ip_network(text, strict=False)
            except ValueError:
                return None
            if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped is not None:
                return None
            return ParsedTarget(raw=text, network=net)
        path = sep + tail if sep else None
        bracket = re.fullmatch(r"\[([0-9A-Fa-f:.%a-zA-Z0-9]+)\](?::(\d{1,5}))?", head)
        if bracket:
            host_text = bracket.group(1)
            port = int(bracket.group(2)) if bracket.group(2) else None
        elif head.count(":") > 1:
            host_text = head
        elif ":" in head:
            host_text, _, port_text = head.rpartition(":")
            if not port_text.isdigit():
                return None
            port = int(port_text)
        else:
            host_text = head
    if port is not None and not 1 <= port <= 65535:
        return None
    host, ip = _host_or_ip(host_text)
    if host is None and ip is None:
        return None
    return ParsedTarget(raw=text, host=host, ip=ip, port=port, path=path)


def _in_targets(target: ParsedTarget, allowed: TargetSet, kind: str) -> bool:
    if kind == "repo_path":
        return target.path is not None and any(fnmatchcase(target.path, pattern) for pattern in allowed.repo_paths)
    if target.network is not None:
        return any(c.version == target.network.version and target.network.subnet_of(c) for c in allowed.cidrs)
    if target.ip is not None:
        return any(c.version == target.ip.version and target.ip in c for c in allowed.cidrs)
    host = target.host or ""
    if any(fnmatchcase(host, pattern) for pattern in allowed.hostnames):
        return True
    return any(host == zone or host.endswith("." + zone) for zone in allowed.domains)


async def system_resolver(host: str, timeout_s: float = 2.0) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=timeout_s)
    except (OSError, asyncio.TimeoutError, UnicodeError):
        return []
    return sorted({str(info[4][0]) for info in infos})


class RateLimiter:
    """Token buckets (capacity == per-minute limit, refill limit/60 per second). A call consumes from every bucket or none."""

    def __init__(self, clock: Callable[[], float] = time.monotonic, max_buckets: int = 20_000) -> None:
        self._clock = clock
        self._max = max_buckets
        self._buckets: dict[tuple[str, ...], tuple[float, float, int]] = {}

    def _level(self, key: tuple[str, ...], limit: int, now: float) -> float:
        tokens, stamp, _ = self._buckets.get(key, (float(limit), now, limit))
        return min(float(limit), tokens + (now - stamp) * limit / 60.0)

    def acquire(self, requirements: list[tuple[tuple[str, ...], int]]) -> str | None:
        """Returns None when all buckets had a token (now consumed), else the name of the exhausted bucket."""
        now = self._clock()
        levels = []
        for key, limit in requirements:
            level = self._level(key, limit, now)
            if level < 1.0:
                return key[0]
            levels.append((key, limit, level))
        for key, limit, level in levels:
            self._buckets[key] = (level - 1.0, now, limit)
        if len(self._buckets) > self._max:
            self._purge(now)
        return None

    def retry_after_s(self, requirements: list[tuple[tuple[str, ...], int]]) -> int:
        now = self._clock()
        waits = [(1.0 - self._level(key, limit, now)) * 60.0 / limit for key, limit in requirements]
        return max(1, math.ceil(max(waits, default=1.0)))

    def _purge(self, now: float) -> None:
        for key in [k for k, (_, stamp, _) in self._buckets.items() if now - stamp > 60.0]:
            del self._buckets[key]


def rate_requirements(policy: Policy, spec: ToolSpec, tenant_id: str, target: ParsedTarget | None) -> list[tuple[tuple[str, ...], int]]:
    reqs: list[tuple[tuple[str, ...], int]] = [
        (("tenant", tenant_id), policy.limits.per_tenant_per_minute),
        (("cluster",), policy.limits.cluster_per_minute),
    ]
    if spec.rate_per_minute is not None:
        reqs.append((("tool", spec.name), spec.rate_per_minute))
    if target is not None:
        reqs.append((("target", target.key), policy.limits.per_target_per_minute))
        if spec.rate_per_target_per_minute is not None:
            reqs.append((("tool_target", spec.name, target.key), spec.rate_per_target_per_minute))
    return reqs
