"""shadow.py - rule shadowing / redundancy analysis by header-space coverage.

Each rule is turned into a union of boxes over (src zone, dst zone, src ip,
dst ip, protocol, src port, dst port, application). A rule is unreachable when
its boxes are fully covered by the UNION of earlier rules (not just one earlier
rule), computed with exact box subtraction. Rules with constructs that are not
modelled (object-groups, FQDNs, schedules, negation, 'established', ICMP types,
user/geo matching, application-default ...) are skipped: they neither report
nor shadow, so results are conservative (missed findings possible, false
positives avoided).
"""
import ipaddress
import itertools
import re
from dataclasses import dataclass, field

M = {"szone": 65535, "dzone": 65535, "src": 2**32 - 1, "dst": 2**32 - 1,
     "proto": 255, "sport": 65535, "dport": 65535, "app": 65535}
def full(d): return [(0, M[d])]
def allip(): return [(0, 2**32 - 1)]

PORTS = {"ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53,
         "bootps": 67, "bootpc": 68, "tftp": 69, "www": 80, "http": 80, "pop3": 110,
         "sunrpc": 111, "ntp": 123, "netbios-ssn": 139, "snmp": 161, "snmptrap": 162,
         "bgp": 179, "ldap": 389, "https": 443, "isakmp": 500, "syslog": 514, "ldaps": 636}
PROTO = {"ip": (0, 255), "icmp": (1, 1), "tcp": (6, 6), "udp": (17, 17), "gre": (47, 47),
         "esp": (50, 50), "ahp": (51, 51), "eigrp": (88, 88), "ospf": (89, 89)}
LOG_OK = {"log", "log-input", "interval", "emergencies", "alerts", "critical", "errors",
          "warnings", "notifications", "informational", "debugging"}

@dataclass
class Rule:
    group: str
    idx: object
    action: str            # "permit" | "deny"
    text: str
    ok: bool = True
    szone: list = field(default_factory=lambda: full("szone"))
    dzone: list = field(default_factory=lambda: full("dzone"))
    src: list = field(default_factory=allip)
    dst: list = field(default_factory=allip)
    app: list = field(default_factory=lambda: full("app"))
    svc: list = field(default_factory=lambda: [(full("proto"), full("sport"), full("dport"))])

def norm(iv):
    out = []
    for lo, hi in sorted(iv):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out

def comp(vals, mx):
    out, prev = [], 0
    for v in sorted(set(vals)):
        if v > prev:
            out.append((prev, v - 1))
        prev = v + 1
    if prev <= mx:
        out.append((prev, mx))
    return out

class Ids:
    """Interns names (zones, applications) as integers."""
    def __init__(self): self.m = {}
    def ivs(self, names, d):
        if not names or "any" in names:
            return full(d)
        ids = [self.m.setdefault(n, len(self.m)) for n in names]
        return norm([(i, i) for i in ids])

# ------------------------------------------------------------ box algebra
def expand(r, cap=4000):
    boxes = []
    for z1, z2, s, d, a in itertools.product(r.szone, r.dzone, r.src, r.dst, r.app):
        for p, sp, dp in r.svc:
            for pp in p:
                for ss in sp:
                    for dd in dp:
                        boxes.append((z1, z2, s, d, pp, ss, dd, a))
                        if len(boxes) > cap:
                            return None
    return boxes

def box_sub(a, b):
    for i in range(len(a)):
        if a[i][1] < b[i][0] or a[i][0] > b[i][1]:
            return [a]
    out, cur = [], list(a)
    for i in range(len(a)):
        lo, hi = cur[i]
        blo, bhi = b[i]
        if lo < blo:
            nb = cur[:]; nb[i] = (lo, blo - 1); out.append(tuple(nb)); lo = blo
        if hi > bhi:
            nb = cur[:]; nb[i] = (bhi + 1, hi); out.append(tuple(nb)); hi = bhi
        cur[i] = (lo, hi)
    return out

def analyze(rules, cap=4000):
    """Return [(rule, kind, blockers)] kind: 'shadowed' (different action) | 'redundant'."""
    hits, earlier = [], []
    for r in rules:
        if not r.ok:
            continue
        boxes = expand(r, cap)
        if boxes is None:
            continue
        remaining, contrib = boxes, []
        for e, eboxes in earlier:
            if not remaining:
                break
            new = []
            for rb in remaining:
                pieces = [rb]
                for eb in eboxes:
                    nxt = []
                    for p in pieces:
                        nxt.extend(box_sub(p, eb))
                    pieces = nxt
                    if not pieces:
                        break
                new.extend(pieces)
            if new != remaining:
                contrib.append(e)
            remaining = new
            if len(remaining) > cap * 4:
                break
        if not remaining and contrib:
            kind = "shadowed" if any(c.action != r.action for c in contrib) else "redundant"
            hits.append((r, kind, contrib))
        earlier.append((r, boxes))
    return hits

# ------------------------------------------------------------ ACL parsing (IOS / NX-OS / ASA)
def _ip(t):
    try:
        return int(ipaddress.IPv4Address(t))
    except ValueError:
        return None

def _addr(tk, i, style):
    if i >= len(tk):
        return None, i
    t = tk[i]
    if t in ("any", "any4"):
        return allip(), i + 1
    if t == "host":
        v = _ip(tk[i + 1]) if i + 1 < len(tk) else None
        return ([(v, v)] if v is not None else None), i + 2
    if "/" in t:
        try:
            n = ipaddress.ip_network(t, strict=False)
        except ValueError:
            return None, i
        if n.version != 4:
            return None, i
        return [(int(n.network_address), int(n.broadcast_address))], i + 1
    v = _ip(t)
    if v is None:
        return None, i
    m = _ip(tk[i + 1]) if i + 1 < len(tk) else None
    if m is None:
        return [(v, v)], i + 1
    wild = m if style == "wild" else (~m & 0xFFFFFFFF)
    if (wild + 1) & wild:
        return None, i                       # non-contiguous mask: not modelled
    lo = v & ~wild & 0xFFFFFFFF
    return [(lo, lo | wild)], i + 2

def _pv(t):
    return int(t) if t.isdigit() else PORTS.get(t)

def _ports(tk, i):
    if i >= len(tk) or tk[i] not in ("eq", "gt", "lt", "neq", "range"):
        return full("sport"), i
    op = tk[i]; i += 1
    if op == "range":
        a = _pv(tk[i]) if i < len(tk) else None
        b = _pv(tk[i + 1]) if i + 1 < len(tk) else None
        if a is None or b is None or a > b:
            return None, i
        return [(a, b)], i + 2
    vals = []
    while i < len(tk) and _pv(tk[i]) is not None:
        vals.append(_pv(tk[i])); i += 1
        if op in ("gt", "lt"):
            break
    if not vals:
        return None, i
    if op == "eq":
        return norm([(v, v) for v in vals]), i
    if op == "gt":
        return [(vals[0] + 1, 65535)], i
    if op == "lt":
        return ([(0, vals[0] - 1)] if vals[0] else None), i
    return comp(vals, 65535), i

def parse_ace(tk, style, std=False):
    if not tk or tk[0] not in ("permit", "deny"):
        return None
    d = {"action": tk[0]}
    if std:
        src, i = _addr(tk, 1, style)
        if src is None or any(t not in LOG_OK for t in tk[i:]):
            return None
        d["src"] = src
        return d
    if len(tk) < 3:
        return None
    pr = tk[1]
    if pr in PROTO:
        proto = [PROTO[pr]]
    elif pr.isdigit() and int(pr) < 256:
        proto = [(int(pr), int(pr))]
    else:
        return None                           # object-group / object / unknown
    src, i = _addr(tk, 2, style)
    if src is None:
        return None
    sp = full("sport")
    if pr in ("tcp", "udp"):
        sp, i = _ports(tk, i)
        if sp is None:
            return None
    dst, i = _addr(tk, i, style)
    if dst is None:
        return None
    dp = full("dport")
    if pr in ("tcp", "udp"):
        dp, i = _ports(tk, i)
        if dp is None:
            return None
    for t in tk[i:]:
        if t not in LOG_OK and not t.isdigit():
            return None                       # established, icmp type, time-range, inactive ...
    d.update(src=src, dst=dst, svc=[(proto, sp, dp)])
    return d

def _mk(group, idx, tk, text, style, std=False):
    a = parse_ace(tk, style, std)
    if a is None:
        return Rule(group, idx, tk[0] if tk and tk[0] in ("permit", "deny") else "?", text, ok=False)
    r = Rule(group, idx, a["action"], text)
    r.src = a["src"]
    if "dst" in a:
        r.dst = a["dst"]
        r.svc = a["svc"]
    return r

def _acl(cfg):
    groups = {}
    for h, ch in cfg.blocks:
        if cfg.vendor in ("ios", "nxos"):
            m = re.match(r"ip access-list (?:(extended|standard) )?(\S+)$", h)
            if m:
                items = []
                for c in ch:
                    tk = c.split(); seq = None
                    if tk and tk[0].isdigit():
                        seq = int(tk[0]); tk = tk[1:]
                    if not tk or tk[0] in ("remark", "statistics", "evaluate"):
                        continue
                    items.append((seq, tk, c))
                if items and all(s is not None for s, _, _ in items):
                    items.sort(key=lambda x: x[0])
                for k, (s, tk, c) in enumerate(items, 1):
                    groups.setdefault(m[2], []).append(
                        _mk(m[2], s if s is not None else k, tk, c, "wild", m[1] == "standard"))
                continue
            m = re.match(r"access-list (\d+) ((?:permit|deny) .*)$", h)
            if m:
                n = int(m[1])
                std = n < 100 or 1300 <= n <= 1999
                lst = groups.setdefault(m[1], [])
                lst.append(_mk(m[1], len(lst) + 1, m[2].split(), h, "wild", std))
        elif cfg.vendor == "asa":
            tk = h.split()
            if tk[0] != "access-list" or len(tk) < 4:
                continue
            name, rest = tk[1], tk[2:]
            if rest[0] == "line":
                rest = rest[2:]
            if not rest or rest[0] == "remark":
                continue
            lst = groups.setdefault(name, [])
            if rest[0] == "extended":
                lst.append(_mk(name, len(lst) + 1, rest[1:], h, "mask"))
            else:
                lst.append(Rule(name, len(lst) + 1, "?", h, ok=False))
    return groups

# ------------------------------------------------------------ Palo Alto
def _ranges(s, mx=65535):
    out = []
    for part in s.split(","):
        a, _, b = part.partition("-")
        if not a.isdigit() or (b and not b.isdigit()):
            return None
        out.append((int(a), int(b or a)))
    return norm(out)

def _pan(cfg):
    addr, grp, svc = {}, {}, {}
    rules = {}
    for l in cfg.set_lines:
        l = l.replace('"', "")
        m = re.match(r"set address (\S+) ip-netmask (\S+)", l)
        if m:
            try:
                n = ipaddress.ip_network(m[2], strict=False)
                addr[m[1]] = [(int(n.network_address), int(n.broadcast_address))]
            except ValueError:
                addr[m[1]] = None
            continue
        m = re.match(r"set address (\S+) ip-range (\S+)-(\S+)", l)
        if m:
            a, b = _ip(m[2]), _ip(m[3])
            addr[m[1]] = [(a, b)] if a is not None and b is not None and a <= b else None
            continue
        m = re.match(r"set address (\S+) ", l)
        if m:
            addr[m[1]] = None                 # fqdn, wildcard ...
            continue
        m = re.match(r"set address-group (\S+) static (.*)", l)
        if m:
            grp.setdefault(m[1], []).extend(t for t in m[2].split() if t not in "[]")
            continue
        m = re.match(r"set service (\S+) protocol (tcp|udp) port (\S+)", l)
        if m:
            p = PROTO[m[2]]
            dp = _ranges(m[3])
            svc[m[1]] = None if dp is None else ([p], full("sport"), dp)
            continue
        m = re.match(r"set rulebase security rules (\S+) (\S+)\s*(.*)$", l)
        if m:
            toks = [t for t in m[3].split() if t not in "[]"]
            rules.setdefault(m[1], {}).setdefault(m[2], []).extend(toks)

    def res(names, seen=()):
        out = []
        for n in names:
            if n == "any":
                return allip()
            if n in grp and n not in seen:
                sub = res(grp[n], seen + (n,))
                if sub is None:
                    return None
                out += sub
            elif addr.get(n):
                out += addr[n]
            else:
                return None
        return norm(out)

    zones, apps = Ids(), Ids()
    out = []
    unsupported = ("negate-source", "negate-destination", "source-user", "category", "schedule",
                   "source-hip", "destination-hip", "hip-profiles", "disabled")
    for k, (name, r) in enumerate(rules.items(), 1):
        act = r.get("action", ["allow"])[0]
        ru = Rule("security-rules", k, "permit" if act == "allow" else "deny", f"rule {name}")
        ok = True
        for u in unsupported:
            v = r.get(u)
            if v and v not in (["any"], ["no"]):
                ok = False
        ru.szone = zones.ivs(r.get("from", []), "szone")
        ru.dzone = zones.ivs(r.get("to", []), "dzone")
        ru.src = res(r.get("source", ["any"]))
        ru.dst = res(r.get("destination", ["any"]))
        ru.app = apps.ivs(r.get("application", []), "app")
        sv = r.get("service", ["any"])
        alts = []
        for s in sv:
            if s == "any":
                alts.append((full("proto"), full("sport"), full("dport")))
            elif s == "service-http":
                alts.append(([(6, 6)], full("sport"), [(80, 80)]))
            elif s == "service-https":
                alts.append(([(6, 6)], full("sport"), [(443, 443)]))
            elif svc.get(s):
                alts.append(svc[s])
            else:
                ok = False                    # application-default / unknown service
        ru.svc = alts or ru.svc
        ru.ok = ok and ru.src is not None and ru.dst is not None
        out.append(ru)
    return {"security-rules": out} if out else {}

# ------------------------------------------------------------ FortiGate
FG_SVC = {"ALL": [(full("proto"), full("sport"), full("dport"))],
          "ALL_TCP": [([(6, 6)], full("sport"), full("dport"))],
          "ALL_UDP": [([(17, 17)], full("sport"), full("dport"))],
          "ALL_ICMP": [([(1, 1)], full("sport"), full("dport"))],
          "PING": [([(1, 1)], full("sport"), full("dport"))]}
for _n, _p, _d in (("HTTP", 6, 80), ("HTTPS", 6, 443), ("SSH", 6, 22), ("TELNET", 6, 23),
                   ("FTP", 6, 21), ("SMTP", 6, 25), ("NTP", 17, 123), ("SYSLOG", 17, 514),
                   ("LDAP", 6, 389), ("RDP", 6, 3389), ("SMB", 6, 445)):
    FG_SVC[_n] = [([(_p, _p)], full("sport"), [(_d, _d)])]
FG_SVC["DNS"] = [([(6, 6)], full("sport"), [(53, 53)]), ([(17, 17)], full("sport"), [(53, 53)])]

def _fg_net(e):
    if "subnet" in e and len(e["subnet"]) >= 2:
        a, m = _ip(e["subnet"][0]), _ip(e["subnet"][1])
        if a is None or m is None:
            return None
        wild = ~m & 0xFFFFFFFF
        if (wild + 1) & wild:
            return None
        lo = a & m
        return [(lo, lo | wild)]
    if "start-ip" in e and "end-ip" in e:
        a, b = _ip(e["start-ip"][0]), _ip(e["end-ip"][0])
        return [(a, b)] if a is not None and b is not None and a <= b else None
    return None                               # fqdn, geography, wildcard ...

def _fg(cfg):
    fg = cfg.fg
    addrs, grps = fg.get("firewall address", {}), fg.get("firewall addrgrp", {})
    custom, sgrp = fg.get("firewall service custom", {}), fg.get("firewall service group", {})

    def addr(names, seen=()):
        out = []
        for n in names:
            if n.lower() in ("all", "any"):
                return allip()
            if n in addrs:
                v = _fg_net(addrs[n])
            elif n in grps and n not in seen:
                v = addr(grps[n].get("member", []), seen + (n,))
            else:
                v = None
            if v is None:
                return None
            out += v
        return norm(out)

    def service(names, seen=()):
        out = []
        for n in names:
            if n in FG_SVC:
                out += FG_SVC[n]
            elif n in custom:
                e = custom[n]
                proto = e.get("protocol", ["TCP/UDP/SCTP"])[0]
                if proto == "ICMP":
                    out.append(([(1, 1)], full("sport"), full("dport")))
                elif proto == "IP":
                    pn = int(e.get("protocol-number", ["0"])[0])
                    out.append(([(pn, pn)], full("sport"), full("dport")))
                else:
                    for key, pv in (("tcp-portrange", 6), ("udp-portrange", 17)):
                        for t in e.get(key, []):
                            d, _, s = t.partition(":")
                            dp, sp = _ranges(d), (_ranges(s) if s else full("sport"))
                            if dp is None or sp is None:
                                return None
                            out.append(([(pv, pv)], sp, dp))
            elif n in sgrp and n not in seen:
                sub = service(sgrp[n].get("member", []), seen + (n,))
                if sub is None:
                    return None
                out += sub
            else:
                return None
        return out or None

    zones = Ids()
    out = []
    pol = fg.get("firewall policy", {})
    for k, (pid, e) in enumerate(pol.items(), 1):
        act = e.get("action", ["deny"])[0]
        name = e.get("name", [""])[0]
        r = Rule("firewall policy", pid, "permit" if act == "accept" else "deny",
                 f"policy {pid}" + (f" ({name})" if name else ""))
        ok = e.get("status", ["enable"])[0] == "enable"
        for key in ("srcaddr-negate", "dstaddr-negate", "service-negate", "internet-service",
                    "internet-service-src"):
            if e.get(key, ["disable"])[0] == "enable":
                ok = False
        if e.get("schedule", ["always"])[0] != "always" or e.get("users") or e.get("groups") \
                or e.get("fsso-groups"):
            ok = False
        r.szone = zones.ivs(e.get("srcintf", []), "szone")
        r.dzone = zones.ivs(e.get("dstintf", []), "dzone")
        r.src = addr(e.get("srcaddr", []))
        r.dst = addr(e.get("dstaddr", []))
        sv = service(e.get("service", []))
        if sv:
            r.svc = sv
        r.ok = ok and r.src is not None and r.dst is not None and sv is not None
        out.append(r)
    return {"firewall policy": out} if out else {}

def collect(cfg):
    """Return {group_name: [Rule, ...]} for a parsed Config."""
    if cfg.vendor in ("ios", "nxos", "asa"):
        return _acl(cfg)
    if cfg.vendor == "paloalto":
        return _pan(cfg)
    if cfg.vendor == "fortinet":
        return _fg(cfg)
    return {}

def findings(cfg):
    """Yield (group, hit_kind, rule, blockers) for a parsed Config."""
    for group, rules in collect(cfg).items():
        for r, kind, blockers in analyze(rules):
            yield group, kind, r, blockers
