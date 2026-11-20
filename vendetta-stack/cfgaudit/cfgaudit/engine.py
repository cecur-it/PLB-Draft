#!/usr/bin/env python3
"""Offline network-device configuration auditor.

Parses Cisco IOS, NX-OS, ASA, Palo Alto (set-format) and FortiGate configs,
runs hardening checks, and reports findings with severity, remediation and
NIST SP 800-53, DISA STIG and CIS references.
Original code; not affiliated with or derived from any commercial product.
"""
import argparse, datetime, html, json, re, shlex, sys
from dataclasses import dataclass, asdict
from pathlib import Path

SEV = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
MISSING = "<not configured>"

# ---------------------------------------------------------------- parsing
def detect_vendor(text):
    if re.search(r"^set (deviceconfig|rulebase|network|mgt-config|shared)\b", text, re.M):
        return "paloalto"
    if re.search(r"^config (system|firewall|router|log) ", text, re.M) and re.search(r"^\s+set ", text, re.M):
        return "fortinet"
    if re.search(r"^(!Command: show running-config|feature (telnet|ssh|nxapi|tacacs\+|bgp|ospf|vpc|lacp|"
                 r"interface-vlan|hsrp|ntp|dhcp)\b)", text, re.M):
        return "nxos"
    if re.search(r"^ASA Version|^\s+nameif ", text, re.M):
        return "asa"
    if re.search(r"^(version \d|service timestamps|hostname )", text, re.M):
        return "ios"
    return None

def parse_fortios(lines):
    """FortiOS 'config/edit/set/next/end' -> {path: {entry: {key: [tokens]}}} (ordered)."""
    tree, stack = {}, []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tk = shlex.split(line)
        except ValueError:
            tk = line.split()
        if not tk:
            continue
        if tk[0] == "config":
            stack.append(("config", " ".join(tk[1:])))
        elif tk[0] == "edit":
            stack.append(("edit", tk[1] if len(tk) > 1 else ""))
        elif tk[0] == "next":
            while stack and stack.pop()[0] != "edit":
                pass
        elif tk[0] == "end":
            while stack and stack.pop()[0] != "config":
                pass
        elif tk[0] in ("set", "unset") and stack:
            path = " > ".join(n for k, n in stack if k == "config")
            entry = " / ".join(n for k, n in stack if k == "edit")
            d = tree.setdefault(path, {}).setdefault(entry, {})
            if tk[0] == "set" and len(tk) > 1:
                d[tk[1]] = tk[2:]
            elif len(tk) > 1:
                d.pop(tk[1], None)
    return tree

class Config:
    def __init__(self, vendor, name, text):
        self.vendor, self.name = vendor, name
        self.lines = text.splitlines()
        self.blocks = []        # [(header, [children])] for IOS/ASA
        self.set_lines = []     # for Palo Alto
        self.fg = {}            # for FortiGate
        if vendor == "fortinet":
            self.fg = parse_fortios(self.lines)
        elif vendor == "paloalto":
            self.set_lines = [l.strip() for l in self.lines if l.startswith("set ")]
        else:
            for l in self.lines:
                if not l.strip() or l.lstrip().startswith(("!", ":")):
                    continue
                if l[0] in " \t" and self.blocks:
                    self.blocks[-1][1].append(l.strip())
                elif l[0] not in " \t":
                    self.blocks.append((l.strip(), []))

    def fgs(self, path):
        """FortiGate section entries: {entry_name: {key: [tokens]}}."""
        return self.fg.get(path, {})

    @property
    def hostname(self):
        if self.vendor == "fortinet":
            h = self.fgs("system global").get("", {}).get("hostname")
            return h[0] if h else Path(self.name).stem
        pool = self.set_lines if self.vendor == "paloalto" else [b[0] for b in self.blocks]
        pat = r"set deviceconfig system hostname (\S+)" if self.vendor == "paloalto" else r"hostname (\S+)"
        for l in pool:
            m = re.match(pat, l)
            if m: return m[1]
        return Path(self.name).stem

    def top(self, pattern):
        """Top-level lines (IOS/ASA) or set lines (PAN) matching regex."""
        pool = self.set_lines if self.vendor == "paloalto" else [b[0] for b in self.blocks]
        return [l for l in pool if re.search(pattern, l, re.I)]

    def blocks_like(self, pattern):
        return [b for b in self.blocks if re.match(pattern, b[0], re.I)]

def pan_security_rules(cfg):
    rules = {}
    for l in cfg.set_lines:
        m = re.match(r'set rulebase security rules ("[^"]+"|\S+) (\S+)\s*(.*)$', l)
        if m:
            toks = [t for t in m[3].replace('"', "").split() if t not in "[]"]
            rules.setdefault(m[1].strip('"'), {}).setdefault(m[2], []).extend(toks)
    return rules

# ---------------------------------------------------------------- engine
@dataclass
class Rule:
    id: str; title: str; severity: str; vendors: tuple; fix: str
    nist: str = ""; stig: str = ""; cis: str = ""; fn: object = None

@dataclass
class Finding:
    rule_id: str; title: str; severity: str; device: str; vendor: str
    evidence: list; remediation: str; refs: dict

RULES = []
def rule(id, title, severity, vendors, fix, nist="", stig="", cis=""):
    def deco(fn):
        RULES.append(Rule(id, title, severity, tuple(vendors), fix, nist, stig, cis, fn))
        return fn
    return deco

# ---- Cisco IOS
@rule("IOS-001", "Telnet permitted on VTY lines", "High", ["ios"],
      "Use 'transport input ssh' on all line vty ranges.", "AC-17(2), IA-5")
def _(c):
    return [f"{h}: {x}" for h, ch in c.blocks_like(r"line vty") for x in ch
            if re.match(r"transport input .*\b(telnet|all)\b", x)]

@rule("IOS-002", "Enable password weak or missing enable secret", "High", ["ios"],
      "Remove 'enable password'; configure 'enable secret 9 <hash>'.", "IA-5(1)")
def _(c):
    ev = c.top(r"^enable password")
    if not c.top(r"^enable secret"): ev.append("enable secret " + MISSING)
    return ev

@rule("IOS-003", "Password encryption service disabled", "Medium", ["ios"],
      "Enable 'service password-encryption' (obfuscation only; prefer secret-type hashes).", "IA-5(1)")
def _(c):
    return [] if c.top(r"^service password-encryption") else ["service password-encryption " + MISSING]

@rule("IOS-004", "Default SNMP community string", "Critical", ["ios", "asa"],
      "Remove public/private communities; use SNMPv3 with authPriv.", "IA-5, SC-8")
def _(c):
    return c.top(r"^snmp-server community (public|private)\b")

@rule("IOS-005", "SNMP read-write community configured", "High", ["ios"],
      "Remove RW communities or migrate to SNMPv3 with restricted views.", "AC-6, CM-7")
def _(c):
    return c.top(r"^snmp-server community \S+ rw\b")

@rule("IOS-006", "No remote syslog destination", "Medium", ["ios"],
      "Configure 'logging host <ip>' and 'logging trap informational'.", "AU-4, AU-9(2)")
def _(c):
    return [] if c.top(r"^logging (host )?\d") else ["logging host " + MISSING]

@rule("IOS-007", "No NTP server configured", "Low", ["ios", "asa", "paloalto"],
      "Configure at least two authenticated NTP sources.", "AU-8")
def _(c):
    pat = {"ios": r"^ntp server", "asa": r"^ntp server",
           "paloalto": r"^set deviceconfig system ntp-servers"}[c.vendor]
    return [] if c.top(pat) else ["NTP server " + MISSING]

@rule("IOS-008", "Login banner missing", "Low", ["ios", "asa"],
      "Configure a legal warning banner (banner login / banner motd).", "AC-8")
def _(c):
    return [] if c.top(r"^banner (login|motd)") else ["banner " + MISSING]

@rule("IOS-009", "HTTP server enabled", "High", ["ios"],
      "'no ip http server'; use 'ip http secure-server' only if required, with ACL.", "CM-7, SC-8")
def _(c):
    return c.top(r"^ip http server")

@rule("IOS-010", "VTY idle timeout missing or disabled", "Medium", ["ios"],
      "Set 'exec-timeout 10 0' (or per policy) on every vty range.", "AC-12")
def _(c):
    ev = []
    for h, ch in c.blocks_like(r"line vty"):
        t = [x for x in ch if x.startswith("exec-timeout")]
        if not t: ev.append(f"{h}: exec-timeout " + MISSING)
        elif re.match(r"exec-timeout 0 0$", t[0]): ev.append(f"{h}: {t[0]}")
    return ev

@rule("IOS-011", "AAA not enabled", "High", ["ios"],
      "Enable 'aaa new-model' with TACACS+/RADIUS and local fallback.", "IA-2, AC-3")
def _(c):
    return [] if c.top(r"^aaa new-model") else ["aaa new-model " + MISSING]

@rule("IOS-012", "SSH version 2 not enforced", "Medium", ["ios"],
      "Configure 'ip ssh version 2'.", "SC-13, SC-8")
def _(c):
    return [] if c.top(r"^ip ssh version 2") else ["ip ssh version 2 " + MISSING]

@rule("IOS-013", "IP source routing enabled", "Medium", ["ios"],
      "Configure 'no ip source-route'.", "CM-7")
def _(c):
    return [] if c.top(r"^no ip source-route") else ["no ip source-route " + MISSING]

@rule("IOS-014", "ACL permits any any", "High", ["ios"],
      "Replace with least-privilege entries; keep explicit deny with logging.", "AC-4, SC-7")
def _(c):
    ev = c.top(r"^access-list \d+ permit (ip )?any( any)?$|^access-list \d+ permit ip any any")
    for h, ch in c.blocks_like(r"ip access-list"):
        ev += [f"{h}: {x}" for x in ch if re.match(r"(\d+ )?permit ip any any", x)]
    return ev

@rule("IOS-015", "CDP enabled globally", "Low", ["ios"],
      "Configure 'no cdp run' or disable per untrusted interface.", "CM-7")
def _(c):
    return [] if c.top(r"^no cdp run") else ["no cdp run " + MISSING]

@rule("IOS-016", "Local user with reversible or clear-text password", "High", ["ios"],
      "Use 'username <u> secret 9 <hash>'.", "IA-5(1)")
def _(c):
    return [l for l in c.top(r"^username \S+ .*password( [07])? ")
            if " secret " not in l]

@rule("IOS-017", "VTY lines lack access-class restriction", "Medium", ["ios"],
      "Apply 'access-class <acl> in' to vty lines limiting management sources.", "AC-17, SC-7")
def _(c):
    return [f"{h}: access-class " + MISSING for h, ch in c.blocks_like(r"line vty")
            if not any(x.startswith("access-class") for x in ch)]

# ---- Cisco ASA
@rule("ASA-001", "Telnet management enabled", "High", ["asa"],
      "Remove 'telnet' entries; use SSH only.", "AC-17(2)")
def _(c):
    return [l for l in c.top(r"^telnet \S") if not l.startswith("telnet timeout")]

@rule("ASA-002", "HTTP (ASDM) access from broad source", "Medium", ["asa"],
      "Restrict 'http <net> <mask> <if>' to management subnets only.", "AC-17, SC-7")
def _(c):
    return c.top(r"^http (0\.0\.0\.0 0\.0\.0\.0|any)\b")

@rule("ASA-003", "Logging not enabled", "Medium", ["asa"],
      "Configure 'logging enable' and 'logging host <if> <ip>'.", "AU-2, AU-12")
def _(c):
    return [] if c.top(r"^logging enable") else ["logging enable " + MISSING]

@rule("ASA-004", "Access-list permits any any", "High", ["asa"],
      "Replace with specific source/destination/service entries.", "AC-4, SC-7")
def _(c):
    return c.top(r"^access-list \S+ (extended )?permit (ip|tcp|udp) (any4?|0\.0\.0\.0 0\.0\.0\.0) (any4?|0\.0\.0\.0 0\.0\.0\.0)\s*$")

@rule("ASA-005", "SSH allowed from any source / timeout missing", "Medium", ["asa"],
      "Restrict 'ssh' sources; set 'ssh timeout 10' and 'ssh version 2'.", "AC-17, AC-12")
def _(c):
    ev = c.top(r"^ssh (0\.0\.0\.0 0\.0\.0\.0|any)\b")
    if not c.top(r"^ssh timeout"): ev.append("ssh timeout " + MISSING)
    if not c.top(r"^ssh version 2"): ev.append("ssh version 2 " + MISSING)
    return ev

# ---- Palo Alto
@rule("PAN-001", "Security rule allows any source, destination and application", "Critical", ["paloalto"],
      "Scope rule to explicit zones/addresses and App-IDs.", "AC-4, SC-7")
def _(c):
    ev = []
    for n, r in pan_security_rules(c).items():
        g = lambda k: set(r.get(k, []))
        if g("action") == {"allow"} and "any" in g("source") and "any" in g("destination") and "any" in g("application"):
            ev.append(f"rule {n}: any/any/any allow")
    return ev

@rule("PAN-002", "Allow rule without end-of-session logging", "Medium", ["paloalto"],
      "Set 'log-end yes' and a log forwarding profile on allow rules.", "AU-2, AU-12")
def _(c):
    return [f"rule {n}: log-end not enabled" for n, r in pan_security_rules(c).items()
            if "allow" in r.get("action", []) and "yes" not in r.get("log-end", [])]

@rule("PAN-003", "Allow rule without threat-prevention profile", "Medium", ["paloalto"],
      "Attach a security profile group (AV, vulnerability, spyware, URL).", "SI-3, SC-7")
def _(c):
    return [f"rule {n}: no profile-setting" for n, r in pan_security_rules(c).items()
            if "allow" in r.get("action", []) and "profile-setting" not in r]

@rule("PAN-004", "Insecure management services on interface profile", "High", ["paloalto"],
      "Disable telnet and http in interface-management-profile; use ssh/https.", "CM-7, SC-8")
def _(c):
    return c.top(r"interface-management-profile \S+ (telnet|http) yes")

@rule("PAN-005", "Default SNMP community string", "Critical", ["paloalto"],
      "Use SNMPv3.", "IA-5, SC-8")
def _(c):
    return c.top(r"snmp.*community\S*\s+(public|private)\b")

@rule("PAN-006", "No syslog server profile", "Medium", ["paloalto"],
      "Define a syslog server profile and reference it in log settings.", "AU-4, AU-9(2)")
def _(c):
    return [] if c.top(r"^set shared log-settings syslog|^set shared server-profile syslog") else ["syslog " + MISSING]


# ---- Cisco NX-OS
@rule("NXOS-001", "Telnet feature enabled", "High", ["nxos"],
      "Configure 'no feature telnet'; use SSH only.", "CM-7, MA-4")
def _(c):
    return c.top(r"^feature telnet$")

@rule("NXOS-002", "Default SNMP community string", "Critical", ["nxos"],
      "Remove public/private communities; use SNMPv3 (snmp-server user ... auth sha priv aes-128).", "IA-5, SC-8")
def _(c):
    return c.top(r"^snmp-server community (public|private)\b")

@rule("NXOS-003", "No remote syslog server", "Medium", ["nxos"],
      "Configure 'logging server <ip> [severity]'.", "AU-4, AU-9(2)")
def _(c):
    return [] if c.top(r"^logging server \S") else ["logging server " + MISSING]

@rule("NXOS-004", "Fewer than two NTP servers", "Low", ["nxos"],
      "Configure at least two NTP sources ('ntp server <ip> use-vrf <vrf>').", "AU-8")
def _(c):
    n = len(c.top(r"^ntp (server|peer) \S"))
    return [] if n >= 2 else [f"{n} NTP source(s) configured"]

@rule("NXOS-005", "VTY idle timeout missing, disabled or over 10 minutes", "Medium", ["nxos"],
      "Under 'line vty' set 'exec-timeout 10' or lower.", "AC-12, SC-10")
def _(c):
    ev = []
    for h, ch in c.blocks_like(r"line vty"):
        t = [x for x in ch if x.startswith("exec-timeout")]
        v = re.match(r"exec-timeout (\d+)", t[0]) if t else None
        if not t:
            ev.append(f"{h}: exec-timeout " + MISSING)
        elif v and (int(v[1]) == 0 or int(v[1]) > 10):
            ev.append(f"{h}: {t[0]}")
    if not c.blocks_like(r"line vty"):
        ev.append("line vty " + MISSING + " (exec-timeout not set)")
    return ev

@rule("NXOS-006", "Pre-login banner missing", "Low", ["nxos"],
      "Configure 'banner motd' with an approved legal notice.", "AC-8")
def _(c):
    return [] if c.top(r"^banner motd") else ["banner motd " + MISSING]

@rule("NXOS-007", "Unnecessary or non-secure features enabled", "Medium", ["nxos"],
      "Disable unused features: no feature dhcp / wccp / nxapi / imp.", "CM-7")
def _(c):
    return c.top(r"^feature (dhcp|wccp|nxapi|imp)$")

@rule("NXOS-008", "ACL permits any any", "High", ["nxos"],
      "Replace with least-privilege entries and an explicit final deny.", "AC-4, SC-7")
def _(c):
    return [f"{h}: {x}" for h, ch in c.blocks_like(r"ip access-list") for x in ch
            if re.match(r"(\d+ )?permit ip any any\b", x)]

@rule("NXOS-009", "SNMP community with network-admin (read-write) role", "High", ["nxos"],
      "Use read-only roles (network-operator) or SNMPv3 users.", "AC-6, CM-7")
def _(c):
    return c.top(r"^snmp-server community \S+ group network-admin\b")

# ---- Fortinet FortiGate
def _fg_accept(c):
    return {k: e for k, e in c.fgs("firewall policy").items() if e.get("action", ["deny"])[0] == "accept"}

@rule("FGT-001", "Insecure management protocol (telnet/http) in interface allowaccess", "High", ["fortinet"],
      "Remove telnet and http from 'set allowaccess'; use https and ssh only.", "CM-7, SC-8, MA-4")
def _(c):
    return [f"interface {k}: allowaccess includes {t}" for k, e in c.fgs("system interface").items()
            for t in ("telnet", "http") if t in e.get("allowaccess", [])]

@rule("FGT-002", "Policy accepts any source, any destination and ALL services", "Critical", ["fortinet"],
      "Scope the policy to explicit addresses and services.", "AC-4, SC-7")
def _(c):
    return [f"policy {k}: srcaddr all / dstaddr all / service ALL / accept" for k, e in _fg_accept(c).items()
            if {"all"} <= {x.lower() for x in e.get("srcaddr", [])}
            and {"all"} <= {x.lower() for x in e.get("dstaddr", [])}
            and "ALL" in e.get("service", [])]

@rule("FGT-003", "Accept policy does not log all sessions", "Medium", ["fortinet"],
      "Set 'logtraffic all' on accept policies.", "AU-2, AU-12")
def _(c):
    return [f"policy {k}: logtraffic {e.get('logtraffic', ['(default)'])[0]}"
            for k, e in _fg_accept(c).items() if e.get("logtraffic", [""])[0] != "all"]

@rule("FGT-004", "Accept policy without security profiles", "Medium", ["fortinet"],
      "Attach AV / IPS / web filter profiles or a profile group.", "SI-3, SI-4")
def _(c):
    keys = ("av-profile", "ips-sensor", "webfilter-profile", "application-list", "profile-group",
            "dnsfilter-profile", "file-filter-profile")
    return [f"policy {k}: no security profile" for k, e in _fg_accept(c).items()
            if not any(x in e for x in keys)]

@rule("FGT-005", "Default SNMP community name", "Critical", ["fortinet"],
      "Use SNMPv3 users; remove 'public'/'private' communities.", "IA-5, SC-8")
def _(c):
    return [f"snmp community {k}: name {e['name'][0]}" for k, e in c.fgs("system snmp community").items()
            if e.get("name") and e["name"][0].lower() in ("public", "private")]

@rule("FGT-006", "NTP synchronisation not enabled", "Low", ["fortinet"],
      "Enable 'config system ntp' with ntpsync enable and at least one server.", "AU-8")
def _(c):
    e = c.fgs("system ntp").get("", {})
    return [] if e.get("ntpsync", [""])[0] == "enable" else ["system ntp: ntpsync " + MISSING]

@rule("FGT-007", "Admin password policy not enabled", "Medium", ["fortinet"],
      "Configure 'config system password-policy' with status enable and complexity settings.", "IA-5(1)")
def _(c):
    e = c.fgs("system password-policy").get("", {})
    return [] if e.get("status", [""])[0] == "enable" else ["system password-policy: status " + MISSING]

@rule("FGT-008", "No central log destination enabled", "Medium", ["fortinet"],
      "Enable syslogd or FortiAnalyzer logging ('config log syslogd setting' / 'log fortianalyzer setting').", "AU-4, AU-9(2)")
def _(c):
    for p in ("log syslogd setting", "log fortianalyzer setting", "log fortianalyzer2 setting"):
        if c.fgs(p).get("", {}).get("status", [""])[0] == "enable":
            return []
    return ["log syslogd / fortianalyzer " + MISSING]

@rule("FGT-009", "Admin idle timeout over 10 minutes", "Medium", ["fortinet"],
      "Set 'admintimeout 10' (or lower) under 'config system global'.", "AC-12, SC-10")
def _(c):
    v = c.fgs("system global").get("", {}).get("admintimeout", [])
    return [f"system global: admintimeout {v[0]}"] if v and v[0].isdigit() and int(v[0]) > 10 else []

@rule("FGT-010", "Login banner not enabled", "Low", ["fortinet"],
      "Enable pre-login-banner and post-login-banner under 'config system global'.", "AC-8")
def _(c):
    g = c.fgs("system global").get("", {})
    ev = [f"system global: {k} " + MISSING for k in ("pre-login-banner", "post-login-banner")
          if g.get(k, [""])[0] != "enable"]
    return ev

@rule("FGT-011", "Admin account without trusted hosts", "High", ["fortinet"],
      "Set trusthost1..n on every administrator account.", "AC-17, SC-7")
def _(c):
    return [f"admin {k}: no trusthost" for k, e in c.fgs("system admin").items()
            if not any(x.startswith("trusthost") for x in e)]

@rule("FGT-012", "Policy uses ALL as service", "Medium", ["fortinet"],
      "Replace 'ALL' with the specific services required.", "AC-4, CM-7")
def _(c):
    return [f"policy {k}: service ALL" for k, e in _fg_accept(c).items() if "ALL" in e.get("service", [])]

# ---- Shadowing (produced by shadow.py / Batfish, not by a pattern check)
RULES.append(Rule("SHD-001", "Shadowed rule: never matches, blocked by earlier rule(s) with a different action",
                  "High", ("ios", "nxos", "asa", "paloalto", "fortinet"),
                  "Reorder, narrow or delete the rule; confirm the intended policy.", "AC-4, CM-6"))
RULES.append(Rule("SHD-002", "Redundant rule: fully covered by earlier rule(s) with the same action",
                  "Low", ("ios", "nxos", "asa", "paloalto", "fortinet"),
                  "Delete the rule to shorten the rule base.", "CM-6"))

# ---------------------------------------------------------------- mappings
# Only mappings checked against published STIG / CIS listings are included.
# rel: "direct"  = the benchmark item tests essentially what the rule tests
#      "related" = same control area but scope/threshold differs (see note)
# Rules without an entry for a vendor have no verified mapping yet.
STIG_SRC = {
    "ios": "Cisco IOS XE Router NDM STIG V3R4 (Apr 2025); ACL rule from IOS XE Router RTR STIG",
    "asa": "Cisco ASA NDM STIG",
    "paloalto": "Palo Alto Networks NDM STIG V3R3 and ALG STIG V3R4 (Mar 2025)",
    "nxos": "Cisco NX-OS Switch NDM STIG",
    "fortinet": "Fortinet FortiGate Firewall NDM STIG V1R5 (Nov 2025) and FortiGate Firewall STIG",
}
CIS_SRC = {"ios": "CIS Cisco IOS XE 16.x Benchmark v2.2.0 Level 1 (numbering differs in other IOS releases)",
           "nxos": "CIS Cisco NX-OS Benchmark v1.1.0 Level 1 (v1.2.0 renumbers some items)",
           "fortinet": "CIS FortiGate 7.0.x Benchmark v1.4.0 (L1; item 7.3.1 is L2)"}

MAPPINGS = {
 "IOS-001": {"ios": {"STIG": [("V-215845", "CISC-ND-001210", "related")], "CIS": [("1.2.2", "direct")]}},
 "IOS-002": {"ios": {"STIG": [("V-215832", "CISC-ND-000620", "related")], "CIS": [("1.4.1", "direct")]}},
 "IOS-003": {"ios": {"STIG": [("V-215832", "CISC-ND-000620", "direct")], "CIS": [("1.4.2", "direct")]}},
 "IOS-004": {"ios": {"STIG": [("V-215841", "CISC-ND-001130", "related"), ("V-215842", "CISC-ND-001140", "related")],
                     "CIS": [("1.5.2", "direct"), ("1.5.3", "direct")]}},
 "IOS-005": {"ios": {"STIG": [("V-215842", "CISC-ND-001140", "related")], "CIS": [("1.5.4", "direct")]}},
 "IOS-006": {"ios": {"STIG": [("V-220139", "CISC-ND-001450", "related")], "CIS": [("2.2.4", "direct")]}},  # STIG needs two servers
 "IOS-007": {"ios": {"STIG": [("V-215838", "CISC-ND-001030", "related")]}},                                # STIG needs two sources
 "IOS-008": {"ios": {"STIG": [("V-215814", "CISC-ND-000160", "related")], "CIS": [("1.3.2", "related"), ("1.3.3", "related")]}},  # STIG needs DoD text
 "IOS-009": {"ios": {"STIG": [("V-215823", "CISC-ND-000470", "direct")]}},
 "IOS-010": {"ios": {"STIG": [("V-215833", "CISC-ND-000720", "related")], "CIS": [("1.2.8", "related")]}},  # STIG <=5 min, CIS <=10 min
 "IOS-011": {"ios": {"STIG": [("V-215854", "CISC-ND-001370", "related")], "CIS": [("1.1.1", "direct")]}},
 "IOS-012": {"ios": {"STIG": [("V-215845", "CISC-ND-001210", "related")], "CIS": [("2.1.1.2", "direct")]}},
 "IOS-014": {"ios": {"STIG": [("V-216641", "", "related")]}},
 "IOS-015": {"ios": {"CIS": [("2.1.2", "direct")]}},
 "IOS-016": {"ios": {"STIG": [("V-215832", "CISC-ND-000620", "related")], "CIS": [("1.4.3", "direct")]}},
 "IOS-017": {"ios": {"STIG": [("V-215812", "CISC-ND-000140", "direct")], "CIS": [("1.2.5", "direct")]}},
 "ASA-001": {"asa": {"STIG": [("V-239911", "CASA-ND-000430", "direct")]}},
 "ASA-002": {"asa": {"STIG": [("V-239911", "CASA-ND-000430", "related")]}},
 "ASA-003": {"asa": {"STIG": [("V-239943", "", "related")]}},
 "PAN-001": {"paloalto": {"STIG": [("V-228862", "", "related")]}},
 "PAN-002": {"paloalto": {"STIG": [("V-228836", "PANW-AG-000024", "related"), ("V-228866", "PANW-AG-000113", "related")]}},  # STIG scopes deny rules
 "PAN-003": {"paloalto": {"STIG": [("V-228872", "PANW-AG-000120", "related")]}},
 "PAN-004": {"paloalto": {"STIG": [("V-228655", "PANW-NM-000061", "direct")]}},
 "PAN-005": {"paloalto": {"STIG": [("V-228645", "", "related")]}},
 "NXOS-001": {"nxos": {"STIG": [("V-220486", "CISC-ND-000470", "direct")], "CIS": [("1.2.7", "direct")]}},
 "NXOS-002": {"nxos": {"STIG": [("V-220500", "CISC-ND-001130", "related")], "CIS": [("1.5.1", "related")]}},
 "NXOS-003": {"nxos": {"STIG": [("V-220512", "CISC-ND-001310", "direct")]}},
 "NXOS-004": {"nxos": {"STIG": [("V-220498", "CISC-ND-001030", "direct")], "CIS": [("1.7.1", "direct")]}},
 "NXOS-005": {"nxos": {"CIS": [("1.2.5", "direct")]}},
 "NXOS-006": {"nxos": {"CIS": [("1.3.1", "related")]}},
 "NXOS-007": {"nxos": {"STIG": [("V-220486", "CISC-ND-000470", "direct")]}},
 "FGT-001": {"fortinet": {"STIG": [("V-234211", "FGFW-ND-000260", "direct"), ("V-234144", "FNFG-FW-000065", "related"),
                                   ("V-234199", "", "related")], "CIS": [("2.4.5", "direct")]}},
 "FGT-002": {"fortinet": {"STIG": [("", "FNFG-FW-000005", "related")], "CIS": [("3.2", "related")]}},
 "FGT-003": {"fortinet": {"STIG": [("", "FNFG-FW-000020", "related")], "CIS": [("3.4", "direct")]}},
 "FGT-004": {"fortinet": {"CIS": [("4.1.2", "related")]}},
 "FGT-005": {"fortinet": {"STIG": [("V-234201", "", "related")]}},
 "FGT-006": {"fortinet": {"CIS": [("2.1.4", "direct")]}},
 "FGT-007": {"fortinet": {"CIS": [("2.2.1", "direct")]}},
 "FGT-008": {"fortinet": {"STIG": [("V-234218", "", "related")], "CIS": [("7.3.1", "related")]}},
 "FGT-009": {"fortinet": {"STIG": [("V-234214", "FGFW-ND-000275", "direct"), ("V-234213", "", "direct")],
                          "CIS": [("2.4.4", "direct")]}},
 "FGT-010": {"fortinet": {"CIS": [("2.1.1", "direct"), ("2.1.2", "direct")]}},
 "FGT-011": {"fortinet": {"CIS": [("2.4.2", "direct")]}},
 "FGT-012": {"fortinet": {"CIS": [("3.2", "direct")]}},
}

def fmt_map(kind, items):
    out = []
    for it in items:
        if kind == "STIG":
            vid, sid, rel = it
            out.append((f"{vid} ({sid})" if vid and sid else vid or sid) + f" [{rel}]")
        else:
            out.append(f"{it[0]} [{it[1]}]")
    return ", ".join(out)

def build_refs(rule, vendor):
    refs = {"NIST 800-53 (indicative)": rule.nist} if rule.nist else {}
    m = MAPPINGS.get(rule.id, {}).get(vendor, {})
    if m.get("STIG"): refs["STIG"] = fmt_map("STIG", m["STIG"])
    if m.get("CIS"): refs["CIS"] = fmt_map("CIS", m["CIS"])
    return refs

def _shd(rule_id, device, vendor, evidence):
    r = next(x for x in RULES if x.id == rule_id)
    return Finding(r.id, r.title, r.severity, device, vendor, evidence, r.fix, build_refs(r, vendor))

def shadow_findings(cfg):
    """Native header-space shadowing analysis (see shadow.py)."""
    from . import shadow
    by = {}
    for group, kind, r, blockers in shadow.findings(cfg):
        by.setdefault("SHD-001" if kind == "shadowed" else "SHD-002", []).append(
            f"[native] {group} #{r.idx} '{r.text}' ({r.action}) covered by " +
            "; ".join(f"#{b.idx} '{b.text}' ({b.action})" for b in blockers))
    return [_shd(k, cfg.hostname, cfg.vendor, v) for k, v in sorted(by.items())]

def batfish_findings(rows, devices):
    """Convert Batfish filterLineReachability rows into findings; devices: {lower hostname: (name, vendor)}."""
    by = {}
    for r in rows:
        dev, vendor = devices.get(r["node"].lower(), (r["node"], "?"))
        key = "SHD-001" if r["different_action"] else "SHD-002"
        by.setdefault((dev, vendor, key), []).append(
            f"[batfish] {r['filter']}: '{r['line']}' ({r['action']}) unreachable; blocked by "
            + "; ".join(f"'{b}'" for b in r["blockers"]) if r["blockers"] else
            f"[batfish] {r['filter']}: '{r['line']}' ({r['action']}) unreachable ({r['reason']})")
    return [(dev, _shd(k, dev, v, ev)) for (dev, v, k), ev in by.items()]

def audit(cfg, min_sev="Info", shadow=True):
    out = []
    for r in RULES:
        if cfg.vendor not in r.vendors or r.fn is None: continue
        if SEV[r.severity] < SEV[min_sev]: continue
        ev = r.fn(cfg)
        if ev:
            out.append(Finding(r.id, r.title, r.severity, cfg.hostname, cfg.vendor, ev, r.fix,
                               build_refs(r, cfg.vendor)))
    if shadow:
        out += [f for f in shadow_findings(cfg) if SEV[f.severity] >= SEV[min_sev]]
    return sorted(out, key=lambda f: (-SEV[f.severity], f.rule_id))

# ---------------------------------------------------------------- reports
def summarize(results):
    s = {k: 0 for k in SEV}
    for fs in results.values():
        for f in fs: s[f.severity] += 1
    return s

def render_text(results):
    L = ["cfgaudit report - " + datetime.date.today().isoformat(), ""]
    for dev, fs in results.items():
        L += [f"== {dev} ({fs[0].vendor if fs else '-'}) : {len(fs)} findings ==" if fs else f"== {dev}: no findings =="]
        for f in fs:
            L += [f"[{f.severity.upper():8}] {f.rule_id}  {f.title}"]
            L += [f"           evidence: {e}" for e in f.evidence[:5]]
            L.append(f"           fix: {f.remediation}")
            if f.refs:
                L.append("           refs: " + "; ".join(f"{k} {v}" for k, v in f.refs.items()))
            L.append("")
    vs = {f.vendor for fs in results.values() for f in fs}
    L += ["Benchmark sources:"] + [f"  STIG [{v}]: {STIG_SRC[v]}" for v in sorted(vs) if v in STIG_SRC] + \
         [f"  CIS  [{v}]: {CIS_SRC[v]}" for v in sorted(vs) if v in CIS_SRC] + [""]
    L.append("Summary: " + ", ".join(f"{k}={v}" for k, v in reversed(list(summarize(results).items()))))
    return "\n".join(L)

def render_html(results):
    colors = {"Critical": "#b00020", "High": "#e65100", "Medium": "#f9a825", "Low": "#558b2f", "Info": "#546e7a"}
    rows = ""
    for dev, fs in results.items():
        for f in fs:
            ev = "<br>".join(html.escape(e) for e in f.evidence[:5])
            rf = html.escape("; ".join(f"{k} {v}" for k, v in f.refs.items()))
            rows += (f"<tr><td>{html.escape(dev)}</td><td style='color:#fff;background:{colors[f.severity]}'>{f.severity}</td>"
                     f"<td>{f.rule_id}</td><td>{html.escape(f.title)}</td><td><code>{ev}</code></td>"
                     f"<td>{html.escape(f.remediation)}</td><td>{rf}</td></tr>")
    s = summarize(results)
    summ = " | ".join(f"{k}: {v}" for k, v in reversed(list(s.items())))
    return ("<!doctype html><meta charset=utf-8><title>cfgaudit</title><style>body{font:14px sans-serif;margin:2em}"
            "table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 8px;vertical-align:top}"
            "th{background:#eee}</style><h1>cfgaudit report</h1><p>" + summ + "</p><table><tr><th>Device<th>Severity<th>ID"
            "<th>Finding<th>Evidence<th>Remediation<th>References</tr>" + rows + "</table>")

# ---------------------------------------------------------------- CLI
def run_audit(paths, vendor=None, min_severity="Info", shadow="native", batfish_host="localhost"):
    """Audit config files. Returns ({device: [Finding]}, [warning strings]). Used by CLI and GUI."""
    results, devices, used, warns = {}, {}, [], []
    for p in paths:
        try:
            text = Path(p).read_text(errors="replace")
        except OSError as ex:
            warns.append(f"skip {p}: {ex}"); continue
        v = vendor or detect_vendor(text)
        if not v:
            warns.append(f"skip {p}: unknown vendor (use --vendor)"); continue
        cfg = Config(v, p, text)
        results[cfg.hostname] = audit(cfg, min_severity, shadow=shadow in ("native", "both"))
        devices[cfg.hostname.lower()] = (cfg.hostname, v)
        used.append(p)
    if shadow in ("batfish", "both") and used:
        try:
            from . import batfish_bridge
            rows = batfish_bridge.run(used, host=batfish_host)
            for dev, f in batfish_findings(rows, devices):
                if SEV[f.severity] >= SEV[min_severity]:
                    results.setdefault(dev, []).append(f)
                    results[dev].sort(key=lambda x: (-SEV[x.severity], x.rule_id))
        except Exception as ex:               # optional backend: never fail the audit
            warns.append(f"batfish analysis skipped: {type(ex).__name__}: {ex}")
    return results, warns

def render(results, fmt):
    return (render_html(results) if fmt == "html" else
            json.dumps({d: [asdict(f) for f in fs] for d, fs in results.items()}, indent=2) if fmt == "json"
            else render_text(results))

def main(argv=None):
    ap = argparse.ArgumentParser(prog="cfgaudit", description=__doc__.splitlines()[0])
    ap.add_argument("configs", nargs="*", help="config files to audit")
    ap.add_argument("-V", "--vendor", choices=["ios", "nxos", "asa", "paloalto", "fortinet"], help="override auto-detect")
    ap.add_argument("--shadow", choices=["native", "batfish", "both", "off"], default="native",
                    help="rule shadowing analysis backend (default native; batfish needs a running service)")
    ap.add_argument("--batfish-host", default="localhost", help="Batfish service host")
    ap.add_argument("-f", "--format", choices=["text", "json", "html"], default="text")
    ap.add_argument("-o", "--output", help="write report to file")
    ap.add_argument("--min-severity", choices=list(SEV), default="Info")
    ap.add_argument("--fail-on", choices=list(SEV), help="exit 2 if any finding >= severity")
    ap.add_argument("--list-rules", action="store_true")
    a = ap.parse_args(argv)
    if a.list_rules:
        for r in RULES:
            m = MAPPINGS.get(r.id, {})
            n = lambda k: sum(len(v.get(k, [])) for v in m.values())
            print(f"{r.id:8} {r.severity:8} {','.join(r.vendors):18} STIG:{n('STIG')} CIS:{n('CIS')}  {r.title}")
        return 0
    if not a.configs: ap.error("no config files given")
    results, warns = run_audit(a.configs, a.vendor, a.min_severity, a.shadow, a.batfish_host)
    for w in warns:
        print(w, file=sys.stderr)
    out = (render_html(results) if a.format == "html" else
           json.dumps({d: [asdict(f) for f in fs] for d, fs in results.items()}, indent=2) if a.format == "json"
           else render_text(results))
    if a.output: Path(a.output).write_text(out)
    else: print(out)
    if a.fail_on and any(SEV[f.severity] >= SEV[a.fail_on] for fs in results.values() for f in fs):
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
