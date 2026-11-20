"""Plain-assert tests: python3 tests/test_shadow.py"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from cfgaudit import engine as cfgaudit, shadow, batfish_bridge

def cfg(vendor, text): return cfgaudit.Config(vendor, "t.cfg", text)
def hits(c): return [(g, k, r.idx, sorted(b.idx for b in bl)) for g, k, r, bl in shadow.findings(c)]

# 1. union coverage: rule 30 is covered only by 10+20 together
c = cfg("ios", """hostname r
ip access-list extended A
 10 permit tcp 10.2.0.0 0.0.0.127 any eq 22
 20 permit tcp 10.2.0.128 0.0.0.127 any eq 22
 30 deny tcp 10.2.0.0 0.0.0.255 any eq 22
""")
assert hits(c) == [("A", "shadowed", 30, [10, 20])], hits(c)

# 2. partial overlap is NOT reported
c = cfg("ios", """hostname r
ip access-list extended A
 10 permit tcp 10.2.0.0 0.0.0.127 any eq 22
 20 deny tcp 10.2.0.0 0.0.0.255 any eq 22
""")
assert hits(c) == []

# 3. ports: gt / lt / neq / range
c = cfg("ios", """hostname r
ip access-list extended A
 10 permit tcp any any gt 1023
 20 permit tcp any any lt 1024
 30 deny tcp any any range 80 90
 40 deny tcp any any neq 25
""")
assert [(h[1], h[2]) for h in hits(c)] == [("shadowed", 30), ("shadowed", 40)], hits(c)

# 4. unmodelled constructs neither report nor shadow
c = cfg("ios", """hostname r
ip access-list extended A
 10 permit tcp any any established
 20 deny tcp any any eq 80
 30 permit ip 10.0.0.0 0.0.255.0 any
 40 deny ip 10.0.0.0 0.0.255.0 any
""")
assert hits(c) == []          # 'established' and non-contiguous wildcard are skipped, not guessed

# 5. ASA netmask style + object-group skipped
c = cfg("asa", """ASA Version 9.1
hostname a
access-list IN extended permit ip 10.0.0.0 255.0.0.0 any
access-list IN extended deny tcp host 10.1.1.1 any eq 80
access-list IN extended deny tcp object-group X any eq 80
""")
assert [(h[1], h[2]) for h in hits(c)] == [("shadowed", 2)], hits(c)

# 6. FortiGate: disabled policy ignored, absent action = deny, negate unsupported
c = cfg("fortinet", """config firewall policy
    edit 1
        set srcintf "a"
        set dstintf "b"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set status disable
        set action accept
    next
    edit 2
        set srcintf "a"
        set dstintf "b"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
    edit 3
        set srcintf "a"
        set dstintf "b"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTP"
        set action accept
    next
    edit 4
        set srcintf "a"
        set dstintf "b"
        set srcaddr "all"
        set dstaddr "all"
        set srcaddr-negate enable
        set service "HTTPS"
        set action accept
    next
end
""")
assert [(h[1], h[2], h[3]) for h in hits(c)] == [("shadowed", "3", ["2"])], hits(c)

# 7. Palo Alto: application-default is not modelled; distinct zones do not shadow
c = cfg("paloalto", """set rulebase security rules r1 from trust
set rulebase security rules r1 to untrust
set rulebase security rules r1 action allow
set rulebase security rules r2 from dmz
set rulebase security rules r2 to untrust
set rulebase security rules r2 action deny
set rulebase security rules r3 from trust
set rulebase security rules r3 to untrust
set rulebase security rules r3 application ssh
set rulebase security rules r3 service application-default
set rulebase security rules r3 action deny
""")
assert [(h[1], h[2]) for h in hits(c)] == [], hits(c)

# 8. NX-OS prefix syntax and sequence ordering
c = cfg("nxos", """hostname n
ip access-list X
  20 deny tcp 10.1.0.0/16 any eq 80
  10 permit ip 10.0.0.0/8 any
""")
assert [(h[1], h[2]) for h in hits(c)] == [("shadowed", 20)], hits(c)

# 9. Batfish row conversion (row shape from Batfish documentation)
rows = batfish_bridge.rows_from_frame([{
    "Sources": ["as2dept1: RESTRICT_HOST_TRAFFIC_OUT"],
    "Unreachable_Line": "deny ip 1.128.0.0 0.0.255.255 2.128.0.0 0.0.255.255",
    "Unreachable_Line_Action": "DENY", "Blocking_Lines": ["permit ip any 2.128.0.0 0.0.255.255"],
    "Different_Action": True, "Reason": "BLOCKING_LINES", "Additional_Info": None}])
f = cfgaudit.batfish_findings(rows, {"as2dept1": ("as2dept1", "ios")})
assert f[0][1].rule_id == "SHD-001" and "[batfish]" in f[0][1].evidence[0], f
print("all shadow tests passed")
