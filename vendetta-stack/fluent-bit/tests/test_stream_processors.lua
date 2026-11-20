-- Traces: PROMPT §4 Phase 4 (validation); CONTRACT §3 (edge sanitization), §4.1 (severity map)
-- Unit tests for fluent-bit/stream_processors.lua. Run: luajit fluent-bit/tests/test_stream_processors.lua
-- Also proves the text rules are the SAME as the CS3 gateway filter (deployment/agents/templates/gateway.d/
-- cs3-otlp-normalize.lua) when that file is present in the checkout.

local here = (arg and arg[0] or ""):match("^(.*)/[^/]*$") or "."
local passed, failed = 0, 0

local function check(name, cond, detail)
  if cond then
    passed = passed + 1
    print("ok   - " .. name)
  else
    failed = failed + 1
    print("FAIL - " .. name .. (detail and (": " .. tostring(detail)) or ""))
  end
end

local function eq(name, got, want)
  check(name, got == want, "got=" .. tostring(got) .. " want=" .. tostring(want))
end

local function valid_utf8(s)
  local i, n = 1, #s
  while i <= n do
    local b = s:byte(i)
    local len = (b < 0x80 and 1) or (b >= 0xC2 and b < 0xE0 and 2) or (b >= 0xE0 and b < 0xF0 and 3) or (b >= 0xF0 and b < 0xF5 and 4) or 0
    if len == 0 or i + len - 1 > n then return false end
    for j = i + 1, i + len - 1 do
      local c = s:byte(j)
      if c < 0x80 or c >= 0xC0 then return false end
    end
    i = i + len
  end
  return true
end

local function contains(list, v)
  for _, x in ipairs(list or {}) do if x == v then return true end end
  return false
end

dofile(here .. "/../stream_processors.lua")
local L = CS3_LUA
local MAX = L.get_max_chars()
eq("default CS3_MESSAGE_MAX_CHARS is 8000 (env unset)", MAX, tonumber(os.getenv("CS3_MESSAGE_MAX_CHARS")) or 8000)
L.set_max_chars(8000)

local function sanitize(record, tag)
  local code, _, out = cs3_sanitize(tag or "errow.findings", { sec = 0, nsec = 0 }, record)
  return out, code
end

-- 1. control characters ------------------------------------------------------------------------------------------
do
  local r = sanitize({ message = "a\0b\1c\8d\ta\ne\11f\12g\13h\27[31mi\127j" })
  eq("C0 controls and DEL stripped, \\t and \\n kept", r.message, "abcd\ta\nefgh[31mij")
end

-- 2. UTF-8-safe truncation --------------------------------------------------------------------------------------
do
  local ascii = string.rep("x", 9000)
  local r = sanitize({ message = ascii })
  eq("ASCII truncated to 8000 + marker", #r.message, 8000 + #"...[truncated]")
  check("marker appended", r.message:sub(-14) == "...[truncated]")

  local two = string.rep("a", 7999) .. string.rep("\xC3\xA9", 100)
  local t = sanitize({ message = two })
  check("2-byte char split at the boundary stays valid UTF-8", valid_utf8(t.message))
  check("2-byte truncation ends with marker", t.message:sub(-14) == "...[truncated]")

  local four = string.rep("a", 7998) .. string.rep("\xF0\x9F\x94\x92", 50)
  local f = sanitize({ message = four })
  check("4-byte char split at the boundary stays valid UTF-8", valid_utf8(f.message))
  check("truncated length never exceeds limit + marker", #f.message <= 8000 + 14)

  local exact = sanitize({ message = string.rep("y", 8000) })
  eq("string of exactly 8000 chars untouched", #exact.message, 8000)

  local twice = sanitize(sanitize({ message = ascii }))
  eq("re-sanitising a truncated string is idempotent", twice.message, r.message)

  L.set_max_chars(20)
  local small = sanitize({ message = string.rep("z", 100) })
  eq("limit follows CS3_MESSAGE_MAX_CHARS", small.message, string.rep("z", 20) .. "...[truncated]")
  L.set_max_chars(8000)
end

-- 3. redaction -----------------------------------------------------------------------------------------------------
do
  local cases = {
    { "Authorization: Bearer abc.DEF-123_xyz== trailing", "Authorization: [REDACTED] [REDACTED] trailing" },
    { "curl -H 'bearer ey.J0.sig' http://x", "curl -H 'bearer [REDACTED]' http://x" },
    { "login password=hunter2 ok", "login password=[REDACTED] ok" },
    { "user=bob passwd: s3cret;next", "user=bob passwd: [REDACTED];next" },
    { '{"api_key":"AKIA123","x":1}', '{"api_key":"[REDACTED]","x":1}' },
    { "API-KEY=zzz&b=1", "API-KEY=[REDACTED]&b=1" },
    { "apikey: foo", "apikey: [REDACTED]" },
    { "SECRET = shh", "SECRET = [REDACTED]" },
    { "token=abc123", "token=[REDACTED]" },
    { "nothing to see here", "nothing to see here" },
  }
  for i, c in ipairs(cases) do
    local r = sanitize({ message = c[1] })
    eq("redaction case " .. i, r.message, c[2])
  end
end

-- 4. recursion over every string field ----------------------------------------------------------------------------
do
  local rec = {
    message = "ok",
    rule = { description = "bad\1 token=abc", groups = { "a\2b", "c" } },
    data = { nested = { deeper = { text = "password=pw\3" } }, list = { { s = "Bearer xyz" }, "plain\4" } },
    access_token = "opaque-value",
    ["X-Api-Key"] = "k",
    tokens_in = 42,
    note = "",
    flag = true,
  }
  local r = sanitize(rec)
  eq("nested map string", r.rule.description, "bad token=[REDACTED]")
  eq("array element string", r.rule.groups[1], "ab")
  eq("deep nested string", r.data.nested.deeper.text, "password=[REDACTED]")
  eq("array of maps", r.data.list[1].s, "Bearer [REDACTED]")
  eq("array of strings", r.data.list[2], "plain")
  eq("secret-named field value redacted", r.access_token, "[REDACTED]")
  eq("x-api-key field value redacted", r["X-Api-Key"], "[REDACTED]")
  eq("numbers untouched", r.tokens_in, 42)
  eq("booleans untouched", r.flag, true)
  eq("empty strings untouched", r.note, "")
  check("tokens_in is not treated as secret key", not L.is_secret_key("tokens_in") and not L.is_secret_key("max_tokens"))
  check("authorization is a secret key", L.is_secret_key("Authorization") and L.is_secret_key("refresh_token"))
end

-- 5. hash-chained gateway events are never mutated ---------------------------------------------------------------
do
  for _, tag in ipairs({ "cs3.ai.inference", "cs3.ai.tool_call" }) do
    local rec = { rationale = "token=abc\1", hash = string.rep("a", 64) }
    local out, code = sanitize(rec, tag)
    eq(tag .. " returns 'unchanged'", code, 0)
    eq(tag .. " record untouched", out.rationale, "token=abc\1")
  end
  local out = sanitize({ root_cause = "token=abc" }, "cs3.ai.enrichment")
  eq("cs3.ai.enrichment IS sanitized", out.root_cause, "token=[REDACTED]")
end

-- 6. classify_vendetta ---------------------------------------------------------------------------------------------
local function classify(rec, tag)
  local _, _, out = classify_vendetta(tag or "vendetta.alerts", { sec = 0, nsec = 0 }, rec)
  return out
end
do
  local bands = { [0] = "info", [3] = "info", [4] = "low", [6] = "low", [7] = "medium", [9] = "medium",
                  [10] = "high", [12] = "high", [13] = "critical", [15] = "critical" }
  for level, want in pairs(bands) do
    eq("rule.level " .. level .. " -> " .. want, classify({ rule = { level = level } }).severity, want)
  end
  eq("level 99 -> critical", classify({ rule = { level = 99 } }).severity, "critical")
  eq("missing level keeps a valid severity", classify({ severity = "HIGH" }).severity, "high")

  local fim = classify({ id = "1.1", rule = { id = "550", level = 7, description = "Integrity checksum changed",
    groups = { "ossec", "syscheck", "syscheck_entry_modified" } }, agent = { id = "001", name = "web01" },
    full_log = "File '/etc/passwd' modified" })
  eq("syscheck group -> fim", fim.stream, "fim")
  eq("console source is a string", fim.source, "vendetta")
  eq("console agentName from agent.name", fim.agentName, "web01")
  check("console message carries description + full_log", fim.message:find("Integrity checksum changed", 1, true) and fim.message:find("/etc/passwd", 1, true))
  eq("fields.alert_id", fim.fields.alert_id, "1.1")
  eq("fields.rule_level", fim.fields.rule_level, 7)

  eq("vulnerability-detector group -> vulnerability", classify({ rule = { level = 10, groups = { "vulnerability-detector" } } }).stream, "vulnerability")
  eq("sca group -> sca", classify({ rule = { level = 3, groups = { "sca", "sca_check" } } }).stream, "sca")
  eq("no group -> alerts", classify({ rule = { level = 5, groups = { "authentication_failed" } } }).stream, "alerts")
  eq("string group accepted", classify({ rule = { level = 5, groups = "syscheck" } }).stream, "fim")
  eq("location fallback", classify({ rule = { level = 5 }, location = "syscheck" }).stream, "fim")
  eq("empty record gets default agentName", classify({}).agentName, "vendetta-manager")
end

-- 7. mitre_enrich --------------------------------------------------------------------------------------------------
local function enrich(rec, tag)
  local _, _, out = mitre_enrich(tag, { sec = 0, nsec = 0 }, rec)
  return out
end
do
  check("static map has >= 40 techniques", L.attack_count() >= 40, L.attack_count())
  local a = enrich({ rule = { mitre = { id = { "T1110", "T1110.001" } } } }, "vendetta.alerts")
  check("T1110 -> Credential Access / Brute Force", contains(a.mitre.tactic, "Credential Access") and contains(a.mitre.technique, "Brute Force"))
  eq("sub-technique ids de-duplicated onto the base map", #a.mitre.technique, 1)
  check("original ids kept", contains(a.mitre.id, "T1110") and contains(a.mitre.id, "T1110.001"))
  local b = enrich({ rule = { mitre = { id = "T1078", tactic = { "Persistence" } } } }, "vendetta.fim")
  check("manager-supplied tactic preserved, map adds the rest", contains(b.mitre.tactic, "Persistence") and contains(b.mitre.tactic, "Initial Access"))
  local c = enrich({ rule = { level = 3 } }, "vendetta.alerts")
  eq("no mitre ids -> no mitre object", c.mitre, nil)

  local f = enrich({ properties = { errow = { cwe = "CWE-89" } } }, "errow.findings")
  check("CWE-89 -> T1190 hint", f.mitre_hint and contains(f.mitre_hint.id, "T1190") and contains(f.mitre_hint.tactic, "Initial Access"))
  local g = enrich({ properties = { errow = { cwe = "CWE-78, CWE-79" } } }, "errow.findings")
  check("multiple CWEs merged", contains(g.mitre_hint.id, "T1059") and contains(g.mitre_hint.id, "T1189"))
  local r = enrich({ ruleId = "CWE-89" }, "errow.findings")
  check("CWE taken from SARIF ruleId when properties.errow.cwe is absent", r.mitre_hint and contains(r.mitre_hint.id, "T1190"))
  local h = enrich({ properties = { errow = { cwe = "CWE-99999" } } }, "errow.findings")
  eq("unknown CWE adds nothing", h.mitre_hint, nil)
  check("SARIF keys never renamed by mitre_enrich", f.properties.errow.cwe == "CWE-89")
end

-- 8. errow_normalize -----------------------------------------------------------------------------------------------
local function normalize(rec, tag)
  local _, _, out = errow_normalize(tag, { sec = 0, nsec = 0 }, rec)
  return out
end
do
  local f = normalize({ ruleId = "errow.sqli", level = "error", message = { text = "SQLi" },
    properties = { errow = { severity = "CRITICAL", cwe = "CWE-89", poc = { description = "d", script_available = true, script = "rm -rf /" } } },
    poc_script_code = "payload" }, "errow.findings")
  eq("findings severity from properties.errow.severity", f.severity, "critical")
  eq("stream defaults from tag", f.stream, "findings")
  eq("source defaults to errow", f.source, "errow")
  eq("SARIF ruleId kept", f.ruleId, "errow.sqli")
  eq("SARIF level kept", f.level, "error")
  eq("poc_script_code never forwarded", f.poc_script_code, nil)
  eq("poc.script never forwarded", f.properties.errow.poc.script, nil)
  eq("poc.description kept", f.properties.errow.poc.description, "d")
  eq("SARIF error -> high", normalize({ level = "error" }, "errow.findings").severity, "high")
  eq("SARIF warning -> medium", normalize({ level = "warning" }, "errow.findings").severity, "medium")
  eq("SARIF note -> low", normalize({ level = "note" }, "errow.findings").severity, "low")
  local l = normalize({ model = "m", prompt = "secret prompt", messages = {}, input_tokens = 5, stream = "llm_logs" }, "errow.llm_logs")
  eq("llm prompt body removed", l.prompt, nil)
  eq("llm token counts kept", l.input_tokens, 5)
  eq("existing stream value kept", l.stream, "llm_logs")
end

-- 9. cs3_stamp -----------------------------------------------------------------------------------------------------
do
  local _, _, r = cs3_stamp("cs3.ai.ollama", { sec = 1731405600, nsec = 123456789 }, { message = "x" })
  eq("@timestamp from event time", r["@timestamp"], "2024-11-12T10:00:00.123Z")
  local code = cs3_stamp("cs3.ai.ollama", { sec = 1, nsec = 0 }, { ["@timestamp"] = "keep" })
  eq("existing @timestamp untouched", code, 0)
end

-- 10. parity with the CS3 gateway normalizer ----------------------------------------------------------------------
do
  local cs3 = here .. "/../../../deployment/agents/templates/gateway.d/cs3-otlp-normalize.lua"
  local f = io.open(cs3, "r")
  if f then
    f:close()
    dofile(cs3)
    local samples = {
      "Authorization: Bearer abc.def-ghi== from 10.0.0.1",
      "password=hunter2 passwd: x secret='y' token=\"z\" api_key=k apikey:k2 api-key=k3",
      "ctl\0\1\2chars\127 kept\ttabs\nnewlines",
      string.rep("é", 5000),
      string.rep("a", 7990) .. "\xF0\x9F\x94\x92\xF0\x9F\x94\x92" .. string.rep("b", 50),
      string.rep("a", 12000),
    }
    for i, s in ipairs(samples) do
      local _, _, want = cs3_normalize("v1_logs", { sec = 0, nsec = 0 }, { message = s })
      local got = sanitize({ message = s })
      eq("parity with cs3-otlp-normalize.lua, sample " .. i, got.message, want and want.message)
    end
  else
    print("skip - parity check (cs3-otlp-normalize.lua not present in this checkout)")
  end
end

print(string.format("\n%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
