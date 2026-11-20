-- Traces: PROMPT §1 Tier 1 (edge sanitization + enrichment), CONTRACT §3 (edge sanitization), §4.1 (severity map),
--         §15 (Errow shipper shapes); deployment/agents/templates/gateway.d/cs3-otlp-normalize.lua (same algorithm)
--
-- Fluent Bit 3.2.10 Lua filter library for vendetta-stack. Loaded by conf.d/*.conf through
--   [FILTER] Name lua  script /etc/fluent-bit/stream_processors.lua  call <function>
--
--   cs3_sanitize       CS3 edge guardrail applied RECURSIVELY to EVERY string value of the record (not only `message`):
--                      strip C0 controls except \t \n and DEL, UTF-8-safe truncate to CS3_MESSAGE_MAX_CHARS (default
--                      8000) + "...[truncated]", redact `Bearer <tok>` and (password|passwd|secret|token|api[_-]?key|
--                      apikey|authorization) values. Identical text rules to cs3-otlp-normalize.lua; additionally the
--                      VALUE of a field whose NAME is one of those secret words (access_token, x-api-key, ...) is
--                      redacted. Idempotent, so records re-entering the pipeline (rewrite_tag emitter, multiline
--                      emitter, forward from another edge node) are not mangled.
--   classify_vendetta  derive stream (alerts|fim|vulnerability|sca) from rule.groups, severity from rule.level
--                      (CONTRACT §4.1), and the console-ingest fields (source/message/agentName/fields).
--   mitre_enrich       static ATT&CK technique->tactic map (49 techniques) for vendetta alerts; CWE->ATT&CK hint
--                      (`mitre_hint`) for Errow SARIF findings. Additive only.
--   errow_normalize    non-destructive Errow normalisation: stream/source defaults, `severity` for findings
--                      (CONTRACT §4.1: properties.errow.severity, else SARIF level), defensive removal of exploit
--                      payload bodies / LLM prompt bodies. SARIF field names are NEVER renamed.
--   cs3_stamp          adds @timestamp (ISO-8601 UTC, from the event time) when absent.
--
-- NOT applied to the hash-chained gateway events (cs3.ai.inference, cs3.ai.tool_call): Fluent Bit's Lua bridge drops
-- null values (e.g. fallback_reason:null) and any rewrite would break `hash = sha256(prev_hash + canonical_json(event))`.
-- The gateway emits those pre-sanitized (CONTRACT §4.3) and the filters below refuse to touch them even if matched.
--
-- Lua is LuaJIT (5.1 semantics): no \d in patterns, integers are doubles.

local DEFAULT_MAX_CHARS = 8000
local MAX_CHARS = tonumber(os.getenv("CS3_MESSAGE_MAX_CHARS")) or DEFAULT_MAX_CHARS
local TRUNCATED = "...[truncated]"
local REDACTED = "[REDACTED]"
local MAX_DEPTH = 32

local CHAINED_TAGS = { ["cs3.ai.inference"] = true, ["cs3.ai.tool_call"] = true }

local function ci(word)
  return (word:gsub("%a", function(c) return "[" .. c:lower() .. c:upper() .. "]" end))
end

local SECRET_WORDS = { "password", "passwd", "secret", "token", "api[_-]?key", "apikey", "authorization" }
local KV_PATTERNS = {}
for _, k in ipairs(SECRET_WORDS) do
  local key = k:gsub("%a", function(c) return "[" .. c:lower() .. c:upper() .. "]" end)
  KV_PATTERNS[#KV_PATTERNS + 1] = "(" .. key .. "[\"']?%s*[:=]%s*[\"']?)[^%s\"',&;]+"
end
local BEARER = "(" .. ci("bearer") .. "%s+)[%w%-%._~%+/]+=*"
local BEARER_WORD = ci("bearer")

local function redact(s)
  if s:find(BEARER_WORD, 1, false) then
    s = s:gsub(BEARER, "%1" .. REDACTED)
  end
  if s:find("[:=]") then
    for _, p in ipairs(KV_PATTERNS) do
      s = s:gsub(p, "%1" .. REDACTED)
    end
  end
  return s
end

local function clean(s)
  s = s:gsub("[%z\1-\8\11-\31\127]", "")
  local limit = MAX_CHARS
  if #s > limit then
    -- Already truncated by an earlier hop: leave the marker intact.
    if #s <= limit + #TRUNCATED and s:sub(-#TRUNCATED) == TRUNCATED then
      return s
    end
    s = s:sub(1, limit)
    local i = #s
    while i > 0 do
      local b = s:byte(i)
      if b >= 0x80 and b < 0xC0 then
        i = i - 1
      else
        if b >= 0xC0 then i = i - 1 end
        break
      end
    end
    s = s:sub(1, i) .. TRUNCATED
  end
  return s
end

local function is_secret_key(k)
  if type(k) ~= "string" then return false end
  local norm = k:lower():gsub("[%s%-]+", "_")
  local last = norm:match("([^_]+)$")
  if last == "password" or last == "passwd" or last == "secret" or last == "token"
      or last == "apikey" or last == "authorization" then
    return true
  end
  return norm:match("api_key$") ~= nil
end

local function sanitize_value(v, depth)
  local t = type(v)
  if t == "string" then
    return redact(clean(v))
  end
  if t == "table" and depth < MAX_DEPTH then
    for k, x in pairs(v) do
      local tx = type(x)
      if tx == "string" then
        if x ~= "" and is_secret_key(k) then
          v[k] = REDACTED
        else
          v[k] = redact(clean(x))
        end
      elseif tx == "table" then
        v[k] = sanitize_value(x, depth + 1)
      end
    end
  end
  return v
end

function cs3_sanitize(tag, timestamp, record)
  if CHAINED_TAGS[tag] then
    return 0, timestamp, record
  end
  sanitize_value(record, 0)
  return 2, timestamp, record
end

-- ---------------------------------------------------------------------------------------------------------------
-- helpers shared by the enrichment functions
-- ---------------------------------------------------------------------------------------------------------------
local SEVERITIES = { critical = true, high = true, medium = true, low = true, info = true }

local function severity_from_level(level)
  if level >= 13 then return "critical" end
  if level >= 10 then return "high" end
  if level >= 7 then return "medium" end
  if level >= 4 then return "low" end
  return "info"
end

local SARIF_LEVEL = { error = "high", warning = "medium", note = "low", none = "info" }

local function as_array(v)
  if v == nil then return {} end
  if type(v) == "table" then return v end
  return { v }
end

local function utf8_prefix(s, n)
  if #s <= n then return s end
  local cut = s:sub(1, n)
  local i = #cut
  while i > 0 do
    local b = cut:byte(i)
    if b >= 0x80 and b < 0xC0 then
      i = i - 1
    else
      if b >= 0xC0 then i = i - 1 end
      break
    end
  end
  return cut:sub(1, i)
end

local function append_unique(list, seen, value)
  if type(value) == "string" and value ~= "" and not seen[value] then
    seen[value] = true
    list[#list + 1] = value
  end
end

-- ---------------------------------------------------------------------------------------------------------------
-- classify_vendetta
-- ---------------------------------------------------------------------------------------------------------------
local function detect_stream(record, tag)
  local rule = type(record.rule) == "table" and record.rule or {}
  local found = {}
  for _, g in ipairs(as_array(rule.groups)) do
    if type(g) == "string" then
      local l = g:lower()
      if l == "fim" or l:find("^syscheck") then
        found.fim = true
      elseif l == "vulnerability-detector" or l == "vulnerability_detector" or l == "vulnerability" then
        found.vulnerability = true
      elseif l == "sca" or l == "sca_check" then
        found.sca = true
      end
    end
  end
  if found.fim then return "fim" end
  if found.vulnerability then return "vulnerability" end
  if found.sca then return "sca" end
  local loc = type(record.location) == "string" and record.location:lower() or ""
  if loc == "syscheck" then return "fim" end
  if loc == "vulnerability-detector" then return "vulnerability" end
  if loc == "sca" then return "sca" end
  local from_tag = type(tag) == "string" and tag:match("^vendetta%.(%a+)$")
  if from_tag == "fim" or from_tag == "vulnerability" or from_tag == "sca" then return from_tag end
  return "alerts"
end

function classify_vendetta(tag, timestamp, record)
  if type(record.rule) ~= "table" then record.rule = {} end
  local rule = record.rule
  local agent = type(record.agent) == "table" and record.agent or {}

  local level = tonumber(rule.level)
  if level ~= nil then
    record.severity = severity_from_level(level)
  elseif type(record.severity) ~= "string" or not SEVERITIES[record.severity:lower()] then
    record.severity = "info"
  else
    record.severity = record.severity:lower()
  end

  record.stream = detect_stream(record, tag)

  -- Console ingest contract (POST /api/cecur/logs/ingest): string source + string message are mandatory.
  record.source = "vendetta"
  local name = agent.name
  if type(name) ~= "string" or name == "" then name = agent.id end
  if type(name) ~= "string" or name == "" then name = "vendetta-manager" end
  record.agentName = name

  local desc = type(rule.description) == "string" and rule.description or ""
  local full = type(record.full_log) == "string" and record.full_log or ""
  local message = desc
  if full ~= "" then
    local excerpt = utf8_prefix(full, 256)
    message = (desc ~= "") and (desc .. " | " .. excerpt) or excerpt
  end
  if message == "" then message = "vendetta alert " .. tostring(record.id or "") end
  record.message = message

  local groups = {}
  for _, g in ipairs(as_array(rule.groups)) do
    if type(g) == "string" then groups[#groups + 1] = g end
  end
  local fields = {
    stream = record.stream,
    severity = record.severity,
    rule_id = tostring(rule.id or ""),
    rule_level = level or 0,
    agent_id = tostring(agent.id or ""),
    location = tostring(record.location or ""),
    alert_id = tostring(record.id or ""),
  }
  if #groups > 0 then fields.rule_groups = groups end
  record.fields = fields

  return 2, timestamp, record
end

-- ---------------------------------------------------------------------------------------------------------------
-- mitre_enrich
-- ---------------------------------------------------------------------------------------------------------------
-- technique id -> { name, tactics }. Tactic names use the MITRE display form that Wazuh/Vendetta emit.
local ATTACK = {
  T1003 = { "OS Credential Dumping", { "Credential Access" } },
  T1021 = { "Remote Services", { "Lateral Movement" } },
  T1027 = { "Obfuscated Files or Information", { "Defense Evasion" } },
  T1033 = { "System Owner/User Discovery", { "Discovery" } },
  T1036 = { "Masquerading", { "Defense Evasion" } },
  T1046 = { "Network Service Discovery", { "Discovery" } },
  T1047 = { "Windows Management Instrumentation", { "Execution" } },
  T1053 = { "Scheduled Task/Job", { "Execution", "Persistence", "Privilege Escalation" } },
  T1055 = { "Process Injection", { "Defense Evasion", "Privilege Escalation" } },
  T1057 = { "Process Discovery", { "Discovery" } },
  T1059 = { "Command and Scripting Interpreter", { "Execution" } },
  T1068 = { "Exploitation for Privilege Escalation", { "Privilege Escalation" } },
  T1070 = { "Indicator Removal", { "Defense Evasion" } },
  T1071 = { "Application Layer Protocol", { "Command and Control" } },
  T1078 = { "Valid Accounts", { "Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access" } },
  T1082 = { "System Information Discovery", { "Discovery" } },
  T1083 = { "File and Directory Discovery", { "Discovery" } },
  T1087 = { "Account Discovery", { "Discovery" } },
  T1098 = { "Account Manipulation", { "Persistence" } },
  T1105 = { "Ingress Tool Transfer", { "Command and Control" } },
  T1110 = { "Brute Force", { "Credential Access" } },
  T1112 = { "Modify Registry", { "Defense Evasion" } },
  T1136 = { "Create Account", { "Persistence" } },
  T1189 = { "Drive-by Compromise", { "Initial Access" } },
  T1190 = { "Exploit Public-Facing Application", { "Initial Access" } },
  T1203 = { "Exploitation for Client Execution", { "Execution" } },
  T1210 = { "Exploitation of Remote Services", { "Lateral Movement" } },
  T1218 = { "System Binary Proxy Execution", { "Defense Evasion" } },
  T1485 = { "Data Destruction", { "Impact" } },
  T1486 = { "Data Encrypted for Impact", { "Impact" } },
  T1489 = { "Service Stop", { "Impact" } },
  T1496 = { "Resource Hijacking", { "Impact" } },
  T1499 = { "Endpoint Denial of Service", { "Impact" } },
  T1505 = { "Server Software Component", { "Persistence" } },
  T1531 = { "Account Access Removal", { "Impact" } },
  T1543 = { "Create or Modify System Process", { "Persistence", "Privilege Escalation" } },
  T1546 = { "Event Triggered Execution", { "Privilege Escalation", "Persistence" } },
  T1547 = { "Boot or Logon Autostart Execution", { "Persistence", "Privilege Escalation" } },
  T1548 = { "Abuse Elevation Control Mechanism", { "Privilege Escalation", "Defense Evasion" } },
  T1552 = { "Unsecured Credentials", { "Credential Access" } },
  T1555 = { "Credentials from Password Stores", { "Credential Access" } },
  T1557 = { "Adversary-in-the-Middle", { "Credential Access", "Collection" } },
  T1562 = { "Impair Defenses", { "Defense Evasion" } },
  T1565 = { "Data Manipulation", { "Impact" } },
  T1566 = { "Phishing", { "Initial Access" } },
  T1567 = { "Exfiltration Over Web Service", { "Exfiltration" } },
  T1574 = { "Hijack Execution Flow", { "Persistence", "Privilege Escalation", "Defense Evasion" } },
  T1595 = { "Active Scanning", { "Reconnaissance" } },
}

-- CWE number -> ATT&CK technique hints (Errow SARIF findings). Hints, not verdicts: they say which technique a
-- weakness typically enables; the authoritative mapping is the OpenSearch ingest pipeline errow-finding-enrichment.
local CWE_TO_ATTACK = {
  ["20"] = { "T1190" }, ["22"] = { "T1190" }, ["77"] = { "T1190", "T1059" }, ["78"] = { "T1190", "T1059" },
  ["79"] = { "T1189" }, ["89"] = { "T1190" }, ["94"] = { "T1190", "T1059" }, ["119"] = { "T1203" },
  ["125"] = { "T1203" }, ["250"] = { "T1548" }, ["269"] = { "T1068" }, ["287"] = { "T1078" },
  ["295"] = { "T1557" }, ["306"] = { "T1078" }, ["311"] = { "T1557" }, ["326"] = { "T1557" },
  ["327"] = { "T1557" }, ["400"] = { "T1499" }, ["434"] = { "T1190", "T1505" }, ["502"] = { "T1190", "T1059" },
  ["522"] = { "T1552" }, ["532"] = { "T1552" }, ["611"] = { "T1190" }, ["639"] = { "T1190" },
  ["732"] = { "T1548" }, ["787"] = { "T1203" }, ["798"] = { "T1552" }, ["862"] = { "T1190" },
  ["863"] = { "T1190" }, ["918"] = { "T1190" },
}

local function base_technique(id)
  if type(id) ~= "string" then return nil end
  return id:upper():match("^(T%d%d%d%d)")
end

local function fill_mitre(ids)
  local out_ids, out_tac, out_tech = {}, {}, {}
  local seen_id, seen_tac, seen_tech = {}, {}, {}
  for _, id in ipairs(ids) do
    append_unique(out_ids, seen_id, id)
    local info = ATTACK[base_technique(id)]
    if info then
      append_unique(out_tech, seen_tech, info[1])
      for _, t in ipairs(info[2]) do append_unique(out_tac, seen_tac, t) end
    end
  end
  return out_ids, out_tac, out_tech
end

function mitre_enrich(tag, timestamp, record)
  if type(tag) == "string" and tag:find("^vendetta%.") then
    local rule = type(record.rule) == "table" and record.rule or {}
    local rm = type(rule.mitre) == "table" and rule.mitre or {}
    local ids = {}
    local existing = type(record.mitre) == "table" and record.mitre or {}
    for _, id in ipairs(as_array(rm.id)) do ids[#ids + 1] = id end
    for _, id in ipairs(as_array(existing.id)) do ids[#ids + 1] = id end
    if #ids == 0 then return 0, timestamp, record end
    local out_ids, out_tac, out_tech = fill_mitre(ids)
    -- Keep what the manager already supplied, add what the map can derive.
    local seen_tac, seen_tech = {}, {}
    local tactic, technique = {}, {}
    for _, t in ipairs(as_array(rm.tactic)) do append_unique(tactic, seen_tac, t) end
    for _, t in ipairs(as_array(rm.technique)) do append_unique(technique, seen_tech, t) end
    for _, t in ipairs(out_tac) do append_unique(tactic, seen_tac, t) end
    for _, t in ipairs(out_tech) do append_unique(technique, seen_tech, t) end
    local m = { id = out_ids }
    if #tactic > 0 then m.tactic = tactic end
    if #technique > 0 then m.technique = technique end
    record.mitre = m
    return 2, timestamp, record
  end

  if tag == "errow.findings" then
    local props = type(record.properties) == "table" and record.properties or {}
    local er = type(props.errow) == "table" and props.errow or {}
    local parts = {}
    for _, cwe in ipairs({ er.cwe or "", props.cwe or "", record.cwe or "", record.ruleId or "" }) do
      if type(cwe) == "table" then
        for _, v in ipairs(cwe) do parts[#parts + 1] = tostring(v) end
      elseif type(cwe) == "string" then
        parts[#parts + 1] = cwe
      end
    end
    local text = table.concat(parts, " ")
    local ids = {}
    for num in text:gmatch("[Cc][Ww][Ee]%-?(%d+)") do
      for _, tid in ipairs(CWE_TO_ATTACK[num] or {}) do ids[#ids + 1] = tid end
    end
    if #ids == 0 then return 0, timestamp, record end
    local out_ids, out_tac, out_tech = fill_mitre(ids)
    record.mitre_hint = { id = out_ids, tactic = out_tac, technique = out_tech, basis = "cwe" }
    return 2, timestamp, record
  end

  return 0, timestamp, record
end

-- ---------------------------------------------------------------------------------------------------------------
-- errow_normalize
-- ---------------------------------------------------------------------------------------------------------------
local LLM_BODY_KEYS = { "prompt", "prompts", "messages", "completion", "completions", "request_body", "response_body", "instructions" }
local POC_BODY_KEYS = { "poc_script_code", "script_code", "script_body", "payload_body" }

function errow_normalize(tag, timestamp, record)
  local stream = type(tag) == "string" and tag:match("^errow%.(.+)$") or nil
  if type(record.stream) ~= "string" or record.stream == "" then record.stream = stream end
  if type(record.source) ~= "string" or record.source == "" then record.source = "errow" end

  if tag == "errow.findings" then
    for _, k in ipairs(POC_BODY_KEYS) do record[k] = nil end
    local props = type(record.properties) == "table" and record.properties or nil
    local er = props and type(props.errow) == "table" and props.errow or nil
    if er then
      for _, k in ipairs(POC_BODY_KEYS) do er[k] = nil end
      if type(er.poc) == "table" then
        for _, k in ipairs(POC_BODY_KEYS) do er.poc[k] = nil end
        er.poc.script = nil
      end
    end
    local sev = er and type(er.severity) == "string" and er.severity:lower() or nil
    if not (sev and SEVERITIES[sev]) then
      sev = SARIF_LEVEL[type(record.level) == "string" and record.level:lower() or ""] or "info"
    end
    record.severity = sev
  elseif tag == "errow.llm_logs" then
    for _, k in ipairs(LLM_BODY_KEYS) do record[k] = nil end
  end
  return 2, timestamp, record
end

-- ---------------------------------------------------------------------------------------------------------------
-- cs3_stamp (requires `time_as_table on` on the filter)
-- ---------------------------------------------------------------------------------------------------------------
function cs3_stamp(tag, timestamp, record)
  if type(record["@timestamp"]) == "string" and record["@timestamp"] ~= "" then
    return 0, timestamp, record
  end
  local sec = timestamp.sec or 0
  local nsec = timestamp.nsec or 0
  record["@timestamp"] = os.date("!%Y-%m-%dT%H:%M:%S", sec) .. string.format(".%03dZ", math.floor(nsec / 1000000))
  return 2, timestamp, record
end

-- Test seam (tests/test_stream_processors.lua); Fluent Bit ignores it.
CS3_LUA = {
  clean = clean,
  redact = redact,
  is_secret_key = is_secret_key,
  severity_from_level = severity_from_level,
  set_max_chars = function(n) MAX_CHARS = n end,
  get_max_chars = function() return MAX_CHARS end,
  attack_count = function() local n = 0; for _ in pairs(ATTACK) do n = n + 1 end; return n end,
}
