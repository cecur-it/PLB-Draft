-- Cecur CS3 gateway: normalise OTLP log records to the CS3 ingest contract
-- { source, message, agentName, severity?, fields } and apply edge-side guardrails.
--
-- Why: OTLP logs are attacker-influenced input that ends up in AI triage prompts
-- (server/inference/guardrails.ts stays authoritative; this is defence in depth and a bandwidth cap).
--
-- Input shapes produced by Fluent Bit's `opentelemetry` input:
--   * string body  -> { log = "<body>" }
--   * kvlist body  -> the map itself (CS3 emitters should send { message, source, severity, ... })
-- Returns -1 (drop) for records with no usable message so a blank event never 400s a whole batch.

local MAX_CHARS = tonumber(os.getenv("CS3_MESSAGE_MAX_CHARS")) or 8000
local TRUNCATED = "...[truncated]"

local RESERVED = { message = true, source = true, agentName = true, severity = true, fields = true }

-- OTLP / syslog severity names -> console severity enum.
local SEVERITY = {
  trace = "info", debug = "info", info = "info", notice = "info",
  warn = "medium", warning = "medium",
  error = "high", err = "high",
  critical = "critical", crit = "critical", alert = "critical", emerg = "critical", fatal = "critical",
  low = "low", medium = "medium", high = "high",
}

-- Case-insensitive Lua pattern for a literal word.
local function ci(word)
  return (word:gsub("%a", function(c) return "[" .. c:lower() .. c:upper() .. "]" end))
end

local SECRET_KEYS = { "password", "passwd", "secret", "token", "api[_-]?key", "apikey", "authorization" }
local KV_PATTERNS = {}
for _, k in ipairs(SECRET_KEYS) do
  -- key=value / key: value / key":"value  (value ends at whitespace, quote, comma, ampersand or semicolon)
  local key = k:gsub("%a", function(c) return "[" .. c:lower() .. c:upper() .. "]" end)
  KV_PATTERNS[#KV_PATTERNS + 1] = "(" .. key .. "[\"']?%s*[:=]%s*[\"']?)[^%s\"',&;]+"
end
local BEARER = "(" .. ci("bearer") .. "%s+)[%w%-%._~%+/]+=*"

local function redact(s)
  s = s:gsub(BEARER, "%1[REDACTED]")
  for _, p in ipairs(KV_PATTERNS) do
    s = s:gsub(p, "%1[REDACTED]")
  end
  return s
end

local function clean(s)
  -- Keep \t (9), \n (10); strip other C0 controls and DEL.
  s = s:gsub("[%z\1-\8\11-\31\127]", "")
  if #s > MAX_CHARS then
    s = s:sub(1, MAX_CHARS)
    -- Do not leave a dangling partial UTF-8 sequence.
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

function cs3_normalize(tag, timestamp, record)
  local msg = record.message
  if msg == nil then msg = record.log end
  record.log = nil

  local fields = record.fields
  if type(fields) ~= "table" then fields = {} end

  if type(msg) == "table" then
    fields.body = msg
    msg = "structured OTLP log body (see fields.body)"
  elseif type(msg) == "number" or type(msg) == "boolean" then
    msg = tostring(msg)
  end
  if type(msg) ~= "string" or msg:match("^%s*$") then
    return -1, timestamp, record
  end
  record.message = redact(clean(msg))

  if type(record.source) ~= "string" or record.source == "" then record.source = nil end
  if type(record.agentName) ~= "string" or record.agentName == "" then record.agentName = nil end

  if record.severity ~= nil then
    local sev = SEVERITY[tostring(record.severity):lower()]
    record.severity = sev -- nil removes an unrecognised value; the console then infers it
  end

  for k, v in pairs(record) do
    if not RESERVED[k] then
      fields[k] = v
      record[k] = nil
    end
  end
  record.fields = fields

  return 1, timestamp, record
end
