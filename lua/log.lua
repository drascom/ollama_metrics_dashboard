local ctx = ngx.ctx.ollama
if not ctx then return end
local cjson = require "cjson.safe"
local function val(v) return v or "-" end
local function num(v) return v or 0 end

local prefix = ngx.config.prefix() or ""
if prefix ~= "" and prefix:sub(-1) ~= "/" then prefix = prefix .. "/" end
local log_path = prefix .. "logs/metrics.log"

local prompt_safe = cjson.encode(val(ctx.prompt))
local response_safe = cjson.encode(val(ctx.response_text))
local timestamp = os.date("!%Y-%m-%dT%H:%M:%S")

local line = string.format(
    "ts=%s rid=%s ip=%s model=%s uri=%s stream=%s prompt=%s response=%s completion=%d ms=%d tps=%s",
    timestamp, val(ctx.rid), val(ctx.client_ip), val(ctx.model), val(ctx.uri), val(ctx.stream),
    prompt_safe, response_safe, num(ctx.completion_tokens), num(ctx.eval_ms), val(ctx.tps)
)

local f, err = io.open(log_path, "a")
if f then f:write(line .. "\n"); f:close() end
