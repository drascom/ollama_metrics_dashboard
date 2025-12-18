local ctx = ngx.ctx.ollama
if not ctx then return end
local cjson = require "cjson.safe"

ctx.partial = ctx.partial or ""
ctx.got_done = ctx.got_done or false
ctx.response_text = ctx.response_text or ""
local chunk = ngx.arg[1] or ""
local eof = ngx.arg[2]

if chunk ~= "" then ctx.partial = ctx.partial .. chunk end

local function process(json_str)
    local obj = cjson.decode(json_str)
    if not obj then return end
    
    local txt = ""
    if obj.response then txt = obj.response
    elseif obj.message then
        if obj.message.content then txt = obj.message.content
        elseif obj.message.tool_calls then txt = " [Tool Call] " end
    end
    
    if #ctx.response_text < 4000 then ctx.response_text = ctx.response_text .. txt end
    
    if obj.done == true and not ctx.got_done then
        ctx.got_done = true
        ctx.res_model = obj.model or ctx.model
        ctx.completion_tokens = tonumber(obj.eval_count) or 0
        ctx.eval_ns = tonumber(obj.eval_duration) or 0
        local dur_sec = ctx.eval_ns / 1e9
        if dur_sec > 0 then
             ctx.tps = string.format("%.2f", ctx.completion_tokens / dur_sec)
             ctx.eval_ms = math.floor(ctx.eval_ns / 1e6)
        else ctx.tps = "0.00"; ctx.eval_ms = 0 end
    end
end

while true do
    local nl = ctx.partial:find("\n", 1, true)
    if not nl then break end
    local line = ctx.partial:sub(1, nl - 1)
    ctx.partial = ctx.partial:sub(nl + 1)
    if line ~= "" then process(line) end
end

if eof then
    if ctx.partial ~= "" then process(ctx.partial) end
    ctx.partial = nil
end
