local cjson = require "cjson.safe"
local prefix = ngx.config.prefix() or ""
if prefix ~= "" and prefix:sub(-1) ~= "/" then prefix = prefix .. "/" end
local log_path = prefix .. "logs/metrics.log"

local f = io.open(log_path, "r")
local logs = {}
if f then
    local lines = {}
    for line in f:lines() do table.insert(lines, line) end
    f:close()
    for i = #lines, math.max(1, #lines - 50), -1 do
        local line = lines[i]
        local entry = {}
        entry.ts = line:match("ts=(%S+)")
        entry.rid = line:match("rid=(%S+)")
        entry.ip = line:match("ip=(%S+)")
        entry.model = line:match("model=(%S+)")
        entry.uri = line:match("uri=(%S+)")
        entry.completion = line:match("completion=(%S+)")
        entry.ms = line:match("ms=(%S+)")
        entry.tps = line:match("tps=(%S+)")
        local raw_p = line:match("prompt=(%b\"\")")
        local raw_r = line:match("response=(%b\"\")")
        if raw_p then entry.prompt = cjson.decode(raw_p) else entry.prompt="" end
        if raw_r then entry.response = cjson.decode(raw_r) else entry.response="" end
        if entry.ts then table.insert(logs, entry) end
    end
end
ngx.header.content_type = "application/json"
ngx.say(cjson.encode(logs))
