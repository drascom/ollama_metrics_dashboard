local prefix = ngx.config.prefix() or ""
if prefix ~= "" and prefix:sub(-1) ~= "/" then prefix = prefix .. "/" end
local log_path = prefix .. "logs/metrics.log"
local f = io.open(log_path, "w")
if f then f:write(""); f:close() end
ngx.header.content_type = "application/json"
ngx.say('{"status": "ok"}')
