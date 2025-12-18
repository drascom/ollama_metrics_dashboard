local uri = ngx.var.uri or ""
if not (uri:find("/api/chat") or uri:find("/api/generate")) then return end

ngx.req.read_body()
local body = ngx.req.get_body_data()
if not body then
    local body_file = ngx.req.get_body_file()
    if body_file then
        local f = io.open(body_file, "r")
        if f then body = f:read("*a"); f:close() end
    end
end

local model, stream, prompt = "unknown", "true", ""
local rid = string.format("%d-%d-%d", ngx.time(), ngx.worker.pid(), ngx.var.connection or 0)

if body and body ~= "" then
  local cjson = require "cjson.safe"
  local req = cjson.decode(body)
  if req then
    if req.model then model = req.model end
    if req.stream == false then stream = "false" end
    
    if req.prompt then 
      prompt = tostring(req.prompt)
    elseif req.messages and type(req.messages) == "table" then
      -- Chat: Get LAST message only (User or Tool Output)
      local count = #req.messages
      if count > 0 then
        local last = req.messages[count]
        if last.content then
           prompt = string.format("[%s]: %s", last.role or "?", last.content)
        end
      end
    end
  end
end

if #prompt > 200 then prompt = prompt:sub(1, 200) .. "..." end

ngx.ctx.ollama = {
  rid=rid, start_ms=ngx.now()*1000, client_ip=ngx.var.remote_addr,
  uri=uri, model=model, stream=stream, prompt=prompt
}
