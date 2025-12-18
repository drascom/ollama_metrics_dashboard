#!/bin/bash

# =================================================================
# OLLAMA MIDDLEWARE - SELF-CONTAINED INSTALLER
# Installs everything into /opt/ollama-middleware
# =================================================================

set -e
APP_DIR="/opt/ollama-middleware"
USER="root" # Running OpenResty as root to avoid permission headaches with logs

# 1. Install Dependencies (OpenResty)
echo "Installing OpenResty..."
if ! command -v openresty &> /dev/null; then
    sudo apt-get update
    sudo apt-get -y install --no-install-recommends wget gnupg ca-certificates lsb-release
    wget -O - https://openresty.org/package/pubkey.gpg | sudo gpg --dearmor -o /usr/share/keyrings/openresty.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/openresty.gpg] http://openresty.org/package/ubuntu $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/openresty.list > /dev/null
    sudo apt-get update
    sudo apt-get -y install openresty
fi

# 2. Prepare Directory Structure
echo "Setting up $APP_DIR..."
# Stop service if exists
sudo systemctl stop ollama-middleware 2>/dev/null || true

sudo mkdir -p "$APP_DIR/conf"
sudo mkdir -p "$APP_DIR/lua"
sudo mkdir -p "$APP_DIR/html"
sudo mkdir -p "$APP_DIR/logs"

# Set permissions
sudo chown -R $USER:$USER "$APP_DIR"
sudo chmod -R 755 "$APP_DIR"
# Logs need to be writable
sudo chmod -R 777 "$APP_DIR/logs"
sudo touch "$APP_DIR/logs/metrics.log"
sudo chmod 666 "$APP_DIR/logs/metrics.log"

# =================================================================
# 3. Write Config (nginx.conf)
# =================================================================
echo "Writing configuration..."

cat <<EOF | sudo tee "$APP_DIR/conf/nginx.conf" > /dev/null
worker_processes 1;
# Run in foreground for systemd
daemon off;
# User needs to match folder owner
user $USER;

events { worker_connections 1024; }

http {
    include /usr/local/openresty/nginx/conf/mime.types;
    default_type application/octet-stream;
    
    # Paths are relative to prefix (-p) passed in systemd
    access_log logs/access.log;
    error_log logs/error.log warn;

    client_body_buffer_size 10m;
    client_max_body_size 20m;
    lua_package_path "$APP_DIR/lua/?.lua;;";

    server {
        listen 11435;
        
        # Dashboard UI
        location = /metrics { return 301 /metrics/; }
        location /metrics/ {
            alias html/;
            index index.html;
        }
        location = /metrics.json {
            default_type application/json;
            content_by_lua_file lua/metrics_json.lua;
        }
        location = /clear {
            default_type application/json;
            content_by_lua_file lua/clear_logs.lua;
        }

        # Ollama Proxy
        location / {
            proxy_pass http://127.0.0.1:11434;
            proxy_http_version 1.1;
            proxy_buffering off;
            proxy_request_buffering off;
            lua_need_request_body on;

            access_by_lua_file lua/request.lua;
            body_filter_by_lua_file lua/response.lua;
            log_by_lua_file lua/log.lua;
        }
    }
}
EOF

# =================================================================
# 4. Write Lua Scripts
# =================================================================
echo "Writing Lua scripts..."

# --- request.lua ---
cat <<'EOF' | sudo tee "$APP_DIR/lua/request.lua" > /dev/null
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
EOF

# --- response.lua ---
cat <<'EOF' | sudo tee "$APP_DIR/lua/response.lua" > /dev/null
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
EOF

# --- log.lua ---
cat <<'EOF' | sudo tee "$APP_DIR/lua/log.lua" > /dev/null
local ctx = ngx.ctx.ollama
if not ctx then return end
local cjson = require "cjson.safe"
local function val(v) return v or "-" end
local function num(v) return v or 0 end

local prompt_safe = cjson.encode(val(ctx.prompt))
local response_safe = cjson.encode(val(ctx.response_text))
local timestamp = os.date("!%Y-%m-%dT%H:%M:%S")

local line = string.format(
    "ts=%s rid=%s ip=%s model=%s uri=%s stream=%s prompt=%s response=%s completion=%d ms=%d tps=%s",
    timestamp, val(ctx.rid), val(ctx.client_ip), val(ctx.model), val(ctx.uri), val(ctx.stream),
    prompt_safe, response_safe, num(ctx.completion_tokens), num(ctx.eval_ms), val(ctx.tps)
)

local f, err = io.open("/opt/ollama-middleware/logs/metrics.log", "a")
if f then f:write(line .. "\n"); f:close() end
EOF

# --- metrics_json.lua ---
cat <<'EOF' | sudo tee "$APP_DIR/lua/metrics_json.lua" > /dev/null
local cjson = require "cjson.safe"
local f = io.open("/opt/ollama-middleware/logs/metrics.log", "r")
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
EOF

# --- clear_logs.lua ---
cat <<'EOF' | sudo tee "$APP_DIR/lua/clear_logs.lua" > /dev/null
local f = io.open("/opt/ollama-middleware/logs/metrics.log", "w")
if f then f:write(""); f:close() end
ngx.header.content_type = "application/json"
ngx.say('{"status": "ok"}')
EOF

# =================================================================
# 5. Write HTML Dashboard
# =================================================================
echo "Writing UI..."

cat <<'HTML_END' | sudo tee "$APP_DIR/html/index.html" > /dev/null
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><title>Ollama Middleware</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { --bg:#0e0f12; --text:#d7dce2; --accent:#4ade80; --border:#232633; }
    body { margin:0; background:var(--bg); color:var(--text); font-family:sans-serif; }
    header { padding:14px; border-bottom:1px solid var(--border); background:#0c0e13; display:flex; justify-content:space-between; align-items:center; }
    input, button { background:#101217; border:1px solid var(--border); color:var(--text); padding:8px; border-radius:6px; }
    table { width:100%; border-collapse:collapse; font-size:13px; margin-top:10px; }
    th, td { padding:10px; text-align:left; border-bottom:1px solid var(--border); }
    tr.data-row:hover { background:rgba(255,255,255,0.05); cursor:pointer; }
    tr.details-row { display:none; background:rgba(0,0,0,0.3); }
    tr.details-row.open { display:table-row; }
    pre { white-space:pre-wrap; max-height:200px; overflow:auto; background:rgba(0,0,0,0.4); padding:10px; }
  </style>
</head>
<body>
  <header>
    <b>Ollama Metrics</b>
    <div style="display:flex;gap:10px">
      <input id="q" placeholder="Filter..." oninput="render()">
      <button onclick="clearLogs()" style="color:#ef4444">Clear</button>
      <button id="liveBtn" onclick="toggle()">Live</button>
    </div>
  </header>
  <div style="padding:15px">
    <table id="t"><thead><tr><th>Time</th><th>Model</th><th>Tokens</th><th>TPS</th><th>ms</th></tr></thead><tbody></tbody></table>
  </div>
  <script>
    let all=[], paused=false;
    const toggle=()=>{paused=!paused; document.getElementById("liveBtn").textContent=paused?"Paused":"Live";};
    const esc=s=>(s??"").toString().replaceAll("<","&lt;");
    const render=()=>{
      const q=document.getElementById("q").value.toLowerCase();
      const openSet=new Set();
      document.querySelectorAll('.open').forEach(r=>openSet.add(r.id));
      
      const rows=all.filter(x=>!q||JSON.stringify(x).toLowerCase().includes(q));
      document.querySelector("tbody").innerHTML=rows.map(x=>{
        let ts=x.ts.split("T")[1]||x.ts; 
        let rid=(x.rid||"").replace(/[^a-z0-9]/gi,"");
        let tpsC = Number(x.tps)>10?'#4ade80':'inherit';
        return `<tr class="data-row" onclick="document.getElementById('d-${rid}').classList.toggle('open')">
          <td style="color:#888">${ts}</td><td style="color:#4ade80">${esc(x.model)}</td>
          <td>${esc(x.completion)}</td><td style="color:${tpsC}">${esc(x.tps)}</td><td>${esc(x.ms)}</td>
        </tr>
        <tr class="details-row ${openSet.has('d-'+rid)?'open':''}" id="d-${rid}"><td colspan="5" style="padding:10px">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
             <div><div style="color:#888">Prompt</div><pre>${esc(x.prompt)}</pre></div>
             <div><div style="color:#888">Response</div><pre>${esc(x.response)}</pre></div>
          </div>
        </td></tr>`
      }).join("");
    };
    const load=async()=>{
       if(paused)return;
       try{ 
         let r=await fetch("/metrics.json"); 
         if(r.ok){ all=(await r.json()).sort((a,b)=>a.ts<b.ts?1:-1); render(); }
       }catch(e){}
    };
    const clearLogs=async()=>{ if(confirm("Clear?")){ await fetch("/clear",{method:"POST"}); all=[]; render(); }};
    setInterval(load,1000); load();
  </script>
</body>
</html>
HTML_END

# =================================================================
# 6. Create Systemd Service
# =================================================================
echo "Creating systemd service..."

cat <<EOF | sudo tee /etc/systemd/system/ollama-middleware.service > /dev/null
[Unit]
Description=Ollama Middleware Metrics
After=network.target ollama.service

[Service]
Type=forking
PIDFile=$APP_DIR/logs/nginx.pid
ExecStart=/usr/bin/openresty -p $APP_DIR -c conf/nginx.conf
ExecReload=/bin/kill -s HUP \$MAINPID
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 7. Start
echo "Starting service..."
sudo systemctl daemon-reload
sudo systemctl enable ollama-middleware
sudo systemctl restart ollama-middleware

echo "====================================================="
echo "✅ INSTALLED in $APP_DIR"
echo "➡️  UI: http://$(hostname -I | awk '{print $1}'):11435/metrics/"
echo "====================================================="