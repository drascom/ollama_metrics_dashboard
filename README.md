# Ollama Middleware Metrics Dashboard

This repository ships a single `install.sh` script that installs a self-contained OpenResty-based middleware for Ollama. The installer provisions an nginx/Lua reverse proxy that records request/response metadata, exposes a lightweight dashboard, and registers a `systemd` unit so the service survives reboots.

## What the installer does

1. Installs OpenResty (nginx + LuaJIT) from the upstream apt repo when it is not already present.
2. Creates the runtime tree in `/opt/ollama-middleware` with `conf/`, `lua/`, `html/`, and `logs/`.
3. Writes all runtime assets: nginx config, Lua filters, helper endpoints, and the dashboard UI.
4. Registers `ollama-middleware.service` that runs `openresty` in prefix mode and restarts automatically.
5. Starts the service on port `11435` where:
   - `/` proxies to the local Ollama API (`127.0.0.1:11434`) while logging requests/responses.
   - `/metrics/` serves the dashboard UI.
   - `/metrics.json` returns the recent log entries as JSON.
   - `/clear` truncates the metrics log.

## Requirements

- Ubuntu/Debian host with `systemd`, `bash`, `sudo`, and connectivity to download OpenResty packages.
- Ollama already running locally on `127.0.0.1:11434`.
- Ability to run the installer as a sudo-capable user (the service itself runs as `root` to simplify log access).

## Installation

```bash
chmod +x install.sh
./install.sh
```

The script is idempotent: re-running it updates files in `/opt/ollama-middleware` and restarts the service.

## Components written by the installer

| Path | Purpose |
|------|---------|
| `/opt/ollama-middleware/conf/nginx.conf` | Configures OpenResty to proxy to Ollama, load Lua hooks, and serve the dashboard. |
| `/opt/ollama-middleware/lua/request.lua` | Captures metadata (model, prompt, etc.) for chat/generate requests. |
| `/opt/ollama-middleware/lua/response.lua` | Streams the Ollama response, extracts completion statistics, and tracks throughput. |
| `/opt/ollama-middleware/lua/log.lua` | Persists a line-oriented log to `/opt/ollama-middleware/logs/metrics.log`. |
| `/opt/ollama-middleware/lua/metrics_json.lua` | Reads the last ~50 log entries and emits JSON for the dashboard. |
| `/opt/ollama-middleware/lua/clear_logs.lua` | Clears the metrics log and returns `{"status":"ok"}`. |
| `/opt/ollama-middleware/html/index.html` | Vanilla HTML/JS dashboard that polls `/metrics.json`, filters, and displays prompts/responses. |
| `/etc/systemd/system/ollama-middleware.service` | Runs OpenResty with the middleware prefix, restarts automatically, and depends on networking. |

Logs live in `/opt/ollama-middleware/logs/metrics.log` and are writable by everyone (mode `0666`) so nginx can append without permission issues.

## Operating the service

- **Dashboard**: open `http://<host>:11435/metrics/` to view and filter recent requests. Use the **Clear** button (or `POST /clear`) to reset the log.
- **Log consumption**: fetch `http://<host>:11435/metrics.json` to programmatically retrieve entries (latest 50).
- **Service management**:
  ```bash
  sudo systemctl status ollama-middleware
  sudo systemctl restart ollama-middleware
  sudo systemctl disable --now ollama-middleware   # optional removal
  sudo rm -rf /opt/ollama-middleware               # remove files if you no longer need them
  sudo rm /etc/systemd/system/ollama-middleware.service
  sudo systemctl daemon-reload
  ```

## Security considerations

- The middleware binds to all interfaces on port `11435`. Restrict inbound access (e.g., firewall) if the dashboard or log endpoints should not be publicly reachable.
- Metrics logs include truncated prompts (first 200 characters) and up to 4000 characters of responses. Ensure that storing this information complies with your data-handling requirements.
- The service runs as `root` to avoid permission hassles with `/opt/ollama-middleware/logs`. If you harden the setup later, adjust `USER` in `install.sh`, set appropriate directory ownership, and update `user` in `nginx.conf`.
