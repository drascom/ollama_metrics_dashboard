# Ollama Middleware Metrics Dashboard

This repository ships a single `install.sh` script that installs a self-contained OpenResty-based middleware for Ollama. The installer provisions an nginx/Lua reverse proxy that records request/response metadata, exposes a lightweight dashboard, and registers the appropriate service (systemd on Linux, LaunchAgent on macOS) so the middleware survives reboots.

## Repository layout

```
ollama-middleware-src/
├── install.sh
├── conf/
│   └── nginx.conf.template
├── html/
│   └── index.html
└── lua/
    ├── request.lua
    ├── response.lua
    ├── log.lua
    ├── metrics_json.lua
    └── clear_logs.lua
```

The installer copies these assets into the runtime prefix (`/opt/ollama-middleware` on Linux, `~/ollama-middleware` on macOS) and performs minimal templating (e.g., substituting MIME type paths in `nginx.conf`).

## What the installer does

1. Installs OpenResty (nginx + LuaJIT) from the upstream apt repo (Linux) or Homebrew (macOS) when it is not already present.
2. Creates the runtime tree in `$INSTALL_DIR` (Linux: `/opt/ollama-middleware`, macOS: `$HOME/ollama-middleware`) with `conf/`, `lua/`, `html/`, and `logs/`.
3. Copies all runtime assets (nginx config template, Lua filters, helper endpoints, and the dashboard UI) into place.
4. Registers `ollama-middleware.service` that runs `openresty` in prefix mode and restarts automatically.
5. Starts the service on port `11435` where:
   - `/` proxies to the local Ollama API (`127.0.0.1:11434`) while logging requests/responses.
   - `/metrics/` serves the dashboard UI.
   - `/metrics.json` returns the recent log entries as JSON.
   - `/clear` truncates the metrics log.

## Requirements

- **Linux (Debian/Ubuntu)** – `systemd`, `bash`, `sudo`, and connectivity to download OpenResty packages; run the installer as `root` (`sudo ./install.sh`).
- **macOS** – Homebrew installed (`https://brew.sh/`) with permissions to tap/install `openresty/brew/openresty`; the installer runs as your user and writes under `$HOME/ollama-middleware`.
- **Common** – Ollama already listening on `127.0.0.1:11434` and the ability to expose port `11435` for the dashboard and metrics endpoints.

## Installation

```bash
chmod +x install.sh
./install.sh
```

The script is idempotent: re-running it updates files in `$INSTALL_DIR` and restarts the registered service.

## Components written by the installer

| Path | Purpose |
|------|---------|
| `$INSTALL_DIR/conf/nginx.conf` | Configures OpenResty to proxy to Ollama, load Lua hooks, and serve the dashboard. |
| `$INSTALL_DIR/lua/request.lua` | Captures metadata (model, prompt, etc.) for chat/generate requests. |
| `$INSTALL_DIR/lua/response.lua` | Streams the Ollama response, extracts completion statistics, and tracks throughput. |
| `$INSTALL_DIR/lua/log.lua` | Persists a line-oriented log to `$INSTALL_DIR/logs/metrics.log`. |
| `$INSTALL_DIR/lua/metrics_json.lua` | Reads the last ~50 log entries and emits JSON for the dashboard. |
| `$INSTALL_DIR/lua/clear_logs.lua` | Clears the metrics log and returns `{"status":"ok"}`. |
| `$INSTALL_DIR/html/index.html` | Vanilla HTML/JS dashboard that polls `/metrics.json`, filters, and displays prompts/responses. |
| `/etc/systemd/system/ollama-middleware.service` (Linux) | Runs OpenResty with the middleware prefix, restarts automatically, and depends on networking. |
| `$HOME/Library/LaunchAgents/uk.drascom.ollama-middleware.plist` (macOS) | LaunchAgent that keeps OpenResty running and restarts it at login. |

Logs live in `$INSTALL_DIR/logs/metrics.log` (or `~/ollama-middleware/logs/metrics.log` on macOS) and are writable by everyone (mode `0666`) so OpenResty can append without permission issues.

## Operating the service

- **Dashboard**: open `http://<host>:11435/metrics/` to view and filter recent requests. Use the **Clear** button (or `POST /clear`) to reset the log.
- **Log consumption**: fetch `http://<host>:11435/metrics.json` to programmatically retrieve entries (latest 50).
- **Service management (Linux)**:
  ```bash
  sudo systemctl status ollama-middleware
  sudo systemctl restart ollama-middleware
  sudo systemctl disable --now ollama-middleware
  sudo rm -rf /opt/ollama-middleware
  sudo rm /etc/systemd/system/ollama-middleware.service
  sudo systemctl daemon-reload
  ```
- **Service management (macOS)**:
  ```bash
  launchctl list uk.drascom.ollama-middleware
  launchctl unload "$HOME/Library/LaunchAgents/uk.drascom.ollama-middleware.plist"
  rm -rf "$HOME/ollama-middleware"
  rm "$HOME/Library/LaunchAgents/uk.drascom.ollama-middleware.plist"
  ```
- **Uninstallation helper**: run `./uninstall.sh` (with `sudo` on Linux) to stop services, remove LaunchAgents/systemd units, and delete the install directory.

## Security considerations

- The middleware binds to all interfaces on port `11435`. Restrict inbound access (e.g., firewall) if the dashboard or log endpoints should not be publicly reachable.
- Metrics logs include truncated prompts (first 200 characters) and up to 4000 characters of responses. Ensure that storing this information complies with your data-handling requirements.
- On Linux the service runs as `root` to avoid permission hassles with `/opt/ollama-middleware/logs`. If you harden the setup later, adjust `USER` in `install.sh`, set appropriate directory ownership, and update `user` in `nginx.conf`.
