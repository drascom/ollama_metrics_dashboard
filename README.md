# Clean Ollama Proxy Installer (Linux)

Clean Ollama Proxy is a single-file installation experience that builds and deploys an Ollama reverse proxy/analytics service on Debian or Ubuntu. It wraps `ollama serve`, adds Prometheus metrics and a lightweight dashboard, and runs everything as a managed `systemd` service at `/root/ollama-metrics`.

> Thanks to [bmeyer99](https://github.com/bmeyer99/Ollama_Proxy_Wrapper) for the Windows installer concept that inspired this Linux-focused version.

## Run it
```bash
sudo bash install.sh
```

Requirements: a Debian/Ubuntu host with `apt`, root privileges, and internet connectivity (for Go modules, apt packages, and the Ollama installer). The script exits immediately when not run as root.

## What happens during install
- Existing `ollama`/`ollama-proxy` services are stopped, disabled, and their processes/ports (`11434`, `11435`) are cleared to avoid conflicts.
- Dependencies (`golang-go`, `curl`, `sqlite3`, plus `strace` for diagnostics) are installed; Ollama itself is downloaded if missing.
- A Go application is generated that:
  - Starts `ollama serve` on port `11435` inside the same process group.
  - Proxies requests on port `11434`, captures per-model Prometheus metrics, and stores request analytics in SQLite (`analytics/ollama_analytics.db`).
  - Exposes `/metrics`, `/analytics`, `/dashboard`, and `/test` endpoints.
- The project is built in `/root/ollama-metrics` and wired up to a `systemd` unit (`ollama-proxy.service`) with sane timeouts, restart policies, and logging.
- Quick checks run before enabling the service: memory/disk summaries, `dmesg` for OOM/security kills, and a `strace` signal trace to catch policy violations.

## What to expect afterwards
- Proxy endpoint: `http://localhost:11434`
- Prometheus metrics: `http://localhost:11434/metrics`
- JSON analytics summary: `http://localhost:11434/analytics`
- Minimal dashboard UI: `http://localhost:11434/dashboard`
- Service management:
  - `systemctl status ollama-proxy`
  - `journalctl -u ollama-proxy -f`
  - `systemctl stop|start|restart ollama-proxy`

All generated files (binary, `main.go`, analytics DB) reside under `/root/ollama-metrics`.

## Troubleshooting tips
- If the service fails to start, rerun the installer or inspect:
  ```bash
  journalctl -u ollama-proxy -n 100 --no-pager
  systemctl status ollama-proxy --no-pager -l
  ```
- Check for port conflicts with `netstat -tlnp | grep -E "(11434|11435)"`.
- Review the installer console output for the pre-run `dmesg`/`strace` diagnostics—it often surfaces AppArmor/SELinux or OOM issues immediately.
