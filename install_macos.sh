#!/bin/bash

################################################################################
# Clean Ollama Proxy Installation Script for macOS
# Builds the Ollama proxy + analytics dashboard and installs it as a launchd job
# Requires sudo/root privileges
################################################################################

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [[ "$(uname -s)" != "Darwin" ]]; then
    print_error "This installer is only supported on macOS"
    exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
    print_error "Please run with sudo (root privileges required)"
    exit 1
fi

ORIGINAL_USER="${SUDO_USER:-}"
if [[ -z "${ORIGINAL_USER}" || "${ORIGINAL_USER}" == "root" ]]; then
    print_error "Run this script via sudo from a non-root user so Homebrew can run safely"
    exit 1
fi

run_brew() {
    sudo -u "${ORIGINAL_USER}" -H \
        NONINTERACTIVE=1 \
        HOMEBREW_NO_ENV_HINTS=1 \
        brew "$@"
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${SCRIPT_DIR}"
ANALYTICS_DIR="${INSTALL_DIR}/analytics"
LOG_DIR="${INSTALL_DIR}/logs"
BIN_PATH="${INSTALL_DIR}/ollama-proxy"
SERVICE_LABEL="com.ollama.metrics"
PLIST_PATH="/Library/LaunchDaemons/${SERVICE_LABEL}.plist"
PROXY_PORT="11434"
BACKEND_PORT="11435"
DASHBOARD_FILE="${INSTALL_DIR}/dashboard.html"

perform_uninstall() {
    print_info "Uninstalling Clean Ollama Proxy for macOS..."

    if [[ -f "${PLIST_PATH}" ]]; then
        print_info "Unloading launchd service..."
        launchctl bootout system "${PLIST_PATH}" >/dev/null 2>&1 || true
        launchctl disable "system/${SERVICE_LABEL}" >/dev/null 2>&1 || true
    else
        print_warn "Launchd service not found; skipping unload."
    fi

    for proc in ollama-proxy ollama; do
        if pgrep -x "${proc}" >/dev/null 2>&1; then
            print_warn "Killing ${proc}..."
            pkill -9 -x "${proc}" >/dev/null 2>&1 || true
        fi
    done

    print_info "Removing installed files..."
    rm -f "${PLIST_PATH}" "${BIN_PATH}" "${INSTALL_DIR}/main.go" \
        "${INSTALL_DIR}/go.mod" "${INSTALL_DIR}/go.sum"
    rm -rf "${ANALYTICS_DIR}" "${LOG_DIR}"

    print_info "Uninstall complete."
}

normalize_action() {
    local choice="${1:-}"
    choice="$(printf '%s' "${choice}" | tr '[:upper:]' '[:lower:]')"
    case "${choice}" in
        i|install) echo "install" ;;
        u|uninstall|remove) echo "uninstall" ;;
        r|reinstall) echo "reinstall" ;;
        *) return 1 ;;
    esac
}

prompt_for_action() {
    while true; do
        echo "Select an action:"
        echo "  [i] Install"
        echo "  [u] Uninstall"
        echo "  [r] Reinstall"
        read -rp "Choice [i/u/r]: " response || exit 1
        if ACTION="$(normalize_action "${response}")"; then
            break
        fi
        print_warn "Invalid choice. Please select install, uninstall, or reinstall."
    done
}

perform_install() {
print_info "Installing Clean Ollama Proxy for macOS..."

# Stop existing launchd job if present
if [[ -f "${PLIST_PATH}" ]]; then
    print_info "Unloading previous launchd service..."
    launchctl bootout system "${PLIST_PATH}" >/dev/null 2>&1 || true
fi

# Kill old processes
for proc in ollama-proxy ollama; do
    if pgrep -x "${proc}" >/dev/null 2>&1; then
        print_warn "Killing ${proc}..."
        pkill -9 -x "${proc}" || true
    fi
done

# Free ports if necessary
for port in "${PROXY_PORT}" "${BACKEND_PORT}"; do
    if lsof -ti tcp:"${port}" >/dev/null 2>&1; then
        print_warn "Port ${port} is busy; terminating processes"
        lsof -ti tcp:"${port}" | xargs -r kill -9 2>/dev/null || true
    fi
done

print_info "Preparing install directories..."
rm -f "${INSTALL_DIR}/ollama-proxy" "${INSTALL_DIR}/main.go" "${INSTALL_DIR}/go.mod" "${INSTALL_DIR}/go.sum"
rm -rf "${ANALYTICS_DIR}"
mkdir -p "${ANALYTICS_DIR}" "${LOG_DIR}"
chmod 755 "${INSTALL_DIR}"

if [[ ! -f "${SCRIPT_DIR}/dashboard.html" ]]; then
    print_error "dashboard.html not found next to install_macos.sh"
    exit 1
fi

if ! command -v brew >/dev/null 2>&1; then
    print_error "Homebrew is required. Install from https://brew.sh and rerun."
    exit 1
fi

print_info "Installing dependencies via Homebrew (Go, SQLite)..."
run_brew update >/dev/null
run_brew install go sqlite3 >/dev/null 2>&1 || true

if ! command -v ollama >/dev/null 2>&1; then
    print_warn "Ollama CLI not found. Installing via official script..."
    curl -fsSL https://ollama.com/install.sh | sh
fi

print_info "Writing Go source..."
cat > "${INSTALL_DIR}/main.go" <<'GOEOF'
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	_ "modernc.org/sqlite"
)

const (
	defaultProxyPort     = "11434"
	defaultBackendPort   = "11435"
	defaultAnalyticsDB   = "/usr/local/ollama-metrics/analytics/ollama_analytics.db"
	defaultDashboardFile = "/usr/local/ollama-metrics/dashboard.html"
	defaultRecentLimit   = 25
)

var (
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ollama_requests_total",
			Help: "Total number of requests by model and endpoint",
		},
		[]string{"model", "endpoint", "status"},
	)

	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ollama_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
		},
		[]string{"model", "endpoint"},
	)

	tokensGenerated = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ollama_tokens_generated",
			Help:    "Number of tokens generated per request",
			Buckets: prometheus.ExponentialBuckets(10, 2, 10),
		},
		[]string{"model"},
	)

	activeRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ollama_active_requests",
			Help: "Number of currently active requests",
		},
	)
)

type Analytics struct {
	db *sql.DB
	mu sync.Mutex
}

type RequestData struct {
	Timestamp      time.Time
	Model          string
	Endpoint       string
	Prompt         string
	Response       string
	InputTokens    int
	OutputTokens   int
	Latency        float64
	Status         string
	ClientIP       string
	TokensPerSec   float64
}

func init() {
	prometheus.MustRegister(requestsTotal)
	prometheus.MustRegister(requestDuration)
	prometheus.MustRegister(tokensGenerated)
	prometheus.MustRegister(activeRequests)
}

func main() {
	proxyPort := flag.String("proxy-port", getEnv("PROXY_PORT", defaultProxyPort), "Proxy port")
	backendPort := flag.String("backend-port", getEnv("OLLAMA_BACKEND_PORT", defaultBackendPort), "Ollama backend port")
	analyticsDB := flag.String("analytics-db", getEnv("ANALYTICS_DB", defaultAnalyticsDB), "Analytics database path")
	dashboardFile := flag.String("dashboard-file", getEnv("DASHBOARD_FILE", defaultDashboardFile), "Dashboard HTML path")
	flag.Parse()

	log.Printf("Starting Ollama Proxy for macOS")
	log.Printf("Proxy Port: %s", *proxyPort)
	log.Printf("Backend Port: %s", *backendPort)
	log.Printf("Analytics DB: %s", *analyticsDB)

	analytics, err := initAnalytics(*analyticsDB)
	if err != nil {
		log.Fatalf("Failed to initialize analytics: %v", err)
	}
	defer analytics.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ollamaCmd := startOllama(ctx, *backendPort)
	defer func() {
		if ollamaCmd != nil && ollamaCmd.Process != nil {
			log.Println("Stopping Ollama process...")
			ollamaCmd.Process.Kill()
		}
	}()

	backendURL := fmt.Sprintf("http://localhost:%s", *backendPort)
	if err := waitForOllama(backendURL); err != nil {
		log.Fatalf("Ollama failed to start: %v", err)
	}

	targetURL, _ := url.Parse(backendURL)
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		log.Printf("[%s] %s %s", req.RemoteAddr, req.Method, req.URL.Path)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleProxy(w, r, proxy, analytics)
	})

	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/analytics", func(w http.ResponseWriter, r *http.Request) {
		handleAnalytics(w, r, analytics)
	})
	mux.HandleFunc("/recent", func(w http.ResponseWriter, r *http.Request) {
		handleRecent(w, r, analytics)
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		serveDashboard(w, r, *dashboardFile)
	})
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Proxy: OK\nOllama: %s\n", backendURL)
	})

	server := &http.Server{
		Addr:    ":" + *proxyPort,
		Handler: mux,
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Shutting down gracefully...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
		cancel()
	}()

	log.Printf("============================================================")
	log.Printf("✓ Ollama Proxy is running!")
	log.Printf("✓ Proxy listening on: http://localhost:%s", *proxyPort)
	log.Printf("✓ Dashboard: http://localhost:%s/dashboard", *proxyPort)
	log.Printf("✓ Metrics: http://localhost:%s/metrics", *proxyPort)
	log.Printf("✓ Analytics API: http://localhost:%s/analytics", *proxyPort)
	log.Printf("============================================================")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}

	log.Println("Server stopped")
}

func startOllama(ctx context.Context, port string) *exec.Cmd {
	// Kill only "ollama serve" processes, not ollama-proxy
	// Use exact match with pgrep to avoid killing ourselves
	out, _ := exec.Command("pgrep", "-x", "ollama").Output()
	if len(out) > 0 {
		log.Println("Killing existing Ollama processes...")
		exec.Command("pkill", "-9", "-x", "ollama").Run()
		time.Sleep(time.Second)
	}

	log.Printf("Starting Ollama on port %s...", port)
	cmd := exec.CommandContext(ctx, "ollama", "serve")
	cmd.Env = append(os.Environ(), fmt.Sprintf("OLLAMA_HOST=0.0.0.0:%s", port))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start Ollama: %v", err)
	}

	log.Printf("Ollama started with PID %d", cmd.Process.Pid)
	return cmd
}

func waitForOllama(backendURL string) error {
	log.Println("Waiting for Ollama to be ready...")
	client := &http.Client{Timeout: 2 * time.Second}

	for i := 0; i < 30; i++ {
		resp, err := client.Get(backendURL + "/api/tags")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			log.Println("✓ Ollama is ready")
			return nil
		}
		time.Sleep(time.Second)
	}

	return fmt.Errorf("Ollama failed to start after 30 seconds")
}

func handleProxy(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy, analytics *Analytics) {
	start := time.Now()
	activeRequests.Inc()
	defer activeRequests.Dec()

	var requestBody []byte
	if r.Body != nil {
		requestBody, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(requestBody)))
	}

	isInference := strings.HasPrefix(r.URL.Path, "/api/generate") || 
		strings.HasPrefix(r.URL.Path, "/api/chat")

	rw := &responseWriter{ResponseWriter: w, statusCode: 200}

	proxy.ServeHTTP(rw, r)

	if isInference {
		duration := time.Since(start).Seconds()
		
		var data RequestData
		json.Unmarshal(requestBody, &data)
		
		model := data.Model
		if model == "" {
			model = "unknown"
		}

		status := fmt.Sprintf("%d", rw.statusCode)
		
		requestsTotal.WithLabelValues(model, r.URL.Path, status).Inc()
		requestDuration.WithLabelValues(model, r.URL.Path).Observe(duration)

		data.Timestamp = start
		data.Endpoint = r.URL.Path
		data.Latency = duration
		data.Status = status
		data.ClientIP = r.RemoteAddr

		go analytics.Store(data)
	}
}

func initAnalytics(dbPath string) (*Analytics, error) {
	os.MkdirAll(strings.TrimSuffix(dbPath, "/ollama_analytics.db"), 0755)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE IF NOT EXISTS requests (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME,
		model TEXT,
		endpoint TEXT,
		prompt TEXT,
		response TEXT,
		input_tokens INTEGER,
		output_tokens INTEGER,
		latency REAL,
		status TEXT,
		client_ip TEXT,
		tokens_per_sec REAL
	);
	CREATE INDEX IF NOT EXISTS idx_timestamp ON requests(timestamp);
	CREATE INDEX IF NOT EXISTS idx_model ON requests(model);
	`

	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	return &Analytics{db: db}, nil
}

func (a *Analytics) Store(data RequestData) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	query := `
		INSERT INTO requests (timestamp, model, endpoint, prompt, response, 
			input_tokens, output_tokens, latency, status, client_ip, tokens_per_sec)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := a.db.Exec(query, data.Timestamp, data.Model, data.Endpoint,
		truncate(data.Prompt, 500), truncate(data.Response, 500),
		data.InputTokens, data.OutputTokens, data.Latency,
		data.Status, data.ClientIP, data.TokensPerSec)

	return err
}

func (a *Analytics) GetStats() (map[string]interface{}, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	stats := make(map[string]interface{})

	var total int
	a.db.QueryRow("SELECT COUNT(*) FROM requests").Scan(&total)
	stats["total_requests"] = total

	rows, _ := a.db.Query("SELECT model, COUNT(*) FROM requests GROUP BY model")
	defer rows.Close()

	modelCounts := make(map[string]int)
	for rows.Next() {
		var model string
		var count int
		rows.Scan(&model, &count)
		modelCounts[model] = count
	}
	stats["by_model"] = modelCounts

	var avgLatency float64
	a.db.QueryRow("SELECT AVG(latency) FROM requests").Scan(&avgLatency)
	stats["avg_latency"] = avgLatency

	return stats, nil
}

func (a *Analytics) Close() error {
	return a.db.Close()
}

func (a *Analytics) GetRecent(limit int) ([]RequestData, error) {
	if limit <= 0 {
		limit = defaultRecentLimit
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	query := `
		SELECT timestamp, model, endpoint, prompt, response,
		       input_tokens, output_tokens, latency, status, client_ip, tokens_per_sec
		FROM requests
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows, err := a.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var recent []RequestData
	for rows.Next() {
		var (
			entry    RequestData
			rawStamp string
		)
		if err := rows.Scan(
			&rawStamp,
			&entry.Model,
			&entry.Endpoint,
			&entry.Prompt,
			&entry.Response,
			&entry.InputTokens,
			&entry.OutputTokens,
			&entry.Latency,
			&entry.Status,
			&entry.ClientIP,
			&entry.TokensPerSec,
		); err != nil {
			return nil, err
		}
		if rawStamp != "" {
			if ts, err := time.Parse(time.RFC3339Nano, rawStamp); err == nil {
				entry.Timestamp = ts
			}
		}
		recent = append(recent, entry)
	}

	return recent, nil
}

func handleAnalytics(w http.ResponseWriter, r *http.Request, analytics *Analytics) {
	stats, err := analytics.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func handleRecent(w http.ResponseWriter, r *http.Request, analytics *Analytics) {
	limit := defaultRecentLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	entries, err := analytics.GetRecent(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length] + "..."
}

func serveDashboard(w http.ResponseWriter, r *http.Request, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, fmt.Sprintf("dashboard unavailable: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}
GOEOF

print_info "Initializing Go module..."
pushd "${INSTALL_DIR}" >/dev/null
export GO111MODULE=on
go mod init ollama-proxy >/dev/null 2>&1 || true
go get github.com/prometheus/client_golang/prometheus >/dev/null
go get github.com/prometheus/client_golang/prometheus/promhttp >/dev/null
go get modernc.org/sqlite >/dev/null
go mod tidy >/dev/null

print_info "Building application..."
go build -o "${BIN_PATH}" main.go
popd >/dev/null

chmod 755 "${BIN_PATH}"

print_info "Creating launchd service..."
cat > "${PLIST_PATH}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${SERVICE_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_PATH}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PROXY_PORT</key><string>${PROXY_PORT}</string>
        <key>OLLAMA_BACKEND_PORT</key><string>${BACKEND_PORT}</string>
        <key>ANALYTICS_DB</key><string>${ANALYTICS_DIR}/ollama_analytics.db</string>
        <key>DASHBOARD_FILE</key><string>${DASHBOARD_FILE}</string>
    </dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>WorkingDirectory</key><string>${INSTALL_DIR}</string>
    <key>StandardOutPath</key><string>${LOG_DIR}/ollama-proxy.log</string>
    <key>StandardErrorPath</key><string>${LOG_DIR}/ollama-proxy-error.log</string>
</dict>
</plist>
EOF

chown root:wheel "${PLIST_PATH}"
chmod 644 "${PLIST_PATH}"

print_info "Loading launchd service..."
launchctl bootstrap system "${PLIST_PATH}"
launchctl enable "system/${SERVICE_LABEL}"
launchctl kickstart -k "system/${SERVICE_LABEL}"

print_info "Installation complete!"
echo "Service: ${SERVICE_LABEL}"
echo "Binary:  ${BIN_PATH}"
echo "Proxy:   http://localhost:${PROXY_PORT}"
echo "Dashboard: http://localhost:${PROXY_PORT}/dashboard"
echo ""
echo "Use 'launchctl print system/${SERVICE_LABEL}' to inspect status."
}

ACTION="${1:-}"
if [[ -n "${ACTION}" ]]; then
    if ! ACTION="$(normalize_action "${ACTION}")"; then
        print_error "Unknown action '${1}'. Use install, uninstall, or reinstall."
        exit 1
    fi
else
    prompt_for_action
fi

case "${ACTION}" in
    install)
        perform_install
        ;;
    uninstall)
        perform_uninstall
        ;;
    reinstall)
        perform_uninstall
        perform_install
        ;;
esac
