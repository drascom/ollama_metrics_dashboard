#!/bin/bash

################################################################################
# Clean Ollama Proxy Installation Script for Debian Linux
# Simple, native Linux implementation
# Installation directory: /root/ollama-metrics
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${SCRIPT_DIR}"
SERVICE_NAME="ollama-proxy"
PROXY_PORT="11434"
BACKEND_PORT="11435"
ANALYTICS_DIR="${INSTALL_DIR}/analytics"
DASHBOARD_FILE="${INSTALL_DIR}/dashboard.html"

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
if [ "$EUID" -ne 0 ]; then 
    print_error "This script must be run as root"
    exit 1
fi

print_info "Installing Clean Ollama Proxy for Linux..."

# Clean up any previous installations
print_info "Cleaning up previous installations..."

# Stop and disable any existing services
for service in ollama-proxy ollama; do
    if systemctl is-active --quiet $service 2>/dev/null; then
        print_info "Stopping $service service..."
        systemctl stop $service 2>/dev/null || true
    fi
    if systemctl is-enabled --quiet $service 2>/dev/null; then
        print_info "Disabling $service service..."
        systemctl disable $service 2>/dev/null || true
    fi
done

# Kill any running processes
print_info "Killing any running Ollama/proxy processes..."
pkill -9 ollama-proxy 2>/dev/null && print_info "Killed ollama-proxy" || print_info "No ollama-proxy running"
pkill -9 ollama 2>/dev/null && print_info "Killed ollama" || print_info "No ollama running"
sleep 2

print_info "Waiting for processes to terminate..."
# Wait for processes to actually die
for i in {1..5}; do
    if ! pgrep -x ollama > /dev/null && ! pgrep ollama-proxy > /dev/null; then
        print_info "All processes terminated"
        break
    fi
    sleep 1
done

# Check if ports are free
print_info "Checking for port conflicts..."
for port in 11434 11435; do
    if netstat -tlnp 2>/dev/null | grep ":$port " > /dev/null; then
        print_warn "Port $port is in use:"
        netstat -tlnp | grep ":$port "
        PID=$(netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d'/' -f1)
        if [ -n "$PID" ]; then
            print_warn "Killing process $PID on port $port"
            kill -9 $PID 2>/dev/null || true
        fi
    fi
done
sleep 1

# Remove old service files
if [ -f /etc/systemd/system/ollama-proxy.service ]; then
    print_info "Removing old service file..."
    rm -f /etc/systemd/system/ollama-proxy.service
    systemctl daemon-reload
fi

# Clean old build artifacts
print_info "Cleaning previous build artifacts..."
rm -f "${INSTALL_DIR}/ollama-proxy" "${INSTALL_DIR}/main.go" "${INSTALL_DIR}/go.mod" "${INSTALL_DIR}/go.sum"
rm -rf "${ANALYTICS_DIR}"

print_info "Cleanup complete. Starting fresh installation..."
echo ""

# Install dependencies
print_info "Installing dependencies..."
apt-get update
apt-get install -y golang-go curl sqlite3

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
print_info "Go version: ${GO_VERSION}"

# Install Ollama if needed
if ! command -v ollama &> /dev/null; then
    print_warn "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    print_info "Ollama installed"
else
    print_info "Ollama already installed: $(ollama --version 2>&1 | head -1)"
fi

# Make sure Ollama service is disabled (we'll manage it ourselves)
if systemctl list-unit-files | grep -q ollama.service; then
    print_info "Ensuring Ollama system service is disabled..."
    systemctl stop ollama 2>/dev/null || true
    systemctl disable ollama 2>/dev/null || true
fi

# Create directories
print_info "Creating directories..."
mkdir -p "${INSTALL_DIR}"
mkdir -p "${ANALYTICS_DIR}"
cd "${INSTALL_DIR}"

if [ ! -f "${SCRIPT_DIR}/dashboard.html" ]; then
    print_error "dashboard.html not found next to install.sh"
    exit 1
fi

# Create the Go application
print_info "Creating ollama-proxy application..."
cat > main.go << 'GOEOF'
package main

import (
	"bufio"
	"bytes"
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
	"path/filepath"
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
	defaultAnalyticsDB   = "analytics/ollama_analytics.db"
	defaultDashboardFile = "dashboard.html"
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
	Timestamp    time.Time `json:"timestamp"`
	Model        string    `json:"model"`
	Endpoint     string    `json:"endpoint"`
	Prompt       string    `json:"prompt"`
	Response     string    `json:"response"`
	InputTokens  int       `json:"inputTokens"`
	OutputTokens int       `json:"outputTokens"`
	Latency      float64   `json:"latency"`
	Status       string    `json:"status"`
	ClientIP     string    `json:"clientIp"`
	TokensPerSec float64   `json:"tokensPerSec"`
	TotalDuration       int64 `json:"totalDuration"`
	LoadDuration        int64 `json:"loadDuration"`
	PromptEvalCount     int   `json:"promptEvalCount"`
	PromptEvalDuration  int64 `json:"promptEvalDuration"`
	EvalCount           int   `json:"evalCount"`
	EvalDuration        int64 `json:"evalDuration"`
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

	log.Printf("Starting Ollama Proxy for Linux")
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
		r.Body = io.NopCloser(bytes.NewReader(requestBody))
	}

	isInference := strings.HasPrefix(r.URL.Path, "/api/generate") || 
		strings.HasPrefix(r.URL.Path, "/api/chat")

	rw := &responseWriter{ResponseWriter: w, statusCode: 200}

	proxy.ServeHTTP(rw, r)

	if isInference {
		duration := time.Since(start).Seconds()

		var data RequestData
		if len(requestBody) > 0 {
			json.Unmarshal(requestBody, &data)
		}

		metrics := parseOllamaResponse(rw.Body())
		if metrics != nil {
			if metrics.Model != "" {
				data.Model = metrics.Model
			}
			if metrics.Response != "" {
				data.Response = metrics.Response
			}
			if metrics.PromptEvalCount > 0 {
				data.InputTokens = metrics.PromptEvalCount
			}
			if metrics.PromptEvalDuration > 0 {
				data.PromptEvalDuration = metrics.PromptEvalDuration
			}
			if metrics.EvalCount > 0 {
				data.OutputTokens = metrics.EvalCount
			}
			if metrics.EvalDuration > 0 {
				data.EvalDuration = metrics.EvalDuration
			}
			if metrics.TotalDuration > 0 {
				data.TotalDuration = metrics.TotalDuration
			}
			if metrics.LoadDuration > 0 {
				data.LoadDuration = metrics.LoadDuration
			}
			if metrics.Response != "" && data.Response == "" {
				data.Response = metrics.Response
			}
			if metrics.PromptEvalCount > 0 {
				data.PromptEvalCount = metrics.PromptEvalCount
			}
		}

		model := data.Model
		if model == "" {
			model = "unknown"
		}

		status := fmt.Sprintf("%d", rw.statusCode)

		requestsTotal.WithLabelValues(model, r.URL.Path, status).Inc()
		requestDuration.WithLabelValues(model, r.URL.Path).Observe(duration)

		if data.OutputTokens > 0 {
			tokensGenerated.WithLabelValues(model).Observe(float64(data.OutputTokens))
		}

		data.Timestamp = start
		data.Endpoint = r.URL.Path
		data.Latency = duration
		data.Status = status
		data.ClientIP = r.RemoteAddr

		if data.TokensPerSec == 0 && data.OutputTokens > 0 {
			var divisor float64
			if data.EvalDuration > 0 {
				divisor = float64(data.EvalDuration) / float64(time.Second)
			} else {
				divisor = duration
			}
			if divisor > 0 {
				data.TokensPerSec = float64(data.OutputTokens) / divisor
			}
		}

		go analytics.Store(data)
	}
}

func initAnalytics(dbPath string) (*Analytics, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, err
	}

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

# Initialize Go module
print_info "Initializing Go module..."
go mod init ollama-proxy 2>/dev/null || true
go get github.com/prometheus/client_golang/prometheus
go get github.com/prometheus/client_golang/prometheus/promhttp
go get modernc.org/sqlite
go mod tidy

# Build
print_info "Building application..."
go build -o ollama-proxy main.go

# Check system resources
print_info "Checking system resources..."
echo "Memory:"
free -h
echo ""
echo "Disk:"
df -h "${INSTALL_DIR}"
echo ""

# Check for OOM killer activity
if dmesg | tail -50 | grep -i "killed process" > /dev/null 2>&1; then
    print_warn "OOM Killer has been active recently:"
    dmesg | tail -50 | grep -i "killed process"
    echo ""
fi

# Check if something is killing processes
print_info "Checking for process restrictions..."
if command -v systemd-analyze &> /dev/null; then
    systemd-analyze security ollama-proxy.service 2>/dev/null || true
fi

# Create systemd service
print_info "Creating systemd service..."
SYSTEMD_WORKDIR_ESCAPED="${INSTALL_DIR}"
if command -v systemd-escape >/dev/null 2>&1; then
    SYSTEMD_WORKDIR_ESCAPED=$(systemd-escape --path "${INSTALL_DIR}")
else
    SYSTEMD_WORKDIR_ESCAPED=$(printf '%s' "${INSTALL_DIR}" | sed 's/\\/\\\\/g; s/ /\\x20/g')
fi
SYSTEMD_EXEC_ESCAPED="${SYSTEMD_WORKDIR_ESCAPED}/ollama-proxy"
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Ollama Proxy Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${SYSTEMD_WORKDIR_ESCAPED}
Environment="PROXY_PORT=${PROXY_PORT}"
Environment="OLLAMA_BACKEND_PORT=${BACKEND_PORT}"
Environment="ANALYTICS_DB=${ANALYTICS_DIR}/ollama_analytics.db"
Environment="DASHBOARD_FILE=${DASHBOARD_FILE}"
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
ExecStart=${SYSTEMD_EXEC_ESCAPED}
Restart=always
RestartSec=10s

# Give it time to start Ollama
TimeoutStartSec=120s
TimeoutStopSec=30s

# Don't kill during startup
KillMode=mixed
SendSIGKILL=no

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ollama-proxy

[Install]
WantedBy=multi-user.target
EOF

# Test the binary first
print_info "Testing binary directly (not in background)..."
echo "If this hangs, press Ctrl+C after 3 seconds..."

# Run in foreground for a moment to see actual output
timeout 3s "${INSTALL_DIR}/ollama-proxy" 2>&1 | head -20 || true

echo ""
print_info "Checking dmesg for OOM or security kills..."
dmesg | tail -30 | grep -iE "(kill|oom|security|audit)" || echo "No kill messages found"

echo ""
print_info "Checking if Ollama is already running..."
if pgrep -x ollama > /dev/null; then
    print_warn "Ollama is already running! Killing it..."
    pkill -9 ollama
    sleep 2
fi

# Try running with strace to see what's killing it
print_info "Installing strace for debugging..."
apt-get install -y strace > /dev/null 2>&1 || true

print_info "Testing with strace to see system calls..."
timeout 3s strace -e trace=signal "${INSTALL_DIR}/ollama-proxy" 2>&1 | tail -20 || true

# Enable and start
print_info "Starting systemd service..."
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl start ${SERVICE_NAME}

# Wait and check with detailed logging
print_info "Waiting for service to start..."
sleep 5

if systemctl is-active --quiet ${SERVICE_NAME}; then
    print_info "✓ Service started successfully!"
    echo ""
    echo "================================================================"
    print_info "Installation Complete!"
    echo "================================================================"
    echo ""
    echo "Service: ${SERVICE_NAME}"
    echo "Proxy: http://localhost:${PROXY_PORT}"
    echo "Metrics: http://localhost:${PROXY_PORT}/metrics"
    echo "Analytics: http://localhost:${PROXY_PORT}/analytics"
    echo ""
    echo "Commands:"
    echo "  systemctl status ${SERVICE_NAME}"
    echo "  journalctl -u ${SERVICE_NAME} -f"
    echo ""
else
    print_error "Service failed to start"
    echo ""
    echo "=== Service Status ==="
    systemctl status ${SERVICE_NAME} --no-pager -l
    echo ""
    echo "=== Journal Logs ==="
    journalctl -u ${SERVICE_NAME} -n 50 --no-pager
    echo ""
    echo "=== Checking for port conflicts ==="
    netstat -tlnp | grep -E "(11434|11435)" || echo "No conflicts found"
    echo ""
    print_warn "Try running manually to see errors:"
    echo "  cd \"${INSTALL_DIR}\""
    echo "  ./ollama-proxy"
    exit 1
fi
