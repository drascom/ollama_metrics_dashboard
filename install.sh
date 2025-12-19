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
INSTALL_DIR="/root/ollama-metrics"
SERVICE_NAME="ollama-proxy"
PROXY_PORT="11434"
BACKEND_PORT="11435"
ANALYTICS_DIR="${INSTALL_DIR}/analytics"

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

# Clean old installation directory
if [ -d "${INSTALL_DIR}" ]; then
    print_info "Removing old installation directory..."
    rm -rf "${INSTALL_DIR}"
fi

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

# Create the Go application
print_info "Creating ollama-proxy application..."
cat > main.go << 'GOEOF'
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	_ "modernc.org/sqlite"
)

const (
	defaultProxyPort   = "11434"
	defaultBackendPort = "11435"
	defaultAnalyticsDB = "/root/ollama-metrics/analytics/ollama_analytics.db"
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
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		serveDashboard(w, r)
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

func handleAnalytics(w http.ResponseWriter, r *http.Request, analytics *Analytics) {
	stats, err := analytics.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
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

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	html := ""
	html += "<!DOCTYPE html>\n"
	html += "<html lang=\"en\">\n"
	html += "<head>\n"
	html += "    <meta charset=\"UTF-8\">\n"
	html += "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
	html += "    <title>Ollama Analytics Dashboard</title>\n"
	html += "    <style>\n"
	html += "        * { margin: 0; padding: 0; box-sizing: border-box; }\n"
	html += "        body {\n"
	html += "            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;\n"
	html += "            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n"
	html += "            min-height: 100vh;\n"
	html += "            padding: 20px;\n"
	html += "        }\n"
	html += "        .container { max-width: 1400px; margin: 0 auto; }\n"
	html += "        .header {\n"
	html += "            background: white;\n"
	html += "            padding: 30px;\n"
	html += "            border-radius: 15px;\n"
	html += "            box-shadow: 0 10px 30px rgba(0,0,0,0.2);\n"
	html += "            margin-bottom: 30px;\n"
	html += "            text-align: center;\n"
	html += "        }\n"
	html += "        .header h1 { color: #667eea; font-size: 2.5em; margin-bottom: 10px; }\n"
	html += "        .stats-grid {\n"
	html += "            display: grid;\n"
	html += "            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));\n"
	html += "            gap: 20px;\n"
	html += "            margin-bottom: 30px;\n"
	html += "        }\n"
	html += "        .stat-card {\n"
	html += "            background: white;\n"
	html += "            padding: 25px;\n"
	html += "            border-radius: 15px;\n"
	html += "            box-shadow: 0 5px 20px rgba(0,0,0,0.1);\n"
	html += "            transition: transform 0.3s;\n"
	html += "        }\n"
	html += "        .stat-card:hover { transform: translateY(-5px); }\n"
	html += "        .stat-card h3 {\n"
	html += "            color: #666;\n"
	html += "            font-size: 0.9em;\n"
	html += "            text-transform: uppercase;\n"
	html += "            letter-spacing: 1px;\n"
	html += "            margin-bottom: 10px;\n"
	html += "        }\n"
	html += "        .stat-card .value { color: #667eea; font-size: 2.5em; font-weight: bold; }\n"
	html += "        .chart-container {\n"
	html += "            background: white;\n"
	html += "            padding: 30px;\n"
	html += "            border-radius: 15px;\n"
	html += "            box-shadow: 0 10px 30px rgba(0,0,0,0.2);\n"
	html += "            margin-bottom: 30px;\n"
	html += "        }\n"
	html += "        .chart-container h2 {\n"
	html += "            color: #333;\n"
	html += "            margin-bottom: 20px;\n"
	html += "            padding-bottom: 10px;\n"
	html += "            border-bottom: 3px solid #667eea;\n"
	html += "        }\n"
	html += "        .model-bar { display: flex; align-items: center; margin-bottom: 15px; }\n"
	html += "        .model-name { width: 150px; font-weight: 600; color: #333; }\n"
	html += "        .bar {\n"
	html += "            flex: 1;\n"
	html += "            height: 30px;\n"
	html += "            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);\n"
	html += "            border-radius: 15px;\n"
	html += "            position: relative;\n"
	html += "            margin: 0 15px;\n"
	html += "        }\n"
	html += "        .bar-label {\n"
	html += "            position: absolute;\n"
	html += "            right: 10px;\n"
	html += "            top: 50%;\n"
	html += "            transform: translateY(-50%);\n"
	html += "            color: white;\n"
	html += "            font-weight: bold;\n"
	html += "        }\n"
	html += "        .refresh-btn {\n"
	html += "            background: #667eea;\n"
	html += "            color: white;\n"
	html += "            border: none;\n"
	html += "            padding: 12px 30px;\n"
	html += "            border-radius: 25px;\n"
	html += "            font-size: 1em;\n"
	html += "            cursor: pointer;\n"
	html += "            transition: all 0.3s;\n"
	html += "            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);\n"
	html += "        }\n"
	html += "        .refresh-btn:hover {\n"
	html += "            background: #764ba2;\n"
	html += "            transform: translateY(-2px);\n"
	html += "            box-shadow: 0 7px 20px rgba(102, 126, 234, 0.6);\n"
	html += "        }\n"
	html += "        .loading { text-align: center; padding: 40px; color: white; font-size: 1.2em; }\n"
	html += "        .error { background: #ff6b6b; color: white; padding: 20px; border-radius: 10px; margin: 20px 0; }\n"
	html += "    </style>\n"
	html += "</head>\n"
	html += "<body>\n"
	html += "    <div class=\"container\">\n"
	html += "        <div class=\"header\">\n"
	html += "            <h1>🦙 Ollama Analytics Dashboard</h1>\n"
	html += "            <p>Real-time metrics and performance monitoring</p>\n"
	html += "        </div>\n"
	html += "        <div id=\"loading\" class=\"loading\">Loading analytics data...</div>\n"
	html += "        <div id=\"error\" class=\"error\" style=\"display:none;\"></div>\n"
	html += "        <div id=\"dashboard\" style=\"display:none;\">\n"
	html += "            <div class=\"stats-grid\">\n"
	html += "                <div class=\"stat-card\">\n"
	html += "                    <h3>Total Requests</h3>\n"
	html += "                    <div class=\"value\" id=\"totalRequests\">0</div>\n"
	html += "                </div>\n"
	html += "                <div class=\"stat-card\">\n"
	html += "                    <h3>Average Latency</h3>\n"
	html += "                    <div class=\"value\" id=\"avgLatency\">0s</div>\n"
	html += "                </div>\n"
	html += "                <div class=\"stat-card\">\n"
	html += "                    <h3>Active Models</h3>\n"
	html += "                    <div class=\"value\" id=\"activeModels\">0</div>\n"
	html += "                </div>\n"
	html += "                <div class=\"stat-card\">\n"
	html += "                    <h3>Success Rate</h3>\n"
	html += "                    <div class=\"value\" id=\"successRate\">100%</div>\n"
	html += "                </div>\n"
	html += "            </div>\n"
	html += "            <div class=\"chart-container\">\n"
	html += "                <h2>Requests by Model</h2>\n"
	html += "                <div id=\"modelChart\"></div>\n"
	html += "            </div>\n"
	html += "            <div style=\"text-align: center; margin-top: 30px;\">\n"
	html += "                <button class=\"refresh-btn\" onclick=\"loadData()\">🔄 Refresh Data</button>\n"
	html += "            </div>\n"
	html += "        </div>\n"
	html += "    </div>\n"
	html += "    <script>\n"
	html += "        async function loadData() {\n"
	html += "            try {\n"
	html += "                document.getElementById('loading').style.display = 'block';\n"
	html += "                document.getElementById('error').style.display = 'none';\n"
	html += "                const response = await fetch('/analytics');\n"
	html += "                if (!response.ok) throw new Error('Failed to fetch analytics');\n"
	html += "                const data = await response.json();\n"
	html += "                document.getElementById('totalRequests').textContent = data.total_requests || 0;\n"
	html += "                document.getElementById('avgLatency').textContent = ((data.avg_latency || 0).toFixed(3)) + 's';\n"
	html += "                document.getElementById('activeModels').textContent = Object.keys(data.by_model || {}).length;\n"
	html += "                document.getElementById('successRate').textContent = '100%';\n"
	html += "                const modelChart = document.getElementById('modelChart');\n"
	html += "                modelChart.innerHTML = '';\n"
	html += "                const models = data.by_model || {};\n"
	html += "                const maxRequests = Math.max(...Object.values(models), 1);\n"
	html += "                for (const [model, count] of Object.entries(models)) {\n"
	html += "                    const width = (count / maxRequests) * 100;\n"
	html += "                    const div = document.createElement('div');\n"
	html += "                    div.className = 'model-bar';\n"
	html += "                    div.innerHTML = '<div class=\"model-name\">' + model + '</div>' +\n"
	html += "                        '<div class=\"bar\" style=\"width: ' + width + '%\">' +\n"
	html += "                        '<div class=\"bar-label\">' + count + '</div></div>';\n"
	html += "                    modelChart.appendChild(div);\n"
	html += "                }\n"
	html += "                document.getElementById('loading').style.display = 'none';\n"
	html += "                document.getElementById('dashboard').style.display = 'block';\n"
	html += "            } catch (error) {\n"
	html += "                document.getElementById('loading').style.display = 'none';\n"
	html += "                document.getElementById('error').style.display = 'block';\n"
	html += "                document.getElementById('error').textContent = 'Error loading data: ' + error.message;\n"
	html += "            }\n"
	html += "        }\n"
	html += "        loadData();\n"
	html += "        setInterval(loadData, 30000);\n"
	html += "    </script>\n"
	html += "</body>\n"
	html += "</html>\n"

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
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
df -h ${INSTALL_DIR}
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
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Ollama Proxy Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="PROXY_PORT=${PROXY_PORT}"
Environment="OLLAMA_BACKEND_PORT=${BACKEND_PORT}"
Environment="ANALYTICS_DB=${ANALYTICS_DIR}/ollama_analytics.db"
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
ExecStart=${INSTALL_DIR}/ollama-proxy
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
timeout 3s ${INSTALL_DIR}/ollama-proxy 2>&1 | head -20 || true

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
timeout 3s strace -e trace=signal ${INSTALL_DIR}/ollama-proxy 2>&1 | tail -20 || true

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
    echo "  cd ${INSTALL_DIR}"
    echo "  ./ollama-proxy"
    exit 1
fi