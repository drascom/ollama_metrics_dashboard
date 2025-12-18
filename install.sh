#!/bin/bash

# =================================================================
# OLLAMA MIDDLEWARE - UNIVERSAL INSTALLER
# Works on: Linux (Debian/Ubuntu) & macOS
# =================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_CONF="$SCRIPT_DIR/conf"
SRC_LUA="$SCRIPT_DIR/lua"
SRC_HTML="$SCRIPT_DIR/html"

# Detect OS
OS="$(uname -s)"
echo "🖥️  Detected OS: $OS"

if [ "$OS" == "Linux" ]; then
    # --- LINUX SETTINGS ---
    if [ "$EUID" -ne 0 ]; then 
        echo "❌ Please run as root (sudo ./install.sh) on Linux."
        exit 1
    fi
    
    INSTALL_DIR="/opt/ollama-middleware"
    NGINX_BIN="/usr/bin/openresty"
    MIME_TYPES="/usr/local/openresty/nginx/conf/mime.types"
    USER_OWNER="root"
    GROUP_OWNER="root"
    
elif [ "$OS" == "Darwin" ]; then
    # --- MACOS SETTINGS ---
    if ! command -v brew &> /dev/null; then
        echo "❌ Homebrew is required. Install it at https://brew.sh/"
        exit 1
    fi
    
    INSTALL_DIR="$HOME/ollama-middleware"
    USER_OWNER="$USER"
    GROUP_OWNER="staff" # Default group for mac users usually
    
else
    echo "❌ Unsupported OS: $OS"
    exit 1
fi

# =================================================================
# 1. Install Dependencies
# =================================================================
echo "📦 Installing Dependencies..."

if [ "$OS" == "Linux" ]; then
    if ! command -v openresty &> /dev/null; then
        apt-get update
        apt-get -y install --no-install-recommends wget gnupg ca-certificates lsb-release
        wget -O - https://openresty.org/package/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/openresty.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/openresty.gpg] http://openresty.org/package/ubuntu $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/openresty.list > /dev/null
        apt-get update
        apt-get -y install openresty
    fi
elif [ "$OS" == "Darwin" ]; then
    brew tap openresty/brew >/dev/null
    if ! brew list openresty/brew/openresty &> /dev/null; then
        brew install openresty/brew/openresty
    fi
    OPENRESTY_PREFIX="$(brew --prefix openresty/brew/openresty)"
    NGINX_BIN="$OPENRESTY_PREFIX/bin/openresty"
    MIME_TYPES="$OPENRESTY_PREFIX/nginx/conf/mime.types"
fi

# =================================================================
# 2. Setup Directories
# =================================================================
echo "📂 Setting up directories in $INSTALL_DIR..."

# Stop existing services
if [ "$OS" == "Linux" ]; then
    systemctl stop ollama-middleware 2>/dev/null || true
elif [ "$OS" == "Darwin" ]; then
    launchctl unload "$HOME/Library/LaunchAgents/uk.drascom.ollama-middleware.plist" 2>/dev/null || true
fi

mkdir -p "$INSTALL_DIR/conf"
mkdir -p "$INSTALL_DIR/lua"
mkdir -p "$INSTALL_DIR/html"
mkdir -p "$INSTALL_DIR/logs"

# Reset permissions
chown -R "$USER_OWNER:$GROUP_OWNER" "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"
chmod -R 777 "$INSTALL_DIR/logs" # Ensure logs are writable

# Create log files
touch "$INSTALL_DIR/logs/metrics.log"
touch "$INSTALL_DIR/logs/access.log"
touch "$INSTALL_DIR/logs/error.log"
chmod 666 "$INSTALL_DIR/logs/"*.log

# =================================================================
# 3. Copy Runtime Assets
# =================================================================
echo "📝 Copying runtime assets..."
cp -R "$SRC_LUA/." "$INSTALL_DIR/lua/"
cp -R "$SRC_HTML/." "$INSTALL_DIR/html/"

# =================================================================
# 4. Write Config (nginx.conf)
# =================================================================
echo "📝 Writing Nginx config..."

# Determine 'user' directive (Linux needs it, macOS ignores it if non-root)
USER_DIRECTIVE=""
if [ "$OS" == "Linux" ]; then
    USER_DIRECTIVE="user $USER_OWNER;"
fi

perl -pe "s#@@USER_DIRECTIVE@@#$USER_DIRECTIVE#g; s#@@MIME_TYPES@@#$MIME_TYPES#g" \
    "$SRC_CONF/nginx.conf.template" > "$INSTALL_DIR/conf/nginx.conf"

# =================================================================
# 5. Service Installation
# =================================================================

if [ "$OS" == "Linux" ]; then
    echo "🐧 Installing Systemd Service..."
    cat <<EOF > /etc/systemd/system/ollama-middleware.service
[Unit]
Description=Ollama Middleware Metrics
After=network.target ollama.service

[Service]
Type=forking
PIDFile=$INSTALL_DIR/logs/nginx.pid
ExecStart=$NGINX_BIN -p $INSTALL_DIR -c conf/nginx.conf
ExecReload=/bin/kill -s HUP \$MAINPID
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ollama-middleware
    systemctl restart ollama-middleware

elif [ "$OS" == "Darwin" ]; then
    echo "🍏 Installing LaunchAgent..."
    LAUNCH_AGENT="$HOME/Library/LaunchAgents/uk.drascom.ollama-middleware.plist"
    cat <<EOF > "$LAUNCH_AGENT"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>uk.drascom.ollama-middleware</string>
    <key>ProgramArguments</key>
    <array>
        <string>$NGINX_BIN</string>
        <string>-p</string>
        <string>$INSTALL_DIR</string>
        <string>-c</string>
        <string>conf/nginx.conf</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/logs/launch-error.log</string>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/logs/launch-out.log</string>
</dict>
</plist>
EOF
    launchctl load "$LAUNCH_AGENT"
fi

echo "====================================================="
echo "✅ Installation Complete!"
if [ "$OS" == "Linux" ]; then
    IP=$(hostname -I | awk '{print $1}')
    echo "➡️  UI: http://$IP:11435/metrics/"
else
    echo "➡️  UI: http://localhost:11435/metrics/"
fi
echo "====================================================="
