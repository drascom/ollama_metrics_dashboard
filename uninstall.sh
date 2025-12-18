#!/bin/bash

set -e

OS="$(uname -s)"
echo "🧹 Removing Ollama middleware assets on $OS"

if [ "$OS" == "Linux" ]; then
    if [ "$EUID" -ne 0 ]; then
        echo "❌ Please run as root (sudo ./uninstall.sh) on Linux."
        exit 1
    fi
    INSTALL_DIR="/opt/ollama-middleware"
    SERVICE_FILE="/etc/systemd/system/ollama-middleware.service"

    systemctl stop ollama-middleware 2>/dev/null || true
    systemctl disable ollama-middleware 2>/dev/null || true

    if [ -f "$SERVICE_FILE" ]; then
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
    fi

elif [ "$OS" == "Darwin" ]; then
    INSTALL_DIR="$HOME/ollama-middleware"
    LAUNCH_AGENT="$HOME/Library/LaunchAgents/uk.drascom.ollama-middleware.plist"

    launchctl unload "$LAUNCH_AGENT" 2>/dev/null || true

    if [ -f "$LAUNCH_AGENT" ]; then
        rm -f "$LAUNCH_AGENT"
    fi
else
    echo "❌ Unsupported OS: $OS"
    exit 1
fi

if [ -d "$INSTALL_DIR" ]; then
    echo "🗑️  Removing $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
else
    echo "ℹ️  Install directory $INSTALL_DIR not found; skipping"
fi

echo "✅ Uninstall complete"
