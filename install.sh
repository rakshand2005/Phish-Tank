#!/bin/bash
# ──────────────────────────────────────────────────────────────────
# Container Security Scanner — Install Script (Linux / macOS)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/<your-repo>/main/install.sh | bash
# ──────────────────────────────────────────────────────────────────

set -e

REPO="your-username/container-scanner"  # ← Change this to your GitHub username/repo
IMAGE="ghcr.io/${REPO}:latest"

echo ""
echo "🛡️  Container Security Scanner — Installer"
echo "───────────────────────────────────────────"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed."
    echo "   Install Docker from: https://docs.docker.com/get-docker/"
    exit 1
fi

echo "📦 Pulling scanner image from GitHub Container Registry..."
docker pull "${IMAGE}"

echo ""
echo "🔧 Creating 'scanner' command..."

# Detect shell config file
SHELL_CONFIG=""
if [ -f "$HOME/.zshrc" ]; then
    SHELL_CONFIG="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_CONFIG="$HOME/.bashrc"
elif [ -f "$HOME/.bash_profile" ]; then
    SHELL_CONFIG="$HOME/.bash_profile"
fi

# Create the alias
ALIAS_CMD="alias scanner='docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ${IMAGE}'"

if [ -n "$SHELL_CONFIG" ]; then
    # Remove old alias if it exists
    grep -v "alias scanner=" "$SHELL_CONFIG" > "$SHELL_CONFIG.tmp" 2>/dev/null || true
    mv "$SHELL_CONFIG.tmp" "$SHELL_CONFIG"

    # Add new alias
    echo "" >> "$SHELL_CONFIG"
    echo "# Container Security Scanner" >> "$SHELL_CONFIG"
    echo "${ALIAS_CMD}" >> "$SHELL_CONFIG"

    echo "   Added to ${SHELL_CONFIG}"
else
    echo "   Could not detect shell config. Add this manually:"
    echo "   ${ALIAS_CMD}"
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "   Usage:"
echo "     scanner scan nginx:1.14"
echo "     scanner scan nginx:1.14 --output json"
echo "     scanner scan nginx:1.14 --fail-on CRITICAL"
echo "     scanner integrity nginx:1.14"
echo ""
echo "   ⚠️  Restart your terminal or run: source ${SHELL_CONFIG}"
echo ""
