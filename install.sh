#!/bin/bash
# ──────────────────────────────────────────────────────────────────
# Phish Net — Install Script (Linux / macOS)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/rakshand2005/Phish-Tank/main/install.sh | bash
# ──────────────────────────────────────────────────────────────────

set -e

REPO="rakshand2005/phish-tank"  # ← Using your GitHub username/repo
IMAGE="ghcr.io/${REPO}:latest"

echo ""
echo "🛡️  Phish Net — Installer"
echo "───────────────────────────────────────────"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed."
    echo "   Install Docker from: https://docs.docker.com/get-docker/"
    exit 1
fi

echo "📦 Pulling Phish Net image from GitHub Container Registry..."
docker pull "${IMAGE}"

echo ""
echo "🔧 Creating 'phishnet' command..."

# Detect shell config file
SHELL_CONFIG=""
if [ -f "$HOME/.zshrc" ]; then
    SHELL_CONFIG="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_CONFIG="$HOME/.bashrc"
elif [ -f "$HOME/.bash_profile" ]; then
    SHELL_CONFIG="$HOME/.bash_profile"
fi

# Create a shell function so the caller's current directory is available to
# scan-dir inside the container as /workspace.
ALIAS_CMD="phishnet() { docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v \"\$PWD:/workspace\" -w /workspace ${IMAGE} \"\$@\"; }"

if [ -n "$SHELL_CONFIG" ]; then
    # Remove old alias if it exists
    grep -vE "alias phishnet=|^phishnet\\(\\)" "$SHELL_CONFIG" > "$SHELL_CONFIG.tmp" 2>/dev/null || true
    mv "$SHELL_CONFIG.tmp" "$SHELL_CONFIG"

    # Add new alias
    echo "" >> "$SHELL_CONFIG"
    echo "# Phish Net" >> "$SHELL_CONFIG"
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
echo "     phishnet scan nginx:1.14"
echo "     phishnet scan-dir ."
echo "     phishnet scan nginx:1.14 --output json"
echo "     phishnet scan nginx:1.14 --fail-on CRITICAL"
echo "     phishnet integrity nginx:1.14"
echo "     phishnet fix nginx:1.14"
echo ""
echo "   ⚠️  Restart your terminal or run: source ${SHELL_CONFIG}"
echo ""
