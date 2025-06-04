#!/bin/bash
set -e

# keyswap installer script
REPO="bmntech-io/keyswap"
BINARY="keyswap"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
esac

case $OS in
    darwin) OS="darwin" ;;
    linux) OS="linux" ;;
    *) echo "Unsupported OS: $OS" && exit 1 ;;
esac

# Get latest release
LATEST=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
    echo "Error: Could not get latest release"
    exit 1
fi

echo "Installing keyswap $LATEST for $OS-$ARCH..."

# Download URL
URL="https://github.com/$REPO/releases/download/$LATEST/keyswap-$OS-$ARCH"
INSTALL_DIR="/usr/local/bin"

# Create temp directory
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# Download binary
echo "Downloading $URL..."
curl -L -o "$TMP_DIR/keyswap" "$URL"

# Make executable
chmod +x "$TMP_DIR/keyswap"

# Install
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP_DIR/keyswap" "$INSTALL_DIR/keyswap"
else
    echo "Installing to $INSTALL_DIR (requires sudo)..."
    sudo mv "$TMP_DIR/keyswap" "$INSTALL_DIR/keyswap"
fi

echo "✓ keyswap installed successfully!"
echo ""
echo "Usage:"
echo "  keyswap user@hostname"
echo "  keyswap --port 2222 user@hostname"
echo ""
echo "Run 'keyswap --help' for more information."
