#!/bin/sh
set -e

# BlastRadius installer
# Usage: curl -sSL https://raw.githubusercontent.com/rickyruima/blastradius/main/blastradius/install.sh | sh

REPO="rickyruima/blastradius"
BINARY="blastradius"
INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Get latest version
VERSION=$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
if [ -z "$VERSION" ]; then
  echo "Failed to fetch latest version"
  exit 1
fi

echo "Installing blastradius v${VERSION} (${OS}/${ARCH})..."

# Download
URL="https://github.com/$REPO/releases/download/v${VERSION}/${BINARY}_${OS}_${ARCH}.tar.gz"
TMP=$(mktemp -d)
curl -sSL "$URL" -o "$TMP/blastradius.tar.gz"
tar -xzf "$TMP/blastradius.tar.gz" -C "$TMP"

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
else
  sudo mv "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
fi

rm -rf "$TMP"
echo "Installed blastradius v${VERSION} to $INSTALL_DIR/$BINARY"
