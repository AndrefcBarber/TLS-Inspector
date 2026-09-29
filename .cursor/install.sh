#!/usr/bin/env bash
# Prepares a fresh machine to build and run TLS Inspector. Safe to re-run.
set -euo pipefail

DOTNET_DIR="$HOME/.dotnet"

if [ ! -x "$DOTNET_DIR/dotnet" ]; then
  curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
  bash /tmp/dotnet-install.sh --channel 9.0 --install-dir "$DOTNET_DIR"
fi

export PATH="$DOTNET_DIR:$PATH"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1

# Interactive shells and terminals need the SDK too, but only add the entry once.
if ! grep -qs '.dotnet:$PATH' "$HOME/.bashrc"; then
  printf '\nexport PATH="$HOME/.dotnet:$PATH"\n' >> "$HOME/.bashrc"
fi

cd "$(dirname "$0")/.."
dotnet restore TlsInspector.sln
dotnet build TlsInspector.sln --no-restore
