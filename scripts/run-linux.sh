#!/usr/bin/env bash
set -euo pipefail
RUNTIME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export XRAY_MANAGER_HOME="${XRAY_MANAGER_HOME:-$RUNTIME}"
export PORT="${PORT:-54321}"
if ! command -v node >/dev/null 2>&1; then
  echo '[xray-manager-v4] Node.js 20+ is required but was not found in PATH.' >&2
  echo 'Install Node.js from https://nodejs.org/ and run this script again.' >&2
  exit 1
fi
echo "[xray-manager-v4] Starting http://127.0.0.1:$PORT"
exec node "$RUNTIME/index.js"
