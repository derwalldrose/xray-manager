#!/usr/bin/env bash
# xray-manager one-liner deployment (China-friendly)
# Usage:
#   bash <(curl -fsSL https://hub.543083.xyz/https://raw.githubusercontent.com/derwalldrose/xray-manager/main/install.sh)
set -e

DEPLOY_URL="https://raw.githubusercontent.com/derwalldrose/xray-manager/main/deploy.sh"
MIRROR="https://hub.543083.xyz/${DEPLOY_URL}"

echo ">>> Downloading deploy.sh..."
if curl -fsSL --connect-timeout 10 --max-time 30 "$DEPLOY_URL" -o /tmp/xm-deploy.sh; then
    echo ">>> OK (direct)"
elif curl -fsSL --connect-timeout 10 --max-time 60 "$MIRROR" -o /tmp/xm-deploy.sh; then
    echo ">>> OK (mirror)"
else
    echo "ERROR: Cannot download deploy.sh"
    exit 1
fi

exec bash /tmp/xm-deploy.sh "$@"
