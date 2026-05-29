#!/usr/bin/env bash
# ============================================================================
# xray-manager — one-click deployment script
# Supports: Linux amd64 / arm64
# Usage:
#   bash <(curl -fsSL https://hub.543083.xyz/https://raw.githubusercontent.com/derwalldrose/xray-manager/main/deploy.sh)
# ============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
XRAY_MANAGER_HOME="/root/xray-manager"
XRAY_BIN="${XRAY_MANAGER_HOME}/bin/xray"
XRAY_CFG="${XRAY_MANAGER_HOME}/config/xray-multi-socks.json"
GEOIP_PATH="${XRAY_MANAGER_HOME}/data/geoip.dat"
GEOSITE_PATH="${XRAY_MANAGER_HOME}/data/geosite.dat"
XRAY_MGR_SERVICE="xray-manager.service"
XRAY_SOCKS_SERVICE="xray-multi-socks.service"
DEPLOY_LOG="${XRAY_MANAGER_HOME}/deploy.log"

# Xray version — bump this when updating
XRAY_VERSION="v26.3.27"

# CDN mirror prefix (transparently proxies GitHub)
CDN="https://hub.543083.xyz"

# GitHub raw base (no CDN prefix — gh_download adds it)
RAW_BASE="https://raw.githubusercontent.com/derwalldrose/xray-manager/main"

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*" >&2; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step()  { echo -e "\n${CYAN}========== $* ==========${NC}"; }

# ---------------------------------------------------------------------------
# Download via CDN, fallback to direct
# ---------------------------------------------------------------------------
gh_download() {
    local url="$1" output="$2"
    info "CDN:  ${CDN}/${url}"
    if curl -fSL --connect-timeout 15 --max-time 600 "${CDN}/${url}" -o "$output" 2>/dev/null; then
        return 0
    fi
    warn "CDN failed, trying direct..."
    if curl -fSL --connect-timeout 15 --max-time 600 "$url" -o "$output" 2>/dev/null; then
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Check root
# ---------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Install system dependencies
# ---------------------------------------------------------------------------
install_deps() {
    step "Installing system dependencies"
    if command -v apt-get &>/dev/null; then
        info "Package manager: apt"
        apt-get update -qq
        apt-get install -y -qq curl unzip ca-certificates python3-venv
    elif command -v yum &>/dev/null; then
        info "Package manager: yum"
        yum install -y -q curl unzip ca-certificates python3
    elif command -v dnf &>/dev/null; then
        info "Package manager: dnf"
        dnf install -y -q curl unzip ca-certificates python3
    else
        warn "Unknown package manager"
    fi
}

# ---------------------------------------------------------------------------
# Setup Python venv + Flask
# ---------------------------------------------------------------------------
install_python() {
    step "Checking Python 3"
    if ! command -v python3 &>/dev/null; then
        error "Python 3 not found. Install it first."
        exit 1
    fi
    info "Python: $(python3 --version 2>&1)"

    local venv="${XRAY_MANAGER_HOME}/.venv"
    info "Creating venv at ${venv}..."
    python3 -m venv "$venv"

    info "Installing Flask..."
    ALL_PROXY= HTTP_PROXY= HTTPS_PROXY= http_proxy= https_proxy= \
        "${venv}/bin/pip" install --quiet flask

    info "Flask: $("${venv}/bin/python3" -c 'import importlib.metadata; print(importlib.metadata.version("flask"))')"
}

# ---------------------------------------------------------------------------
# Detect architecture → Xray naming
# ---------------------------------------------------------------------------
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "64" ;;
        aarch64|arm64)  echo "arm64-v8a" ;;
        *) error "Unsupported: $(uname -m)"; exit 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Install Xray binary
# ---------------------------------------------------------------------------
install_xray() {
    step "Installing Xray-core"

    local arch
    arch="$(detect_arch)"
    info "Arch: $arch  Version: $XRAY_VERSION"

    local url="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${arch}.zip"
    local tmp
    tmp="$(mktemp -d)"

    if ! gh_download "$url" "${tmp}/xray.zip"; then
        error "Failed to download Xray"
        rm -rf "$tmp"
        exit 1
    fi

    info "Extracting..."
    unzip -o "${tmp}/xray.zip" -d "${tmp}/ext" >/dev/null 2>&1
    install -m 755 "${tmp}/ext/xray" "$XRAY_BIN"
    rm -rf "$tmp"

    info "Xray: $($XRAY_BIN version 2>/dev/null | head -1)"
}

# ---------------------------------------------------------------------------
# Download geo data
# ---------------------------------------------------------------------------
install_geo_data() {
    step "Installing geoip.dat & geosite.dat"
    mkdir -p "$(dirname "$GEOIP_PATH")"

    if gh_download "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" "$GEOIP_PATH"; then
        info "geoip.dat ✓  ($(du -h "$GEOIP_PATH" | cut -f1))"
    else
        warn "geoip.dat failed"
    fi

    if gh_download "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" "$GEOSITE_PATH"; then
        info "geosite.dat ✓  ($(du -h "$GEOSITE_PATH" | cut -f1))"
    else
        warn "geosite.dat failed"
    fi
}

# ---------------------------------------------------------------------------
# Setup app.py + default config
# ---------------------------------------------------------------------------
setup_app() {
    step "Setting up xray-manager"

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ -f "${script_dir}/app.py" ]]; then
        cp "${script_dir}/app.py" "${XRAY_MANAGER_HOME}/app.py"
        info "app.py copied from local"
    else
        info "Downloading app.py..."
        if gh_download "${RAW_BASE}/app.py" "${XRAY_MANAGER_HOME}/app.py"; then
            info "app.py ✓"
        else
            error "Failed to download app.py"
            exit 1
        fi
    fi

    if [[ ! -f "$XRAY_CFG" ]]; then
        cat > "$XRAY_CFG" <<'EOF'
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"tag":"socks-in","listen":"0.0.0.0","port":10808,"protocol":"socks","settings":{"udp":true}},
    {"tag":"http-in","listen":"0.0.0.0","port":10809,"protocol":"http"}
  ],
  "outbounds": [{"tag":"direct","protocol":"freedom"}],
  "routing": {"domainStrategy":"AsIs","rules":[]}
}
EOF
        info "Default config created"
        warn "Edit $XRAY_CFG to add your proxy nodes!"
    else
        info "Config exists: $XRAY_CFG"
    fi
}

# ---------------------------------------------------------------------------
# Systemd services
# ---------------------------------------------------------------------------
create_xray_service() {
    step "Service: ${XRAY_SOCKS_SERVICE}"

    cat > "/etc/systemd/system/${XRAY_SOCKS_SERVICE}" <<EOF
[Unit]
Description=Xray Multi-Socks Proxy Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=${XRAY_BIN} run -config ${XRAY_CFG}
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${XRAY_SOCKS_SERVICE}" 2>/dev/null || true
    info "Created & enabled"
}

create_manager_service() {
    step "Service: ${XRAY_MGR_SERVICE}"

    cat > "/etc/systemd/system/${XRAY_MGR_SERVICE}" <<EOF
[Unit]
Description=Xray Manager Web Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${XRAY_MANAGER_HOME}
ExecStart=${XRAY_MANAGER_HOME}/.venv/bin/python3 ${XRAY_MANAGER_HOME}/app.py --host 0.0.0.0 --port 54321 --xray-config ${XRAY_CFG} --xray-binary ${XRAY_BIN} --service ${XRAY_SOCKS_SERVICE}
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${XRAY_MGR_SERVICE}" 2>/dev/null || true

    info "Starting xray-manager..."
    systemctl restart "${XRAY_MGR_SERVICE}" 2>/dev/null || true
    sleep 2

    if systemctl is-active --quiet "${XRAY_MGR_SERVICE}" 2>/dev/null; then
        info "xray-manager running ✓"
    else
        warn "xray-manager failed: journalctl -u ${XRAY_MGR_SERVICE} -f"
    fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    local ip
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"

    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "  ${GREEN}xray-manager deployment complete!${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "  Xray:       ${CYAN}$($XRAY_BIN version 2>/dev/null | head -1)${NC}"
    echo -e "  Config:     ${CYAN}${XRAY_CFG}${NC}"
    echo -e "  Geo data:   ${CYAN}${XRAY_MANAGER_HOME}/data/${NC}"
    echo -e "  Panel:      ${CYAN}http://${ip}:54321${NC}"
    echo -e "  Token:      ${CYAN}Root2023!${NC}"
    echo ""
    echo -e "  Next steps:"
    echo -e "    1. Open panel, add proxy nodes"
    echo -e "    2. ${YELLOW}systemctl start xray-multi-socks${NC}"
    echo ""
    echo -e "  Log: ${DEPLOY_LOG}"
    echo -e "${CYAN}================================================================${NC}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    mkdir -p "${XRAY_MANAGER_HOME}"
    mkdir -p "${XRAY_MANAGER_HOME}"/{bin,data,config,backup,state,logs}

    echo -e "${CYAN}"
    echo "  ██╗  ██╗██████╗  █████╗ ██╗   ██╗"
    echo "  ╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝"
    echo "   ╚███╔╝ ██████╔╝███████║ ╚████╔╝ "
    echo "   ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝  "
    echo "  ██╔╝ ██╗██║  ██║██║  ██║   ██║   "
    echo "  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   "
    echo -e "  xray-manager deploy${NC}"
    echo ""

    check_root
    install_deps
    install_python
    install_xray
    install_geo_data
    setup_app
    create_xray_service
    create_manager_service
    print_summary
}

# Run
mkdir -p "${XRAY_MANAGER_HOME}" 2>/dev/null || true
main 2>&1 | tee "$DEPLOY_LOG"
