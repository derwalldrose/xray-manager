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

# Xray version — bump when updating
XRAY_VER="v26.3.27"

# CDN prefix for GitHub downloads (China-friendly)
CDN="https://hub.543083.xyz"

# GitHub domains built at runtime (prevents CDN text rewriting)
GH="gi""thub.com"
GH_RAW="ra""w.gi""thubusercontent.com"

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
# Download helper — CDN first, then direct
# ---------------------------------------------------------------------------
gh_dl() {
    local url="$1" output="$2"
    # CDN first (works in China)
    info "CDN: ${CDN}/${url}"
    if curl -fSL --connect-timeout 15 --max-time 1200 "${CDN}/${url}" -o "$output" 2>/dev/null; then
        return 0
    fi
    # Direct fallback (for environments with direct GitHub access)
    warn "CDN failed, trying direct..."
    if curl -fSL --connect-timeout 15 --max-time 600 "$url" -o "$output" 2>/dev/null; then
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
check_root() {
    [[ $EUID -eq 0 ]] || { error "Must run as root"; exit 1; }
}

# ---------------------------------------------------------------------------
install_deps() {
    step "System dependencies"
    if command -v apt-get &>/dev/null; then
        info "apt"
        apt-get update -qq
        apt-get install -y -qq curl unzip ca-certificates python3-venv
    elif command -v yum &>/dev/null; then
        info "yum"
        yum install -y -q curl unzip ca-certificates python3
    elif command -v dnf &>/dev/null; then
        info "dnf"
        dnf install -y -q curl unzip ca-certificates python3
    fi
}

# ---------------------------------------------------------------------------
install_python() {
    step "Python 3 + Flask"
    command -v python3 &>/dev/null || { error "Python 3 not found"; exit 1; }
    info "$(python3 --version)"

    local venv="${XRAY_MANAGER_HOME}/.venv"
    python3 -m venv "$venv"
    ALL_PROXY= HTTP_PROXY= HTTPS_PROXY= http_proxy= https_proxy= \
        "${venv}/bin/pip" install --quiet flask
    info "Flask $("${venv}/bin/python3" -c 'import importlib.metadata;print(importlib.metadata.version("flask"))')"
}

# ---------------------------------------------------------------------------
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "64" ;;
        aarch64|arm64)  echo "arm64-v8a" ;;
        *) error "Unsupported arch"; exit 1 ;;
    esac
}

# ---------------------------------------------------------------------------
install_xray() {
    step "Xray-core"

    # Skip if already installed with correct version
    if [[ -x "$XRAY_BIN" ]]; then
        local cur
        cur="$($XRAY_BIN version 2>/dev/null | head -1)"
        local ver="${XRAY_VER#v}"  # strip 'v' prefix
        if echo "$cur" | grep -q "$ver"; then
            info "Already installed: $cur"
            return 0
        fi
        info "Upgrading: $cur → $XRAY_VER"
    fi

    local arch
    arch="$(detect_arch)"
    info "Arch=$arch  Version=$XRAY_VER"

    local url="https://${GH}/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-${arch}.zip"
    local tmp
    tmp="$(mktemp -d)"

    gh_dl "$url" "${tmp}/xray.zip" || { error "Download failed"; rm -rf "$tmp"; exit 1; }

    unzip -o "${tmp}/xray.zip" -d "${tmp}/ext" >/dev/null 2>&1
    install -m 755 "${tmp}/ext/xray" "$XRAY_BIN"
    rm -rf "$tmp"
    info "Installed: $($XRAY_BIN version | head -1)"
}

# ---------------------------------------------------------------------------
install_geo() {
    step "GeoIP / GeoSite"
    mkdir -p "$(dirname "$GEOIP_PATH")"

    if [[ -f "$GEOIP_PATH" ]] && [[ $(stat -c%s "$GEOIP_PATH" 2>/dev/null || echo 0) -gt 10000000 ]]; then
        info "geoip.dat exists ($(du -h "$GEOIP_PATH" | cut -f1))"
    elif gh_dl "https://${GH}/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" "$GEOIP_PATH"; then
        info "geoip.dat ✓ ($(du -h "$GEOIP_PATH" | cut -f1))"
    else
        warn "geoip.dat failed"
    fi

    if [[ -f "$GEOSITE_PATH" ]] && [[ $(stat -c%s "$GEOSITE_PATH" 2>/dev/null || echo 0) -gt 5000000 ]]; then
        info "geosite.dat exists ($(du -h "$GEOSITE_PATH" | cut -f1))"
    elif gh_dl "https://${GH}/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" "$GEOSITE_PATH"; then
        info "geosite.dat ✓ ($(du -h "$GEOSITE_PATH" | cut -f1))"
    else
        warn "geosite.dat failed"
    fi
}

# ---------------------------------------------------------------------------
setup_app() {
    step "xray-manager app"

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ -f "${script_dir}/app.py" ]]; then
        cp "${script_dir}/app.py" "${XRAY_MANAGER_HOME}/app.py"
        info "Copied from local"
    else
        gh_dl "https://${GH_RAW}/derwalldrose/xray-manager/main/app.py" "${XRAY_MANAGER_HOME}/app.py" \
            || { error "app.py download failed"; exit 1; }
        info "Downloaded app.py"
    fi

    [[ -f "$XRAY_CFG" ]] && { info "Config exists"; return; }

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
    warn "Edit $XRAY_CFG to add proxy nodes!"
}

# ---------------------------------------------------------------------------
create_services() {
    step "Systemd services"

    cat > "/etc/systemd/system/${XRAY_SOCKS_SERVICE}" <<EOF
[Unit]
Description=Xray Multi-Socks Proxy
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
    systemctl enable "${XRAY_SOCKS_SERVICE}" "${XRAY_MGR_SERVICE}" 2>/dev/null || true

    info "Starting xray-manager..."
    systemctl restart "${XRAY_MGR_SERVICE}"
    sleep 2
    systemctl is-active --quiet "${XRAY_MGR_SERVICE}" && info "xray-manager running ✓" || warn "Check: journalctl -u ${XRAY_MGR_SERVICE} -f"
}

# ---------------------------------------------------------------------------
print_summary() {
    local ip
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "  ${GREEN}xray-manager deployed!${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "  Xray:     ${CYAN}$($XRAY_BIN version 2>/dev/null | head -1)${NC}"
    echo -e "  Config:   ${CYAN}${XRAY_CFG}${NC}"
    echo -e "  Panel:    ${CYAN}http://${ip}:54321${NC}"
    echo -e "  Token:    ${CYAN}Root2023!${NC}"
    echo ""
    echo -e "  Next: open panel → add nodes → systemctl start xray-multi-socks"
    echo -e "${CYAN}================================================================${NC}"
}

# ---------------------------------------------------------------------------
main() {
    mkdir -p "${XRAY_MANAGER_HOME}"/{bin,data,config,backup,state,logs}

    echo -e "${CYAN}"
    echo "  ██╗  ██╗██████╗  █████╗ ██╗   ██╗"
    echo "  ╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝"
    echo "   ╚███╔╝ ██████╔╝███████║ ╚████╔╝ "
    echo "   ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝  "
    echo "  ██╔╝ ██╗██║  ██║██║  ██║   ██║   "
    echo "  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   "
    echo -e "  deploy${NC}"
    echo ""

    check_root
    install_deps
    install_python
    install_xray
    install_geo
    setup_app
    create_services
    print_summary
}

# Run (pipefail + tee causes SIGPIPE=141 on SSH disconnect)
mkdir -p "${XRAY_MANAGER_HOME}" 2>/dev/null || true
set +o pipefail
main 2>&1 | tee "$DEPLOY_LOG"
rc=${PIPESTATUS[0]}
set -o pipefail
exit $rc
