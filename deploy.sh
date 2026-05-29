#!/usr/bin/env bash
# ============================================================================
# xray-manager — one-click deployment script
# Supports: Linux amd64 / arm64
# Usage:
#   bash deploy.sh                      # direct download
#   bash deploy.sh --proxy ghproxy      # use ghproxy.net mirror
#   bash deploy.sh --proxy direct       # explicit direct (default)
#   bash deploy.sh --proxy http://127.0.0.1:7890  # custom HTTP proxy
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

XRAY_RELEASE_URL="https://github.com/XTLS/Xray-core/releases/latest"
GEOIP_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
GEOSITE_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

GHPROXY_PREFIX="https://ghproxy.net/"

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
# Parse arguments
# ---------------------------------------------------------------------------
PROXY_MODE="direct"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --proxy)
            PROXY_MODE="${2:-direct}"
            shift 2
            ;;
        --help|-h)
            echo "Usage: bash deploy.sh [--proxy direct|ghproxy|http://...]"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

GHPROXY_MIRRORS=(
    "https://hub.543083.xyz/"
    "https://ghproxy.net/"
    "https://mirror.ghproxy.com/"
    "https://gh-proxy.com/"
)

# ---------------------------------------------------------------------------
# URL helper — apply proxy prefix if needed
# ---------------------------------------------------------------------------
mirror_url() {
    local url="$1"
    if [[ "$PROXY_MODE" == "ghproxy" ]]; then
        echo "${GHPROXY_MIRRORS[0]}${url}"
    else
        echo "$url"
    fi
}

# Try all mirrors until one works
mirror_download() {
    local url="$1"
    local output="$2"
    shift 2
    local extra_args=("$@")

    if [[ "$PROXY_MODE" != "ghproxy" ]]; then
        curl -fSL --connect-timeout 15 --max-time 300 "${extra_args[@]}" "$url" -o "$output"
        return $?
    fi

    for mirror in "${GHPROXY_MIRRORS[@]}"; do
        local mirrored="${mirror}${url}"
        info "Trying: $mirrored"
        if curl -fSL --connect-timeout 10 --max-time 300 "${extra_args[@]}" "$mirrored" -o "$output" 2>/dev/null; then
            info "Downloaded via $mirror ✓"
            return 0
        fi
        warn "Failed: $mirror"
    done
    return 1
}

# If user provides a custom proxy, export it for curl/wget
setup_curl_proxy() {
    if [[ "$PROXY_MODE" =~ ^https?:// ]]; then
        export http_proxy="$PROXY_MODE"
        export https_proxy="$PROXY_MODE"
        export HTTP_PROXY="$PROXY_MODE"
        export HTTPS_PROXY="$PROXY_MODE"
        info "Using HTTP proxy: $PROXY_MODE"
    fi
}

# ---------------------------------------------------------------------------
# Detect architecture
# ---------------------------------------------------------------------------
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)
            echo "64"
            ;;
        aarch64|arm64)
            echo "arm64-v8a"
            ;;
        *)
            error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Check root
# ---------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Install system dependencies
# ---------------------------------------------------------------------------
install_deps() {
    step "Installing system dependencies"

    # Detect package manager
    local pm=""
    if command -v apt-get &>/dev/null; then
        pm="apt"
    elif command -v yum &>/dev/null; then
        pm="yum"
    elif command -v dnf &>/dev/null; then
        pm="dnf"
    else
        warn "Unknown package manager — trying apt"
        pm="apt"
    fi

    info "Package manager: $pm"

    # Ensure curl, unzip are present
    local pkgs="curl unzip"
    if [[ "$pm" == "apt" ]]; then
        apt-get update -qq
        apt-get install -y -qq $pkgs 2>/dev/null || true
    elif [[ "$pm" == "yum" ]]; then
        yum install -y -q $pkgs 2>/dev/null || true
    elif [[ "$pm" == "dnf" ]]; then
        dnf install -y -q $pkgs 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# Install Python 3 + pip
# ---------------------------------------------------------------------------
install_python() {
    step "Checking Python 3"

    if command -v python3 &>/dev/null; then
        local pyver
        pyver="$(python3 --version 2>&1)"
        info "Python already installed: $pyver"
    else
        info "Installing Python 3..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq
            apt-get install -y -qq python3 python3-venv
        elif command -v yum &>/dev/null; then
            yum install -y -q python3 python3-pip
        elif command -v dnf &>/dev/null; then
            dnf install -y -q python3 python3-pip
        fi
    fi

    # Ensure python3-venv is installed (Debian 12+ needs it)
    if command -v apt-get &>/dev/null; then
        apt-get install -y -qq python3-venv 2>/dev/null || true
    fi

    # Create virtual environment
    local venv_dir="${XRAY_MANAGER_HOME}/.venv"
    info "Creating venv at ${venv_dir}..."
    python3 -m venv "${venv_dir}"

    info "Installing Flask in venv..."
    # Unset SOCKS proxy vars (pip doesn't have pysocks in fresh venv)
    "${venv_dir}/bin/pip" install --quiet flask 2>/dev/null \
        || ALL_PROXY= HTTP_PROXY= HTTPS_PROXY= http_proxy= https_proxy= \
           "${venv_dir}/bin/pip" install --quiet flask

    info "Flask installed: $("${venv_dir}/bin/python3" -c 'import flask; print(flask.__version__)')"
}

# ---------------------------------------------------------------------------
# Resolve latest Xray download URL
# ---------------------------------------------------------------------------
resolve_xray_download_url() {
    local arch="$1"
    local api_url="https://api.github.com/repos/XTLS/Xray-core/releases/latest"

    info "Resolving latest Xray release..."

    # Try GitHub API first to get the exact tag
    local tag=""
    local json
    json="$(curl -sL --connect-timeout 10 --max-time 20 "$(mirror_url "$api_url")" 2>/dev/null || true)"

    if [[ -n "$json" ]]; then
        tag="$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tag_name',''))" 2>/dev/null || true)"
    fi

    # Fallback: use /releases/latest redirect
    if [[ -z "$tag" ]]; then
        tag="latest"
        local resolved_url
        resolved_url="$(curl -sI -o /dev/null -w '%{redirect_url}' --connect-timeout 10 "$(mirror_url "https://github.com/XTLS/Xray-core/releases/latest")" 2>/dev/null || true)"
        if [[ "$resolved_url" =~ /tag/([^/]+)$ ]]; then
            tag="${BASH_REMATCH[1]}"
        fi
    fi

    if [[ -z "$tag" || "$tag" == "latest" ]]; then
        # Absolute fallback: let GitHub redirect us
        echo "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${arch}.zip"
        return
    fi

    info "Latest Xray release: $tag"
    echo "https://github.com/XTLS/Xray-core/releases/download/${tag}/Xray-linux-${arch}.zip"
}

# ---------------------------------------------------------------------------
# Download & install Xray
# ---------------------------------------------------------------------------
install_xray() {
    step "Installing Xray-core"

    local arch
    arch="$(detect_arch)"
    info "Detected architecture: $arch"

    if [[ -x "$XRAY_BIN" ]]; then
        local current_ver
        current_ver="$($XRAY_BIN version 2>/dev/null || echo 'unknown')"
        info "Xray already installed: $current_ver"
        info "Updating to latest version..."
    fi

    local download_url
    download_url="$(resolve_xray_download_url "$arch")"
    info "Download URL: $download_url"

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap "rm -rf '$tmp_dir'" EXIT

    local zip_file="${tmp_dir}/xray.zip"

    info "Downloading Xray binary..."
    setup_curl_proxy

    if ! mirror_download "$download_url" "$zip_file"; then
        error "Failed to download Xray from: $download_url"
        error "All mirrors failed. Try: bash deploy.sh --proxy http://your-proxy:port"
        exit 1
    fi

    info "Extracting Xray..."
    unzip -o "$zip_file" -d "$tmp_dir/xray-extract" >/dev/null 2>&1

    # Install binary
    install -m 755 "$tmp_dir/xray-extract/xray" "$XRAY_BIN"
    info "Xray installed: $($XRAY_BIN version 2>/dev/null || echo 'installed')"

    # Cleanup
    rm -rf "$tmp_dir"
    trap - EXIT
}

# ---------------------------------------------------------------------------
# Download geoip.dat & geosite.dat
# ---------------------------------------------------------------------------
install_geo_data() {
    step "Installing geoip.dat & geosite.dat"

    local geo_dir
    geo_dir="$(dirname "$GEOIP_PATH")"
    mkdir -p "$geo_dir"

    info "Downloading geoip.dat..."
    if ! mirror_download "$GEOIP_URL" "$GEOIP_PATH"; then
        warn "Failed to download geoip.dat — will use Xray default"
    else
        info "geoip.dat installed to $GEOIP_PATH"
    fi

    info "Downloading geosite.dat..."
    if ! mirror_download "$GEOSITE_URL" "$GEOSITE_PATH"; then
        warn "Failed to download geosite.dat — will use Xray default"
    else
        info "geosite.dat installed to $GEOSITE_PATH"
    fi
}

# ---------------------------------------------------------------------------
# Setup directory & copy app
# ---------------------------------------------------------------------------
setup_app() {
    step "Setting up xray-manager"

    mkdir -p "$XRAY_MANAGER_HOME"

    # Determine source directory (where this script lives)
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    info "Source directory: $script_dir"

    # Copy app.py
    if [[ -f "${script_dir}/app.py" ]]; then
        cp "${script_dir}/app.py" "${XRAY_MANAGER_HOME}/app.py"
        info "Copied app.py -> ${XRAY_MANAGER_HOME}/app.py"
    else
        warn "app.py not found in script directory — skipping copy"
    fi

    # Copy requirements.txt if present
    if [[ -f "${script_dir}/requirements.txt" ]]; then
        cp "${script_dir}/requirements.txt" "${XRAY_MANAGER_HOME}/requirements.txt"
    fi

    # Create default xray config if it doesn't exist
    if [[ ! -f "$XRAY_CFG" ]]; then
        cat > "$XRAY_CFG" <<'XRAY_EOF'
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "socks-in",
      "listen": "0.0.0.0",
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": []
  }
}
XRAY_EOF
        info "Created default Xray config at $XRAY_CFG"
        info "  ⚠ Edit this file to add your proxy outbounds!"
    else
        info "Xray config already exists: $XRAY_CFG"
    fi
}

# ---------------------------------------------------------------------------
# Create systemd service: xray-multi-socks
# ---------------------------------------------------------------------------
create_xray_service() {
    step "Creating systemd service: ${XRAY_SOCKS_SERVICE}"

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

    info "Created /etc/systemd/system/${XRAY_SOCKS_SERVICE}"

    # Enable but don't start yet (config may not be ready)
    systemctl daemon-reload
    systemctl enable "${XRAY_SOCKS_SERVICE}" 2>/dev/null || true
    info "Service enabled (not started — configure Xray first)"
}

# ---------------------------------------------------------------------------
# Create systemd service: xray-manager
# ---------------------------------------------------------------------------
create_manager_service() {
    step "Creating systemd service: ${XRAY_MGR_SERVICE}"

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

    info "Created /etc/systemd/system/${XRAY_MGR_SERVICE}"

    systemctl daemon-reload
    systemctl enable "${XRAY_MGR_SERVICE}" 2>/dev/null || true

    # Start the manager
    info "Starting xray-manager..."
    systemctl restart "${XRAY_MGR_SERVICE}" 2>/dev/null || true
    sleep 2

    if systemctl is-active --quiet "${XRAY_MGR_SERVICE}" 2>/dev/null; then
        info "xray-manager is running ✓"
    else
        warn "xray-manager failed to start. Check: journalctl -u ${XRAY_MGR_SERVICE} -f"
    fi
}

# ---------------------------------------------------------------------------
# Configure firewall (optional)
# ---------------------------------------------------------------------------
configure_firewall() {
    step "Configuring firewall"

    local port=54321

    # ufw
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
        info "Opening port ${port} in ufw..."
        ufw allow "${port}/tcp" 2>/dev/null || true
    fi

    # firewalld
    if command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q "running"; then
        info "Opening port ${port} in firewalld..."
        firewall-cmd --permanent --add-port="${port}/tcp" 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    fi

    info "Firewall configuration done (if applicable)"
}

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------
print_summary() {
    local arch
    arch="$(detect_arch)"
    local ip
    ip="$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null || echo '<your-server-ip>')"

    echo ""
    echo -e "${GREEN}================================================================${NC}"
    echo -e "${GREEN}  xray-manager deployment complete!${NC}"
    echo -e "${GREEN}================================================================${NC}"
    echo ""
    echo -e "  Architecture:     ${CYAN}${arch}${NC}"
    echo -e "  Xray binary:      ${CYAN}${XRAY_BIN}${NC}"
    echo -e "  Xray version:     ${CYAN}$($XRAY_BIN version 2>/dev/null || echo 'unknown')${NC}"
    echo -e "  Xray config:      ${CYAN}${XRAY_CFG}${NC}"
    echo -e "  Manager app:      ${CYAN}${XRAY_MANAGER_HOME}/app.py${NC}"
    echo -e "  Geo data:         ${CYAN}/usr/local/share/xray/${NC}"
    echo ""
    echo -e "  Web Panel URL:    ${CYAN}http://${ip}:54321${NC}"
    echo -e "  Default token:    ${CYAN}Root2023!${NC}"
    echo ""
    echo -e "  Service commands:"
    echo -e "    ${YELLOW}systemctl start xray-manager${NC}      # start web panel"
    echo -e "    ${YELLOW}systemctl start xray-multi-socks${NC}  # start xray proxy"
    echo -e "    ${YELLOW}systemctl status xray-manager${NC}     # check status"
    echo -e "    ${YELLOW}journalctl -u xray-manager -f${NC}     # view logs"
    echo ""
    echo -e "  Quick start:"
    echo -e "    1. Edit ${CYAN}${XRAY_CFG}${NC} with your proxy config"
    echo -e "    2. ${YELLOW}systemctl start xray-multi-socks${NC}"
    echo -e "    3. Open ${CYAN}http://${ip}:54321${NC} in your browser"
    echo ""
    echo -e "  Deploy log:       ${CYAN}${DEPLOY_LOG}${NC}"
    echo -e "${GREEN}================================================================${NC}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    # Create base directory first (needed for deploy.log)
    mkdir -p "${XRAY_MANAGER_HOME}"
    mkdir -p "${XRAY_MANAGER_HOME}"/{bin,data,config,backup,state,logs}

    echo -e "${CYAN}"
    echo "  ██╗  ██╗██████╗  █████╗ ██╗   ██╗"
    echo "  ╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝"
    echo "   ╚███╔╝ ██████╔╝███████║ ╚████╔╝ "
    echo "   ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝  "
    echo "  ██╔╝ ██╗██║  ██║██║  ██║   ██║   "
    echo "  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   "
    echo -e "  xray-manager deployment script${NC}"
    echo ""

    info "Proxy mode: $PROXY_MODE"
    info "Starting deployment..."
    echo ""

    check_root
    install_deps
    install_python
    install_xray
    install_geo_data
    setup_app
    create_xray_service
    create_manager_service
    configure_firewall
    print_summary
}

# Run
main 2>&1 | tee "$DEPLOY_LOG"
