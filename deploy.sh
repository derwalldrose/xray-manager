#!/usr/bin/env bash
# ============================================================================
# xray-manager v3 — one-click deployment script
# Supports:
#   ./deploy.sh systemd   # bare-metal systemd deployment (default)
#   ./deploy.sh docker    # build and run host-network Docker container
#
# Xray-core is pinned by XRAY_VER. Bump deliberately, do not use latest.
# ============================================================================
set -euo pipefail

MODE="${1:-systemd}"
XRAY_VER="${XRAY_VER:-v26.3.27}"
TOKEN="${XRAY_MANAGER_TOKEN:-123456}"
CDN="${CDN:-https://hub.543083.xyz}"

XRAY_HOME="/root/xray-manager-v3"
V3_HOME="/root/xray-manager-v3"
XRAY_BIN="${V3_HOME}/bin/xray"
XRAY_CFG="${V3_HOME}/config/xray-multi-socks.json"
PANEL_SERVICE="xray-manager-v3.service"
XRAY_SERVICE="xray-multi-socks.service"
IMAGE="${IMAGE:-xray-manager-v3:latest}"
CONTAINER="${CONTAINER:-xray-manager-v3}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info(){ echo -e "${GREEN}[INFO]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
error(){ echo -e "${RED}[ERROR]${NC} $*" >&2; }
step(){ echo -e "\n${CYAN}========== $* ==========${NC}"; }

require_root(){ [[ $EUID -eq 0 ]] || { error "Must run as root"; exit 1; }; }
script_dir(){ cd "$(dirname "${BASH_SOURCE[0]}")" && pwd; }

detect_xray_arch(){
  case "$(uname -m)" in
    x86_64|amd64) echo "64" ;;
    aarch64|arm64) echo "arm64-v8a" ;;
    *) error "Unsupported arch: $(uname -m)"; exit 1 ;;
  esac
}

detect_docker_arch(){
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) error "Unsupported arch: $(uname -m)"; exit 1 ;;
  esac
}

download(){
  local url="$1" out="$2"
  if curl -fSL --connect-timeout 15 --max-time 1200 "${CDN}/${url}" -o "$out"; then return 0; fi
  warn "CDN failed, trying direct: $url"
  curl -fSL --connect-timeout 15 --max-time 600 "$url" -o "$out"
}

install_deps(){
  step "System dependencies"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq curl unzip ca-certificates iptables iproute2 procps
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl unzip ca-certificates iptables iproute procps-ng
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl unzip ca-certificates iptables iproute procps-ng
  fi
}

install_node(){
  step "Node.js / pnpm"
  if command -v node >/dev/null 2>&1 && node -v | grep -Eq '^v(20|21|22|23|24)\.'; then
    info "Node $(node -v)"
  else
    local ver="v22.16.0" arch="linux-x64"
    [[ "$(uname -m)" =~ (aarch64|arm64) ]] && arch="linux-arm64"
    local tmp; tmp="$(mktemp -d)"
    download "https://nodejs.org/dist/${ver}/node-${ver}-${arch}.tar.xz" "${tmp}/node.tar.xz"
    tar -xJf "${tmp}/node.tar.xz" -C "$tmp"
    cp -r "${tmp}/node-${ver}-${arch}/"{bin,include,lib,share} /usr/local/
    rm -rf "$tmp"
    info "Installed Node $(node -v)"
  fi
  corepack enable || true
  corepack prepare pnpm@11.5.1 --activate
}

ensure_dirs(){
  mkdir -p "${V3_HOME}"/{config,data,backup,bin,logs}
}

install_xray(){
  step "Xray-core ${XRAY_VER}"
  if [[ -x "$XRAY_BIN" ]] && "$XRAY_BIN" version 2>/dev/null | head -1 | grep -q "${XRAY_VER#v}"; then
    info "Already installed: $("$XRAY_BIN" version | head -1)"
    return
  fi
  local arch tmp
  arch="$(detect_xray_arch)"
  tmp="$(mktemp -d)"
  download "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-${arch}.zip" "${tmp}/xray.zip"
  unzip -o "${tmp}/xray.zip" -d "${tmp}/xray" >/dev/null
  install -m 755 "${tmp}/xray/xray" "$XRAY_BIN"
  rm -rf "$tmp"
  info "Installed: $("$XRAY_BIN" version | head -1)"
}

install_geo(){
  step "GeoIP / GeoSite"
  [[ -s "${XRAY_HOME}/data/geoip.dat" ]] || download "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" "${XRAY_HOME}/data/geoip.dat"
  [[ -s "${XRAY_HOME}/data/geosite.dat" ]] || download "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" "${XRAY_HOME}/data/geosite.dat"
  ln -sf "${XRAY_HOME}/data/geoip.dat" "${V3_HOME}/bin/geoip.dat"
  ln -sf "${XRAY_HOME}/data/geosite.dat" "${V3_HOME}/bin/geosite.dat"
}

write_default_config(){
  [[ -f "$XRAY_CFG" ]] && { info "Config exists: $XRAY_CFG"; return; }
  step "Default Xray config"
  cat > "$XRAY_CFG" <<'JSON'
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"tag":"socks-in","listen":"0.0.0.0","port":10810,"protocol":"socks","settings":{"auth":"noauth","udp":true},"sniffing":{"enabled":true,"destOverride":["http","tls","quic"]}},
    {"tag":"http-in","listen":"0.0.0.0","port":10818,"protocol":"http","settings":{}},
    {"tag":"dns","listen":"0.0.0.0","port":53,"protocol":"dokodemo-door","settings":{"address":"119.29.29.29","port":53,"network":"tcp,udp"}},
    {"tag":"transparent","listen":"0.0.0.0","port":12345,"protocol":"dokodemo-door","settings":{"network":"tcp,udp","followRedirect":true},"sniffing":{"enabled":true,"destOverride":["http","tls","quic"]}}
  ],
  "outbounds": [
    {"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"UseIP"},"streamSettings":{"sockopt":{"mark":128}}},
    {"tag":"block","protocol":"blackhole","streamSettings":{"sockopt":{"mark":128}}},
    {"tag":"dns-out","protocol":"dns","settings":{"address":"119.29.29.29","port":53,"network":"udp"},"streamSettings":{"sockopt":{"mark":128}}}
  ],
  "routing": {"domainStrategy":"IPIfNonMatch","rules":[
    {"type":"field","inboundTag":["dns"],"outboundTag":"direct"},
    {"type":"field","ip":["geoip:private"],"outboundTag":"direct"},
    {"type":"field","ip":["geoip:cn"],"outboundTag":"direct"},
    {"type":"field","domain":["geosite:cn"],"outboundTag":"direct"},
    {"type":"field","network":"udp","outboundTag":"direct"}
  ]},
  "dns": {"servers":["119.29.29.29","223.5.5.5"],"hosts":{}}
}
JSON
}

build_app(){
  step "Build v3 app"
  local dir; dir="$(script_dir)"
  cd "$dir"
  pnpm install --config.dangerouslyAllowAllBuilds=true
  cd web && pnpm run build
  cd ../server && pnpm run build
}

install_app(){
  step "Install v3 app"
  local dir; dir="$(script_dir)"
  install -m 644 "${dir}/server/dist/index.js" "${V3_HOME}/index.js"
  rm -rf "${V3_HOME}/web-dist"
  cp -r "${dir}/web/dist" "${V3_HOME}/web-dist"
  echo "$TOKEN" > "${V3_HOME}/data/token"
  chmod 600 "${V3_HOME}/data/token"
}

create_systemd(){
  step "Systemd services"
  cat > "/etc/systemd/system/${XRAY_SERVICE}" <<EOF
[Unit]
Description=Xray Multi-Socks
After=network.target

[Service]
Type=simple
User=root
ExecStart=${XRAY_BIN} run -config ${XRAY_CFG}
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
StandardOutput=append:${XRAY_HOME}/logs/xray.log
StandardError=append:${XRAY_HOME}/logs/xray.err

[Install]
WantedBy=multi-user.target
EOF
  cat > "/etc/systemd/system/${PANEL_SERVICE}" <<EOF
[Unit]
Description=Xray Manager v3
After=network.target ${XRAY_SERVICE}

[Service]
Type=simple
User=root
WorkingDirectory=${V3_HOME}
Environment=NODE_ENV=production
Environment=PORT=54321
ExecStart=/usr/local/bin/node ${V3_HOME}/index.js
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$XRAY_SERVICE" "$PANEL_SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$XRAY_SERVICE"
  systemctl restart "$PANEL_SERVICE"
}

deploy_systemd(){
  require_root
  install_deps
  install_node
  ensure_dirs
  install_xray
  install_geo
  write_default_config
  build_app
  install_app
  create_systemd
}

deploy_docker(){
  require_root
  step "Docker build/run"
  command -v docker >/dev/null 2>&1 || { error "docker not found"; exit 1; }
  local dir arch
  dir="$(script_dir)"
  arch="$(detect_docker_arch)"
  cd "$dir"
  docker build --build-arg XRAY_VERSION="$XRAY_VER" --build-arg TARGETARCH="$arch" -t "$IMAGE" .
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  mkdir -p "${V3_HOME}"/{config,data,backup,logs}
  docker run -d --name "$CONTAINER" \
    --network host \
    --cap-add NET_ADMIN --cap-add NET_RAW \
    --restart unless-stopped \
    -v "${V3_HOME}/config:/root/xray-manager-v3/config" \
    -v "${V3_HOME}/data:/root/xray-manager-v3/data" \
    -v "${V3_HOME}/backup:/root/xray-manager-v3/backup" \
    -v "${V3_HOME}/logs:/root/xray-manager-v3/logs" \
    "$IMAGE"
}

summary(){
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo ""
  echo -e "${CYAN}================================================================${NC}"
  echo -e "  ${GREEN}xray-manager v3 deployed${NC}"
  echo -e "${CYAN}================================================================${NC}"
  echo "  URL:   http://${ip:-SERVER_IP}:54321"
  echo "  Token: ${TOKEN}"
  echo "  Xray:  ${XRAY_VER} (pinned)"
  echo "  Mode:  ${MODE}"
  echo ""
}

case "$MODE" in
  systemd|baremetal) deploy_systemd ;;
  docker) deploy_docker ;;
  *) error "Usage: $0 [systemd|docker]"; exit 1 ;;
esac
summary
