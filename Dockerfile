FROM python:3.11-slim

LABEL maintainer="derwalldrose" \
      description="derwalld — Xray proxy (bin: der) + web management panel"

ARG XRAY_VERSION=v26.3.27
ARG TARGETARCH=amd64

# Code/binaries live here (baked into image, NEVER mounted).
# All runtime data lives under BASE_DIR (a single host volume).
ENV CODE_DIR=/opt/derwalld \
    BASE_DIR=/root/xray-manager

# Install system deps + supervisor
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl unzip ca-certificates supervisor iptables iproute2 && \
    rm -rf /var/lib/apt/lists/* && \
    update-alternatives --set iptables /usr/sbin/iptables-legacy && \
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

# Create directory structure: code dir + data dir
RUN mkdir -p ${CODE_DIR}/bin && \
    mkdir -p ${BASE_DIR}/data ${BASE_DIR}/config \
             ${BASE_DIR}/backup ${BASE_DIR}/state ${BASE_DIR}/logs

# Download Xray-core (via CDN for China compatibility), shipped as `der`
RUN ARCH="${TARGETARCH}" && \
    if [ "$ARCH" = "amd64" ]; then XRAY_ARCH="64"; \
    elif [ "$ARCH" = "arm64" ]; then XRAY_ARCH="arm64-v8a"; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -fSL "https://hub.543083.xyz/https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip" \
        -o /tmp/xray.zip && \
    unzip -o /tmp/xray.zip -d /tmp/xray-extract && \
    mv /tmp/xray-extract/xray ${CODE_DIR}/bin/der && \
    chmod +x ${CODE_DIR}/bin/der && \
    rm -rf /tmp/xray.zip /tmp/xray-extract

# Bake geo data into CODE_DIR/templates/geo (never shadowed by the data
# volume). The "seed" program copies them into BASE_DIR/data on first boot,
# so no host has to reach the CDN at runtime.
RUN mkdir -p ${CODE_DIR}/templates/geo && \
    curl -fSL "https://hub.543083.xyz/https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" \
        -o ${CODE_DIR}/templates/geo/geoip.dat && \
    curl -fSL "https://hub.543083.xyz/https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" \
        -o ${CODE_DIR}/templates/geo/geosite.dat && \
    ln -sf ${BASE_DIR}/data/geoip.dat ${CODE_DIR}/bin/geoip.dat && \
    ln -sf ${BASE_DIR}/data/geosite.dat ${CODE_DIR}/bin/geosite.dat

# Default config template (no node credentials). The "seed" program copies it
# into BASE_DIR/config on first boot when absent. DNS servers kept plain (no
# "udp:" prefix — xray would treat it as a domain and fail with "too many
# colons in address").
RUN printf '%s\n' \
  '{' \
  '  "log": { "loglevel": "warning" },' \
  '  "dns": {' \
  '    "servers": ["223.5.5.5", "https://dns.alidns.com/dns-query"],' \
  '    "tag": "dns-out"' \
  '  },' \
  '  "inbounds": [' \
  '    { "tag": "socks-in", "listen": "0.0.0.0", "port": 10808, "protocol": "socks", "settings": { "udp": true } },' \
  '    { "tag": "http-in", "listen": "0.0.0.0", "port": 10809, "protocol": "http" }' \
  '  ],' \
  '  "outbounds": [ { "tag": "direct", "protocol": "freedom" } ],' \
  '  "routing": { "domainStrategy": "AsIs", "rules": [] }' \
  '}' > ${CODE_DIR}/templates/xray-multi-socks.json \
  && python3 -c "import json; json.load(open('${CODE_DIR}/templates/xray-multi-socks.json'))"

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Copy application (code dir, never mounted)
COPY app.py ${CODE_DIR}/app.py
COPY txt_endpoints.py ${CODE_DIR}/txt_endpoints.py
COPY xray-entrypoint.py ${CODE_DIR}/xray-entrypoint.py

# Panel port (override at runtime: docker run -e PANEL_PORT=54322 ...)
ENV PANEL_PORT=54321

# Supervisord config
COPY xray-manager.conf /etc/supervisor/conf.d/xray-manager.conf

WORKDIR ${BASE_DIR}

EXPOSE 54321 10808 10809

# HEALTHCHECK uses sh -c so $PANEL_PORT expands at HEALTHCHECK time (inside the
# container, where the -e PANEL_PORT env exists). Writing $$PANEL_PORT makes
# Docker expand it at `docker run` time (CLI env, usually empty) ->
# "URL rejected: Port number was not a decimal number".
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["sh", "-c", "curl -f http://localhost:${PANEL_PORT}/ || exit 1"]

# Bootstrap: ensure data subdirs exist (a fresh single-volume mount starts
# empty and supervisord requires log dirs to exist before it will start).
CMD ["/bin/sh", "-c", "mkdir -p ${BASE_DIR}/config ${BASE_DIR}/data ${BASE_DIR}/backup ${BASE_DIR}/state ${BASE_DIR}/logs && exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf"]
