FROM python:3.11-slim

LABEL maintainer="derwalldrose" \
      description="xray-manager — Xray proxy + web management panel"

ARG XRAY_VERSION=v25.4.30
ARG TARGETARCH=amd64

ENV BASE_DIR=/root/xray-manager

# Install system deps + supervisor
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl unzip ca-certificates supervisor iptables iproute2 && \
    rm -rf /var/lib/apt/lists/*

# Create directory structure
RUN mkdir -p ${BASE_DIR}/{bin,data,config,backup,state,logs}

# Download Xray-core
RUN ARCH="${TARGETARCH}" && \
    if [ "$ARCH" = "amd64" ]; then XRAY_ARCH="64"; \
    elif [ "$ARCH" = "arm64" ]; then XRAY_ARCH="arm64-v8a"; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -fSL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip" \
        -o /tmp/xray.zip && \
    unzip -o /tmp/xray.zip -d /tmp/xray-extract && \
    mv /tmp/xray-extract/xray ${BASE_DIR}/bin/xray && \
    chmod +x ${BASE_DIR}/bin/xray && \
    rm -rf /tmp/xray.zip /tmp/xray-extract

# Download geo data
RUN curl -fSL "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" \
        -o ${BASE_DIR}/data/geoip.dat && \
    curl -fSL "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" \
        -o ${BASE_DIR}/data/geosite.dat

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Copy application
COPY app.py ${BASE_DIR}/app.py

# Create default xray config if not mounted
RUN if [ ! -f ${BASE_DIR}/config/xray-multi-socks.json ]; then \
    echo '{ \
  "log": {"loglevel": "warning"}, \
  "inbounds": [ \
    {"tag":"socks-in","listen":"0.0.0.0","port":10808,"protocol":"socks","settings":{"udp":true}}, \
    {"tag":"http-in","listen":"0.0.0.0","port":10809,"protocol":"http"} \
  ], \
  "outbounds": [{"tag":"direct","protocol":"freedom"}], \
  "routing": {"domainStrategy":"AsIs","rules":[]} \
}' > ${BASE_DIR}/config/xray-multi-socks.json; fi

# Supervisord config: run both Xray and the panel
RUN cat > /etc/supervisor/conf.d/xray-manager.conf <<'EOF'
[program:xray]
command=/root/xray-manager/bin/xray run -config /root/xray-manager/config/xray-multi-socks.json
autostart=true
autorestart=true
stdout_logfile=/root/xray-manager/logs/xray.log
stderr_logfile=/root/xray-manager/logs/xray.err
stdout_logfile_maxbytes=10MB
stdout_logfile_backups=3

[program:xray-panel]
command=python3 /root/xray-manager/app.py --host 0.0.0.0 --port 54321 --xray-config /root/xray-manager/config/xray-multi-socks.json --xray-binary /root/xray-manager/bin/xray --service xray
autostart=true
autorestart=true
stdout_logfile=/root/xray-manager/logs/panel.log
stderr_logfile=/root/xray-manager/logs/panel.err
stdout_logfile_maxbytes=5MB
stdout_logfile_backups=3

[group:xray-all]
programs=xray,xray-panel
EOF

WORKDIR ${BASE_DIR}

EXPOSE 54321 10808 10809

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:54321/ || exit 1

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
