FROM python:3.11-slim

LABEL maintainer="derwalldrose" \
      description="xray-manager — lightweight web panel for Xray service management"

# Versions (override at build time if needed)
ARG XRAY_VERSION=v25.4.30
ARG TARGETARCH=amd64

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        unzip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and install Xray-core
RUN ARCH="${TARGETARCH}" && \
    if [ "$ARCH" = "amd64" ]; then XRAY_ARCH="64"; \
    elif [ "$ARCH" = "arm64" ]; then XRAY_ARCH="arm64-v8a"; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -fSL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip" \
        -o /tmp/xray.zip && \
    unzip -o /tmp/xray.zip -d /tmp/xray-extract && \
    mv /tmp/xray-extract/xray /usr/local/bin/xray && \
    chmod +x /usr/local/bin/xray && \
    rm -rf /tmp/xray.zip /tmp/xray-extract

# Download geo data
RUN mkdir -p /usr/local/share/xray && \
    curl -fSL "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" \
        -o /usr/local/share/xray/geoip.dat && \
    curl -fSL "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" \
        -o /usr/local/share/xray/geosite.dat

# Create config directory
RUN mkdir -p /root/xray-manager

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Copy application
COPY app.py /root/xray-manager/app.py

# Create default xray config if not mounted
RUN if [ ! -f /root/xray-multi-socks.json ]; then \
    echo '{ \
  "log": {"loglevel": "warning"}, \
  "inbounds": [{ \
    "tag": "socks-in", "listen": "0.0.0.0", "port": 10808, \
    "protocol": "socks", "settings": {"udp": true} \
  }], \
  "outbounds": [{"tag": "direct", "protocol": "freedom"}], \
  "routing": {"domainStrategy": "AsIs", "rules": []} \
}' > /root/xray-multi-socks.json; fi

WORKDIR /root/xray-manager

EXPOSE 54321

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:54321/ || exit 1

CMD ["python3", "app.py", \
     "--host", "0.0.0.0", \
     "--port", "54321", \
     "--xray-config", "/root/xray-multi-socks.json", \
     "--xray-binary", "/usr/local/bin/xray"]
