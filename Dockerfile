FROM python:3.11-slim

LABEL maintainer="derwalldrose" \
      description="xray-manager — lightweight web panel for Xray service management"

# Versions (override at build time if needed)
ARG XRAY_VERSION=v25.4.30
ARG TARGETARCH=amd64

# Base directory
ENV BASE_DIR=/root/xray-manager

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        unzip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create directory structure
RUN mkdir -p ${BASE_DIR}/{bin,data,config,backup,state}

# Download and install Xray-core
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
RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Copy application
COPY app.py ${BASE_DIR}/app.py

# Create default xray config if not mounted
RUN if [ ! -f ${BASE_DIR}/config/xray-multi-socks.json ]; then \
    echo '{ \
  "log": {"loglevel": "warning"}, \
  "inbounds": [{ \
    "tag": "socks-in", "listen": "0.0.0.0", "port": 10808, \
    "protocol": "socks", "settings": {"udp": true} \
  }], \
  "outbounds": [{"tag": "direct", "protocol": "freedom"}], \
  "routing": {"domainStrategy": "AsIs", "rules": []} \
}' > ${BASE_DIR}/config/xray-multi-socks.json; fi

WORKDIR ${BASE_DIR}

EXPOSE 54321

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:54321/ || exit 1

CMD ["python3", "app.py", \
     "--host", "0.0.0.0", \
     "--port", "54321"]
