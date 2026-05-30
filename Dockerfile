FROM python:3.11-slim

LABEL maintainer="derwalldrose" \
      description="xray-manager — Xray proxy + web management panel"

ARG XRAY_VERSION=v26.3.27
ARG TARGETARCH=amd64

ENV BASE_DIR=/root/xray-manager

# Install system deps + supervisor
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl unzip ca-certificates supervisor iptables iproute2 && \
    rm -rf /var/lib/apt/lists/* && \
    update-alternatives --set iptables /usr/sbin/iptables-legacy && \
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

# Create directory structure
RUN mkdir -p ${BASE_DIR}/bin && \
    mkdir -p ${BASE_DIR}/data && \
    mkdir -p ${BASE_DIR}/config && \
    mkdir -p ${BASE_DIR}/backup && \
    mkdir -p ${BASE_DIR}/state && \
    mkdir -p ${BASE_DIR}/logs

# Download Xray-core (via CDN for China compatibility)
RUN ARCH="${TARGETARCH}" && \
    if [ "$ARCH" = "amd64" ]; then XRAY_ARCH="64"; \
    elif [ "$ARCH" = "arm64" ]; then XRAY_ARCH="arm64-v8a"; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -fSL "https://hub.543083.xyz/https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip" \
        -o /tmp/xray.zip && \
    unzip -o /tmp/xray.zip -d /tmp/xray-extract && \
    mv /tmp/xray-extract/xray ${BASE_DIR}/bin/xray && \
    chmod +x ${BASE_DIR}/bin/xray && \
    rm -rf /tmp/xray.zip /tmp/xray-extract

# Download geo data (via CDN)
RUN curl -fSL "https://hub.543083.xyz/https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" \
        -o ${BASE_DIR}/data/geoip.dat && \
    curl -fSL "https://hub.543083.xyz/https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" \
        -o ${BASE_DIR}/data/geosite.dat && \
    ln -sf ${BASE_DIR}/data/geoip.dat ${BASE_DIR}/bin/geoip.dat && \
    ln -sf ${BASE_DIR}/data/geosite.dat ${BASE_DIR}/bin/geosite.dat

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

# Set initial token
RUN echo "123456" > ${BASE_DIR}/state/token && chmod 600 ${BASE_DIR}/state/token

# Supervisord config
COPY xray-manager.conf /etc/supervisor/conf.d/xray-manager.conf

WORKDIR ${BASE_DIR}

EXPOSE 54321 10808 10809

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:54321/ || exit 1

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
