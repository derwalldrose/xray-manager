FROM node:22-bookworm-slim AS builder

WORKDIR /src
RUN corepack enable && corepack prepare pnpm@11.5.1 --activate

COPY pnpm-workspace.yaml pnpm-lock.yaml package.json ./
COPY shared/package.json shared/package.json
COPY server/package.json server/package.json
COPY web/package.json web/package.json
RUN pnpm install --frozen-lockfile --config.dangerouslyAllowAllBuilds=true

COPY shared shared
COPY server server
COPY web web
RUN cd web && pnpm run build && cd ../server && pnpm run build

FROM node:22-bookworm-slim

LABEL maintainer="derwalldrose" \
      description="xray-manager v3 — standalone Xray proxy + web management panel"

ARG XRAY_VERSION=v26.3.27
ARG TARGETARCH=amd64

ENV XRAY_MANAGER_V3_HOME=/root/xray-manager-v3 \
    NODE_ENV=production \
    PORT=54321

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl unzip supervisor iptables iproute2 procps && \
    rm -rf /var/lib/apt/lists/* && \
    if command -v update-alternatives >/dev/null 2>&1 && [ -x /usr/sbin/iptables-legacy ]; then \
      update-alternatives --set iptables /usr/sbin/iptables-legacy || true; \
      update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy || true; \
    fi

RUN mkdir -p \
      ${XRAY_MANAGER_V3_HOME}/config \
      ${XRAY_MANAGER_V3_HOME}/data \
      ${XRAY_MANAGER_V3_HOME}/backup \
      ${XRAY_MANAGER_V3_HOME}/bin \
      ${XRAY_MANAGER_V3_HOME}/logs

# Fixed Xray-core version. Override only deliberately with --build-arg XRAY_VERSION=vX.Y.Z.
RUN ARCH="${TARGETARCH}" && \
    if [ "$ARCH" = "amd64" ]; then XRAY_ARCH="64"; \
    elif [ "$ARCH" = "arm64" ]; then XRAY_ARCH="arm64-v8a"; \
    else echo "Unsupported arch: $ARCH" >&2; exit 1; fi && \
    curl -fSL "https://hub.543083.xyz/https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip" -o /tmp/xray.zip && \
    unzip -o /tmp/xray.zip -d /tmp/xray && \
    install -m 755 /tmp/xray/xray ${XRAY_MANAGER_V3_HOME}/bin/xray && \
    rm -rf /tmp/xray.zip /tmp/xray

RUN curl -fSL "https://hub.543083.xyz/https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" -o ${XRAY_MANAGER_V3_HOME}/data/geoip.dat && \
    curl -fSL "https://hub.543083.xyz/https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" -o ${XRAY_MANAGER_V3_HOME}/data/geosite.dat && \
    ln -sf ${XRAY_MANAGER_V3_HOME}/data/geoip.dat ${XRAY_MANAGER_V3_HOME}/bin/geoip.dat && \
    ln -sf ${XRAY_MANAGER_V3_HOME}/data/geosite.dat ${XRAY_MANAGER_V3_HOME}/bin/geosite.dat

COPY --from=builder /src/server/dist/index.js ${XRAY_MANAGER_V3_HOME}/index.js
COPY --from=builder /src/web/dist ${XRAY_MANAGER_V3_HOME}/web-dist
COPY xray-manager-v3.conf /etc/supervisor/conf.d/xray-manager-v3.conf

RUN if [ ! -f ${XRAY_MANAGER_V3_HOME}/config/xray-multi-socks.json ]; then \
      printf '%s\n' \
'{' \
'  "log": {"loglevel": "warning"},' \
'  "inbounds": [' \
'    {"tag":"socks-in","listen":"0.0.0.0","port":10810,"protocol":"socks","settings":{"auth":"noauth","udp":true},"sniffing":{"enabled":true,"destOverride":["http","tls","quic"]}},' \
'    {"tag":"http-in","listen":"0.0.0.0","port":10818,"protocol":"http","settings":{}},' \
'    {"tag":"dns","listen":"0.0.0.0","port":53,"protocol":"dokodemo-door","settings":{"address":"119.29.29.29","port":53,"network":"tcp,udp"}},' \
'    {"tag":"transparent","listen":"0.0.0.0","port":12345,"protocol":"dokodemo-door","settings":{"network":"tcp,udp","followRedirect":true},"sniffing":{"enabled":true,"destOverride":["http","tls","quic"]}}' \
'  ],' \
'  "outbounds": [' \
'    {"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"UseIP"},"streamSettings":{"sockopt":{"mark":128}}},' \
'    {"tag":"block","protocol":"blackhole","streamSettings":{"sockopt":{"mark":128}}},' \
'    {"tag":"dns-out","protocol":"dns","settings":{"address":"119.29.29.29","port":53,"network":"udp"},"streamSettings":{"sockopt":{"mark":128}}}' \
'  ],' \
'  "routing": {"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","inboundTag":["dns"],"outboundTag":"direct"},{"type":"field","ip":["geoip:private"],"outboundTag":"direct"},{"type":"field","ip":["geoip:cn"],"outboundTag":"direct"},{"type":"field","domain":["geosite:cn"],"outboundTag":"direct"},{"type":"field","network":"udp","outboundTag":"direct"}]},' \
'  "dns": {"servers":["119.29.29.29","223.5.5.5"],"hosts":{}}' \
'}' > ${XRAY_MANAGER_V3_HOME}/config/xray-multi-socks.json; \
    fi && \
    echo 123456 > ${XRAY_MANAGER_V3_HOME}/data/token && \
    chmod 600 ${XRAY_MANAGER_V3_HOME}/data/token

WORKDIR ${XRAY_MANAGER_V3_HOME}

EXPOSE 54321 10810 10818 12345 53/tcp 53/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD sh -c 'curl -fsS -H "X-Token: $(cat /root/xray-manager-v3/data/token 2>/dev/null || echo 123456)" http://127.0.0.1:54321/api/status >/dev/null || exit 1'

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
