# xray-manager

轻量级 Xray 代理管理面板，单文件 Flask 应用。

## 一键部署

```bash
bash <(curl -fsSL https://hub.543083.xyz/https://raw.githubusercontent.com/derwalldrose/xray-manager/main/deploy.sh)
```

部署完成后访问 `http://<IP>:54321`，初始 Token: `123456`（首次登录后在配置页面修改）。

## 功能

- 出站节点管理（vless/vmess/ss/trojan，表单编辑/JSON编辑/链接解析导入/导出）
- 节点延迟测试 & 速度测试（单节点/批量）
- 透明代理（iptables redirect 模式，支持 geoip/geosite bypass）
- 负载均衡（roundRobin/leastPing/random）
- DNS 劫持（自动备份/还原 resolv.conf）
- 路由规则管理
- 配置备份 & 恢复

## 服务管理

```bash
systemctl start xray-manager      # 启动面板
systemctl start xray-multi-socks  # 启动代理
systemctl status xray-manager     # 查看状态
journalctl -u xray-manager -f     # 查看日志
```

## Docker 部署

使用预构建镜像（推荐，进程名 `der`，内置 geo 数据与默认配置，空目录自举）：

```bash
docker pull docker.io/derwalldrose/derwalld:v1-clean
docker run -d --name manager --restart unless-stopped --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW -e PYTHONUNBUFFERED=1 \
  -e PANEL_PORT=54321 \
  -v /root/manager/config:/root/xray-manager/config \
  -v /root/manager/state:/root/xray-manager/state \
  -v /root/manager/logs:/root/xray-manager/logs \
  -v /etc/resolv.conf:/etc/resolv.conf \
  docker.io/derwalldrose/derwalld:v1-clean
```

- 宿主机目录无需预建，`docker run` 会自动创建；配置/geo/token 由镜像内 seed 程序自举
- 只挂载 `config`（节点配置）、`state`（token + 透明代理状态）、`logs`（日志）；`data`/`backup` 已不需要
- `PANEL_PORT` 改面板端口（默认 54321，如与 v2raya 等共存冲突可设 54322）
- 初始 Token: `123456`，访问 `http://<IP>:<PANEL_PORT>`

或从源码构建：

```bash
git clone https://github.com/derwalldrose/xray-manager.git
cd xray-manager
docker build -t derwalld:local .
```

## 目录结构

```
/root/xray-manager/          # 容器内路径（宿主挂载目录可自定义，如 /root/manager）
├── bin/der                   # Xray 二进制（进程名 der）
├── config/xray-multi-socks.json # Xray 配置（持久化）
├── data/geoip.dat, geosite.dat  # GeoIP 数据（镜像内置，首启拷入）
├── state/                    # token + 透明代理状态（持久化）
├── templates/                # 内置默认配置与 geo 数据（seed 源）
├── logs/                     # 运行日志（持久化）
└── app.py                    # 管理面板
```
