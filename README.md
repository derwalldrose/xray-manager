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

使用预构建镜像（推荐）。**只需一个数据目录挂载**（+ resolv.conf）：

```bash
docker pull docker.io/derwalldrose/derwalld:v2
docker run -d --name manager --restart unless-stopped --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW -e PYTHONUNBUFFERED=1 \
  -e PANEL_PORT=54321 \
  -v /root/manager:/root/xray-manager \
  -v /etc/resolv.conf:/etc/resolv.conf \
  docker.io/derwalldrose/derwalld:v2
```

- 宿主机目录无需预建，`docker run` 自动创建；首次启动 seed 程序自动放入默认配置、token、geo 数据
- 节点配置存 `/root/manager/config/`，状态（token/透明代理）存 `/root/manager/state/`，日志 `/root/manager/logs/`——备份就是打包这一个目录
- `PANEL_PORT` 改面板端口（默认 54321，与 v2raya 等共存冲突时可设 54322/54323）
- 初始 Token: `123456`，访问 `http://<IP>:<PANEL_PORT>`；代理进程名 `der`

镜像结构：代码与二进制烧在 `/opt/derwalld`（永不挂载），运行数据全在 `/root/xray-manager`（单卷）。

或从源码构建：

```bash
git clone https://github.com/derwalldrose/xray-manager.git
cd xray-manager
docker build -t derwalld:local .
```

## 目录结构

```
/opt/derwalld/                 # 镜像内代码（不挂载）
├── bin/der                     # Xray 二进制（进程名 der）
├── templates/                  # 默认配置 + geo 数据（seed 源）
├── app.py                      # 管理面板
└── txt_endpoints.py xray-entrypoint.py

/root/xray-manager/             # 唯一数据卷（宿主目录可自定义，如 /root/manager）
├── config/xray-multi-socks.json # Xray 配置
├── data/geoip.dat, geosite.dat  # GeoIP 数据（首启自举）
├── state/                      # token + 透明代理状态
└── logs/                       # 运行日志
```
