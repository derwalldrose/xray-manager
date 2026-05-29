# xray-manager

轻量级 Xray 代理管理面板，单文件 Flask 应用。

## 一键部署

```bash
bash <(curl -fsSL https://hub.543083.xyz/https://raw.githubusercontent.com/derwalldrose/xray-manager/main/deploy.sh)
```

部署完成后访问 `http://<IP>:54321`，Token: `Root2023!`

## 功能

- 出站节点管理（vless/vmess/ss/trojan，表单编辑/JSON编辑/链接解析导入/导出）
- 节点延迟测试 & 速度测试（单节点/批量）
- 透明代理（iptables redirect 模式，支持 geoip/geosite bypass）
- 负载均衡（roundRobin/leastPing/random）
- DNS 劫持（自动备份/还原 resolv.conf）
- 路由规则管理
- 配置备份 & 恢复

## 目录结构

```
/root/xray-manager/
├── bin/xray                    # Xray 二进制
├── config/xray-multi-socks.json # Xray 配置
├── data/geoip.dat, geosite.dat  # GeoIP 数据
├── backup/                     # 配置备份
├── state/                      # 运行状态
├── app.py                      # 管理面板
└── .venv/                      # Python 虚拟环境
```

## 服务管理

```bash
systemctl start xray-manager      # 启动面板
systemctl start xray-multi-socks  # 启动代理
systemctl status xray-manager     # 查看状态
journalctl -u xray-manager -f     # 查看日志
```

## Docker 部署

```bash
git clone https://github.com/derwalldrose/xray-manager.git
cd xray-manager
docker-compose up -d
```
