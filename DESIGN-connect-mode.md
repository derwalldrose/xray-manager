# xray-manager "连接模式" 设计方案

> 类似 v2raya 的一站式代理管理：选节点 → 负载均衡 → 开启代理

---

## 1. 现状分析

**已有的能力（app.py 3795行，纯API + 内嵌HTML）：**

| 能力 | 状态 | 位置 |
|------|------|------|
| 出站节点列表/编辑 | ✅ 完整 | `/api/outbounds`, 出站 tab |
| 节点链接解析导入 | ✅ 完整 | `parse-vless/vmess/ss/trojan` |
| 批量测延迟/测速 | ✅ 完整 | `/api/outbounds/batch-test` |
| HTTP + SOCKS 入站 | ✅ 配置已有 | 端口 10810-10813, 10818 |
| 透明代理 (dokodemo-door) | ✅ 完整 | `/api/transparent/*` |
| 负载均衡器 | ✅ 基础 | `/api/transparent/balancer` |
| 路由规则管理 | ✅ 完整 | `/api/routing` |
| 服务启停 | ✅ 完整 | `/api/service/start\|stop\|restart` |

**缺失的核心体验：**
- 没有"一键连接"流程 — 用户需要分别操作出站 tab、透明代理 tab、路由 tab
- 没有"当前连接状态"概览 — 不知道当前流量走哪个节点
- 负载均衡仅绑定在透明代理下，不能独立用于普通代理
- 入站端口（HTTP/SOCKS）没有走统一的"选中节点"出站

---

## 2. 目标设计

### 核心理念

```
┌─────────────────────────────────────────────────────┐
│  Xray Manager  -  连接模式                           │
│                                                     │
│  ① 节点列表（可多选）                                 │
│  ┌─────────────────────────────────────────────────┐ │
│  │ ☐ proxy-us   vless  us.270376.xyz:443   120ms  │ │
│  │ ☑ proxy-kr   vless  kr.270376.xyz:10000  85ms  │ │
│  │ ☑ proxy-jp   vless  jp.270376.xyz:443    92ms  │ │
│  │ ☐ ech-turn   vless  103.112.1.131:443   200ms  │ │
│  │ ☑ ss-notls1  ss     198.41.209.8:8880   150ms  │ │
│  └─────────────────────────────────────────────────┘ │
│                                                     │
│  ② 连接设置                                         │
│  负载均衡: [轮询 ▾]  (多选时自动启用)                  │
│  透明代理: [ ] 启用  (iptables REDIRECT)              │
│                                                     │
│  ③ [▶ 启动连接]  [■ 断开]  状态: ● 已连接 (3节点)    │
│                                                     │
│  入站端口:                                           │
│    SOCKS5 → 0.0.0.0:10810                           │
│    HTTP   → 0.0.0.0:10818                           │
│    透明    → 0.0.0.0:12345 (如启用)                  │
└─────────────────────────────────────────────────────┘
```

---

## 3. 详细设计

### 3.1 新增状态文件: `state/connect-mode.json`

```json
{
  "active": true,
  "selected_tags": ["proxy-kr", "proxy-jp", "ss-notls1"],
  "balancer_strategy": "roundRobin",
  "transparent_enabled": false,
  "started_at": "2026-05-30T12:00:00",
  "inbound_socks_port": 10810,
  "inbound_http_port": 10818,
  "transparent_port": 12345
}
```

### 3.2 新增 API 端点

#### `GET /api/connect/status`
返回当前连接模式状态 + 节点列表（带延迟数据）

```json
{
  "active": true,
  "selected_tags": ["proxy-kr", "proxy-jp"],
  "balancer_strategy": "roundRobin",
  "transparent_enabled": false,
  "started_at": "...",
  "inbound_socks_port": 10810,
  "inbound_http_port": 10818,
  "transparent_port": 12345,
  "xray_running": true,
  "nodes": [
    {
      "tag": "proxy-kr",
      "protocol": "vless",
      "address": "kr.270376.xyz",
      "port": 10000,
      "network": "ws",
      "selected": true,
      "last_latency_ms": 85,
      "last_speed_mbps": null
    }
  ]
}
```

#### `POST /api/connect/start`
一键启动连接。Body:

```json
{
  "tags": ["proxy-kr", "proxy-jp", "ss-notls1"],
  "strategy": "roundRobin",
  "transparent": false
}
```

**执行流程：**
1. 验证 tags 均存在于 outbounds
2. 根据选中数量决定路由方式：
   - **单节点** → routing rule 直接指向该 outbound tag
   - **多节点** → 创建 `proxy-balancer`，selector = tags，strategy = 策略
3. 生成入站配置：
   - `socks-in`: 0.0.0.0:10810 (SOCKS5 + UDP)
   - `http-in`: 0.0.0.0:10818 (HTTP)
   - 如 `transparent=true`: `dokodemo-door` on 12345 + iptables + DNS hijack
4. 设置路由规则：
   - `socks-in` → balancer/selected_tag
   - `http-in` → balancer/selected_tag
   - `dns` inbound → direct
   - `geoip:cn` / `geosite:cn` / `geoip:private` → direct
   - `transparent` (if enabled) → balancer/selected_tag
5. 所有 proxy outbounds 加 `sockopt.mark=128` (防回环)
6. 写入配置 → `xray run -test` → 重启 xray
7. 如启用了透明代理 → 执行 iptables + DNS hijack
8. 保存状态到 `state/connect-mode.json`

#### `POST /api/connect/stop`
断开连接。恢复默认路由（所有入站 → direct）。

**执行流程：**
1. 如果透明代理已启用 → 清理 iptables + 恢复 DNS
2. 移除 connect-mode 添加的 routing rules / balancers
3. 恢复入站默认路由为 direct
4. 更新状态文件
5. 重启 xray

#### `POST /api/connect/test-selected`
批量测试选中节点的延迟/速度（复用现有 batch-test 逻辑）

### 3.3 配置生成逻辑

**核心函数: `_build_connect_config(tags, strategy, transparent, ports)`**

```
输入:
  tags = ["proxy-kr", "proxy-jp"]
  strategy = "roundRobin"
  transparent = false
  ports = {socks: 10818, http: 10810, transparent: 12345}

输出 (xray config delta):
  inbounds:
    - socks-in (SOCKS5, 10810)
    - http-in (HTTP, 10818)
    - dns (dokodemo-door, 53) [always]
    - transparent (dokodemo-door, 12345) [if transparent=true]

  outbounds:
    - [保留所有现有 proxy outbounds 不变]
    - direct (freedom, mark=128)
    - block (blackhole)
    - dns-out (dns, mark=128)

  routing:
    balancers:
      - tag: "proxy-balancer"
        selector: ["proxy-kr", "proxy-jp"]
        strategy: {type: "roundRobin"}  [仅多节点时]
    rules (优先级从高到低):
      - dns inbound → direct
      - socks-in → balancer (或单节点 tag)
      - http-in → balancer (或单节点 tag)
      - transparent → balancer [if enabled]
      - geoip:cn → direct
      - geosite:cn → direct
      - geoip:private → direct
      - udp → direct
```

**关键: 不修改现有 outbounds 内容，只改 inbounds 和 routing。**

### 3.4 前端 UI 设计

#### 新增 Tab: "连接" (放在第一个位置)

```
┌─ Tabs ────────────────────────────────────────────────────┐
│ 连接 │ 状态 │ 入站 │ 出站 │ 路由 │ 配置 │ DNS │ 日志 │ ... │
└──────────────────────────────────────────────────────────┘
```

#### 连接 Tab 布局

**上半部分: 节点选择表格**

```
┌─────────────────────────────────────────────────────────────┐
│  节点列表                         [刷新延迟] [全选] [清空]    │
│                                                             │
│  ┌──┬────────┬──────┬──────────────────┬──────┬───────┐    │
│  │☑ │ Tag    │ 协议  │ 地址              │ 端口  │ 延迟  │    │
│  ├──┼────────┼──────┼──────────────────┼──────┼───────┤    │
│  │☐ │proxy-us│vless │us.270376.xyz     │ 443  │ 120ms │    │
│  │☑ │proxy-kr│vless │kr.270376.xyz     │10000 │  85ms │    │
│  │☑ │proxy-jp│vless │jp.270376.xyz     │ 443  │  92ms │    │
│  │☐ │ech-turn│vless │103.112.1.131     │ 443  │ 200ms │    │
│  │☑ │ss-notls│ss    │198.41.209.8      │8880  │ 150ms │    │
│  └──┴────────┴──────┴──────────────────┴──────┴───────┘    │
│  已选: 3 个节点                                              │
└─────────────────────────────────────────────────────────────┘
```

**下半部分: 连接控制面板**

```
┌─────────────────────────────────────────────────────────────┐
│  连接设置                                                    │
│                                                             │
│  负载均衡策略:  [轮询 (roundRobin) ▾]                        │
│                 (多选节点时自动启用, 单选时禁用)                │
│                                                             │
│  ☐ 启用透明代理  (iptables REDIRECT, 所有设备走代理)          │
│    端口: [12345]                                             │
│                                                             │
│  ┌─────────────────────────────────────────────────┐        │
│  │ 入站端点:                                        │        │
│  │   SOCKS5  →  0.0.0.0:10810                      │        │
│  │   HTTP    →  0.0.0.0:10818                      │        │
│  │   透明代理 →  0.0.0.0:12345  (未启用)            │        │
│  └─────────────────────────────────────────────────┘        │
│                                                             │
│  [▶ 启动连接]   [■ 断开连接]                                 │
│                                                             │
│  状态: ● 已连接 (3节点, 轮询)   运行时间: 2h 15m             │
│        ○ 未连接                                              │
└─────────────────────────────────────────────────────────────┘
```

### 3.5 与现有功能的关系

| 现有功能 | 连接模式影响 |
|----------|-------------|
| 出站 tab | **不变** — 仍然可单独编辑/导入/删除节点 |
| 透明代理 tab | **不变** — 仍然可独立操作，但连接模式可一键启用 |
| 路由 tab | **不变** — 显示当前路由规则（包括连接模式生成的） |
| 状态 tab | **不变** — 显示服务状态 |
| 负载均衡配置 (透明代理下) | **被连接模式覆盖** — 连接模式优先 |
| 配置 tab | **不变** — 可手动编辑 JSON |

**核心原则: 连接模式是"快捷操作层"，不破坏底层配置能力。**

### 3.6 状态转换图

```
                    ┌──────────┐
                    │  空闲     │
                    │ (direct)  │
                    └────┬─────┘
                         │ 用户选择节点 + 点击启动
                         ▼
                    ┌──────────┐
         ┌────────│  运行中    │────────┐
         │        │ (proxy)   │        │
         │        └────┬─────┘        │
         │             │              │
    添加节点      修改策略        启用透明代理
    重新启动      热更新           热更新
         │             │              │
         ▼             ▼              ▼
    ┌──────────────────────────────────────┐
    │           热更新 (不中断)              │
    │  修改 routing.balancers + rules      │
    │  重启 xray (~1s)                     │
    └──────────────────────────────────────┘
                         │
                         │ 用户点击断开 / 选择0个节点
                         ▼
                    ┌──────────┐
                    │  空闲     │
                    │ (direct)  │
                    └──────────┘
```

---

## 4. 实现步骤

### Phase 1: 后端 API (app.py)

1. **新增 `_build_connect_config()` 函数** — 核心配置生成逻辑
   - 输入: selected tags, strategy, transparent flag, port config
   - 输出: 完整的 xray config dict
   - 复用现有的 `_tp_add_dokodemo_to_config()` 的部分逻辑

2. **新增状态管理函数**
   - `_connect_state_read()` / `_connect_state_write()`
   - 文件: `state/connect-mode.json`

3. **新增 API 端点**
   - `GET /api/connect/status` — 返回状态 + 节点列表
   - `POST /api/connect/start` — 一键启动
   - `POST /api/connect/stop` — 断开
   - `POST /api/connect/test-selected` — 测试选中节点

4. **修改 `_tp_startup_cleanup()`** — 启动时也检查 connect-mode 状态

### Phase 2: 前端 UI (HTML/JS in app.py)

1. **新增 "连接" tab** — HTML 结构
2. **节点选择表格** — 复用出站 tab 的数据加载逻辑
3. **连接控制面板** — 策略选择、透明代理开关、启动/断开按钮
4. **状态显示** — 运行状态、入站端点、运行时间
5. **JS 逻辑**
   - `loadConnectNodes()` — 加载节点列表
   - `toggleNode(tag)` — 选中/取消节点
   - `startConnect()` — 调用 start API
   - `stopConnect()` — 调用 stop API
   - `refreshLatency()` — 批量测延迟
   - `updateConnectStatus()` — 定期刷新状态

### Phase 3: 整合与优化

1. **节点排序** — 按延迟升序
2. **记忆上次选择** — 从 connect-mode.json 恢复
3. **连接状态指示器** — header 上显示连接状态
4. **快捷键** — Enter 启动 / Escape 断开

---

## 5. 配置生成伪代码

```python
def _build_connect_config(selected_tags, strategy, transparent, ports):
    """
    基于用户选择的节点，生成完整的 xray 配置。
    保留所有现有 outbounds，只修改 inbounds + routing。
    """
    cfg, err = _parse_config()  # 读取当前配置
    if err:
        return None, err

    # --- Inbounds ---
    # 移除旧的 connect-mode inbounds
    keep_tags = set()
    cfg["inbounds"] = [ib for ib in cfg["inbounds"]
                       if ib.get("tag") not in ("socks-in", "http-in", "dns", "transparent")]

    # SOCKS5 入站
    cfg["inbounds"].append({
        "tag": "socks-in",
        "listen": "0.0.0.0",
        "port": ports["socks"],
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    })

    # HTTP 入站
    cfg["inbounds"].append({
        "tag": "http-in",
        "listen": "0.0.0.0",
        "port": ports["http"],
        "protocol": "http",
    })

    # DNS 入站 (始终需要)
    cfg["inbounds"].append({
        "tag": "dns", "listen": "0.0.0.0", "port": 53,
        "protocol": "dokodemo-door",
        "settings": {"address": "119.29.29.29", "port": 53, "network": "tcp,udp"},
    })

    # 透明代理入站 (可选)
    if transparent:
        cfg["inbounds"].append({
            "tag": "transparent", "listen": "0.0.0.0", "port": ports["transparent"],
            "protocol": "dokodemo-door",
            "settings": {"network": "tcp,udp", "followRedirect": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"],
                         "domainsExcluded": ["argotunnel.com"]},
        })

    # --- Outbounds ---
    # 确保 mark=128 (防回环)
    for ob in cfg["outbounds"]:
        if ob.get("protocol") not in ("freedom", "blackhole", "dns"):
            ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["mark"] = 128

    # 确保 direct / block / dns-out 存在
    _ensure_system_outbounds(cfg)

    # --- Routing ---
    is_multi = len(selected_tags) > 1

    # Balancers
    if is_multi:
        balancer = {
            "tag": "proxy-balancer",
            "selector": selected_tags,
            "strategy": {"type": strategy},
        }
        cfg["routing"]["balancers"] = [balancer]

    # Rules
    rules = []
    rules.append({"type": "field", "inboundTag": ["dns"], "outboundTag": "direct"})

    if is_multi:
        rules.append({"type": "field", "inboundTag": ["socks-in"], "balancerTag": "proxy-balancer"})
        rules.append({"type": "field", "inboundTag": ["http-in"], "balancerTag": "proxy-balancer"})
        if transparent:
            rules.append({"type": "field", "inboundTag": ["transparent"], "balancerTag": "proxy-balancer"})
    else:
        tag = selected_tags[0]
        rules.append({"type": "field", "inboundTag": ["socks-in"], "outboundTag": tag})
        rules.append({"type": "field", "inboundTag": ["http-in"], "outboundTag": tag})
        if transparent:
            rules.append({"type": "field", "inboundTag": ["transparent"], "outboundTag": tag})
        cfg["routing"]["balancers"] = []

    # GeoIP bypass
    rules.append({"type": "field", "ip": ["geoip:cn"], "outboundTag": "direct"})
    rules.append({"type": "field", "domain": ["geosite:cn"], "outboundTag": "direct"})
    rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"})
    rules.append({"type": "field", "network": "udp", "outboundTag": "direct"})

    cfg["routing"]["rules"] = rules

    # --- DNS ---
    cfg["dns"] = {
        "servers": ["119.29.29.29", "223.5.5.5",
                     "https://dns.alidns.com/dns-query",
                     "https://cloudflare-dns.com/dns-query"],
        "hosts": {
            "domain:googleapis.cn": "googleapis.com",
            "geosite:category-ads-all": "127.0.0.1",
        },
    }

    return cfg, None
```

---

## 6. 关键设计决策

### Q: 为什么要单独的"连接模式"而不是改进现有透明代理 tab?

**A:** 现有架构把"选节点"和"开代理"分在了不同 tab，用户心智负担大。连接模式提供一个"一站式入口"：看到节点 → 选节点 → 启动。这正是 v2raya 的核心 UX 优势。

### Q: 连接模式和现有出站 tab 会冲突吗?

**A:** 不会。连接模式只修改 routing（指向哪些 outbounds），不修改 outbounds 本身。出站 tab 仍然可以编辑/导入/删除节点。连接模式启动时会重新读取最新 outbounds。

### Q: 单节点和多节点有什么区别?

**A:**
- **单节点** → 直接 routing rule，无 balancer
- **多节点** → 自动创建 `proxy-balancer`，用户选策略

### Q: 透明代理是必须的吗?

**A:** 不是。默认关闭。用户可以只用 HTTP/SOCKS 代理（浏览器手动配置或系统代理），也可以勾选透明代理让所有设备自动走代理。

### Q: 对现有配置的侵入性?

**A:** 最小化。connect-mode 启动时，只替换 `inbounds` 和 `routing`，不碰 `outbounds` 内容。停止时恢复原来的 inbounds + routing。配置 tab 仍可手动编辑 JSON。
