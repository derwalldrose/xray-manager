#!/usr/bin/env python3
"""
Xray Manager - lightweight web panel for Xray service management.
Single-file Flask app with embedded dark-themed UI.

Features:
  - Service status / start / stop / restart
  - JSON config editor with syntax validation
  - Inbound port table with live editing
  - Routing rule viewer
  - Live logs viewer
  - API-based (all endpoints return JSON)

Usage:
  python3 xray-manager.py                      # default :54321
  python3 xray-manager.py --port 8080
  python3 xray-manager.py --xray-config /path/to/config.json
  python3 xray-manager.py --xray-binary /usr/local/bin/xray
  python3 xray-manager.py --service xray-multi-socks.service
"""

import argparse
import json
import ipaddress
import re
import os
import subprocess
import time
import shlex
import random
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
import base64 as _b64
import urllib.request

from flask import Flask, jsonify, request, Response

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
BASE_DIR = "/root/xray-manager"
DEFAULT_XRAY_BIN = f"{BASE_DIR}/bin/xray"
DEFAULT_XRAY_CFG = f"{BASE_DIR}/config/xray-multi-socks.json"
DEFAULT_SVC_NAME = "xray-multi-socks.service"
DEFAULT_PORT = 54321
DEFAULT_TOKEN = "123456"  # initial token; change via web UI or --token
DEFAULT_TEST_URLS = [
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
    "https://ipinfo.io/json",
    "https://ip.im/info",
]
DEFAULT_TEST_URLS_FILE = f"{BASE_DIR}/state/test-urls.json"
DEFAULT_SPEEDTEST_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
DEFAULT_SPEEDTEST_TIMEOUT = 20
DEFAULT_TRANSPARENT_PORT = 12345
TRANSPARENT_STATE_FILE = f"{BASE_DIR}/state/transparent-state.json"
IPTABLES_BACKUP_FILE = f"{BASE_DIR}/backup/iptables-backup.rules"
RESOLV_BACKUP_FILE = f"{BASE_DIR}/backup/resolv.conf.bak"
CHAIN_PREFIX = "XRAY_MGR"
CUSTOM_BYPASS_FILE = f"{BASE_DIR}/state/transparent-bypass.json"
BALANCER_CONFIG_FILE = f"{BASE_DIR}/state/balancer-config.json"
CONNECT_STATE_FILE = f"{BASE_DIR}/state/connect-mode.json"
TOKEN_FILE = f"{BASE_DIR}/state/token"
GEOIP_PATH = f"{BASE_DIR}/data/geoip.dat"
GEOSITE_PATH = f"{BASE_DIR}/data/geosite.dat"
GEO_CDN_PREFIX = "https://hub.543083.xyz/"
GEO_URLS_FILE = f"{BASE_DIR}/state/geo-urls.json"

DEFAULT_GEO_URLS = {
    "geoip": f"{GEO_CDN_PREFIX}https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
    "geosite": f"{GEO_CDN_PREFIX}https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
}


def _load_geo_urls():
    """Load geo URLs from state file, fallback to defaults."""
    try:
        with open(GEO_URLS_FILE) as f:
            saved = json.load(f)
        # Merge with defaults (in case new keys added)
        result = dict(DEFAULT_GEO_URLS)
        result.update(saved)
        return result
    except Exception:
        return dict(DEFAULT_GEO_URLS)


def _save_geo_urls(urls):
    """Save geo URLs to state file."""
    Path(GEO_URLS_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(GEO_URLS_FILE, "w") as f:
        json.dump(urls, f, indent=2)

app = Flask(__name__)

# populated in main()
XRAY_BIN = DEFAULT_XRAY_BIN


def _init_dirs():
    """Create all required subdirectories."""
    for d in [f"{BASE_DIR}/bin", f"{BASE_DIR}/data", f"{BASE_DIR}/config",
              f"{BASE_DIR}/backup", f"{BASE_DIR}/state"]:
        Path(d).mkdir(parents=True, exist_ok=True)

XRAY_CFG = DEFAULT_XRAY_CFG
SVC_NAME = DEFAULT_SVC_NAME
AUTH_TOKEN = DEFAULT_TOKEN  # may be overridden by --token or token file
TEST_URLS_FILE = DEFAULT_TEST_URLS_FILE

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd, timeout=15):
    """Run a shell command, return (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1


def _load_test_urls():
    try:
        with open(TEST_URLS_FILE, "r") as f:
            urls = json.load(f)
        if isinstance(urls, list) and all(isinstance(x, str) for x in urls):
            merged = []
            for u in urls + DEFAULT_TEST_URLS:
                if u and u not in merged:
                    merged.append(u)
            return merged
    except Exception:
        pass
    return list(DEFAULT_TEST_URLS)


def _save_test_urls(urls):
    clean = []
    for u in urls:
        u = str(u).strip()
        if u and u not in clean:
            clean.append(u)
    Path(TEST_URLS_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(TEST_URLS_FILE, "w") as f:
        json.dump(clean, f, ensure_ascii=False, indent=2)
    return clean


def _curl_via_socks(host, port, url, timeout=25):
    if host in ("0.0.0.0", "::", ""):
        host = "127.0.0.1"
    proxy = f"{host}:{int(port)}"
    cmd = (
        "curl -L -m " + shlex.quote(str(timeout)) +
        " -sS --socks5-hostname " + shlex.quote(proxy) +
        " -w " + shlex.quote("\n__HTTP_CODE__:%{http_code}\n__TIME_TOTAL__:%{time_total}\n") +
        " " + shlex.quote(url)
    )
    return _curl_proxy_common(cmd, timeout, proxy, url)


def _curl_via_http(host, port, url, timeout=25):
    if host in ("0.0.0.0", "::", ""):
        host = "127.0.0.1"
    proxy = f"http://{host}:{int(port)}"
    cmd = (
        "curl -L -m " + shlex.quote(str(timeout)) +
        " -sS --proxy " + shlex.quote(proxy) +
        " -w " + shlex.quote("\n__HTTP_CODE__:%{http_code}\n__TIME_TOTAL__:%{time_total}\n") +
        " " + shlex.quote(url)
    )
    return _curl_proxy_common(cmd, timeout, proxy, url)


def _curl_proxy_common(cmd, timeout, proxy="", url=""):
    started = time.time()
    out, err, rc = _run(cmd, timeout=timeout + 5)
    elapsed = time.time() - started
    http_code = ""
    time_total = ""
    body = out
    if "__HTTP_CODE__:" in out:
        before, after = out.rsplit("__HTTP_CODE__:", 1)
        body = before.rstrip("\n")
        lines = after.splitlines()
        http_code = lines[0].strip() if lines else ""
        for line in lines[1:]:
            if line.startswith("__TIME_TOTAL__:"):
                time_total = line.split(":", 1)[1].strip()
    return {
        "ok": rc == 0 and bool(http_code) and http_code != "000",
        "proxy": proxy,
        "url": url,
        "http_code": http_code,
        "time_total": time_total or f"{elapsed:.3f}",
        "exit_code": rc,
        "stdout": body[:4000],
        "stderr": err[:2000],
    }


def _curl_speedtest(host, port, url, timeout=20):
    """Download a file via SOCKS proxy and measure speed (bytes/sec -> Mbps)."""
    if host in ("0.0.0.0", "::", ""):
        host = "127.0.0.1"
    proxy = f"{host}:{int(port)}"
    cmd = (
        "curl -L -m " + shlex.quote(str(timeout)) +
        " -sS --socks5-hostname " + shlex.quote(proxy) +
        " -o /dev/null"
        " -w " + shlex.quote("%{size_download} %{speed_download} %{time_total} %{http_code}") +
        " " + shlex.quote(url)
    )
    out, err, rc = _run(cmd, timeout=timeout + 5)
    parts = out.strip().split()
    result = {
        "ok": False, "proxy": proxy, "url": url,
        "bytes": 0, "speed_bytes": 0, "speed_mbps": 0.0,
        "time_total": 0.0, "http_code": "", "exit_code": rc,
    }
    if len(parts) >= 4 and rc == 0:
        try:
            result["bytes"] = int(parts[0])
            result["speed_bytes"] = float(parts[1])
            result["speed_mbps"] = round(float(parts[1]) * 8 / 1000000, 2)
            result["time_total"] = float(parts[2])
            result["http_code"] = parts[3]
            result["ok"] = result["bytes"] > 0 and result["http_code"] == "200"
        except (ValueError, IndexError):
            pass
    if err:
        result["stderr"] = err[:1000]
    return result


def _build_temp_multi_config(outbounds, base_port=30000):
    """Build one temp Xray config with multiple inbounds, one per outbound. Returns (config_dict, port_map)."""
    inbounds = []
    rules = []
    port_map = {}  # tag -> port
    port = base_port
    all_outbounds = list(outbounds) + [{"tag": "direct", "protocol": "freedom"}]

    for ob in outbounds:
        tag = ob.get("tag", f"test-{port}")
        in_tag = f"in-{tag}"
        inbounds.append({
            "tag": in_tag,
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"udp": False},
        })
        rules.append({
            "type": "field",
            "inboundTag": [in_tag],
            "outboundTag": tag,
        })
        port_map[tag] = port
        port += 1

    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": all_outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    return cfg, port_map


def _start_temp_xray(config):
    """Write config to temp file, validate, start process. Returns (proc, tmp_path, error_msg)."""
    import tempfile
    fd, tmp = tempfile.mkstemp(suffix=".json", prefix="xray-test-")
    os.close(fd)
    with open(tmp, "w") as f:
        json.dump(config, f)

    out, err, rc = _run(f"{XRAY_BIN} run -test -config {tmp}")
    if "Configuration OK" not in (out + err):
        os.unlink(tmp)
        return None, None, (out + err).strip()

    proc = subprocess.Popen([XRAY_BIN, "run", "-config", tmp], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)
    if proc.poll() is not None:
        stderr = proc.stderr.read().decode() if proc.stderr else ""
        try:
            os.unlink(tmp)
        except Exception:
            pass
        return None, None, stderr[:2000]

    return proc, tmp, None


def _stop_temp_xray(proc, tmp_path):
    """Stop temp xray process and clean up."""
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        if tmp_path:
            os.unlink(tmp_path)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Transparent proxy helpers
# ---------------------------------------------------------------------------

_BYPASS_CIDRS = [
    "0.0.0.0/32", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
]


def _tp_state_read():
    try:
        with open(TRANSPARENT_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"enabled": False}


def _tp_state_write(state):
    Path(TRANSPARENT_STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(TRANSPARENT_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def _balancer_read():
    """Load balancer config from file."""
    try:
        with open(BALANCER_CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {"enabled": False, "tags": [], "strategy": "roundRobin"}


def _balancer_write(cfg):
    """Save balancer config to file."""
    Path(BALANCER_CONFIG_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(BALANCER_CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def _connect_state_read():
    """Load connect-mode state from file."""
    try:
        with open(CONNECT_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"active": False, "selected_tags": [], "balancer_strategy": "roundRobin", "transparent_enabled": False}


def _connect_state_write(state):
    """Save connect-mode state to file."""
    Path(CONNECT_STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(CONNECT_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def _reconcile_connect_state():
    """Reconcile actual system state with connect-mode.json.
    Returns the corrected state dict with actual_* fields.
    """
    state = _connect_state_read()
    xray_running = _service_status().get("running", False)
    dns_active = _dns_hijack_is_active()
    tp_has_rules = _tp_has_iptables_rules()
    tp_expected = state.get("transparent_enabled", False)
    active_expected = state.get("active", False)

    # Case 1: active + xray running → ensure DNS + iptables match
    if active_expected and xray_running:
        if not dns_active:
            print("[reconcile] DNS hijack missing, applying...")
            _dns_hijack_apply()
        if tp_expected and not tp_has_rules:
            tp_port = state.get("transparent_port", 12345)
            print(f"[reconcile] iptables missing, applying (port {tp_port})...")
            _iptables_setup_redirect(tp_port)
        if not tp_expected and tp_has_rules:
            print("[reconcile] Stale iptables, cleaning...")
            _iptables_cleanup()

    # Case 2: active but xray NOT running → mark inactive, clean all
    elif active_expected and not xray_running:
        print("[reconcile] Active but xray stopped → cleaning up")
        state["active"] = False
        state["was_active_but_stopped"] = True
        if dns_active:
            _dns_hijack_restore()
        if tp_has_rules:
            _iptables_cleanup()
        _connect_state_write(state)

    # Case 3: inactive → ensure iptables/DNS are clean (but keep config as-is)
    elif not active_expected:
        if dns_active:
            print("[reconcile] Stale DNS hijack, restoring...")
            _dns_hijack_restore()
        if tp_has_rules:
            print("[reconcile] Stale iptables, cleaning...")
            _iptables_cleanup()

    # Always ensure dokodemo/dns inbound exist in config
    _ensure_dns_inbound_in_config()

    state["xray_running"] = xray_running
    state["dns_actual"] = _dns_hijack_is_active()
    state["transparent_actual"] = _tp_has_iptables_rules()
    return state


def _extract_node_info(ob):
    """Extract display info from an outbound."""
    tag = ob.get("tag", "")
    protocol = ob.get("protocol", "")
    address = ""
    port = ""
    network = ""
    try:
        v = ob.get("settings", {}).get("vnext", [{}])[0]
        s = ob.get("settings", {}).get("servers", [{}])[0]
        src = v or s
        if src:
            address = str(src.get("address", ""))
            port = src.get("port", "")
        network = (ob.get("streamSettings") or {}).get("network", "tcp")
    except Exception:
        pass
    return {"tag": tag, "protocol": protocol, "address": address, "port": port, "network": network}


def _build_connect_config(selected_tags, strategy, transparent, ports):
    """Build complete xray config based on user's node selection.
    Only modifies inbounds + routing, preserves all outbounds.
    """
    cfg, err = _parse_config()
    if err:
        return None, err

    # --- Inbounds ---
    # Connect mode takes full control: remove ALL existing inbounds
    # (they'll be restored on stop)
    cfg["inbounds"] = []

    socks_port = ports.get("socks", 10810)
    http_port = ports.get("http", 10818)
    tp_port = ports.get("transparent", 12345)

    # SOCKS5 inbound
    cfg["inbounds"].append({
        "tag": "socks-in",
        "listen": "0.0.0.0",
        "port": socks_port,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    })

    # HTTP inbound
    cfg["inbounds"].append({
        "tag": "http-in",
        "listen": "0.0.0.0",
        "port": http_port,
        "protocol": "http",
        "settings": {},
    })

    # DNS inbound (always)
    cfg["inbounds"].append({
        "tag": "dns", "listen": "0.0.0.0", "port": 53,
        "protocol": "dokodemo-door",
        "settings": {"address": "119.29.29.29", "port": 53, "network": "tcp,udp"},
    })

    # Transparent inbound (optional)
    if transparent:
        cfg["inbounds"].append({
            "tag": "transparent", "listen": "0.0.0.0", "port": tp_port,
            "protocol": "dokodemo-door",
            "settings": {"network": "tcp,udp", "followRedirect": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"],
                         "domainsExcluded": ["argotunnel.com"]},
        })

    # --- Outbounds: ensure mark=128 for anti-loop ---
    outbounds = cfg.get("outbounds", [])
    for ob in outbounds:
        tag = ob.get("tag", "")
        proto = ob.get("protocol", "")
        if proto in ("freedom", "blackhole", "dns"):
            if proto in ("freedom", "dns"):
                ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["mark"] = 128
                if proto == "freedom":
                    ob.setdefault("settings", {})["domainStrategy"] = "UseIP"
            continue
        ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["mark"] = 128

    # Ensure direct/block/dns-out exist
    has_direct = any(ob.get("tag") == "direct" for ob in outbounds)
    has_block = any(ob.get("tag") == "block" for ob in outbounds)
    has_dns_out = any(ob.get("tag") == "dns-out" for ob in outbounds)
    if not has_direct:
        outbounds.append({
            "tag": "direct", "protocol": "freedom",
            "settings": {"domainStrategy": "UseIP"},
            "streamSettings": {"sockopt": {"mark": 128}},
        })
    if not has_block:
        outbounds.append({"tag": "block", "protocol": "blackhole", "streamSettings": {"sockopt": {"mark": 128}}})
    if not has_dns_out:
        outbounds.append({
            "tag": "dns-out", "protocol": "dns",
            "settings": {"port": 53, "address": "119.29.29.29", "network": "udp"},
            "streamSettings": {"sockopt": {"mark": 128}},
        })
    cfg["outbounds"] = outbounds

    # --- Routing ---
    is_multi = len(selected_tags) > 1
    routing = cfg.setdefault("routing", {})
    routing["domainStrategy"] = routing.get("domainStrategy", "IPIfNonMatch")

    # Balancers
    if is_multi:
        balancer = {
            "tag": "proxy-balancer",
            "selector": selected_tags,
            "strategy": {"type": strategy},
        }
        routing["balancers"] = [balancer]
    else:
        routing["balancers"] = []

    # Rules
    rules = []
    rules.append({"type": "field", "inboundTag": ["dns"], "outboundTag": "direct"})

    if is_multi:
        rules.append({"type": "field", "inboundTag": ["socks-in"], "balancerTag": "proxy-balancer"})
        rules.append({"type": "field", "inboundTag": ["http-in"], "balancerTag": "proxy-balancer"})
        if transparent:
            rules.append({"type": "field", "inboundTag": ["transparent"], "balancerTag": "proxy-balancer"})
    else:
        tag = selected_tags[0] if selected_tags else "direct"
        rules.append({"type": "field", "inboundTag": ["socks-in"], "outboundTag": tag})
        rules.append({"type": "field", "inboundTag": ["http-in"], "outboundTag": tag})
        if transparent:
            rules.append({"type": "field", "inboundTag": ["transparent"], "outboundTag": tag})

    # GeoIP bypass
    rules.append({"type": "field", "ip": ["geoip:cn"], "outboundTag": "direct"})
    rules.append({"type": "field", "domain": ["geosite:cn"], "outboundTag": "direct"})
    rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"})
    rules.append({"type": "field", "network": "udp", "outboundTag": "direct"})

    routing["rules"] = rules

    # --- DNS ---
    cfg["dns"] = {
        "servers": ["119.29.29.29", "223.5.5.5",
                     "https://dns.alidns.com/dns-query",
                     "https://cloudflare-dns.com/dns-query"],
        "tag": "dns",
        "hosts": {
            "domain:googleapis.cn": "googleapis.com",
            "geosite:category-ads-all": "127.0.0.1",
        },
    }

    return cfg, None


def _tp_load_custom_bypass():
    """Load user-customized bypass CIDRs from file."""
    try:
        with open(CUSTOM_BYPASS_FILE) as f:
            data = json.load(f)
        if isinstance(data, list):
            return [c.strip() for c in data if c.strip()]
    except Exception:
        pass
    return []


def _tp_save_custom_bypass(cidrs):
    """Save user-customized bypass CIDRs to file."""
    # Deduplicate and validate
    clean = []
    seen = set()
    for c in cidrs:
        c = c.strip()
        if c and c not in seen and ((":" not in c and "/" in c) or c.count(".") == 3):
            clean.append(c)
            seen.add(c)
    Path(CUSTOM_BYPASS_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(CUSTOM_BYPASS_FILE, "w") as f:
        json.dump(clean, f, indent=2)
    return clean


def _extract_dns_bypass_cidrs_from_config():
    """Auto-extract DNS-related IPs from current Xray dns.hosts and literal dns server IPs.
    Returns CIDRs like 1.1.1.1/32 or ipv6/128.
    """
    cfg, err = _parse_config()
    if err:
        return []
    dns = cfg.get("dns", {}) or {}
    out = []
    seen = set()
    def add_ip(ip):
        try:
            obj = ipaddress.ip_address(str(ip))
            cidr = f"{obj}/32" if obj.version == 4 else f"{obj}/128"
            if cidr not in seen:
                seen.add(cidr)
                out.append(cidr)
        except Exception:
            pass
    for vals in (dns.get("hosts") or {}).values():
        if isinstance(vals, list):
            for ip in vals:
                add_ip(ip)
        elif isinstance(vals, str):
            add_ip(vals)
    for server in (dns.get("servers") or []):
        if isinstance(server, str):
            add_ip(server)
        elif isinstance(server, dict):
            add_ip(server.get("address", ""))
    return out


def _tp_get_all_bypass_cidrs():
    """Get merged list: default + auto DNS IPs + custom, deduplicated."""
    all_cidrs = list(_BYPASS_CIDRS)
    seen = set(all_cidrs)
    for c in _extract_dns_bypass_cidrs_from_config() + _tp_load_custom_bypass():
        if c not in seen and ":" not in c:
            all_cidrs.append(c)
            seen.add(c)
    return all_cidrs


def _iptables_save():
    out, _, rc = _run("iptables-save -t nat", timeout=10)
    if rc == 0 and out.strip():
        with open(IPTABLES_BACKUP_FILE, "w") as f:
            f.write(out)
        return True
    return False


def _iptables_restore():
    if not Path(IPTABLES_BACKUP_FILE).exists():
        return False
    _, _, rc = _run("iptables-restore < " + IPTABLES_BACKUP_FILE, timeout=10)
    return rc == 0


def _iptables_cleanup():
    ch = CHAIN_PREFIX
    cmds = [
        f"iptables -t nat -F {ch}_OUT 2>/dev/null",
        f"iptables -t nat -D OUTPUT -p tcp -j {ch}_OUT 2>/dev/null",
        f"iptables -t nat -X {ch}_OUT 2>/dev/null",
        f"iptables -t nat -F {ch}_PRE 2>/dev/null",
        f"iptables -t nat -D PREROUTING -p tcp -j {ch}_PRE 2>/dev/null",
        f"iptables -t nat -D PREROUTING -p udp --dport 53 -j {ch}_PRE 2>/dev/null",
        f"iptables -t nat -X {ch}_PRE 2>/dev/null",
        f"iptables -t nat -F {ch}_RULE 2>/dev/null",
        f"iptables -t nat -X {ch}_RULE 2>/dev/null",
    ]
    for cmd in cmds:
        _run(cmd, timeout=5)
    # Clean up LAN gateway rules (FORWARD ACCEPT + MASQUERADE)
    _run("iptables -D FORWARD -j ACCEPT 2>/dev/null", timeout=5)
    # Remove MASQUERADE rules we added (for detected subnets)
    try:
        import subprocess as _sp
        _out = _sp.check_output(["iptables-legacy", "-t", "nat", "-S", "POSTROUTING"], text=True, timeout=5)
        for _line in _out.splitlines():
            if "MASQUERADE" in _line and "! -o lo" in _line:
                _run(_line.replace("-A", "-D"), timeout=5)
    except Exception:
        pass


def _tp_has_iptables_rules():
    """Check if XRAY_MGR iptables chains currently exist."""
    out, _, rc = _run(f"iptables -t nat -L {CHAIN_PREFIX}_RULE -n 2>/dev/null", timeout=5)
    return rc == 0 and CHAIN_PREFIX in (out or "")


def _tp_has_dokodemo_inbound():
    """Check if the xray config has a transparent dokodemo-door inbound."""
    try:
        with open(XRAY_CFG) as f:
            cfg = json.load(f)
        return any(ib.get("tag") == "transparent" for ib in cfg.get("inbounds", []))
    except Exception:
        return False


def _tp_startup_cleanup():
    """On startup: restore iptables if state says enabled, clean up stale rules otherwise."""
    state = _tp_state_read()
    has_dokodemo = _tp_has_dokodemo_inbound()
    has_iptables = _tp_has_iptables_rules()

    # Case 1: State says enabled + config has dokodemo → restore iptables if missing
    if state.get("enabled") and has_dokodemo:
        if not has_iptables:
            port = state.get("port", DEFAULT_TRANSPARENT_PORT)
            print(f"[transparent-proxy] Restoring iptables rules (port {port})...")
            _iptables_setup_redirect(port)
            _dns_hijack_apply()
            print("[transparent-proxy] iptables + DNS restored")
        else:
            print("[transparent-proxy] Active — iptables rules and dokodemo inbound present")

    # Case 2: iptables exist but no dokodemo → stale, clean up
    elif has_iptables and not has_dokodemo:
        print("[transparent-proxy] Stale iptables rules detected without dokodemo inbound — cleaning up")
        _iptables_cleanup()
        _tp_state_write({"enabled": False})
        print("[transparent-proxy] Stale rules cleaned up")

    # Case 3: State says enabled but no dokodemo → inconsistent, fix state
    elif state.get("enabled") and not has_dokodemo:
        _tp_state_write({"enabled": False})

    # Restore stale DNS hijack if transparent proxy is off
    if _dns_hijack_is_active() and not has_dokodemo:
        if _dns_hijack_restore():
            print("[transparent-proxy] Stale DNS hijack restored")

    # Connect-mode: reconcile state on startup
    conn_state = _reconcile_connect_state()
    if conn_state.get("active"):
        print("[connect-mode] Active, state reconciled")
    elif conn_state.get("was_active_but_stopped"):
        print("[connect-mode] Was active but xray stopped, cleaned up")


def _dns_hijack_backup():
    """Backup /etc/resolv.conf before hijacking."""
    resolv = Path("/etc/resolv.conf")
    if not resolv.exists():
        return False
    import shutil
    shutil.copy2(resolv, RESOLV_BACKUP_FILE)
    return True


def _dns_hijack_apply():
    """Hijack system DNS to point to Xray's dns inbound (127.0.0.1:53)."""
    _dns_hijack_backup()
    with open("/etc/resolv.conf", "w") as f:
        f.write("# Xray DNS hijack (xray-manager transparent proxy)\n")
        f.write("nameserver 127.0.0.1\n")
        f.write("nameserver 119.29.29.29\n")
    return True


def _dns_hijack_restore():
    """Restore original /etc/resolv.conf from backup."""
    if not Path(RESOLV_BACKUP_FILE).exists():
        return False
    import shutil
    shutil.copy2(RESOLV_BACKUP_FILE, "/etc/resolv.conf")
    return True


def _dns_hijack_is_active():
    """Check if /etc/resolv.conf points to our hijack address."""
    try:
        with open("/etc/resolv.conf") as f:
            content = f.read()
        return "127.0.0.1" in content and "Xray DNS hijack" in content
    except Exception:
        return False


def _ensure_dns_inbound_in_config():
    """Ensure dokodemo-door transparent + dns inbound always exist in config.
    Does NOT touch iptables or DNS hijack — those are separate on/off switches.
    """
    cfg, err = _parse_config()
    if err:
        return

    changed = False
    inbounds = cfg.get("inbounds", [])
    outbounds = cfg.get("outbounds", [])
    routing = cfg.get("routing", {})
    rules = routing.get("rules", [])

    # Ensure transparent dokodemo-door inbound
    if not any(ib.get("tag") == "transparent" for ib in inbounds):
        inbounds.append({
            "tag": "transparent", "listen": "0.0.0.0", "port": 12345,
            "protocol": "dokodemo-door",
            "settings": {"network": "tcp,udp", "followRedirect": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"],
                         "domainsExcluded": ["argotunnel.com"]},
        })
        changed = True

    # Ensure dns dokodemo-door inbound
    if not any(ib.get("tag") == "dns" for ib in inbounds):
        inbounds.append({
            "tag": "dns", "listen": "0.0.0.0", "port": 53,
            "protocol": "dokodemo-door",
            "settings": {"address": "119.29.29.29", "port": 53, "network": "tcp,udp"},
        })
        changed = True

    # Ensure dns-out outbound
    if not any(ob.get("tag") == "dns-out" for ob in outbounds):
        outbounds.append({
            "tag": "dns-out", "protocol": "dns",
            "settings": {"port": 53, "address": "119.29.29.29", "network": "udp"},
            "streamSettings": {"sockopt": {"mark": 128}},
        })
        changed = True

    # Ensure dns routing rule
    if not any(r.get("inboundTag") == ["dns"] for r in rules):
        rules.append({"type": "field", "inboundTag": ["dns"], "outboundTag": "direct"})
        changed = True

    if changed:
        cfg["inbounds"] = inbounds
        cfg["outbounds"] = outbounds
        routing["rules"] = rules
        _save_config_object(cfg)
        print("[dns-config] Added missing dokodemo/dns inbound to config")


def _iptables_setup_redirect(port, bypass_cidrs=None):
    ch = CHAIN_PREFIX
    if bypass_cidrs is None:
        bypass_cidrs = _tp_get_all_bypass_cidrs()
    setup = [
        f"iptables -t nat -N {ch}_OUT",
        f"iptables -t nat -N {ch}_PRE",
        f"iptables -t nat -N {ch}_RULE",
    ]
    for cidr in bypass_cidrs:
        setup.append(f"iptables -t nat -A {ch}_RULE -d {cidr} -j RETURN")
    setup.append(f"iptables -t nat -A {ch}_RULE -m mark --mark 0x80/0x80 -j RETURN")
    setup.append(f"iptables -t nat -A {ch}_RULE -p tcp -j REDIRECT --to-ports {port}")
    setup.append(f"iptables -t nat -A {ch}_RULE -p udp --dport 53 -j REDIRECT --to-ports {port}")
    setup.append(f"iptables -t nat -I PREROUTING -p tcp -j {ch}_PRE")
    setup.append(f"iptables -t nat -I PREROUTING -p udp --dport 53 -j {ch}_PRE")
    setup.append(f"iptables -t nat -I OUTPUT -p tcp -j {ch}_OUT")
    setup.append(f"iptables -t nat -A {ch}_PRE -j {ch}_RULE")
    setup.append(f"iptables -t nat -A {ch}_OUT -j {ch}_RULE")
    # LAN gateway support: FORWARD + MASQUERADE
    setup.append("iptables -C FORWARD -j ACCEPT 2>/dev/null || iptables -I FORWARD -j ACCEPT")
    # Auto-detect local subnets for MASQUERADE
    import subprocess as _sp
    try:
        _out = _sp.check_output(["ip", "-4", "-o", "addr", "show"], text=True, timeout=5)
        _seen = set()
        for _line in _out.splitlines():
            parts = _line.split()
            if len(parts) >= 4 and "/" in parts[3]:
                _cidr = parts[3]
                _net = _cidr.split("/")[0]
                # Skip loopback and docker subnets
                if _net.startswith("127.") or _net.startswith("172."):
                    continue
                if _cidr not in _seen:
                    _seen.add(_cidr)
                    setup.append(f"iptables -t nat -C POSTROUTING -s {_cidr} ! -o lo -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {_cidr} ! -o lo -j MASQUERADE")
    except Exception:
        # Fallback: broad LAN range
        setup.append("iptables -t nat -C POSTROUTING -s 192.168.0.0/16 ! -o lo -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 192.168.0.0/16 ! -o lo -j MASQUERADE")
    for cmd in setup:
        out, err, rc = _run(cmd, timeout=5)
        if rc != 0:
            _iptables_cleanup()
            return False, f"failed: {cmd}\n{err}"
    return True, "ok"


def _tp_add_dokodemo_to_config(port, balancer_cfg=None):
    cfg, err = _parse_config()
    if err:
        return None, err

    # -- Inbound: transparent dokodemo-door --
    has_tp = any(ib.get("tag") == "transparent" for ib in cfg.get("inbounds", []))
    if not has_tp:
        dokodemo = {
            "tag": "transparent", "listen": "0.0.0.0", "port": port,
            "protocol": "dokodemo-door",
            "settings": {"network": "tcp,udp", "followRedirect": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"],
                         "domainsExcluded": ["argotunnel.com"]},
        }
        cfg.setdefault("inbounds", []).append(dokodemo)

    # -- Inbound: DNS (port 53) --
    has_dns_ib = any(ib.get("tag") == "dns" for ib in cfg.get("inbounds", []))
    if not has_dns_ib:
        dns_ib = {
            "tag": "dns", "listen": "0.0.0.0", "port": 53,
            "protocol": "dokodemo-door",
            "settings": {"address": "119.29.29.29", "port": 53, "network": "tcp,udp"},
        }
        cfg["inbounds"].append(dns_ib)

    # -- Outbound: dns-out --
    outbounds = cfg.get("outbounds", [])
    has_dns_ob = any(ob.get("tag") == "dns-out" for ob in outbounds)
    if not has_dns_ob:
        dns_ob = {
            "tag": "dns-out", "protocol": "dns",
            "settings": {"port": 53, "address": "119.29.29.29", "network": "udp"},
            "streamSettings": {"sockopt": {"mark": 128}},
        }
        outbounds.append(dns_ob)

    # -- sockopt.mark: 128 on all proxy outbounds + direct --
    for ob in outbounds:
        tag = ob.get("tag", "")
        proto = ob.get("protocol", "")
        if proto in ("freedom", "blackhole", "dns"):
            # direct/dns-out also need mark for anti-loop
            if proto == "freedom" or proto == "dns":
                ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["mark"] = 128
                if proto == "freedom":
                    ob.setdefault("settings", {})["domainStrategy"] = "UseIP"
            continue
        ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["mark"] = 128

    # -- Routing rules --
    rules = cfg.get("routing", {}).get("rules", [])

    # Build geoip bypass rules (insert at top, highest priority)
    geo_rules = []
    has_geoip_cn = any("geoip:cn" in json.dumps(r) for r in rules)
    has_geosite_cn = any("geosite:cn" in json.dumps(r) for r in rules)
    has_geoip_private = any("geoip:private" in json.dumps(r) for r in rules)
    has_udp_direct = any(r.get("network") == "udp" and r.get("outboundTag") == "direct" for r in rules)

    if not has_geoip_cn:
        geo_rules.append({"type": "field", "ip": ["geoip:cn"], "outboundTag": "direct"})
    if not has_geosite_cn:
        geo_rules.append({"type": "field", "domain": ["geosite:cn"], "outboundTag": "direct"})
    if not has_geoip_private:
        geo_rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"})
    if not has_udp_direct:
        geo_rules.append({"type": "field", "network": "udp", "outboundTag": "direct"})

    # DNS routing rules
    dns_rules = []
    has_dns_rule = any(r.get("inboundTag") == ["dns"] for r in rules)
    if not has_dns_rule:
        dns_rules.append({"type": "field", "inboundTag": ["dns"], "outboundTag": "direct"})

    # Transparent proxy routing rule
    default_tag = None
    for ob in outbounds:
        if ob.get("protocol") not in ("freedom", "blackhole", "dns"):
            default_tag = ob.get("tag")
            break
    if not default_tag:
        return None, "no proxy outbound found"

    has_tp_rule = any(r.get("inboundTag") == ["transparent"] for r in rules)
    if not has_tp_rule:
        if balancer_cfg and balancer_cfg.get("enabled") and balancer_cfg.get("tags"):
            # Use balancer instead of fixed outbound
            bal_tag = "proxy-balancer"
            strategy_map = {
                "roundRobin": {"type": "roundRobin"},
                "leastPing": {"type": "leastPing"},
                "random": {"type": "random"},
            }
            strategy = strategy_map.get(balancer_cfg.get("strategy", "roundRobin"), {"type": "roundRobin"})
            balancer = {
                "tag": bal_tag,
                "selector": balancer_cfg["tags"],
                "strategy": strategy,
            }
            # Remove existing balancer with same tag, then add
            balancers = cfg.get("routing", {}).get("balancers", [])
            balancers = [b for b in balancers if b.get("tag") != bal_tag]
            balancers.append(balancer)
            cfg.setdefault("routing", {})["balancers"] = balancers
            rules.insert(0, {"type": "field", "inboundTag": ["transparent"], "balancerTag": bal_tag})
        else:
            rules.insert(0, {"type": "field", "inboundTag": ["transparent"], "outboundTag": default_tag})

    # Insert geo + dns rules at the beginning
    cfg["routing"]["rules"] = geo_rules + dns_rules + rules

    # -- DNS config --
    cfg.setdefault("dns", {})
    default_servers = [
        "119.29.29.29",
        "223.5.5.5",
        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query",
        "https://cloudflare-dns.com/dns-query",
    ]
    default_hosts = {
        "domain:googleapis.cn": "googleapis.com",
        "geosite:category-ads-all": "127.0.0.1",
        "domain:evil.com": "127.0.0.1",
    }
    if not cfg["dns"].get("servers"):
        cfg["dns"]["servers"] = default_servers
    if not cfg["dns"].get("hosts"):
        cfg["dns"]["hosts"] = default_hosts

    return cfg, None


def _tp_remove_dokodemo_from_config():
    cfg, err = _parse_config()
    if err:
        return None, err
    # Remove transparent + dns inbounds
    cfg["inbounds"] = [ib for ib in cfg.get("inbounds", []) if ib.get("tag") not in ("transparent", "dns")]
    # Remove dns-out outbound
    cfg["outbounds"] = [ob for ob in cfg.get("outbounds", []) if ob.get("tag") != "dns-out"]
    # Remove routing rules: transparent, dns, geoip, geosite, udp-direct
    rules = cfg.get("routing", {}).get("rules", [])
    def _is_tp_added(r):
        # Remove rules added by transparent proxy enable
        if r.get("inboundTag") == ["transparent"]:
            return True
        if r.get("inboundTag") == ["dns"]:
            return True
        dump = json.dumps(r)
        if "geoip:cn" in dump or "geosite:cn" in dump or "geoip:private" in dump:
            return True
        if r.get("network") == "udp" and r.get("outboundTag") == "direct":
            return True
        return False
    cfg["routing"]["rules"] = [r for r in rules if not _is_tp_added(r)]
    # Remove balancers added by transparent proxy
    cfg["routing"]["balancers"] = [b for b in cfg.get("routing", {}).get("balancers", []) if b.get("tag") != "proxy-balancer"]
    # Remove sockopt.mark and domainStrategy from outbounds
    for ob in cfg.get("outbounds", []):
        sockopt = ob.get("streamSettings", {}).get("sockopt", {})
        sockopt.pop("mark", None)
        if not sockopt and "sockopt" in ob.get("streamSettings", {}):
            ob["streamSettings"].pop("sockopt", None)
        # Remove UseIP domainStrategy added for direct
        if ob.get("protocol") == "freedom":
            settings = ob.get("settings", {})
            if settings.get("domainStrategy") == "UseIP":
                settings.pop("domainStrategy", None)
    # Remove dns config added by transparent proxy
    dns = cfg.get("dns", {})
    default_servers = [
        "119.29.29.29",
        "223.5.5.5",
        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query",
        "https://cloudflare-dns.com/dns-query",
    ]
    default_hosts = {
        "domain:googleapis.cn": "googleapis.com",
        "geosite:category-ads-all": "127.0.0.1",
        "domain:evil.com": "127.0.0.1",
    }
    if dns.get("servers") == default_servers and (not dns.get("hosts") or dns.get("hosts") == default_hosts):
        cfg.pop("dns", None)
    return cfg, None


def _has_systemd():
    """Check if systemd/systemctl is available."""
    _, _, rc = _run("command -v systemctl")
    return rc == 0


def _has_supervisord():
    """Check if supervisord/supervisorctl is available."""
    _, _, rc = _run("command -v supervisorctl")
    return rc == 0


def _service_status():
    """Get service status info."""
    info = {"name": SVC_NAME, "running": False}

    if _has_systemd():
        out, _, rc = _run(f"systemctl is-active {SVC_NAME}")
        info["active"] = out.strip()
        info["running"] = out.strip() == "active"
        out, _, _ = _run(f"systemctl show {SVC_NAME} --property=ActiveEnterTimestamp --value")
        info["started_at"] = out.strip()
        out, _, _ = _run(f"systemctl show {SVC_NAME} --property=MainPID --value")
        info["pid"] = out.strip()
        out, _, _ = _run(f"systemctl show {SVC_NAME} --property=MemoryCurrent --value")
        mem = out.strip()
        try:
            info["memory"] = f"{int(mem) / 1024 / 1024:.1f} MB" if mem and mem != "[not set]" else "N/A"
        except ValueError:
            info["memory"] = mem
    elif _has_supervisord():
        out, _, rc = _run("supervisorctl status xray-all:xray 2>/dev/null")
        info["active"] = "active" if "RUNNING" in out else "inactive"
        info["running"] = "RUNNING" in out
        # Parse: "xray-all:xray  RUNNING  pid 8, uptime 0:12:34"
        import re as _re
        pid_m = _re.search(r"pid (\d+)", out)
        uptime_m = _re.search(r"uptime (.+?)(?:,|$)", out)
        info["pid"] = pid_m.group(1) if pid_m else ""
        info["started_at"] = uptime_m.group(1).strip() if uptime_m else ""
        # Memory from /proc
        if info["pid"]:
            try:
                with open(f"/proc/{info['pid']}/status") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            mem_kb = int(line.split()[1])
                            info["memory"] = f"{mem_kb / 1024:.1f} MB"
                            break
                if "memory" not in info:
                    info["memory"] = "N/A"
            except Exception:
                info["memory"] = "N/A"
        else:
            info["memory"] = "N/A"
    else:
        # Try checking if xray process is running
        out, _, rc = _run("pgrep -x xray")
        info["active"] = "active" if rc == 0 else "inactive"
        info["running"] = rc == 0
        info["started_at"] = ""
        info["pid"] = out.strip().split("\n")[0] if out.strip() else ""
        info["memory"] = "N/A"

    # listen ports via ss
    out, _, _ = _run("ss -lntp")
    ports = []
    for line in out.splitlines():
        if "xray" in line.lower():
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3]
                ports.append(addr)
    info["listen"] = ports
    return info


def _read_config():
    """Read Xray config file."""
    try:
        with open(XRAY_CFG, "r") as f:
            return f.read(), None
    except Exception as e:
        return "", str(e)


def _parse_config():
    """Parse Xray config as JSON."""
    raw, err = _read_config()
    if err:
        return None, err
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as e:
        return None, str(e)


def _test_config():
    """Run xray -test on current config."""
    out, err, rc = _run(f"{XRAY_BIN} run -test -config {XRAY_CFG}")
    combined = (out + err).strip()
    ok = "Configuration OK" in combined
    return {"ok": ok, "output": combined, "exit_code": rc}


def _xray_version():
    out, _, _ = _run(f"{XRAY_BIN} version")
    return out.strip().split("\n")[0] if out.strip() else "unknown"


def _backup_config():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = f"{BASE_DIR}/backup"
    Path(backup_dir).mkdir(parents=True, exist_ok=True)
    backup = f"{backup_dir}/config-{ts}.json.bak"
    try:
        raw, _ = _read_config()
        with open(backup, "w") as f:
            f.write(raw)
        return backup
    except Exception:
        return ""


def _save_config_object(cfg):
    backup = _backup_config()
    with open(XRAY_CFG, "w") as f:
        f.write(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")
    test = _test_config()
    if not test["ok"] and backup:
        try:
            with open(backup, "r") as f:
                old = f.read()
            with open(XRAY_CFG, "w") as f:
                f.write(old)
        except Exception:
            pass
    return backup, test


def _restart_xray():
    """Restart Xray service, return restart result."""
    if _has_systemd():
        _run(f"systemctl --no-block restart {SVC_NAME}")
        time.sleep(1.5)
        out, _, rc = _run(f"systemctl is-active {SVC_NAME}")
        return {"active": out.strip(), "success": out.strip() == "active"}
    elif _has_supervisord():
        _run("supervisorctl restart xray-all:xray")
        time.sleep(1.5)
        out, _, _ = _run("supervisorctl status xray-all:xray")
        active = "active" if "RUNNING" in out else "inactive"
        return {"active": active, "success": "RUNNING" in out}
    else:
        return {"active": "unknown", "success": False}


def _bool_param(qs, *names, default=False):
    for name in names:
        if name in qs:
            v = qs[name][0].lower()
            return v in ("1", "true", "yes")
    return default


def _apply_stream_settings(outbound, qs, address, default_network="tcp"):
    """Apply common stream/transport settings (tls, ws, grpc, etc.) from query params."""
    network = qs.get("type", qs.get("network", [default_network]))[0] or default_network
    security = qs.get("security", ["none"])[0] or "none"
    stream = {"network": network, "security": security}

    if security == "tls":
        tls = {
            "serverName": qs.get("sni", qs.get("serverName", [address]))[0],
            "allowInsecure": _bool_param(qs, "allowInsecure", "insecure", default=False),
        }
        fp = qs.get("fp", qs.get("fingerprint", [""]))[0]
        if fp:
            tls["fingerprint"] = fp
        alpn = qs.get("alpn", [""])[0]
        if alpn:
            tls["alpn"] = [x for x in alpn.split(",") if x]
        ech = qs.get("ech", [""])[0]
        if ech:
            tls["echConfigList"] = ech
            tls["echForceQuery"] = "full"
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality = {
            "serverName": qs.get("sni", [address])[0],
            "fingerprint": qs.get("fp", ["chrome"])[0],
            "publicKey": qs.get("pbk", [""])[0],
            "shortId": qs.get("sid", [""])[0],
            "spiderX": qs.get("spx", [""])[0],
        }
        stream["realitySettings"] = {k: v for k, v in reality.items() if v}

    if network == "ws":
        ws = {"path": qs.get("path", ["/"])[0]}
        host = qs.get("host", [""])[0]
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": qs.get("serviceName", [""])[0]}
    elif network == "xhttp":
        stream["xhttpSettings"] = {"path": qs.get("path", ["/"])[0]}

    outbound["streamSettings"] = stream


def _parse_vless_link(link):
    parsed = urlparse(link.strip())
    uuid = parsed.username
    if not uuid:
        raise ValueError("missing UUID in vless link")
    address = parsed.hostname
    port = parsed.port or 443
    qs = parse_qs(parsed.query)
    tag = unquote(parsed.fragment or "") or f"vless-{address}-{port}"

    outbound = {
        "tag": tag, "protocol": "vless",
        "settings": {"vnext": [{"address": address, "port": port, "users": [{"id": uuid, "encryption": qs.get("encryption", ["none"])[0] or "none"}]}]},
    }
    flow = qs.get("flow", [""])[0]
    if flow:
        outbound["settings"]["vnext"][0]["users"][0]["flow"] = flow
    _apply_stream_settings(outbound, qs, address)
    return outbound


def _parse_vmess_link(link):
    """Parse vmess:// link (base64 JSON format)."""
    b64 = link.strip()
    if b64.startswith("vmess://"):
        b64 = b64[8:]
    # Add padding if needed
    b64 += "=" * (-len(b64) % 4)
    try:
        data = json.loads(base64.b64decode(b64).decode("utf-8"))
    except Exception as e:
        raise ValueError(f"invalid vmess base64: {e}")

    address = data.get("add", "")
    port = int(data.get("port", 443))
    uuid = data.get("id", "")
    aid = int(data.get("aid", 0))
    tag = data.get("ps", "") or f"vmess-{address}-{port}"
    net = data.get("net", "tcp") or "tcp"
    if net == "tcp" and data.get("type") == "http":
        net = "raw"  # raw with http header type

    outbound = {
        "tag": tag, "protocol": "vmess",
        "settings": {"vnext": [{"address": address, "port": port, "users": [{"id": uuid, "alterId": aid, "security": data.get("scy", "auto") or "auto"}]}]},
    }

    stream = {"network": net, "security": data.get("tls", "") or ""}
    if stream["security"] == "tls":
        tls = {"serverName": data.get("sni", address)}
        fp = data.get("fp", "")
        if fp:
            tls["fingerprint"] = fp
        alpn = data.get("alpn", "")
        if alpn:
            tls["alpn"] = [x for x in str(alpn).split(",") if x]
        insecure = data.get("insecure", "0")
        if str(insecure) in ("1", "true"):
            tls["allowInsecure"] = True
        stream["tlsSettings"] = tls

    if net == "ws":
        ws = {"path": data.get("path", "/") or "/"}
        host = data.get("host", "")
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": data.get("path", "") or ""}
    elif net == "h2" or net == "http":
        http = {"path": data.get("path", "/") or "/"}
        host = data.get("host", "")
        if host:
            http["host"] = [host]
        stream["httpSettings"] = http

    outbound["streamSettings"] = stream
    return outbound


def _parse_ss_link(link):
    """Parse ss:// link (SIP002 and legacy formats, with v2ray-plugin support)."""
    raw = link.strip()
    if raw.startswith("ss://"):
        raw = raw[5:]

    parsed = urlparse(link.strip()) if link.strip().startswith("ss://") else None
    if not parsed:
        raise ValueError("invalid ss:// link")

    tag = unquote(parsed.fragment or "") or f"ss-{parsed.hostname}-{parsed.port}"

    # Decode userinfo: either base64(method:password) or method:password
    userinfo = parsed.username or ""
    if ":" not in userinfo:
        # Base64 encoded (standard or URL-safe)
        padded = userinfo + "=" * (-len(userinfo) % 4)
        decoded = None
        for decoder in (_b64.b64decode, _b64.urlsafe_b64decode):
            try:
                decoded = decoder(padded).decode("utf-8")
                break
            except Exception:
                continue
        if not decoded or ":" not in decoded:
            raise ValueError("cannot decode ss userinfo")
        method, password = decoded.split(":", 1)
    else:
        method = unquote(userinfo)
        password = unquote(parsed.password or "")
        if ":" in method:
            parts = method.split(":", 1)
            method = parts[0]
            password = parts[1]

    address = parsed.hostname
    port = parsed.port or 443
    # Parse plugin separately - it may contain unescaped & in path values
    raw_query = parsed.query
    plugin_str = ""
    qs = {}
    # Extract plugin=... first (it may span until next known param or end)
    plugin_match = re.search(r'(?:^|&)plugin=([^&]*(?:%26[^&]*)*)', raw_query, re.IGNORECASE)
    if plugin_match:
        plugin_str = unquote(plugin_match.group(1))
        remaining = raw_query[:plugin_match.start()] + raw_query[plugin_match.end():]
        qs = parse_qs(remaining)
    else:
        qs = parse_qs(raw_query)

    outbound = {
        "tag": tag, "protocol": "shadowsocks",
        "settings": {"servers": [{"address": address, "port": port, "method": method, "password": password}]},
    }

    # Parse plugin (v2ray-plugin / obfs-local)
    if plugin_str:
        parts = plugin_str.split(";")
        plugin_name = parts[0]
        plugin_args = {k: v for k, v in (p.split("=", 1) if "=" in p else (p, "") for p in parts[1:]) if k}

        if plugin_name == "v2ray-plugin":
            mode = plugin_args.get("mode", "websocket")
            if mode == "websocket":
                ws = {}
                host = plugin_args.get("host", "")
                path = plugin_args.get("path", "/")
                # Unescape v2ray-plugin escapes: \= -> =, \, -> , , \\ -> \
                path = path.replace("\\=", "=").replace("\\,", ",").replace("\\\\", "\\")
                if host:
                    ws["headers"] = {"Host": host}
                ws["path"] = path
                stream = {"network": "ws", "wsSettings": ws}
                if "tls" in plugin_args:
                    stream["security"] = "tls"
                    tls = {"serverName": host or address}
                    stream["tlsSettings"] = tls
                outbound["streamSettings"] = stream
        elif plugin_name in ("obfs-local", "simple-obfs"):
            obfs = plugin_args.get("obfs", "")
            obfs_host = plugin_args.get("obfs-host", "")
            if obfs == "http" and obfs_host:
                outbound["streamSettings"] = {
                    "network": "raw",
                    "tcpSettings": {"header": {"type": "http", "request": {"headers": {"Host": [obfs_host]}}}},
                }

    return outbound


def _parse_trojan_link(link):
    """Parse trojan:// link."""
    parsed = urlparse(link.strip())
    password = unquote(parsed.username or "")
    if not password:
        raise ValueError("missing password in trojan link")
    address = parsed.hostname
    port = parsed.port or 443
    qs = parse_qs(parsed.query)
    tag = unquote(parsed.fragment or "") or f"trojan-{address}-{port}"

    outbound = {
        "tag": tag, "protocol": "trojan",
        "settings": {"servers": [{"address": address, "port": port, "password": password}]},
    }

    _apply_stream_settings(outbound, qs, address, default_network="tcp")
    # Trojan usually implies TLS
    if "security" not in outbound.get("streamSettings", {}):
        outbound.setdefault("streamSettings", {})["security"] = "tls"
        outbound["streamSettings"].setdefault("tlsSettings", {"serverName": address})
    return outbound


def _parse_share_link(link):
    """Unified parser: detect protocol and dispatch to the right parser."""
    link = link.strip()
    if link.startswith("vless://"):
        return _parse_vless_link(link)
    elif link.startswith("vmess://"):
        return _parse_vmess_link(link)
    elif link.startswith("ss://"):
        return _parse_ss_link(link)
    elif link.startswith("trojan://"):
        return _parse_trojan_link(link)
    else:
        raise ValueError(f"unsupported protocol: {link.split('://')[0]}:// (supported: vless, vmess, ss, trojan)")


# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------

@app.before_request
def _check_auth():
    if not AUTH_TOKEN:
        return
    if request.path == "/":
        return  # let HTML through, JS handles auth
    token = request.headers.get("X-Token") or request.args.get("token")
    if token != AUTH_TOKEN:
        return jsonify({"error": "unauthorized"}), 401


@app.route("/api/token", methods=["POST"])
def api_change_token():
    """Change auth token at runtime."""
    global AUTH_TOKEN
    data = request.json or {}
    old = data.get("old", "")
    new = data.get("new", "")
    confirm = data.get("confirm", "")
    if old != AUTH_TOKEN:
        return jsonify({"error": "当前 Token 不正确"}), 400
    if not new or len(new) < 4:
        return jsonify({"error": "新 Token 至少 4 位"}), 400
    if new != confirm:
        return jsonify({"error": "两次输入不一致"}), 400
    AUTH_TOKEN = new
    Path(TOKEN_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(TOKEN_FILE, "w") as f:
        f.write(new)
    return jsonify({"ok": True, "message": "Token 已修改，请重新登录"})


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.route("/api/status")
def api_status():
    info = _service_status()
    info["xray_version"] = _xray_version()
    info["config_path"] = XRAY_CFG
    info["binary_path"] = XRAY_BIN
    # Connect-mode state
    conn = _connect_state_read()
    info["connect_mode"] = {
        "active": conn.get("active", False),
        "selected_tags": conn.get("selected_tags", []),
        "strategy": conn.get("balancer_strategy", "roundRobin"),
        "transparent": conn.get("transparent_enabled", False),
    }
    # Transparent proxy actual state
    info["transparent"] = {
        "enabled": _tp_state_read().get("enabled", False),
        "has_iptables": _tp_has_iptables_rules(),
        "has_dokodemo": _tp_has_dokodemo_inbound(),
    }
    return jsonify(info)


@app.route("/api/dns")
def api_dns_get():
    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"dns": cfg.get("dns", {"servers": []})})


@app.route("/api/dns", methods=["POST"])
def api_dns_post():
    data = request.json or {}
    dns = data.get("dns")
    if not isinstance(dns, dict):
        return jsonify({"error": "dns must be an object"}), 400
    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500
    cfg["dns"] = dns
    backup, test = _save_config_object(cfg)
    if not test["ok"]:
        return jsonify({"error": "config test failed, rolled back", "detail": test["output"]}), 400
    restart = _restart_xray() if test["ok"] else {}
    return jsonify({"ok": True, "backup": backup, "test": test, "restart": restart})


@app.route("/api/dns/hosts")
def api_dns_hosts_get():
    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500
    hosts = cfg.get("dns", {}).get("hosts", {})
    # Convert to simple format: "domain IP" lines
    lines = []
    for domain, ip in hosts.items():
        if isinstance(ip, list):
            for i in ip:
                lines.append(f"{domain} {i}")
        else:
            lines.append(f"{domain} {ip}")
    return jsonify({"hosts": hosts, "text": "\n".join(lines)})


@app.route("/api/dns/hosts", methods=["POST"])
def api_dns_hosts_post():
    data = request.json or {}
    text = data.get("text", "").strip()
    hosts = {}
    if text:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                domain, ip = parts[0], parts[1]
                if domain in hosts:
                    existing = hosts[domain]
                    if isinstance(existing, list):
                        existing.append(ip)
                    else:
                        hosts[domain] = [existing, ip]
                else:
                    hosts[domain] = ip
    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500
    cfg.setdefault("dns", {})
    cfg["dns"]["hosts"] = hosts
    backup, test = _save_config_object(cfg)
    if not test["ok"]:
        return jsonify({"error": "config test failed, rolled back", "detail": test["output"]}), 400
    restart = _restart_xray() if test["ok"] else {}
    return jsonify({"ok": True, "hosts": hosts, "backup": backup, "test": test, "restart": restart})


@app.route("/api/geo/update", methods=["POST"])
def api_geo_update():
    """Download latest geoip.dat and geosite from configured URLs."""
    _init_dirs()
    urls = _load_geo_urls()
    results = {}
    geo_files = [
        {"name": "geoip.dat", "url": urls.get("geoip", DEFAULT_GEO_URLS["geoip"]), "path": GEOIP_PATH},
        {"name": "geosite.dat", "url": urls.get("geosite", DEFAULT_GEO_URLS["geosite"]), "path": GEOSITE_PATH},
    ]
    for gf in geo_files:
        try:
            tmp_path = gf["path"] + ".tmp"
            urllib.request.urlretrieve(gf["url"], tmp_path)
            # Verify it's a valid file (not empty)
            if os.path.getsize(tmp_path) < 100:
                os.remove(tmp_path)
                results[gf["name"]] = {"ok": False, "error": "downloaded file too small, CDN may be down"}
                continue
            os.replace(tmp_path, gf["path"])
            # Symlink to bin/
            link_path = f"{BASE_DIR}/bin/{gf['name']}"
            if os.path.islink(link_path) or os.path.exists(link_path):
                os.remove(link_path)
            os.symlink(gf["path"], link_path)
            stat = os.stat(gf["path"])
            results[gf["name"]] = {
                "ok": True,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
        except Exception as e:
            results[gf["name"]] = {"ok": False, "error": str(e)}
    return jsonify({"ok": all(r.get("ok") for r in results.values()), "results": results})


@app.route("/api/geo/info")
def api_geo_info():
    """Return current geoip/geosite file info and URLs."""
    urls = _load_geo_urls()
    info = {"urls": urls}
    for name, path in [("geoip.dat", GEOIP_PATH), ("geosite.dat", GEOSITE_PATH)]:
        if os.path.exists(path):
            stat = os.stat(path)
            info[name] = {
                "exists": True,
                "size": stat.st_size,
                "size_human": _human_size(stat.st_size),
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
        else:
            info[name] = {"exists": False, "size": 0, "size_human": "N/A", "modified": "N/A"}
    return jsonify(info)


@app.route("/api/geo/urls", methods=["POST"])
def api_geo_urls():
    """Save configurable geo URLs."""
    data = request.json or {}
    urls = _load_geo_urls()
    if "geoip" in data:
        urls["geoip"] = data["geoip"].strip()
    if "geosite" in data:
        urls["geosite"] = data["geosite"].strip()
    _save_geo_urls(urls)
    return jsonify({"ok": True, "urls": urls})


def _human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


@app.route("/api/config")
def api_config_get():
    raw, err = _read_config()
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"config": raw})


@app.route("/api/config", methods=["POST"])
def api_config_post():
    data = request.json
    if not data or "config" not in data:
        return jsonify({"error": "missing 'config' field"}), 400

    new_config = data["config"]
    # validate JSON
    try:
        json.loads(new_config)
    except json.JSONDecodeError as e:
        return jsonify({"error": f"invalid JSON: {e}"}), 400

    _backup_config()

    # write
    with open(XRAY_CFG, "w") as f:
        f.write(new_config)

    # test
    test = _test_config()
    if not test["ok"]:
        # rollback
        try:
            with open(backup, "r") as f:
                with open(XRAY_CFG, "w") as f2:
                    f2.write(f.read())
        except Exception:
            pass
        return jsonify({"error": "config test failed, rolled back", "detail": test["output"]}), 400

    restart = _restart_xray() if test["ok"] else {}
    return jsonify({"ok": True, "backup": backup, "test": test, "restart": restart})


@app.route("/api/config/test")
def api_config_test():
    return jsonify(_test_config())


@app.route("/api/inbounds")
def api_inbounds():
    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"inbounds": cfg.get("inbounds", []), "routing": cfg.get("routing", {})})


@app.route("/api/inbounds", methods=["POST"])
def api_inbounds_post():
    """Update inbounds list in config."""
    data = request.json
    if not data or "inbounds" not in data:
        return jsonify({"error": "missing 'inbounds' field"}), 400

    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500

    cfg["inbounds"] = data["inbounds"]
    if "routing" in data and isinstance(data["routing"], dict):
        cfg["routing"] = data["routing"]
    new_raw = json.dumps(cfg, ensure_ascii=False, indent=2)

    _backup_config()

    with open(XRAY_CFG, "w") as f:
        f.write(new_raw + "\n")

    test = _test_config()
    if not test["ok"]:
        try:
            with open(backup, "r") as f:
                with open(XRAY_CFG, "w") as f2:
                    f2.write(f.read())
        except Exception:
            pass
        return jsonify({"error": "config test failed, rolled back", "detail": test["output"]}), 400

    restart = _restart_xray() if test["ok"] else {}
    return jsonify({"ok": True, "test": test, "restart": restart})


@app.route("/api/outbounds")
def api_outbounds():
    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"outbounds": cfg.get("outbounds", [])})


@app.route("/api/outbounds", methods=["POST"])
def api_outbounds_post():
    data = request.json
    if not data or "outbounds" not in data:
        return jsonify({"error": "missing 'outbounds' field"}), 400
    if not isinstance(data["outbounds"], list):
        return jsonify({"error": "outbounds must be a list"}), 400

    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500
    cfg["outbounds"] = data["outbounds"]
    # If transparent proxy is enabled, ensure all outbounds have mark:128
    state = _tp_state_read()
    if state.get("enabled"):
        for ob in cfg["outbounds"]:
            ss = ob.setdefault("streamSettings", {})
            so = ss.setdefault("sockopt", {})
            if "mark" not in so:
                so["mark"] = 128
    backup, test = _save_config_object(cfg)
    if not test["ok"]:
        return jsonify({"error": "config test failed, rolled back", "detail": test["output"]}), 400
    restart = _restart_xray() if test["ok"] else {}
    return jsonify({"ok": True, "backup": backup, "test": test, "restart": restart})


@app.route("/api/outbounds/parse-vless", methods=["POST"])
def api_outbounds_parse_vless():
    data = request.json
    link = (data or {}).get("link", "")
    tfo = (data or {}).get("tfo", False)
    try:
        outbound = _parse_share_link(link)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    if tfo:
        outbound.setdefault("streamSettings", {}).setdefault("sockopt", {})["tcpFastOpen"] = True
    return jsonify({"outbound": outbound, "protocol": outbound.get("protocol",""), "json": json.dumps(outbound, ensure_ascii=False, indent=2)})


@app.route("/api/routing")
def api_routing():
    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"routing": cfg.get("routing", {})})


@app.route("/api/routing", methods=["POST"])
def api_routing_post():
    data = request.json
    if not data or "routing" not in data:
        return jsonify({"error": "missing 'routing' field"}), 400

    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500

    cfg["routing"] = data["routing"]
    new_raw = json.dumps(cfg, ensure_ascii=False, indent=2)

    _backup_config()

    with open(XRAY_CFG, "w") as f:
        f.write(new_raw + "\n")

    test = _test_config()
    if not test["ok"]:
        try:
            with open(backup, "r") as f:
                with open(XRAY_CFG, "w") as f2:
                    f2.write(f.read())
        except Exception:
            pass
        return jsonify({"error": "config test failed, rolled back", "detail": test["output"]}), 400

    restart = _restart_xray() if test["ok"] else {}
    return jsonify({"ok": True, "test": test, "restart": restart})


@app.route("/api/test-urls")
def api_test_urls_get():
    return jsonify({"urls": _load_test_urls(), "defaults": DEFAULT_TEST_URLS})


@app.route("/api/test-urls", methods=["POST"])
def api_test_urls_post():
    data = request.json or {}
    urls = data.get("urls")
    if not isinstance(urls, list):
        return jsonify({"error": "urls must be a list"}), 400
    clean = _save_test_urls(urls)
    return jsonify({"ok": True, "urls": clean})


@app.route("/api/inbounds/test", methods=["POST"])
def api_inbounds_test():
    data = request.json or {}
    tag = data.get("tag")
    url = (data.get("url") or DEFAULT_TEST_URLS[0]).strip()
    listen = data.get("listen")
    port = data.get("port")

    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500

    inbound = None
    if tag:
        for ib in cfg.get("inbounds", []):
            if ib.get("tag") == tag:
                inbound = ib
                break
    if inbound:
        listen = inbound.get("listen", listen or "127.0.0.1")
        port = inbound.get("port", port)
    if not listen or not port:
        return jsonify({"error": "missing inbound listen/port or valid tag"}), 400
    if not (url.startswith("http://") or url.startswith("https://")):
        return jsonify({"error": "test url must start with http:// or https://"}), 400

    # Auto-detect protocol
    protocol = (inbound or {}).get("protocol", "socks").lower()
    if protocol == "http":
        result = _curl_via_http(str(listen), int(port), url)
    else:
        result = _curl_via_socks(str(listen), int(port), url)
    result["tag"] = tag or (inbound or {}).get("tag", "")
    result["proxy"] = f"{protocol}://{listen}:{port}"
    return jsonify(result)


@app.route("/api/outbounds/test", methods=["POST"])
def api_outbounds_test():
    """Test an outbound by spinning up a temp Xray with a SOCKS port, curling through it."""
    data = request.json or {}
    outbound = data.get("outbound")
    tag = data.get("tag")
    url = (data.get("url") or DEFAULT_TEST_URLS[0]).strip()
    test_type = data.get("type", "ping")  # "ping" or "speed"

    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500

    if not outbound and tag:
        for ob in cfg.get("outbounds", []):
            if ob.get("tag") == tag:
                outbound = ob
                break
    if not outbound:
        return jsonify({"error": "missing outbound or valid tag"}), 400
    if not (url.startswith("http://") or url.startswith("https://")):
        return jsonify({"error": "test url must start with http:// or https://"}), 400

    temp_cfg, port_map = _build_temp_multi_config([outbound], base_port=random.randint(30000, 45000))
    proc, tmp, error = _start_temp_xray(temp_cfg)
    if error:
        return jsonify({"ok": False, "tag": outbound.get("tag", ""), "error": "xray start failed", "detail": error})

    try:
        test_port = port_map[outbound.get("tag", "")]
        if test_type == "speed":
            result = _curl_speedtest("127.0.0.1", test_port, url, timeout=DEFAULT_SPEEDTEST_TIMEOUT)
        else:
            result = _curl_via_socks("127.0.0.1", test_port, url, timeout=20)
        result["tag"] = outbound.get("tag", "")
        result["outbound_addr"] = ""
        try:
            v = outbound.get("settings", {}).get("vnext", [{}])[0]
            result["outbound_addr"] = str(v.get("address", "?")) + ":" + str(v.get("port", "?"))
        except Exception:
            pass
        return jsonify(result)
    finally:
        _stop_temp_xray(proc, tmp)


@app.route("/api/outbounds/batch-test", methods=["POST"])
def api_outbounds_batch_test():
    """Batch test all outbounds: latency + optional speed. One temp Xray with all nodes."""
    data = request.json or {}
    tags = data.get("tags")  # list of tags, or None for all
    url = (data.get("url") or DEFAULT_TEST_URLS[0]).strip()
    speed_url = (data.get("speed_url") or DEFAULT_SPEEDTEST_URL).strip()
    mode = data.get("mode", "ping")  # "ping" or "speed"
    do_speed = mode == "speed"

    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500

    all_obs = [ob for ob in cfg.get("outbounds", []) if ob.get("protocol") not in ("freedom", "blackhole")]
    if tags:
        all_obs = [ob for ob in all_obs if ob.get("tag") in tags]
    if not all_obs:
        return jsonify({"error": "no outbounds to test"}), 400

    base_port = random.randint(30000, 40000)
    temp_cfg, port_map = _build_temp_multi_config(all_obs, base_port=base_port)
    proc, tmp, error = _start_temp_xray(temp_cfg)
    if error:
        return jsonify({"ok": False, "error": "xray start failed", "detail": error})

    results = []
    try:
        import concurrent.futures
        def test_one(ob):
            tag = ob.get("tag", "")
            port = port_map.get(tag)
            if not port:
                return {"tag": tag, "ok": False, "error": "port not found"}
            r = {"tag": tag}
            addr = ""
            try:
                v = ob.get("settings", {}).get("vnext", [{}])[0]
                addr = str(v.get("address", "?")) + ":" + str(v.get("port", "?"))
            except Exception:
                pass
            r["outbound_addr"] = addr
            # Latency test
            ping = _curl_via_socks("127.0.0.1", port, url, timeout=15)
            r["ping_ok"] = ping.get("ok", False)
            r["ping_ms"] = ping.get("time_total", "")
            r["ping_code"] = ping.get("http_code", "")
            r["exit_ip"] = ping.get("stdout", "").strip()
            # Speed test
            if do_speed and r["ping_ok"]:
                sp = _curl_speedtest("127.0.0.1", port, speed_url, timeout=DEFAULT_SPEEDTEST_TIMEOUT)
                r["speed_ok"] = sp.get("ok", False)
                r["speed_mbps"] = sp.get("speed_mbps", 0)
                r["speed_bytes"] = sp.get("bytes", 0)
                r["speed_time"] = sp.get("time_total", 0)
            else:
                r["speed_ok"] = False
                r["speed_mbps"] = 0
            return r

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(all_obs), 6)) as ex:
            futures = {ex.submit(test_one, ob): ob for ob in all_obs}
            for fut in concurrent.futures.as_completed(futures):
                results.append(fut.result())
    finally:
        _stop_temp_xray(proc, tmp)

    # Sort by original order
    tag_order = {ob.get("tag", ""): i for i, ob in enumerate(all_obs)}
    results.sort(key=lambda r: tag_order.get(r.get("tag", ""), 999))
    return jsonify({"ok": True, "count": len(results), "results": results})


@app.route("/api/transparent/bypass")
def api_transparent_bypass_get():
    return jsonify({
        "defaults": _BYPASS_CIDRS,
        "auto": _extract_dns_bypass_cidrs_from_config(),
        "custom": _tp_load_custom_bypass(),
        "all": _tp_get_all_bypass_cidrs(),
    })


@app.route("/api/transparent/bypass", methods=["POST"])
def api_transparent_bypass_post():
    data = request.json or {}
    cidrs = data.get("custom", [])
    if not isinstance(cidrs, list):
        return jsonify({"error": "custom must be a list of CIDR strings"}), 400
    saved = _tp_save_custom_bypass(cidrs)
    # If transparent proxy is currently active, rebuild iptables rules
    state = _tp_state_read()
    iptables_on = False
    out, _, rc = _run("iptables -t nat -L " + CHAIN_PREFIX + "_RULE -n 2>/dev/null")
    if rc == 0 and CHAIN_PREFIX in out:
        iptables_on = True
    if iptables_on:
        port = state.get("port", DEFAULT_TRANSPARENT_PORT)
        _iptables_cleanup()
        ok, msg = _iptables_setup_redirect(port)
        if not ok:
            return jsonify({"error": "iptables rebuild failed: " + msg, "custom": saved}), 400
    return jsonify({"ok": True, "custom": saved, "reloaded": iptables_on})


@app.route("/api/transparent/status")
def api_transparent_status():
    state = _tp_state_read()
    out, _, rc = _run("iptables -t nat -L " + CHAIN_PREFIX + "_RULE -n 2>/dev/null")
    state["iptables_active"] = rc == 0 and CHAIN_PREFIX in out
    state["port"] = state.get("port", DEFAULT_TRANSPARENT_PORT)
    return jsonify(state)


@app.route("/api/transparent/enable", methods=["POST"])
def api_transparent_enable():
    data = request.json or {}
    port = int(data.get("port", DEFAULT_TRANSPARENT_PORT))
    proxy_tag = data.get("proxy_tag")
    _iptables_cleanup()
    backed_up = _iptables_save()
    balancer_cfg = _balancer_read()
    cfg, err = _tp_add_dokodemo_to_config(port, balancer_cfg)
    if err:
        if backed_up:
            _iptables_restore()
        return jsonify({"error": str(err)}), 400
    if proxy_tag and not (balancer_cfg.get("enabled") and balancer_cfg.get("tags")):
        for r in cfg.get("routing", {}).get("rules", []):
            if r.get("inboundTag") == ["transparent"]:
                r["outboundTag"] = proxy_tag
                break
    backup, test = _save_config_object(cfg)
    if not test["ok"]:
        if backed_up:
            _iptables_restore()
        return jsonify({"error": "config test failed", "detail": test["output"]}), 400
    ok, msg = _iptables_setup_redirect(port)
    if not ok:
        if backed_up:
            _iptables_restore()
        _tp_remove_dokodemo_from_config()
        return jsonify({"error": msg}), 400
    restart = _restart_xray()
    _dns_hijack_apply()
    _tp_state_write({"enabled": True, "port": port, "proxy_tag": proxy_tag})
    return jsonify({"ok": True, "port": port, "restart": restart})


@app.route("/api/transparent/disable", methods=["POST"])
def api_transparent_disable():
    _iptables_cleanup()
    cfg, err = _tp_remove_dokodemo_from_config()
    if cfg:
        _save_config_object(cfg)
    restart = _restart_xray()
    _dns_hijack_restore()
    _tp_state_write({"enabled": False})
    return jsonify({"ok": True, "restart": restart})


@app.route("/api/transparent/restore-iptables", methods=["POST"])
def api_transparent_restore():
    _iptables_cleanup()
    ok = _iptables_restore()
    return jsonify({"ok": ok})


@app.route("/api/transparent/balancer", methods=["GET"])
def api_balancer_get():
    cfg = _balancer_read()
    # Also return list of available proxy outbounds for the UI
    parsed, err = _parse_config()
    outbounds = []
    if not err:
        for ob in parsed.get("outbounds", []):
            if ob.get("protocol") not in ("freedom", "blackhole", "dns"):
                outbounds.append(ob.get("tag"))
    cfg["available_tags"] = outbounds
    return jsonify(cfg)


@app.route("/api/transparent/balancer", methods=["POST"])
def api_balancer_set():
    data = request.json or {}
    enabled = bool(data.get("enabled", False))
    tags = data.get("tags", [])
    strategy = data.get("strategy", "roundRobin")
    if strategy not in ("roundRobin", "leastPing", "random"):
        return jsonify({"error": "invalid strategy"}), 400
    cfg = {"enabled": enabled, "tags": tags, "strategy": strategy}
    _balancer_write(cfg)
    # If transparent proxy is currently enabled, re-apply config with new balancer
    state = _tp_state_read()
    reloaded = False
    if state.get("enabled"):
        port = state.get("port", DEFAULT_TRANSPARENT_PORT)
        new_cfg, err = _tp_add_dokodemo_to_config(port, cfg)
        if not err and new_cfg:
            _save_config_object(new_cfg)
            _restart_xray()
            reloaded = True
    return jsonify({"ok": True, "config": cfg, "reloaded": reloaded})


# ---------------------------------------------------------------------------
# Connect Mode API
# ---------------------------------------------------------------------------

@app.route("/api/connect/status")
def api_connect_status():
    """Return current connect-mode state + node list, with state reconciliation."""
    state = _reconcile_connect_state()

    cfg, err = _parse_config()
    nodes = []
    if not err:
        for ob in cfg.get("outbounds", []):
            if ob.get("protocol") in ("freedom", "blackhole", "dns"):
                continue
            info = _extract_node_info(ob)
            info["selected"] = info["tag"] in state.get("selected_tags", [])
            nodes.append(info)
    state["nodes"] = nodes
    return jsonify(state)


@app.route("/api/connect/start", methods=["POST"])
def api_connect_start():
    """One-click start: apply selected nodes, routing, optional transparent proxy."""
    data = request.json or {}
    tags = data.get("tags", [])
    strategy = data.get("strategy", "roundRobin")
    transparent = bool(data.get("transparent", False))
    ports = data.get("ports", {"socks": 10810, "http": 10818, "transparent": 12345})

    if not tags:
        return jsonify({"error": "请至少选择一个节点"}), 400

    # Verify tags exist in outbounds
    cfg_check, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500
    existing = {ob.get("tag") for ob in cfg_check.get("outbounds", [])}
    invalid = [t for t in tags if t not in existing]
    if invalid:
        return jsonify({"error": f"节点不存在: {', '.join(invalid)}"}), 400

    if strategy not in ("roundRobin", "leastPing", "random"):
        strategy = "roundRobin"

    # Build config
    cfg, err = _build_connect_config(tags, strategy, transparent, ports)
    if err:
        return jsonify({"error": str(err)}), 400

    # Save original inbounds for restoration on stop
    original_inbounds = cfg_check.get("inbounds", [])

    # If transparent proxy requested, backup iptables first
    backed_up = False
    if transparent:
        _iptables_cleanup()
        backed_up = _iptables_save()

    # Save config
    backup, test = _save_config_object(cfg)
    if not test["ok"]:
        if backed_up:
            _iptables_restore()
        return jsonify({"error": "配置测试失败", "detail": test["output"]}), 400

    # Setup iptables if transparent
    if transparent:
        tp_port = ports.get("transparent", 12345)
        ok, msg = _iptables_setup_redirect(tp_port)
        if not ok:
            if backed_up:
                _iptables_restore()
            return jsonify({"error": f"iptables 设置失败: {msg}"}), 400

    # DNS hijack (always, independent of transparent proxy)
    _dns_hijack_apply()

    # Restart xray
    restart = _restart_xray()

    # Save state
    import datetime as _dt
    state = {
        "active": True,
        "selected_tags": tags,
        "balancer_strategy": strategy,
        "transparent_enabled": transparent,
        "started_at": _dt.datetime.now().isoformat(),
        "inbound_socks_port": ports.get("socks", 10810),
        "inbound_http_port": ports.get("http", 10818),
        "transparent_port": ports.get("transparent", 12345),
        "original_inbounds": original_inbounds,
    }
    _connect_state_write(state)

    return jsonify({"ok": True, "state": state, "restart": restart})


@app.route("/api/connect/stop", methods=["POST"])
def api_connect_stop():
    """Stop connect mode: clean up iptables, restore DNS, remove connect routing rules."""
    state = _connect_state_read()

    # Clean up iptables (always, regardless of what state says)
    _iptables_cleanup()

    # Restore DNS hijack (always)
    _dns_hijack_restore()

    # Remove connect-mode routing rules but KEEP dokodemo/dns inbound
    cfg, err = _parse_config()
    if not err:
        routing = cfg.get("routing", {})
        routing["balancers"] = []
        # Remove rules that reference connect-mode inbounds
        new_rules = []
        for r in routing.get("rules", []):
            ib_tags = r.get("inboundTag", [])
            if any(t in ib_tags for t in ("socks-in", "http-in")):
                continue
            new_rules.append(r)
        routing["rules"] = new_rules
        _save_config_object(cfg)

    restart = _restart_xray()

    _connect_state_write({
        "active": False,
        "selected_tags": [],
        "balancer_strategy": "roundRobin",
        "transparent_enabled": False,
    })

    return jsonify({"ok": True, "restart": restart})


@app.route("/api/connect/test-selected", methods=["POST"])
def api_connect_test_selected():
    """Batch test latency/speed for selected outbound nodes (reuses outbounds batch-test logic)."""
    data = request.json or {}
    tags = data.get("tags", [])
    url = (data.get("url") or DEFAULT_TEST_URLS[0]).strip()
    speed_url = (data.get("speed_url") or DEFAULT_SPEEDTEST_URL).strip()
    mode = data.get("mode", "ping")

    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500

    all_obs = [ob for ob in cfg.get("outbounds", []) if ob.get("protocol") not in ("freedom", "blackhole", "dns")]
    if tags:
        all_obs = [ob for ob in all_obs if ob.get("tag") in tags]
    if not all_obs:
        return jsonify({"error": "没有可测试的节点"}), 400

    base_port = random.randint(30000, 40000)
    temp_cfg, port_map = _build_temp_multi_config(all_obs, base_port=base_port)
    proc, tmp, error = _start_temp_xray(temp_cfg)
    if error:
        return jsonify({"ok": False, "error": "xray 启动失败", "detail": error})

    results = []
    try:
        import concurrent.futures
        def test_one(ob):
            tag = ob.get("tag", "")
            port = port_map.get(tag)
            if not port:
                return {"tag": tag, "ok": False, "error": "port not found"}
            r = {"tag": tag}
            addr = ""
            try:
                v = ob.get("settings", {}).get("vnext", [{}])[0]
                s = ob.get("settings", {}).get("servers", [{}])[0]
                src = v or s
                if src:
                    addr = str(src.get("address", "?")) + ":" + str(src.get("port", "?"))
            except Exception:
                pass
            r["outbound_addr"] = addr
            ping = _curl_via_socks("127.0.0.1", port, url, timeout=15)
            r["ping_ok"] = ping.get("ok", False)
            r["ping_ms"] = ping.get("time_total", "")
            r["ping_code"] = ping.get("http_code", "")
            r["exit_ip"] = ping.get("stdout", "").strip()
            if mode == "speed" and r["ping_ok"]:
                sp = _curl_speedtest("127.0.0.1", port, speed_url, timeout=DEFAULT_SPEEDTEST_TIMEOUT)
                r["speed_ok"] = sp.get("ok", False)
                r["speed_mbps"] = sp.get("speed_mbps", 0)
            else:
                r["speed_ok"] = False
                r["speed_mbps"] = 0
            return r

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(all_obs), 6)) as ex:
            futures = {ex.submit(test_one, ob): ob for ob in all_obs}
            for fut in concurrent.futures.as_completed(futures):
                results.append(fut.result())
    finally:
        _stop_temp_xray(proc, tmp)

    tag_order = {ob.get("tag", ""): i for i, ob in enumerate(all_obs)}
    results.sort(key=lambda r: tag_order.get(r.get("tag", ""), 999))
    return jsonify({"ok": True, "count": len(results), "results": results})


@app.route("/api/service/<action>", methods=["POST"])
def api_service_action(action):
    if action not in ("restart", "stop", "start"):
        return jsonify({"error": f"unknown action: {action}"}), 400

    if _has_systemd():
        _, err, rc = _run(f"systemctl {action} {SVC_NAME}")
    elif _has_supervisord():
        svc = "xray-all:xray"
        if action == "restart":
            _, err, rc = _run(f"supervisorctl restart {svc}")
        elif action == "stop":
            _, err, rc = _run(f"supervisorctl stop {svc}")
        else:
            _, err, rc = _run(f"supervisorctl start {svc}")
    else:
        return jsonify({"error": "no service manager found"}), 500

    time.sleep(1)
    info = _service_status()
    info["action"] = action
    info["success"] = rc == 0
    if err:
        info["error_output"] = err
    return jsonify(info)


# ---------------------------------------------------------------------------
# Traffic stats (reads /proc/net/dev)
# ---------------------------------------------------------------------------
_prev_net_stats = {}
_prev_net_time = 0

def _read_net_dev():
    """Read /proc/net/dev, return {iface: (rx_bytes, tx_bytes)}."""
    stats = {}
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                line = line.strip()
                if ":" not in line or line.startswith("Inter") or line.startswith("face"):
                    continue
                parts = line.split()
                iface = parts[0].rstrip(":")
                if iface == "lo":
                    continue
                rx = int(parts[1])
                tx = int(parts[9])
                stats[iface] = (rx, tx)
    except Exception:
        pass
    return stats


@app.route("/api/stats")
def api_stats():
    global _prev_net_stats, _prev_net_time
    import time
    now = time.time()
    cur = _read_net_dev()

    result = {"interfaces": {}, "total_rx_speed": 0, "total_tx_speed": 0}
    elapsed = now - _prev_net_time if _prev_net_time > 0 else 0

    for iface, (rx, tx) in cur.items():
        info = {"rx_bytes": rx, "tx_bytes": tx, "rx_speed": 0, "tx_speed": 0}
        if elapsed > 0.5 and iface in _prev_net_stats:
            prev_rx, prev_tx = _prev_net_stats[iface]
            info["rx_speed"] = max(0, (rx - prev_rx) / elapsed)
            info["tx_speed"] = max(0, (tx - prev_tx) / elapsed)
            result["total_rx_speed"] += info["rx_speed"]
            result["total_tx_speed"] += info["tx_speed"]
        result["interfaces"][iface] = info

    _prev_net_stats = cur
    _prev_net_time = now
    return jsonify(result)


@app.route("/api/logs")
def api_logs():
    lines = request.args.get("lines", 80, type=int)
    out = ""

    # Try journalctl first (systemd)
    if _has_systemd():
        out, _, _ = _run(f"journalctl -u {SVC_NAME} --no-pager -n {lines} 2>&1")
        if out.strip() and "No journal files" not in out and "-- No entries --" not in out:
            return jsonify({"logs": out})

    # Fallback: read log files (works in Docker and systemd with file logging)
    for log_file in [f"{BASE_DIR}/logs/xray.err", f"{BASE_DIR}/logs/xray.log"]:
        try:
            with open(log_file) as f:
                all_lines = f.readlines()
                out += "".join(all_lines[-lines:])
        except Exception:
            pass

    return jsonify({"logs": out if out.strip() else "(no logs found)"})


@app.route("/api/backups")
def api_backups():
    cfg_dir = Path(XRAY_CFG).parent
    cfg_name = Path(XRAY_CFG).name
    backups = sorted(
        [str(p) for p in cfg_dir.glob(f"{cfg_name}.bak.*")],
        reverse=True,
    )[:20]
    return jsonify({"backups": backups})


@app.route("/api/restore", methods=["POST"])
def api_restore():
    data = request.json
    if not data or "path" not in data:
        return jsonify({"error": "missing 'path' field"}), 400
    path = data["path"]
    if not os.path.isfile(path):
        return jsonify({"error": "backup not found"}), 404
    with open(path, "r") as f:
        content = f.read()
    try:
        json.loads(content)
    except json.JSONDecodeError as e:
        return jsonify({"error": f"backup is not valid JSON: {e}"}), 400

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = f"{XRAY_CFG}.bak.{ts}"
    raw, _ = _read_config()
    try:
        with open(backup, "w") as f:
            f.write(raw)
    except Exception:
        pass

    with open(XRAY_CFG, "w") as f:
        f.write(content)

    return jsonify({"ok": True, "restored_from": path})


# ---------------------------------------------------------------------------
# Sysctl tuning API
# ---------------------------------------------------------------------------
SYSCTL_PARAMS = [
    ("net.ipv4.tcp_slow_start_after_idle", "tcp_slow_start_after_idle", "空闲后重置拥塞窗口", "0"),
    ("net.ipv4.tcp_fastopen", "tcp_fastopen", "TCP Fast Open (0=关 1=客户端 2=服务端 3=两端)", "3"),
    ("net.ipv4.tcp_max_syn_backlog", "tcp_max_syn_backlog", "SYN 队列长度", "4096"),
    ("net.core.netdev_max_backlog", "netdev_max_backlog", "网卡收包队列长度", "5000"),
    ("net.ipv4.tcp_fin_timeout", "tcp_fin_timeout", "FIN_WAIT2 超时(秒)", "15"),
    ("net.ipv4.tcp_keepalive_time", "tcp_keepalive_time", "Keepalive 探测间隔(秒)", "300"),
    ("net.core.somaxconn", "somaxconn", "Listen 队列最大值", "4096"),
    ("net.ipv4.tcp_window_scaling", "tcp_window_scaling", "窗口缩放 (0/1)", "1"),
    ("net.ipv4.tcp_timestamps", "tcp_timestamps", "时间戳 (0/1)", "1"),
    ("net.ipv4.tcp_sack", "tcp_sack", "选择性确认 (0/1)", "1"),
    ("net.ipv4.tcp_congestion_control", "tcp_congestion_control", "拥塞控制算法", ""),
]


@app.route("/api/sysctl")
def api_sysctl_get():
    result = []
    for full_key, short, desc, recommended in SYSCTL_PARAMS:
        proc_path = "/proc/sys/" + full_key.replace(".", "/")
        try:
            val = Path(proc_path).read_text().strip()
        except Exception:
            try:
                val = subprocess.check_output(["sysctl", "-n", full_key], stderr=subprocess.DEVNULL, timeout=3).decode().strip()
            except Exception:
                val = "(unavailable)"
        result.append({"key": full_key, "short": short, "value": val, "desc": desc, "recommended": recommended})
    return jsonify({"params": result})


@app.route("/api/sysctl", methods=["POST"])
def api_sysctl_set():
    data = request.json or {}
    changes = data.get("changes", {})
    if not changes:
        return jsonify({"error": "no changes"}), 400
    applied = []
    errors = []
    for key, val in changes.items():
        if not any(key == p[0] for p in SYSCTL_PARAMS):
            errors.append(f"{key}: not allowed")
            continue
        proc_path = "/proc/sys/" + key.replace(".", "/")
        try:
            Path(proc_path).write_text(str(val))
            applied.append(f"{key}={val}")
        except Exception:
            try:
                subprocess.check_call(["sysctl", "-w", f"{key}={val}"], stderr=subprocess.PIPE, timeout=5)
                applied.append(f"{key}={val}")
            except Exception as e:
                errors.append(f"{key}: {e}")
    # persist to /etc/sysctl.conf
    if applied:
        try:
            existing = Path("/etc/sysctl.conf").read_text() if Path("/etc/sysctl.conf").exists() else ""
            lines = existing.splitlines()
            for item in applied:
                k, v = item.split("=", 1)
                k = k.strip()
                found = False
                for i, line in enumerate(lines):
                    if line.strip().startswith(k):
                        lines[i] = f"{k} = {v}"
                        found = True
                        break
                if not found:
                    lines.append(f"{k} = {v}")
            Path("/etc/sysctl.conf").write_text("\n".join(lines) + "\n")
        except Exception as e:
            errors.append(f"persist: {e}")
    return jsonify({"ok": True, "applied": applied, "errors": errors})


# ---------------------------------------------------------------------------
# HTML UI (single page, embedded)
# ---------------------------------------------------------------------------

HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Xray Manager</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#c9d1d9;--text2:#8b949e;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--orange:#db6d28}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
a{color:var(--accent);text-decoration:none}
.header{background:var(--bg2);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.header h1{font-size:18px;font-weight:600;display:flex;align-items:center;gap:8px}
.header h1 svg{width:22px;height:22px}
.header .version{color:var(--text2);font-size:12px;background:var(--bg3);padding:2px 8px;border-radius:10px}
.container{max-width:1200px;margin:0 auto;padding:20px}
.tabs{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid var(--border);padding-bottom:0}
.tab{padding:8px 16px;cursor:pointer;border-bottom:2px solid transparent;color:var(--text2);font-size:14px;transition:all .2s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-content{display:none}
.tab-content.active{display:block}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}
.card h2{font-size:15px;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.card h2 .dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.dot.on{background:var(--green)}
.dot.off{background:var(--red)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.stat{background:var(--bg3);padding:12px;border-radius:6px}
.stat .label{color:var(--text2);font-size:12px;margin-bottom:4px}
.stat .value{font-size:18px;font-weight:600;font-family:'SF Mono',SFMono-Regular,consolas,monospace}
.btn{padding:6px 14px;border-radius:6px;border:1px solid var(--border);background:var(--bg3);color:var(--text);cursor:pointer;font-size:13px;transition:all .15s}
.btn:hover{background:var(--border)}
.btn.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn.primary:hover{opacity:.85}
.btn.danger{background:var(--red);color:#fff;border-color:var(--red)}
.btn.danger:hover{opacity:.85}
.btn.success{background:var(--green);color:#fff;border-color:var(--green)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;align-items:center}
.conn-node-list{max-height:420px;overflow-y:auto;border:1px solid var(--border);border-radius:6px}
.conn-node{display:flex;align-items:center;gap:10px;padding:8px 12px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s;font-size:13px}
.conn-node:last-child{border-bottom:none}
.conn-node:hover{background:var(--bg3)}
.conn-node.selected{background:rgba(56,139,253,.1);border-left:3px solid var(--accent)}
.conn-node .cb{flex-shrink:0}
.conn-node .tag-col{min-width:120px;font-weight:500;font-family:monospace}
.conn-node .proto-col{min-width:70px;color:var(--text2);font-size:12px}
.conn-node .addr-col{flex:1;color:var(--text2);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.conn-node .latency-col{min-width:70px;text-align:right;font-family:monospace;font-size:12px}
.conn-ctrl{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}
.conn-ctrl .card-inner{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px}
.conn-status-bar{display:flex;align-items:center;gap:12px;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:6px;margin-top:12px;font-size:13px}
.conn-status-bar .indicator{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.conn-status-bar .indicator.on{background:var(--green);box-shadow:0 0 6px var(--green)}
.conn-status-bar .indicator.off{background:var(--text2)}
textarea.config-editor{width:100%;min-height:500px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:12px;font-family:'SF Mono',SFMono-Regular,consolas,monospace;font-size:13px;resize:vertical;tab-size:2;white-space:pre;overflow:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--border);font-size:13px}
th{color:var(--text2);font-weight:500;font-size:12px;text-transform:uppercase}
td{font-family:'SF Mono',SFMono-Regular,consolas,monospace;font-size:12px}
.ob-addr{max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr.ob-system td{opacity:.6;border-bottom-style:dashed}
tr.ob-system:hover td{opacity:.8;background:var(--bg)}
.tag{display:inline-block;padding:1px 6px;border-radius:4px;font-size:11px;font-weight:500}
.tag.us{background:rgba(56,139,253,.15);color:#58a6ff}
.tag.kr{background:rgba(63,185,80,.15);color:#3fb950}
.tag.jp{background:rgba(210,153,34,.15);color:#d29922}
.tag.hk{background:rgba(219,109,40,.15);color:#db6d28}
.tag.default{background:var(--bg3);color:var(--text2)}
.log-box{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px;font-family:'SF Mono',SFMono-Regular,consolas,monospace;font-size:11px;line-height:1.6;max-height:500px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;color:var(--text2)}
.toast{position:fixed;top:20px;right:20px;padding:10px 18px;border-radius:6px;font-size:13px;z-index:999;animation:slideIn .3s;max-width:400px}
.toast.ok{background:var(--green);color:#fff}
.toast.err{background:var(--red);color:#fff}
@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
.edit-row{display:grid;grid-template-columns:130px 1fr;gap:8px;align-items:center;margin-bottom:8px}
.edit-row label{color:var(--text2);font-size:13px;text-align:right;padding-right:4px;white-space:nowrap}
.edit-row input,.edit-row select{width:100%}
.edit-row input,.edit-row select,.edit-row textarea{padding:5px 8px;background:var(--bg);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:13px;font-family:monospace}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:200;display:none;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:20px;width:90%;max-width:900px;max-height:85vh;overflow-y:auto}
.modal h3{margin-bottom:16px;font-size:16px}
.modal-footer{display:flex;justify-content:flex-end;gap:8px;margin-top:16px;padding-top:12px;border-top:1px solid var(--border)}
.modal-footer .btn-group{margin-top:0}
.ob-actions{display:flex;gap:4px;flex-wrap:nowrap;align-items:center;white-space:nowrap}
.ob-actions .btn{padding:3px 8px;font-size:11px;line-height:1.4;border-radius:4px;flex-shrink:0}
.backup-item{display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px;font-family:monospace}
.status-pill{display:inline-block;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:600}
.status-pill.active{background:rgba(63,185,80,.15);color:var(--green)}
.status-pill.inactive{background:rgba(248,81,73,.15);color:var(--red)}
@media(max-width:768px){
  .header{padding:10px 14px}
  .header h1{font-size:15px}
  .container{padding:10px}
  .tabs{overflow-x:auto;flex-wrap:nowrap;-webkit-overflow-scrolling:touch;scrollbar-width:none}
  .tabs::-webkit-scrollbar{display:none}
  .tab{padding:8px 10px;font-size:13px;white-space:nowrap}
  .card{padding:12px}
  .card h2{font-size:14px}
  .grid{grid-template-columns:repeat(2,1fr);gap:8px}
  .stat .value{font-size:14px}
  .btn-group{gap:4px}
  .btn{padding:5px 10px;font-size:12px}
  table{display:block;overflow-x:auto;-webkit-overflow-scrolling:touch}
  th,td{padding:6px 8px;font-size:11px}
  .modal{width:95%;padding:14px;max-height:90vh}
  .modal h3{font-size:14px}
  .edit-row{grid-template-columns:100px 1fr}
  textarea.config-editor{min-height:300px;font-size:11px}
  .log-box{font-size:10px;max-height:300px}
  .toast{top:10px;right:10px;left:10px;max-width:none;font-size:12px}
  #ob-test-url-select,#ob-test-url-custom,#ob-speed-url{min-width:100%!important;flex:1}
  .header .version{display:none}
}
</style>
</head>
<body>

<!-- Login Overlay -->
<div id="login-overlay" style="position:fixed;inset:0;background:var(--bg);z-index:9999;display:flex;align-items:center;justify-content:center">
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:32px;width:360px;text-align:center">
    <svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" style="width:40px;height:40px;margin-bottom:12px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    <h2 style="margin-bottom:20px;font-size:18px;color:var(--text)">Xray Manager</h2>
    <input type="password" id="login-token" placeholder="输入 Token" autocomplete="off"
      style="width:100%;padding:10px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:14px;outline:none;margin-bottom:12px"
      onkeydown="if(event.key==='Enter')doLogin()">
    <button onclick="doLogin()" style="width:100%;padding:10px;background:var(--accent);color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer">登录</button>
    <p id="login-error" style="color:var(--red);font-size:12px;margin-top:10px;display:none"></p>
  </div>
</div>

<div class="header">
  <h1>
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    Xray Manager
  </h1>
  <div style="display:flex;align-items:center;gap:10px">
    <span id="header-stats" style="font-size:11px;color:var(--text2);font-family:monospace">↓ - ↑ -</span>
    <span class="version" id="version">-</span>
    <button onclick="doLogout()" style="padding:4px 10px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;color:var(--text2);font-size:12px;cursor:pointer">退出</button>
  </div>
</div>

<div class="container">
  <div class="tabs">
    <div class="tab active" onclick="switchTab('connect')">连接</div>
    <div class="tab" onclick="switchTab('status')">状态</div>
    <div class="tab" onclick="switchTab('inbounds')">入站</div>
    <div class="tab" onclick="switchTab('outbounds')">出站</div>
    <div class="tab" onclick="switchTab('routing')">路由</div>
    <div class="tab" onclick="switchTab('config')">配置</div>
    <div class="tab" onclick="switchTab('dns')">DNS</div>
    <div class="tab" onclick="switchTab('logs')">日志</div>
    <div class="tab" onclick="switchTab('system')">系统</div>
    <div class="tab" onclick="switchTab('backups')">备份</div>
  </div>

  <!-- Connect Mode -->
  <div class="tab-content active" id="tab-connect">
    <div class="card">
      <h2>🔌 连接模式</h2>
      <p style="color:var(--text2);font-size:12px;margin-bottom:12px">选择出站节点 → 一键启动代理。支持多节点负载均衡和可选透明代理。</p>

      <!-- Node List -->
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
        <span style="color:var(--text2);font-size:13px" id="conn-selected-count">已选: 0 个节点</span>
        <div style="display:flex;gap:6px">
          <button class="btn" onclick="connSelectAll()">全选</button>
          <button class="btn" onclick="connClearAll()">清空</button>
          <button class="btn primary" onclick="connTestSelected()">测试选中</button>
          <button class="btn" onclick="connTestAll()">测试全部</button>
          <button class="btn" onclick="connSpeedTest()">测速</button>
          <button class="btn primary" onclick="showAddOutboundModal()">新增节点</button>
        </div>
      </div>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
        <label style="color:var(--text2);font-size:12px">测试URL</label>
        <select id="conn-test-url-select" style="min-width:240px;padding:5px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-size:12px"></select>
        <input id="conn-test-url-custom" placeholder="自定义" style="min-width:200px;padding:5px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace;font-size:12px">
        <label style="color:var(--text2);font-size:12px">测速URL</label>
        <input id="conn-speed-url" value="https://speed.cloudflare.com/__down?bytes=10000000" style="min-width:300px;padding:5px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace;font-size:12px">
      </div>
      <div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:10px;flex-wrap:wrap">
        <textarea id="conn-import-links" placeholder="快速导入：vless:// vmess:// ss:// trojan://（支持多行）" style="flex:1;min-width:350px;min-height:50px;padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace;font-size:12px;resize:vertical"></textarea>
        <div style="display:flex;flex-direction:column;gap:4px;align-self:flex-end">
          <label style="display:flex;align-items:center;gap:4px;font-size:11px;color:var(--text2);cursor:pointer"><input type="checkbox" id="conn-import-tfo"> TFO</label>
          <button class="btn primary" onclick="connImportLinks()" style="font-size:12px">导入</button>
        </div>
      </div>
      <div class="conn-node-list" id="conn-node-list">
        <div style="padding:20px;text-align:center;color:var(--text2)">加载中...</div>
      </div>

      <!-- Connection Controls -->
      <div class="conn-ctrl">
        <div class="card-inner">
          <label style="color:var(--text2);font-size:12px;display:block;margin-bottom:6px">负载均衡策略</label>
          <select id="conn-strategy" style="width:100%;padding:6px;background:var(--bg2);color:var(--text);border:1px solid var(--border);border-radius:4px;font-size:13px">
            <option value="roundRobin">轮询 (roundRobin)</option>
            <option value="leastPing">最低延迟 (leastPing)</option>
            <option value="random">随机 (random)</option>
          </select>
          <p style="color:var(--text2);font-size:11px;margin-top:4px">多选节点时自动启用负载均衡</p>
        </div>
        <div class="card-inner">
          <label style="color:var(--text2);font-size:12px;display:block;margin-bottom:6px">透明代理</label>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:8px">
            <input type="checkbox" id="conn-transparent" onchange="connToggleTp()"> <span style="font-size:13px">启用 iptables REDIRECT (局域网/本机全走代理)</span>
          </label>
          <div id="conn-tp-details" style="display:none;margin-top:8px;padding-top:8px;border-top:1px solid var(--border)">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;padding:8px;background:var(--bg);border-radius:4px;border:1px solid var(--border)">
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
                <input type="checkbox" id="tp-ip-forward" onchange="tpToggleForward(this.checked)">
                <span style="font-size:12px">IP 转发 (ip_forward)</span>
              </label>
              <span id="tp-forward-status" style="font-size:11px;color:var(--text2)"></span>
            </div>
            <details style="margin-bottom:8px">
              <summary style="cursor:pointer;color:var(--text2);font-size:12px;margin-bottom:6px">绕过 IP/CIDR 配置</summary>
              <p style="color:var(--text2);font-size:11px;margin-bottom:6px">默认绕过私有/保留地址 + 自动提取 DNS 相关 IP。每行一个 CIDR。</p>
              <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px">
                <div>
                  <label style="color:var(--text2);font-size:11px;display:block;margin-bottom:3px">默认（只读）</label>
                  <textarea id="tp-default-cidrs" readonly style="width:100%;min-height:100px;background:var(--bg);color:var(--text2);border:1px solid var(--border);border-radius:4px;padding:6px;font-family:monospace;font-size:10px;resize:vertical"></textarea>
                </div>
                <div>
                  <label style="color:var(--text2);font-size:11px;display:block;margin-bottom:3px">自动（DNS）</label>
                  <textarea id="tp-auto-cidrs" readonly style="width:100%;min-height:100px;background:var(--bg);color:var(--yellow);border:1px solid var(--border);border-radius:4px;padding:6px;font-family:monospace;font-size:10px;resize:vertical"></textarea>
                </div>
                <div>
                  <label style="color:var(--text2);font-size:11px;display:block;margin-bottom:3px">自定义</label>
                  <textarea id="tp-custom-cidrs" placeholder="1.1.1.1/32&#10;8.8.8.8/32" style="width:100%;min-height:100px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:6px;font-family:monospace;font-size:10px;resize:vertical"></textarea>
                </div>
              </div>
              <div class="btn-group" style="margin-top:6px">
                <button class="btn" onclick="tpSaveBypass()" style="font-size:11px;padding:3px 10px">保存绕过规则</button>
              </div>
            </details>
          </div>
        </div>
        <div class="card-inner">
          <label style="color:var(--text2);font-size:12px;display:block;margin-bottom:6px">端口配置</label>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <span style="color:var(--text2);font-size:12px">SOCKS</span>
            <input id="conn-port-socks" type="number" value="10810" style="width:80px;padding:4px;background:var(--bg2);color:var(--text);border:1px solid var(--border);border-radius:4px;font-size:12px;font-family:monospace">
            <span style="color:var(--text2);font-size:12px">HTTP</span>
            <input id="conn-port-http" type="number" value="10818" style="width:80px;padding:4px;background:var(--bg2);color:var(--text);border:1px solid var(--border);border-radius:4px;font-size:12px;font-family:monospace">
            <span style="color:var(--text2);font-size:12px">透明</span>
            <input id="conn-port-tp" type="number" value="12345" style="width:80px;padding:4px;background:var(--bg2);color:var(--text);border:1px solid var(--border);border-radius:4px;font-size:12px;font-family:monospace">
          </div>
        </div>
      </div>

      <!-- Action Buttons -->
      <div class="btn-group" style="margin-top:16px">
        <button class="btn success" onclick="connStart()" id="btn-conn-start">▶ 启动连接</button>
        <button class="btn danger" onclick="connStop()" id="btn-conn-stop">■ 断开连接</button>
      </div>

      <!-- Status Bar -->
      <div class="conn-status-bar" id="conn-status-bar">
        <div class="indicator off" id="conn-indicator"></div>
        <span id="conn-status-text">未连接</span>
        <span style="flex:1"></span>
        <span id="conn-endpoints" style="color:var(--text2);font-size:12px"></span>
      </div>

      <!-- Test Output -->
      <div class="log-box" id="conn-test-output" style="display:none;margin-top:12px;max-height:300px;overflow-y:auto"></div>
    </div>
  </div>

  <!-- Status -->
  <div class="tab-content" id="tab-status">
    <div class="card">
      <h2><span class="dot" id="status-dot"></span> 服务状态</h2>
      <div class="grid" id="status-grid"></div>
      <div class="btn-group">
        <button class="btn success" onclick="svcAction('start')">启动</button>
        <button class="btn primary" onclick="svcAction('restart')">重启</button>
        <button class="btn danger" onclick="svcAction('stop')">停止</button>
      </div>
    </div>
    <div class="card">
      <h2>流量监控</h2>
      <div id="stats-grid" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
        <div class="stat"><div class="label">↓ 下载速度</div><div class="value" id="stat-rx" style="color:var(--green)">-</div></div>
        <div class="stat"><div class="label">↑ 上传速度</div><div class="value" id="stat-tx" style="color:var(--yellow)">-</div></div>
      </div>
      <div id="stats-interfaces" style="font-size:12px;color:var(--text2)"></div>
    </div>
    <div class="card">
      <h2>监听端口</h2>
      <table><thead><tr><th>地址</th><th>出口</th></tr></thead><tbody id="listen-tbody"></tbody></table>
    </div>
  </div>

  <!-- Inbounds -->
  <div class="tab-content" id="tab-inbounds">
    <div class="card">
      <h2>入站端口管理</h2>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap">
        <label style="color:var(--text2);font-size:13px">测试 URL</label>
        <select id="test-url-select" style="min-width:260px;padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px"></select>
        <input id="test-url-custom" placeholder="自定义测试 URL" style="min-width:360px;padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace">
        <button class="btn" onclick="saveCurrentTestUrl()">加入常用</button>
      </div>
      <div class="log-box" id="inbound-test-output" style="display:none;margin-bottom:12px;max-height:220px"></div>
      <table>
        <thead><tr><th>Tag</th><th>协议</th><th>监听地址</th><th>端口</th><th>出口</th><th></th></tr></thead>
        <tbody id="inbounds-tbody"></tbody>
      </table>
      <div class="btn-group">
        <button class="btn primary" onclick="showAddInboundModal()">新增入站</button>
        <button class="btn success" onclick="saveInbounds()">保存变更</button>
      </div>
    </div>
  </div>

  <!-- Outbounds -->
  <div class="tab-content" id="tab-outbounds">
    <div class="card">
      <h2>出站节点管理</h2>
      <div class="btn-group" style="margin-bottom:12px">
        <button class="btn primary" onclick="showAddOutboundModal()">新增节点</button>
        <button class="btn success" onclick="saveOutbounds()">保存变更</button>
      </div>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
        <label style="color:var(--text2);font-size:13px">测试 URL</label>
        <select id="ob-test-url-select" style="min-width:260px;padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px"></select>
        <input id="ob-test-url-custom" placeholder="自定义 URL" style="min-width:320px;padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace">
      </div>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap">
        <label style="color:var(--text2);font-size:13px">测速 URL</label>
        <input id="ob-speed-url" value="https://speed.cloudflare.com/__down?bytes=10000000" style="min-width:460px;padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace">
        <button class="btn primary" onclick="batchTestSelected('ping')">批量测延迟</button>
        <button class="btn" onclick="batchTestSelected('speed')">批量测速</button>
        <button class="btn" onclick="batchExportOutbounds()">批量导出</button>
      </div>
      <div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:12px;flex-wrap:wrap">
        <textarea id="quick-import-links" placeholder="快速导入：粘贴 vless:// vmess:// ss:// trojan:// 链接（支持多行）" style="flex:1;min-width:400px;min-height:60px;padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace;font-size:12px;resize:vertical"></textarea>
        <div style="display:flex;flex-direction:column;gap:6px;align-self:flex-end">
          <label style="display:flex;align-items:center;gap:4px;font-size:12px;color:var(--text2);cursor:pointer"><input type="checkbox" id="quick-import-tfo"> TCP Fast Open</label>
          <button class="btn primary" onclick="quickImportLinks()">解析导入</button>
        </div>
      </div>
      <div class="log-box" id="outbound-test-output" style="display:none;margin-bottom:12px;max-height:400px;overflow-y:auto"></div>
      <table>
        <thead><tr><th><input type="checkbox" id="ob-select-all" onchange="toggleSelectAll(this.checked)"></th><th>Tag</th><th>协议</th><th>地址</th><th>端口</th><th>传输</th><th>延迟</th><th>速度</th><th>操作</th></tr></thead>
        <tbody id="outbounds-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- Routing -->
  <div class="tab-content" id="tab-routing">
    <div class="card">
      <h2>路由规则</h2>
      <table>
        <thead><tr><th>类型</th><th>条件</th><th>出口</th></tr></thead>
        <tbody id="routing-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- Config -->
  <div class="tab-content" id="tab-config">
    <div class="card">
      <h2>配置编辑器</h2>
      <textarea class="config-editor" id="config-editor" spellcheck="false"></textarea>
      <div class="btn-group">
        <button class="btn primary" onclick="saveConfig()">保存</button>
        <button class="btn" onclick="loadConfig()">重新加载</button>
        <button class="btn" onclick="testConfig()">校验</button>
      </div>
    </div>
    <div class="card" style="margin-top:16px">
      <h2>修改 Token</h2>
      <p style="color:var(--text2);font-size:12px;margin-bottom:12px">修改后需要重新登录。</p>
      <div class="edit-row"><label>当前 Token</label><input id="token-old" type="password" placeholder="输入当前 Token"></div>
      <div class="edit-row"><label>新 Token</label><input id="token-new" type="password" placeholder="输入新 Token"></div>
      <div class="edit-row"><label>确认新 Token</label><input id="token-confirm" type="password" placeholder="再次输入新 Token"></div>
      <div class="btn-group"><button class="btn primary" onclick="changeToken()">修改 Token</button></div>
    </div>
    <div class="card" style="margin-top:16px">
      <h2>GeoIP / GeoSite</h2>
      <p style="color:var(--text2);font-size:12px;margin-bottom:12px">更新 geoip.dat 和 geosite.dat 数据文件。可自定义下载地址。</p>
      <div class="edit-row" style="margin-bottom:8px">
        <label>geoip URL</label>
        <input id="geo-ip-url" style="font-size:11px" placeholder="https://hub.543083.xyz/https://github.com/.../geoip.dat">
      </div>
      <div class="edit-row" style="margin-bottom:8px">
        <label>geosite URL</label>
        <input id="geo-site-url" style="font-size:11px" placeholder="https://hub.543083.xyz/https://github.com/.../geosite.dat">
      </div>
      <div class="grid" style="margin-bottom:12px">
        <div class="stat"><div class="label">geoip.dat</div><div class="value" id="geo-ip-size">-</div></div>
        <div class="stat"><div class="label">geosite.dat</div><div class="value" id="geo-site-size">-</div></div>
      </div>
      <div style="font-size:12px;color:var(--text2);margin-bottom:12px">
        <span id="geo-ip-modified">-</span> &nbsp;|&nbsp; <span id="geo-site-modified">-</span>
      </div>
      <div class="btn-group">
        <button class="btn" onclick="saveGeoUrls()">保存 URL</button>
        <button class="btn primary" id="geo-update-btn" onclick="updateGeo()">更新 GeoIP/GeoSite</button>
      </div>
      <div id="geo-update-status" style="margin-top:8px;font-size:13px;color:var(--text2)"></div>
    </div>
  </div>

  <!-- DNS -->
  <div class="tab-content" id="tab-dns">
    <div class="card">
      <h2>DNS 配置</h2>
      <p style="color:var(--text2);font-size:12px;margin-bottom:12px">编辑 Xray 的 <code>dns</code> 配置。常见 DoH：<code>https://dns.alidns.com/dns-query</code>、<code>https://doh.pub/dns-query</code>、<code>https://cloudflare-dns.com/dns-query</code>、<code>https://dns.google/dns-query</code></p>
      <div class="edit-row"><label>服务器（每行一个）</label><textarea id="dns-servers" style="min-height:140px"></textarea></div>
      <div class="edit-row"><label>clientIp</label><input id="dns-client-ip" placeholder="可选，如 1.1.1.1"></div>
      <div class="btn-group"><button class="btn primary" onclick="saveDns()">保存 DNS</button></div>
    </div>
    <div class="card" style="margin-top:16px">
      <h2>DNS Hosts</h2>
      <p style="color:var(--text2);font-size:12px;margin-bottom:12px">自定义域名解析，类似 /etc/hosts。每行一条：<code>域名 IP</code>。支持 <code>#</code> 注释。可选前缀：<code>domain:</code>、<code>geosite:</code>、<code>full:</code></p>
      <textarea id="dns-hosts-editor" style="width:100%;min-height:180px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:8px;font-family:monospace;font-size:12px;resize:vertical" placeholder="googleapis.cn 203.208.41.96&#10;domain:google.com 8.8.8.8&#10;full:ads.example.com 127.0.0.1&#10;# 这是注释"></textarea>
      <div class="btn-group" style="margin-top:8px"><button class="btn primary" onclick="saveDnsHosts()">保存 Hosts</button></div>
    </div>
  </div>

  <!-- Transparent Proxy -->
  <!-- Logs -->
  <div class="tab-content" id="tab-logs">
    <div class="card">
      <h2>服务日志</h2>
      <div class="btn-group" style="margin-bottom:12px">
        <button class="btn" onclick="loadLogs(50)">50行</button>
        <button class="btn" onclick="loadLogs(200)">200行</button>
        <button class="btn" onclick="loadLogs(500)">500行</button>
        <button class="btn primary" onclick="loadLogs(200)">刷新</button>
      </div>
      <div class="log-box" id="log-box">加载中...</div>
    </div>
  </div>

  <!-- System / Sysctl -->
  <div class="tab-content" id="tab-system">
    <div class="card">
      <h2>内核参数调优</h2>
      <p style="color:var(--text2);font-size:12px;margin-bottom:12px">修改后立即生效并持久化到 /etc/sysctl.conf。标黄的值与推荐值不一致。</p>
      <table>
        <thead><tr><th>参数</th><th>说明</th><th>当前值</th><th>推荐值</th><th>操作</th></tr></thead>
        <tbody id="sysctl-tbody"></tbody>
      </table>
      <div class="btn-group" style="margin-top:12px">
        <button class="btn primary" onclick="saveSysctl()">保存修改</button>
        <button class="btn" onclick="loadSysctl()">刷新</button>
        <button class="btn" onclick="applyRecommended()">一键应用推荐值</button>
      </div>
    </div>
  </div>

  <!-- Backups -->
  <div class="tab-content" id="tab-backups">
    <div class="card">
      <h2>配置备份</h2>
      <div id="backup-list">加载中...</div>
    </div>
  </div>
</div>

<!-- Edit Inbound Modal -->
<div class="modal-overlay" id="modal-edit-inbound">
  <div class="modal">
    <h3 id="modal-inbound-title">编辑入站</h3>
    <div class="edit-row"><label>Tag</label><input id="ei-tag" placeholder="my-proxy"></div>
    <div class="edit-row"><label>协议</label>
      <select id="ei-protocol">
        <option value="socks">SOCKS5</option>
        <option value="http">HTTP</option>
      </select>
    </div>
    <div class="edit-row"><label>监听地址</label><input id="ei-listen" value="0.0.0.0"></div>
    <div class="edit-row"><label>端口</label><input id="ei-port" type="number" placeholder="10808"></div>
    <div class="edit-row"><label>UDP</label>
      <select id="ei-udp"><option value="true">是</option><option value="false">否</option></select>
    </div>
    <div class="edit-row"><label>Sniffing</label>
      <select id="ei-sniff"><option value="true">是</option><option value="false">否</option></select>
    </div>
    <div class="edit-row"><label>出口</label>
      <select id="ei-outbound"></select>
    </div>
    <div class="btn-group" style="margin-top:16px">
      <button class="btn primary" onclick="saveEditInbound()">确定</button>
      <button class="btn danger" onclick="deleteInbound()" id="btn-delete-inbound" style="display:none">删除</button>
      <button class="btn" onclick="closeModal('modal-edit-inbound')">取消</button>
    </div>
  </div>
</div>

<!-- Unified Add/Edit Outbound Modal -->
<div class="modal-overlay" id="modal-outbound">
  <div class="modal">
    <h3 id="modal-ob-title">新增节点</h3>
    <div style="display:flex;gap:0;margin-bottom:16px;border-bottom:1px solid var(--border)">
      <div class="tab active" id="mob-tab-link" onclick="switchObModalTab('link')">解析节点链接</div>
      <div class="tab" id="mob-tab-form" onclick="switchObModalTab('form')">表单编辑</div>
      <div class="tab" id="mob-tab-json" onclick="switchObModalTab('json')">编辑 JSON</div>
    </div>
    <div id="mob-pane-link">
      <textarea class="config-editor" id="vless-link" spellcheck="false" style="min-height:120px" placeholder="vless:// vmess:// ss:// trojan:// ..."></textarea>
      <p style="color:var(--text2);font-size:12px;margin-top:8px">支持 vless:// vmess:// ss:// trojan://，可粘贴多行批量添加。</p>
      <label style="display:flex;align-items:center;gap:4px;font-size:12px;color:var(--text2);margin-top:6px;cursor:pointer"><input type="checkbox" id="modal-tfo"> TCP Fast Open</label>
      <div class="btn-group" style="margin-top:12px">
        <button class="btn primary" onclick="parseAndAddVless()">解析并新增</button>
      </div>
    </div>
    <div id="mob-pane-form" style="display:none">
      <div class="edit-row"><label>Tag</label><input id="of-tag" autocomplete="off"></div>
      <div class="edit-row"><label>协议</label><select id="of-protocol"><option value="vless">vless</option><option value="vmess">vmess</option><option value="shadowsocks">shadowsocks</option><option value="trojan">trojan</option></select></div>
      <div class="edit-row"><label>地址</label><input id="of-address"></div>
      <div class="edit-row"><label>端口</label><input id="of-port" type="number"></div>
      <div class="edit-row"><label>用户ID/密码</label><input id="of-id"></div>
      <div class="edit-row"><label>加密/方法</label><input id="of-security" placeholder="vless:none vmess:auto ss:aes-128-gcm"></div>
      <div class="edit-row"><label>flow</label><input id="of-flow" placeholder="可选，仅 vless/trojan 常见"></div>
      <div class="edit-row"><label>network</label><select id="of-network"><option value="tcp">tcp</option><option value="ws">ws</option><option value="grpc">grpc</option><option value="xhttp">xhttp</option></select></div>
      <div class="edit-row"><label>security</label><select id="of-tls-mode"><option value="none">none</option><option value="tls">tls</option><option value="reality">reality</option></select></div>
      <div class="edit-row"><label>SNI</label><input id="of-sni"></div>
      <div class="edit-row"><label>Host</label><input id="of-host"></div>
      <div class="edit-row"><label>Path</label><input id="of-path"></div>
      <div class="edit-row"><label>Fingerprint</label><input id="of-fp" placeholder="random/chrome"></div>
      <div class="edit-row"><label>ALPN</label><input id="of-alpn" placeholder="h3 或 h2,http/1.1"></div>
      <div class="edit-row"><label>allowInsecure</label><select id="of-insecure"><option value="false">false</option><option value="true">true</option></select></div>
      <div class="edit-row"><label>ECH</label><input id="of-ech" placeholder="cloudflare-ech.com+https://dns.alidns.com/dns-query"></div>
      <div class="edit-row"><label>mux</label><select id="of-mux"><option value="off">off</option><option value="on">on</option></select></div>
      <div class="btn-group" style="margin-top:12px"><button class="btn primary" onclick="saveFormOutbound()">从表单生成并保存到编辑区</button></div>
    </div>
    <div id="mob-pane-json" style="display:none">
      <textarea class="config-editor" id="eo-json" spellcheck="false" style="min-height:300px"></textarea>
      <div class="btn-group" style="margin-top:12px">
        <button class="btn primary" onclick="saveEditOutbound()">确认</button>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn" onclick="closeModal('modal-outbound')">关闭</button>
    </div>
  </div>
</div>

<!-- Restore Modal -->
<div class="modal-overlay" id="modal-restore">
  <div class="modal">
    <h3>确认恢复</h3>
    <p style="margin-bottom:16px;color:var(--text2)">将用此备份覆盖当前配置文件。当前配置会自动备份。</p>
    <p id="restore-path" style="font-family:monospace;font-size:13px;margin-bottom:16px;word-break:break-all"></p>
    <div class="btn-group">
      <button class="btn danger" onclick="confirmRestore()">确认恢复</button>
      <button class="btn" onclick="closeModal('modal-restore')">取消</button>
    </div>
  </div>
</div>

<script>
const API = '';
let token = localStorage.getItem('xray_token') || '';

function doLogin(){
  const val=document.getElementById('login-token').value.trim();
  if(!val){showLoginError('请输入 Token');return;}
  token=val;
  localStorage.setItem('xray_token', token);
  // validate by calling status API
  fetch(API+'/api/status',{headers:{'X-Token':token}}).then(r=>{
    if(r.ok){
      document.getElementById('login-overlay').style.display='none';
      loadStatus();
    }else{
      showLoginError('Token 错误，请重新输入');
      localStorage.removeItem('xray_token');
      token='';
    }
  }).catch(e=>showLoginError('连接失败: '+e.message));
}

function showLoginError(msg){
  const el=document.getElementById('login-error');
  el.textContent=msg;
  el.style.display='block';
}

function doLogout(){
  localStorage.removeItem('xray_token');
  token='';
  document.getElementById('login-overlay').style.display='flex';
  document.getElementById('login-token').value='';
  document.getElementById('login-error').style.display='none';
}

// Auto-login if token exists in storage
if(token){
  fetch(API+'/api/status',{headers:{'X-Token':token}}).then(r=>{
    if(r.ok){
      document.getElementById('login-overlay').style.display='none';
    }else{
      localStorage.removeItem('xray_token');
      token='';
      document.getElementById('login-token').focus();
    }
  }).catch(()=>document.getElementById('login-token').focus());
}else{
  document.getElementById('login-token').focus();
}
let statusData = null;
let configData = null;
let inboundsData = [];
let routingData = {};
let inboundRouteMap = {};
let outboundsData = [];
let editingIdx = -1;
let editingOutboundIdx = -1;
let restoreTarget = '';

function hdrs(){return {'Content-Type':'application/json','X-Token':token}}

function copyToClipboard(text){
  if(navigator.clipboard&&window.isSecureContext){
    navigator.clipboard.writeText(text).then(()=>true).catch(()=>fallbackCopy(text));
  }else{
    fallbackCopy(text);
  }
}
function fallbackCopy(text){
  const ta=document.createElement('textarea');
  ta.value=text;ta.style.position='fixed';ta.style.left='-9999px';
  document.body.appendChild(ta);ta.select();
  try{document.execCommand('copy');}catch(e){}
  document.body.removeChild(ta);
}
function toast(msg, ok=true){
  const d=document.createElement('div');
  d.className='toast '+(ok?'ok':'err');
  d.textContent=msg;
  document.body.appendChild(d);
  setTimeout(()=>d.remove(),3500);
}

async function api(path, opts={}){
  try{
    const r=await fetch(API+path,{headers:hdrs(),...opts});
    const j=await r.json();
    if(j.error){toast(j.error,false);return null}
    return j;
  }catch(e){toast(e.message,false);return null}
}

function switchTab(name){
  document.querySelectorAll('.tab').forEach((t,i)=>{
    t.classList.toggle('active',t.textContent.trim()===({connect:'连接',status:'状态',inbounds:'入站',outbounds:'出站',routing:'路由',config:'配置',dns:'DNS',logs:'日志',system:'系统',backups:'备份'}[name]));
  });
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  if(name==='connect')loadConnect();
  if(name==='status'){loadStatus();startStatsPolling();}else{stopStatsPolling();}
  if(name==='inbounds'){loadInbounds();loadTestUrls();}
  if(name==='outbounds'){loadOutbounds();loadObTestUrls();}
  if(name==='routing')loadRouting();
  if(name==='config'){loadConfig();loadGeoInfo();}
  if(name==='dns'){loadDns();loadDnsHosts();}
  if(name==='logs')loadLogs(200);
  if(name==='transparent')loadTransparent();
  if(name==='system')loadSysctl();
  if(name==='backups')loadBackups();
}

function tagForPort(port){
  const m={10810:'us',10811:'kr',10812:'jp',10813:'hk'};
  return m[port]||'default';
}
function nameForTag(t){
  const m={us:'美国',kr:'韩国',jp:'日本',hk:'香港',direct:'直连',block:'拦截'};
  return m[t]||t;
}

async function loadStatus(){
  const d=await api('/api/status');
  if(!d)return;
  statusData=d;
  document.getElementById('version').textContent=d.xray_version||'-';
  const dot=document.getElementById('status-dot');
  dot.className='dot '+(d.running?'on':'off');

  // Connect-mode summary
  const cm=d.connect_mode||{};
  const tp=d.transparent||{};
  const stratMap={roundRobin:'轮询',leastPing:'最低延迟',random:'随机'};
  let connStr='<span style="color:var(--text2)">未启用</span>';
  if(cm.active){
    const n=cm.selected_tags?cm.selected_tags.length:0;
    const s=cm.strategy?stratMap[cm.strategy]||cm.strategy:'';
    const t=cm.transparent?' · 透明代理':'';
    connStr='<span style="color:var(--green)">'+n+'节点 · '+s+t+'</span>';
  }
  let tpStr='<span style="color:var(--text2)">关闭</span>';
  if(tp.has_iptables)tpStr='<span style="color:var(--green)">运行中</span>';
  else if(tp.has_dokodemo)tpStr='<span style="color:var(--yellow)">配置残留</span>';

  document.getElementById('status-grid').innerHTML=`
    <div class="stat"><div class="label">状态</div><div class="value"><span class="status-pill ${d.running?'active':'inactive'}">${d.running?'运行中':'已停止'}</span></div></div>
    <div class="stat"><div class="label">PID</div><div class="value">${d.pid||'-'}</div></div>
    <div class="stat"><div class="label">内存</div><div class="value">${d.memory||'-'}</div></div>
    <div class="stat"><div class="label">启动时间</div><div class="value" style="font-size:12px">${d.started_at||'-'}</div></div>
    <div class="stat"><div class="label">连接模式</div><div class="value" style="font-size:12px">${connStr}</div></div>
    <div class="stat"><div class="label">透明代理</div><div class="value" style="font-size:12px">${tpStr}</div></div>
    <div class="stat"><div class="label">配置文件</div><div class="value" style="font-size:11px">${d.config_path||'-'}</div></div>
    <div class="stat"><div class="label">二进制</div><div class="value" style="font-size:11px">${d.binary_path||'-'}</div></div>
  `;
  const tb=document.getElementById('listen-tbody');
  tb.innerHTML=(d.listen||[]).map(a=>{
    const parts=a.split(':');
    const port=parts[parts.length-1];
    const tf=tagForPort(parseInt(port));
    return `<tr><td>${a}</td><td><span class="tag ${tf}">${nameForTag(tf)}</span></td></tr>`;
  }).join('');
}

function fmtSpeed(bps){
  if(bps<=0)return '0 B/s';
  if(bps<1024)return bps.toFixed(0)+' B/s';
  if(bps<1048576)return (bps/1024).toFixed(1)+' KB/s';
  if(bps<1073741824)return (bps/1048576).toFixed(1)+' MB/s';
  return (bps/1073741824).toFixed(2)+' GB/s';
}
function fmtBytes(b){
  if(b<1024)return b+' B';
  if(b<1048576)return (b/1024).toFixed(1)+' KB';
  if(b<1073741824)return (b/1048576).toFixed(1)+' MB';
  if(b<1099511627776)return (b/1073741824).toFixed(2)+' GB';
  return (b/1099511627776).toFixed(2)+' TB';
}

let statsTimer=null;
async function loadStats(){
  const d=await api('/api/stats');
  if(!d)return;
  const rx=fmtSpeed(d.total_rx_speed);
  const tx=fmtSpeed(d.total_tx_speed);
  // Update header
  const hdr=document.getElementById('header-stats');
  if(hdr)hdr.textContent='↓ '+rx+' ↑ '+tx;
  // Update status tab detail
  const rxEl=document.getElementById('stat-rx');
  const txEl=document.getElementById('stat-tx');
  if(rxEl)rxEl.textContent=rx;
  if(txEl)txEl.textContent=tx;
  const ifEl=document.getElementById('stats-interfaces');
  if(ifEl){
    ifEl.innerHTML=Object.entries(d.interfaces||{}).map(function(e){
      var name=e[0], info=e[1];
      return '<div style="display:flex;justify-content:space-between;padding:2px 0"><span>'+name+'</span><span>↓'+fmtBytes(info.rx_bytes)+' ↑'+fmtBytes(info.tx_bytes)+'</span></div>';
    }).join('');
  }
}
function startStatsPolling(){
  if(statsTimer)return;
  loadStats();
  statsTimer=setInterval(loadStats,2000);
}
function stopStatsPolling(){
  // Never stop — always show in header
  // if(statsTimer){clearInterval(statsTimer);statsTimer=null;}
}

async function svcAction(action){
  const d=await api('/api/service/'+action,{method:'POST',body:'{}'});
  if(d&&d.success){toast(action+' 成功');setTimeout(loadStatus,500);}
  else toast(action+' 失败',false);
}

async function loadTestUrls(){
  const d=await api('/api/test-urls');
  if(!d)return;
  const sel=document.getElementById('test-url-select');
  if(!sel)return;
  sel.innerHTML=(d.urls||[]).map(u=>`<option value="${u.replace(/"/g,'&quot;')}">${u}</option>`).join('');
}

function currentTestUrl(){
  const custom=(document.getElementById('test-url-custom')?.value||'').trim();
  if(custom)return custom;
  return document.getElementById('test-url-select')?.value || 'https://api.ipify.org';
}

async function saveCurrentTestUrl(){
  const u=currentTestUrl();
  const sel=document.getElementById('test-url-select');
  const urls=Array.from(sel.options).map(o=>o.value);
  if(!urls.includes(u)) urls.unshift(u);
  const d=await api('/api/test-urls',{method:'POST',body:JSON.stringify({urls})});
  if(d&&d.ok){toast('测试 URL 已保存'); loadTestUrls();}
}

async function testInbound(idx){
  const ib=inboundsData[idx];
  const box=document.getElementById('inbound-test-output');
  box.style.display='block';
  box.textContent=`Testing ${ib.tag} ${ib.listen}:${ib.port} -> ${currentTestUrl()} ...`;
  const d=await api('/api/inbounds/test',{method:'POST',body:JSON.stringify({tag:ib.tag,url:currentTestUrl()})});
  if(!d){box.textContent+='\n请求失败';return;}
  const status=d.ok?'OK':'FAILED';
  box.textContent=`[${status}] ${d.tag} via ${d.proxy} -> ${d.url}\nHTTP: ${d.http_code || '-'}  time: ${d.time_total || '-'}s  exit: ${d.exit_code}\n\nSTDOUT:\n${d.stdout || ''}\n\nSTDERR:\n${d.stderr || ''}`;
}

async function loadInbounds(){
  const d=await api('/api/inbounds');
  if(!d)return;
  inboundsData=d.inbounds||[];
  inboundRouteMap={};
  const rout=(d.routing||{});
  if(rout&&rout.rules){
    rout.rules.forEach(r=>{
      if(r.inboundTag){
        const dest=r.balancerTag||r.outboundTag||'?';
        r.inboundTag.forEach(t=>{inboundRouteMap[t]=dest;});
      }
    });
  }
  const tb=document.getElementById('inbounds-tbody');
  tb.innerHTML=inboundsData.map((ib,i)=>{
    const ob=inboundRouteMap[ib.tag]||'-';
    return `<tr>
      <td>${ib.tag}</td>
      <td>${ib.protocol}</td>
      <td>${ib.listen||'0.0.0.0'}</td>
      <td>${ib.port}</td>
      <td><span class="tag ${tagForPort(ib.port)}">${ob}</span></td>
      <td><button class="btn primary" onclick="testInbound(${i})">测试</button> <button class="btn" onclick="editInbound(${i})">编辑</button></td>
    </tr>`;
  }).join('');
}

function editInbound(idx){
  editingIdx=idx;
  const ib=inboundsData[idx];
  document.getElementById('modal-inbound-title').textContent='编辑入站';
  document.getElementById('btn-delete-inbound').style.display='';
  document.getElementById('ei-tag').value=ib.tag||'';
  document.getElementById('ei-protocol').value=ib.protocol||'socks';
  document.getElementById('ei-listen').value=ib.listen||'0.0.0.0';
  document.getElementById('ei-port').value=ib.port||'';
  document.getElementById('ei-udp').value=(ib.settings&&ib.settings.udp)?'true':'false';
  document.getElementById('ei-sniff').value=(ib.sniffing&&ib.sniffing.enabled)?'true':'false';
  loadOutboundSelector(inboundRouteMap[ib.tag]||'');
  document.getElementById('modal-edit-inbound').classList.add('show');
}

function showAddInboundModal(){
  editingIdx=-1;
  document.getElementById('modal-inbound-title').textContent='新增入站';
  document.getElementById('btn-delete-inbound').style.display='none';
  document.getElementById('ei-tag').value='';
  document.getElementById('ei-protocol').value='socks';
  document.getElementById('ei-listen').value='0.0.0.0';
  document.getElementById('ei-port').value='';
  document.getElementById('ei-udp').value='true';
  document.getElementById('ei-sniff').value='true';
  loadOutboundSelector('');
  document.getElementById('modal-edit-inbound').classList.add('show');
}

async function loadOutboundSelector(selected){
  const sel=document.getElementById('ei-outbound');
  // Load outbounds
  const od=await api('/api/outbounds');
  let opts='<option value="">(未绑定)</option>';
  const obTags=[];
  if(od&&od.outbounds){
    od.outbounds.filter(ob=>ob.tag).forEach(ob=>{
      obTags.push(ob.tag);
      opts+=`<option value="${ob.tag}">${ob.tag}</option>`;
    });
  }
  // Load balancers
  const rd=await api('/api/routing');
  if(rd&&rd.routing&&rd.routing.balancers){
    rd.routing.balancers.forEach(b=>{
      opts+=`<option value="bal:${b.tag}">⚖ ${b.tag} (${(b.selector||[]).join(', ')})</option>`;
    });
  }
  sel.innerHTML=opts;
  // Find matching option
  for(const opt of sel.options){
    if(opt.value===selected||opt.value===('bal:'+selected)){opt.selected=true;break;}
  }
}

async function saveEditInbound(){
  const isNew=editingIdx<0;
  const ib=isNew?{}:inboundsData[editingIdx];
  const oldTag=ib.tag||'';
  ib.tag=document.getElementById('ei-tag').value.trim();
  ib.protocol=document.getElementById('ei-protocol').value.trim();
  ib.listen=document.getElementById('ei-listen').value.trim()||'0.0.0.0';
  ib.port=parseInt(document.getElementById('ei-port').value);
  if(!ib.tag||!ib.port){toast('Tag 和端口必填',false);return;}
  if(!ib.settings)ib.settings={};
  ib.settings.udp=document.getElementById('ei-udp').value==='true';
  if(ib.protocol==='socks'){ib.settings.auth='noauth';}
  if(!ib.sniffing)ib.sniffing={};
  ib.sniffing.enabled=document.getElementById('ei-sniff').value==='true';
  ib.sniffing.destOverride=['http','tls','quic'];
  const selVal=document.getElementById('ei-outbound').value||'';
  if(isNew){
    inboundsData.push(ib);
  }
  // Handle bal: prefix
  if(selVal.startsWith('bal:')){
    inboundRouteMap[ib.tag]=selVal.slice(4);
  } else {
    inboundRouteMap[ib.tag]=selVal;
  }
  if(oldTag&&oldTag!==ib.tag){
    delete inboundRouteMap[oldTag];
  }
  closeModal('modal-edit-inbound');
  await saveInbounds();
  await loadInbounds();
}

async function deleteInbound(){
  if(editingIdx<0)return;
  const ib=inboundsData[editingIdx];
  if(!confirm('确定删除入站 '+ib.tag+'?'))return;
  delete inboundRouteMap[ib.tag];
  inboundsData.splice(editingIdx,1);
  closeModal('modal-edit-inbound');
  await saveInbounds();
  await loadInbounds();
}

async function saveInbounds(){
  const rd=await api('/api/routing');
  let routing=(rd&&rd.routing)||{rules:[]};
  const rules=(routing.rules||[]).filter(r=>!(r.inboundTag&&r.inboundTag.some(t=>inboundsData.some(ib=>ib.tag===t))));
  for(const ib of inboundsData){
    const out=inboundRouteMap[ib.tag];
    if(out){
      const rule={type:'field', inboundTag:[ib.tag]};
      // Check if it's a balancer
      if(routing.balancers&&routing.balancers.some(b=>b.tag===out)){
        rule.balancerTag=out;
      } else {
        rule.outboundTag=out;
      }
      rules.unshift(rule);
    }
  }
  routing.rules=rules;
  const d=await api('/api/inbounds',{method:'POST',body:JSON.stringify({inbounds:inboundsData,routing})});
  if(d&&d.ok){toast('入站已保存'+(d.restart&&d.restart.success?'，Xray 已重启':''));}
}

function renderOutbounds(){
  const tb=document.getElementById('outbounds-tbody');
  // Sort: proxy nodes first, system outbounds (freedom/blackhole/dns) last
  const sorted=outboundsData.map((ob,i)=>({ob,i})).sort((a,b)=>{
    const sa=(a.ob.protocol==='freedom'||a.ob.protocol==='blackhole'||a.ob.protocol==='dns')?1:0;
    const sb=(b.ob.protocol==='freedom'||b.ob.protocol==='blackhole'||b.ob.protocol==='dns')?1:0;
    return sa-sb;
  });
  tb.innerHTML=sorted.map(({ob,i})=>{
    let addr='-', port='-', net='-';
    try{
      const v=ob.settings&&ob.settings.vnext&&ob.settings.vnext[0];
      const s=ob.settings&&ob.settings.servers&&ob.settings.servers[0];
      const src=v||s;
      if(src){addr=src.address||'-'; port=src.port||'-';}
      net=(ob.streamSettings&&ob.streamSettings.network)||'-';
    }catch(e){}
    const delay=ob._delay||'-';
    const speed=ob._speed||'-';
    const p=ob.protocol||'';
    const isSystem=p==='freedom'||p==='blackhole';
    const isDns=p==='dns';
    const rowCls=isSystem?' class="ob-system"':isDns?' class="ob-system"':'';
    const protoLabel=p==='freedom'?'direct':p==='blackhole'?'block':p;
    if(isSystem){
      return `<tr${rowCls}>
        <td></td>
        <td><span style="opacity:.7">${ob.tag||'-'}</span></td>
        <td><span style="opacity:.5">${protoLabel}</span></td>
        <td colspan="5" style="opacity:.4;font-size:11px">${p==='freedom'?'直连出口':'丢弃出口'}</td>
        <td><button class="btn" onclick="editOutbound(${i})">编辑</button></td>
      </tr>`;
    }
    if(isDns){
      return `<tr${rowCls}>
        <td></td>
        <td><span style="opacity:.7">${ob.tag||'-'}</span></td>
        <td><span style="opacity:.5">dns</span></td>
        <td colspan="5" style="opacity:.4;font-size:11px">DNS出口</td>
        <td><button class="btn" onclick="editOutbound(${i})">编辑</button></td>
      </tr>`;
    }
    const addrTip=addr!=='-'?` title="${addr}:${port}"`:'';
    return `<tr>
      <td><input type="checkbox" class="ob-check" data-idx="${i}"></td>
      <td>${ob.tag||'-'}</td><td>${p}</td><td class="ob-addr"${addrTip}>${addr}</td><td>${port}</td><td>${net}</td>
      <td id="ob-delay-${i}" style="color:var(--green)">${delay}</td><td id="ob-speed-${i}" style="color:var(--yellow)">${speed}</td>
      <td><div class="ob-actions"><button class="btn primary" onclick="testOutbound(${i})">延迟</button><button class="btn" onclick="speedtestOutbound(${i})">测速</button><button class="btn" onclick="editOutbound(${i})">编辑</button><button class="btn" onclick="exportOutbound(${i})">导出</button><button class="btn danger" onclick="deleteOutbound(${i})">删除</button></div></td>
    </tr>`;
  }).join('');
}

async function loadObTestUrls(){
  const d=await api('/api/test-urls');
  if(!d)return;
  const sel=document.getElementById('ob-test-url-select');
  if(!sel)return;
  sel.innerHTML=(d.urls||[]).map(u=>`<option value="${u.replace(/"/g,'&quot;')}">${u}</option>`).join('');
}

function obTestUrl(){
  const custom=(document.getElementById('ob-test-url-custom')?.value||'').trim();
  if(custom)return custom;
  return document.getElementById('ob-test-url-select')?.value || 'https://api.ipify.org';
}

function toggleSelectAll(checked){
  document.querySelectorAll('.ob-check').forEach(cb=>cb.checked=checked);
}

function getSelectedIndices(){
  const cbs=document.querySelectorAll('.ob-check:checked');
  if(!cbs.length) return null;  // null = all
  return Array.from(cbs).map(cb=>parseInt(cb.dataset.idx));
}

async function batchTestSelected(mode){
  const sel=getSelectedIndices();
  const tags=sel
    ? sel.map(i=>outboundsData[i]).filter(ob=>ob.protocol&&ob.protocol!=='freedom'&&ob.protocol!=='blackhole').map(ob=>ob.tag)
    : outboundsData.filter(ob=>ob.protocol&&ob.protocol!=='freedom'&&ob.protocol!=='blackhole').map(ob=>ob.tag);
  if(!tags.length){toast('没有可测试的节点',false);return;}
  const doSpeed=mode==='speed';
  const box=document.getElementById('outbound-test-output');
  box.style.display='block';
  box.textContent='Batch '+(doSpeed?'speedtest':'latency')+' ('+tags.length+' nodes)...\nStarting temp Xray...';
  const d=await api('/api/outbounds/batch-test',{method:'POST',body:JSON.stringify({tags,url:obTestUrl(),speed_url:document.getElementById('ob-speed-url').value.trim(),mode:doSpeed?'speed':'ping'})});
  if(!d||!d.ok){box.textContent='Failed: '+(d&&d.error||'unknown');return;}
  let lines=['=== '+(doSpeed?'Speed Test':'Latency Test')+' ('+d.count+' nodes) ===',''];
  for(const r of d.results){
    const idx=outboundsData.findIndex(ob=>ob.tag===r.tag);
    if(idx>=0){
      if(r.ping_ok){
        outboundsData[idx]._delay=r.ping_ms?sprintf(r.ping_ms)+'s':'-';
        const el=document.getElementById('ob-delay-'+idx);
        if(el)el.textContent=outboundsData[idx]._delay;
      }
      if(doSpeed&&r.speed_ok){
        outboundsData[idx]._speed=r.speed_mbps?r.speed_mbps+' Mbps':'-';
        const el=document.getElementById('ob-speed-'+idx);
        if(el)el.textContent=outboundsData[idx]._speed;
      }
    }
    const tag=(r.tag||'').padEnd(18);
    const ping=r.ping_ok?(parseFloat(r.ping_ms).toFixed(0)+'ms').padStart(8):'    FAIL';
    const ip=(r.exit_ip||'-').slice(0,18).padStart(18);
    const speed=doSpeed&&r.speed_ok?(r.speed_mbps+' Mbps').padStart(12):'          - ';
    lines.push(tag+ping+ip+speed+(r.ping_ok?' OK':' FAIL'));
  }
  box.textContent=lines.join('\n');
}

function sprintf(v){return parseFloat(v).toFixed(0);}

async function testOutbound(idx){
  const ob=outboundsData[idx];
  if(!ob){toast('节点数据异常',false);return;}
  const box=document.getElementById('outbound-test-output');
  box.style.display='block';
  let addr='-';
  try{const v=ob.settings.vnext[0];addr=v.address+':'+v.port;}catch(e){}
  box.textContent=`Testing ${ob.tag} (${addr}) ...\nStarting temp Xray...`;
  const d=await api('/api/outbounds/test',{method:'POST',body:JSON.stringify({outbound:ob,url:obTestUrl(),type:'ping'})});
  if(!d){box.textContent+='\n请求失败';return;}
  if(!d.ok){
    box.textContent=`[FAILED] ${d.tag} (${d.outbound_addr||addr})\nError: ${d.error||''}\n${d.detail||''}`;
    return;
  }
  box.textContent=`[OK] ${d.tag} (${d.outbound_addr||addr})\nHTTP: ${d.http_code||'-'}  latency: ${d.time_total||'-'}s\nExit IP: ${d.stdout||'(empty)'}`;
}

async function speedtestOutbound(idx){
  const ob=outboundsData[idx];
  if(!ob){toast('节点数据异常',false);return;}
  const box=document.getElementById('outbound-test-output');
  box.style.display='block';
  let addr='-';
  try{const v=ob.settings.vnext[0];addr=v.address+':'+v.port;}catch(e){}
  const speedUrl=document.getElementById('ob-speed-url').value.trim()||'https://speed.cloudflare.com/__down?bytes=10000000';
  box.textContent=`Speedtest ${ob.tag} (${addr}) ...\nDownloading: ${speedUrl}\nStarting temp Xray...`;
  const d=await api('/api/outbounds/test',{method:'POST',body:JSON.stringify({outbound:ob,url:speedUrl,type:'speed'})});
  if(!d){box.textContent+='\n请求失败';return;}
  if(!d.ok){
    box.textContent=`[FAILED] ${d.tag}\nError: ${d.error||''}\n${d.detail||''}`;
    return;
  }
  box.textContent=`[OK] ${d.tag} (${d.outbound_addr||addr})\nSpeed: ${d.speed_mbps||0} Mbps (${(d.bytes/1024/1024).toFixed(1)} MB in ${d.time_total}s)\nHTTP: ${d.http_code||'-'}`;
}



async function loadOutbounds(){
  const d=await api('/api/outbounds');
  if(!d)return;
  outboundsData=d.outbounds||[];
  renderOutbounds();
}

function outboundToForm(ob){
  const p=ob.protocol||'vless';
  document.getElementById('of-tag').value=ob.tag||'';
  document.getElementById('of-protocol').value=p;
  let address='', port='', ident='', sec='';
  try{
    if(p==='shadowsocks'){
      const s=ob.settings.servers[0]; address=s.address||''; port=s.port||''; ident=s.password||''; sec=s.method||'';
    }else if(p==='trojan'){
      const s=ob.settings.servers[0]; address=s.address||''; port=s.port||''; ident=s.password||'';
    }else{
      const v=ob.settings.vnext[0]; const u=v.users[0]||{}; address=v.address||''; port=v.port||''; ident=u.id||''; sec=u.security||u.encryption||''; document.getElementById('of-flow').value=u.flow||'';
    }
  }catch(e){}
  document.getElementById('of-address').value=address;
  document.getElementById('of-port').value=port;
  document.getElementById('of-id').value=ident;
  document.getElementById('of-security').value=sec;
  const ss=ob.streamSettings||{};
  document.getElementById('of-network').value=ss.network||'tcp';
  document.getElementById('of-tls-mode').value=ss.security||'none';
  const tls=ss.tlsSettings||ss.realitySettings||{};
  document.getElementById('of-sni').value=tls.serverName||'';
  document.getElementById('of-fp').value=tls.fingerprint||'';
  document.getElementById('of-alpn').value=Array.isArray(tls.alpn)?tls.alpn.join(','):'';
  document.getElementById('of-insecure').value=(tls.allowInsecure?'true':'false');
  document.getElementById('of-ech').value=tls.echConfigList||'';
  const ws=ss.wsSettings||{};
  document.getElementById('of-host').value=ws.host || (ws.headers&&ws.headers.Host) || '';
  document.getElementById('of-path').value=ws.path||'';
  const mux=ob.mux||{};
  document.getElementById('of-mux').value=(mux.enabled?'on':'off');
}

function formToOutbound(){
  const protocol=document.getElementById('of-protocol').value;
  const tag=document.getElementById('of-tag').value.trim()||'new-node';
  const address=document.getElementById('of-address').value.trim();
  const port=parseInt(document.getElementById('of-port').value||'0');
  const ident=document.getElementById('of-id').value.trim();
  const sec=document.getElementById('of-security').value.trim();
  const flow=document.getElementById('of-flow').value.trim();
  const network=document.getElementById('of-network').value;
  const tlsMode=document.getElementById('of-tls-mode').value;
  const sni=document.getElementById('of-sni').value.trim();
  const host=document.getElementById('of-host').value.trim();
  const path=document.getElementById('of-path').value.trim()||'/';
  const fp=document.getElementById('of-fp').value.trim();
  const alpn=document.getElementById('of-alpn').value.trim();
  const allowInsecure=document.getElementById('of-insecure').value==='true';
  const ech=document.getElementById('of-ech').value.trim();
  const muxOn=document.getElementById('of-mux').value==='on';
  let ob={tag, protocol};
  if(protocol==='shadowsocks'){
    ob.settings={servers:[{address, port, method:sec||'aes-128-gcm', password:ident, ota:false, level:1}]};
  }else if(protocol==='trojan'){
    ob.settings={servers:[{address, port, password:ident}]};
  }else if(protocol==='vmess'){
    ob.settings={vnext:[{address, port, users:[{id:ident, alterId:0, security:sec||'auto'}]}]};
  }else {
    const user={id:ident, encryption:sec||'none'}; if(flow) user.flow=flow;
    ob.settings={vnext:[{address, port, users:[user]}]};
  }
  ob.streamSettings={network, security:tlsMode};
  if(tlsMode==='tls'){
    ob.streamSettings.tlsSettings={serverName:sni||host||address, allowInsecure};
    if(fp) ob.streamSettings.tlsSettings.fingerprint=fp;
    if(alpn) ob.streamSettings.tlsSettings.alpn=alpn.split(',').map(s=>s.trim()).filter(Boolean);
    if(ech){ ob.streamSettings.tlsSettings.echConfigList=ech; ob.streamSettings.tlsSettings.echForceQuery='full'; }
  }else if(tlsMode==='reality'){
    ob.streamSettings.realitySettings={serverName:sni||host||address};
    if(fp) ob.streamSettings.realitySettings.fingerprint=fp;
  }
  if(network==='ws'){
    ob.streamSettings.wsSettings={host, path, headers:{}};
  }else if(network==='grpc'){
    ob.streamSettings.grpcSettings={serviceName:path==='/'?'':path};
  }else if(network==='xhttp'){
    ob.streamSettings.xhttpSettings={path};
  }
  if(muxOn) ob.mux={enabled:true, concurrency:8};
  else if(protocol==='shadowsocks') ob.mux={enabled:false, concurrency:-1};
  return ob;
}

function saveFormOutbound(){
  try{
    const ob=formToOutbound();
    document.getElementById('eo-json').value=JSON.stringify(ob,null,2);
    switchObModalTab('json');
    toast('已根据表单生成 JSON');
  }catch(e){ toast('表单生成失败: '+e.message,false); }
}

function showAddOutboundModal(){
  editingOutboundIdx=-1;
  document.getElementById('modal-ob-title').textContent='新增节点';
  document.getElementById('vless-link').value='';
  document.getElementById('eo-json').value=JSON.stringify({tag:'new-proxy',protocol:'vless',settings:{vnext:[{address:'example.com',port:443,users:[{id:'UUID',encryption:'none'}]}]},streamSettings:{network:'ws',security:'tls',tlsSettings:{serverName:'example.com',allowInsecure:false},wsSettings:{host:'example.com',path:'/'}}}, null, 2);
  outboundToForm(JSON.parse(document.getElementById('eo-json').value));
  switchObModalTab('link');
  document.getElementById('modal-outbound').classList.add('show');
}

function editOutbound(idx){
  editingOutboundIdx=idx;
  document.getElementById('modal-ob-title').textContent='编辑出站 JSON';
  document.getElementById('eo-json').value=JSON.stringify(outboundsData[idx], null, 2);
  outboundToForm(outboundsData[idx]);
  switchObModalTab('form');
  document.getElementById('modal-outbound').classList.add('show');
}

function switchObModalTab(tab){
  const isLink=tab==='link';
  const isForm=tab==='form';
  document.getElementById('mob-tab-link').className='tab'+(isLink?' active':'');
  document.getElementById('mob-tab-form').className='tab'+(isForm?' active':'');
  document.getElementById('mob-tab-json').className='tab'+((!isLink&&!isForm)?' active':'');
  document.getElementById('mob-pane-link').style.display=isLink?'block':'none';
  document.getElementById('mob-pane-form').style.display=isForm?'block':'none';
  document.getElementById('mob-pane-json').style.display=(!isLink&&!isForm)?'block':'none';
}

function saveEditOutbound(){
  let ob;
  try{ ob=JSON.parse(document.getElementById('eo-json').value); }catch(e){ toast('JSON 解析失败: '+e.message,false); return; }
  if(editingOutboundIdx>=0) outboundsData[editingOutboundIdx]=ob; else outboundsData.push(ob);
  closeModal('modal-outbound');
  renderOutbounds();
  saveOutbounds();
}

function deleteOutbound(idx){
  if(!confirm('确认删除 outbound: '+(outboundsData[idx].tag||idx)+' ?')) return;
  outboundsData.splice(idx,1);
  renderOutbounds();
}

async function parseAndAddVless(){
  const raw=document.getElementById('vless-link').value.trim();
  if(!raw){toast('请输入节点链接',false);return;}
  const tfo=document.getElementById('modal-tfo')?.checked||false;
  const lines=raw.split('\n').map(l=>l.trim()).filter(l=>l&&l.includes('://'));
  if(!lines.length){toast('未识别到有效链接',false);return;}
  let added=0;
  for(const link of lines){
    const d=await api('/api/outbounds/parse-vless',{method:'POST',body:JSON.stringify({link,tfo})});
    if(d&&d.outbound){outboundsData.push(d.outbound);added++;}
  }
  closeModal('modal-outbound');
  renderOutbounds();
  if(!added){toast('解析失败',false);return;}
  // auto-save + restart
  const s=await api('/api/outbounds',{method:'POST',body:JSON.stringify({outbounds:outboundsData})});
  if(s&&s.ok) toast('已添加 '+added+' 个节点并保存'+(s.restart&&s.restart.success?'，Xray 已重启':''));
  else toast('已解析但保存失败，请手动点保存',false);
}

async function saveOutbounds(){
  const d=await api('/api/outbounds',{method:'POST',body:JSON.stringify({outbounds:outboundsData})});
  if(d&&d.ok)toast('出站已保存'+(d.restart&&d.restart.success?'，Xray 已重启':''));
}

// --- Export: outbound config -> share link ---
function outboundToShareLink(ob){
  const p=ob.protocol||'';
  const ss=ob.streamSettings||{};
  const net=ss.network||'tcp';
  const sec=ss.security||'none';
  try{
    if(p==='vless'){
      const v=ob.settings.vnext[0]; const u=v.users[0];
      let link='vless://'+encodeURIComponent(u.id)+'@'+v.address+':'+v.port;
      const params=[];
      if(u.encryption&&u.encryption!=='none') params.push('encryption='+u.encryption);
      if(u.flow) params.push('flow='+u.flow);
      if(sec&&sec!=='none') params.push('security='+sec);
      if(sec==='tls'){
        const tls=ss.tlsSettings||{};
        if(tls.serverName) params.push('sni='+tls.serverName);
        if(tls.fingerprint) params.push('fp='+tls.fingerprint);
        if(tls.alpn&&tls.alpn.length) params.push('alpn='+tls.alpn.join(','));
        if(tls.allowInsecure) params.push('allowInsecure=1');
        if(tls.echConfigList) params.push('ech='+tls.echConfigList);
      }else if(sec==='reality'){
        const r=ss.realitySettings||{};
        if(r.serverName) params.push('sni='+r.serverName);
        if(r.fingerprint) params.push('fp='+r.fingerprint);
        if(r.publicKey) params.push('pbk='+r.publicKey);
        if(r.shortId) params.push('sid='+r.shortId);
        if(r.spiderX) params.push('spx='+r.spiderX);
      }
      if(net&&net!=='tcp') params.push('type='+net);
      if(net==='ws'){
        const ws=ss.wsSettings||{};
        if(ws.path) params.push('path='+encodeURIComponent(ws.path));
        if(ws.headers&&ws.headers.Host) params.push('host='+ws.headers.Host);
      }else if(net==='grpc'){
        const g=ss.grpcSettings||{};
        if(g.serviceName) params.push('serviceName='+g.serviceName);
      }else if(net==='xhttp'){
        const x=ss.xhttpSettings||{};
        if(x.path) params.push('path='+encodeURIComponent(x.path));
      }
      if(params.length) link+='?'+params.join('&');
      link+='#'+encodeURIComponent(ob.tag||'');
      return link;
    }
    if(p==='vmess'){
      const v=ob.settings.vnext[0]; const u=v.users[0];
      const obj={
        v:'2', ps:ob.tag||'', add:v.address, port:String(v.port),
        id:u.id, aid:String(u.alterId||0), scy:u.security||'auto',
        net:net, type:'none', host:'', path:'', tls:sec||'none', sni:''
      };
      if(ss.tlsSettings){
        if(ss.tlsSettings.serverName) obj.sni=ss.tlsSettings.serverName;
        if(ss.tlsSettings.fingerprint) obj.fp=ss.tlsSettings.fingerprint;
        if(ss.tlsSettings.alpn) obj.alpn=ss.tlsSettings.alpn.join(',');
        if(ss.tlsSettings.allowInsecure) obj.insecure='1';
      }
      if(net==='ws'){
        const ws=ss.wsSettings||{};
        obj.path=ws.path||'/';
        if(ws.headers&&ws.headers.Host) obj.host=ws.headers.Host;
      }else if(net==='grpc'){
        const g=ss.grpcSettings||{};
        obj.path=g.serviceName||'';
      }else if(net==='h2'||net==='http'){
        const h=ss.httpSettings||{};
        obj.path=h.path||'/';
        if(h.host&&h.host.length) obj.host=h.host[0];
      }
      const jsonStr=JSON.stringify(obj);
      return 'vmess://'+btoa(jsonStr);
    }
    if(p==='shadowsocks'){
      const s=ob.settings.servers[0];
      const mp=s.method+':'+s.password;
      return 'ss://'+btoa(mp)+'@'+s.address+':'+s.port+'#'+encodeURIComponent(ob.tag||'');
    }
    if(p==='trojan'){
      const s=ob.settings.servers[0];
      let link='trojan://'+encodeURIComponent(s.password)+'@'+s.address+':'+s.port;
      const params=[];
      if(sec&&sec!=='none'&&sec!=='tls') params.push('security='+sec);
      if(ss.tlsSettings){
        if(ss.tlsSettings.serverName) params.push('sni='+ss.tlsSettings.serverName);
        if(ss.tlsSettings.fingerprint) params.push('fp='+ss.tlsSettings.fingerprint);
        if(ss.tlsSettings.allowInsecure) params.push('allowInsecure=1');
      }
      if(net&&net!=='tcp') params.push('type='+net);
      if(net==='ws'){
        const ws=ss.wsSettings||{};
        if(ws.path) params.push('path='+encodeURIComponent(ws.path));
        if(ws.headers&&ws.headers.Host) params.push('host='+ws.headers.Host);
      }else if(net==='grpc'){
        const g=ss.grpcSettings||{};
        if(g.serviceName) params.push('serviceName='+g.serviceName);
      }
      if(params.length) link+='?'+params.join('&');
      link+='#'+encodeURIComponent(ob.tag||'');
      return link;
    }
  }catch(e){console.error('export error:',e);}
  return null;
}

function exportOutbound(idx){
  const ob=outboundsData[idx];
  if(!ob){toast('节点数据异常',false);return;}
  const link=outboundToShareLink(ob);
  if(!link){toast('不支持导出该协议: '+ob.protocol,false);return;}
  copyToClipboard(link);toast('已复制: '+ob.tag);
  // Also show in a temporary box
  const box=document.getElementById('outbound-test-output');
  box.style.display='block';
  box.textContent='['+ob.tag+'] '+link;
}

function batchExportOutbounds(){
  const sel=getSelectedIndices();
  const indices=sel||outboundsData.map((_,i)=>i);
  const links=[];
  for(const i of indices){
    const ob=outboundsData[i];
    if(!ob.protocol||ob.protocol==='freedom'||ob.protocol==='blackhole'||ob.protocol==='dns') continue;
    const link=outboundToShareLink(ob);
    if(link) links.push(link);
  }
  if(!links.length){toast('没有可导出的代理节点',false);return;}
  const text=links.join('\n');
  copyToClipboard(text);toast('已复制 '+links.length+' 个节点链接');
  const box=document.getElementById('outbound-test-output');
  box.style.display='block';
  box.textContent='=== 已导出 '+links.length+' 个节点 ===\n\n'+text;
}

// --- Import: quick paste area ---
async function quickImportLinks(){
  const raw=(document.getElementById('quick-import-links')?.value||'').trim();
  if(!raw){toast('请粘贴节点链接',false);return;}
  const tfo=document.getElementById('quick-import-tfo')?.checked||false;
  const lines=raw.split('\n').map(l=>l.trim()).filter(l=>l&&l.includes('://'));
  if(!lines.length){toast('未识别到有效链接',false);return;}
  let added=0;
  for(const link of lines){
    const d=await api('/api/outbounds/parse-vless',{method:'POST',body:JSON.stringify({link,tfo})});
    if(d&&d.outbound){outboundsData.push(d.outbound);added++;}
  }
  renderOutbounds();
  if(!added){toast('解析失败',false);return;}
  document.getElementById('quick-import-links').value='';
  const s=await api('/api/outbounds',{method:'POST',body:JSON.stringify({outbounds:outboundsData})});
  if(s&&s.ok) toast('已导入 '+added+' 个节点并保存'+(s.restart&&s.restart.success?'，Xray 已重启':''));
  else toast('已解析但保存失败，请手动点保存',false);
}

async function loadRouting(){
  const d=await api('/api/routing');
  if(!d)return;
  routingData=d.routing||{};
  const rules=routingData.rules||[];
  const tb=document.getElementById('routing-tbody');
  tb.innerHTML=rules.map(r=>{
    let cond='-';
    if(r.inboundTag)cond='入口: '+r.inboundTag.join(', ');
    if(r.domain)cond='域名: '+r.domain.join(', ');
    if(r.ip)cond='IP: '+r.ip.join(', ');
    const ob=r.outboundTag||r.balancerTag||'-';
    return `<tr><td>${r.type||'-'}</td><td style="font-size:11px">${cond}</td><td><span class="tag ${tagForPort(0)}">${ob}</span></td></tr>`;
  }).join('');
}

async function loadDns(){
  const d=await api('/api/dns');
  if(!d)return;
  const dns=d.dns||{};
  const servers=Array.isArray(dns.servers)?dns.servers:[];
  document.getElementById('dns-servers').value=servers.map(s=>typeof s==='string'?s:JSON.stringify(s)).join('\n');
  document.getElementById('dns-hosts').value=dns.hosts?JSON.stringify(dns.hosts,null,2):'';
  document.getElementById('dns-client-ip').value=dns.clientIp||'';
}

async function saveDns(){
  let hosts={};
  const hostsRaw=document.getElementById('dns-hosts').value.trim();
  if(hostsRaw){
    try{hosts=JSON.parse(hostsRaw);}catch(e){toast('hosts JSON 解析失败: '+e.message,false);return;}
  }
  const servers=document.getElementById('dns-servers').value.split('\n').map(s=>s.trim()).filter(Boolean).map(s=>{
    if(s.startsWith('{')){ try{return JSON.parse(s);}catch(e){ return s; } }
    return s;
  });
  const dns={servers};
  if(Object.keys(hosts).length) dns.hosts=hosts;
  const cip=document.getElementById('dns-client-ip').value.trim();
  if(cip) dns.clientIp=cip;
  const d=await api('/api/dns',{method:'POST',body:JSON.stringify({dns})});
  if(d&&d.ok) toast('DNS 已保存'+(d.restart&&d.restart.success?'，Xray 已重启':''));
}

async function loadDnsHosts(){
  const d=await api('/api/dns/hosts');
  if(!d)return;
  document.getElementById('dns-hosts-editor').value=d.text||'';
}

async function saveDnsHosts(){
  const text=document.getElementById('dns-hosts-editor').value;
  const d=await api('/api/dns/hosts',{method:'POST',body:JSON.stringify({text})});
  if(d&&d.ok) toast('Hosts 已保存'+(d.restart&&d.restart.success?'，Xray 已重启':''));
  else if(d&&d.error) toast(d.error,false);
}

async function loadGeoInfo(){
  const d=await api('/api/geo/info');
  if(!d)return;
  document.getElementById('geo-ip-size').textContent=d['geoip.dat']?d['geoip.dat'].size_human:'N/A';
  document.getElementById('geo-site-size').textContent=d['geosite.dat']?d['geosite.dat'].size_human:'N/A';
  document.getElementById('geo-ip-modified').textContent='geoip: '+(d['geoip.dat']?d['geoip.dat'].modified:'N/A');
  document.getElementById('geo-site-modified').textContent='geosite: '+(d['geosite.dat']?d['geosite.dat'].modified:'N/A');
  if(d.urls){
    document.getElementById('geo-ip-url').value=d.urls.geoip||'';
    document.getElementById('geo-site-url').value=d.urls.geosite||'';
  }
}

async function saveGeoUrls(){
  const geoip=document.getElementById('geo-ip-url').value.trim();
  const geosite=document.getElementById('geo-site-url').value.trim();
  const d=await api('/api/geo/urls',{method:'POST',body:JSON.stringify({geoip,geosite})});
  if(d&&d.ok)toast('Geo URL 已保存');
  else toast('保存失败',false);
}

async function updateGeo(){
  const btn=document.getElementById('geo-update-btn');
  const status=document.getElementById('geo-update-status');
  btn.disabled=true;btn.textContent='更新中...';status.textContent='正在下载，请稍候...';
  try{
    const d=await api('/api/geo/update',{method:'POST'});
    if(d&&d.ok){
      status.innerHTML='<span style="color:var(--green)">✓ 更新成功</span>';
      if(d.results){
        for(const[k,v]of Object.entries(d.results)){
          status.innerHTML+=`<br>${k}: ${v.ok?v.size_human||'OK':'失败 - '+v.error}`;
        }
      }
      loadGeoInfo();
    }else{
      status.innerHTML='<span style="color:var(--red)">✗ 更新失败</span>';
      if(d&&d.results){
        for(const[k,v]of Object.entries(d.results)){
          if(!v.ok)status.innerHTML+=`<br>${k}: ${v.error}`;
        }
      }
    }
  }catch(e){status.innerHTML='<span style="color:var(--red)">✗ 请求异常: '+e.message+'</span>';}
  finally{btn.disabled=false;btn.textContent='更新 GeoIP/GeoSite';}
}

async function loadConfig(){
  const d=await api('/api/config');
  if(!d)return;
  configData=d.config;
  document.getElementById('config-editor').value=d.config;
}

async function saveConfig(){
  const val=document.getElementById('config-editor').value;
  const d=await api('/api/config',{method:'POST',body:JSON.stringify({config:val})});
  if(d&&d.ok)toast('配置已保存'+(d&&d.restart&&d.restart.success?'，Xray 已重启':''));
  else toast('保存失败',false);
}

async function testConfig(){
  const d=await api('/api/config/test');
  if(d)toast(d.ok?'配置校验通过':'配置校验失败: '+d.output.slice(0,200),d.ok);
}

async function changeToken(){
  const old=document.getElementById('token-old').value.trim();
  const nw=document.getElementById('token-new').value.trim();
  const cf=document.getElementById('token-confirm').value.trim();
  if(!old||!nw||!cf){toast('请填写所有字段',false);return;}
  const d=await api('/api/token',{method:'POST',body:JSON.stringify({old,new:nw,confirm:cf})});
  if(!d){toast('请求失败',false);return;}
  if(d.error){toast(d.error,false);return;}
  toast(d.message||'Token 已修改');
  token=nw;
  localStorage.setItem('xray_token',token);
  document.getElementById('token-old').value='';
  document.getElementById('token-new').value='';
  document.getElementById('token-confirm').value='';
}

async function loadLogs(n){
  const d=await api('/api/logs?lines='+n);
  if(!d)return;
  document.getElementById('log-box').textContent=d.logs;
  const box=document.getElementById('log-box');
  box.scrollTop=box.scrollHeight;
}

async function loadBackups(){
  const d=await api('/api/backups');
  if(!d)return;
  const el=document.getElementById('backup-list');
  if(!d.backups.length){el.innerHTML='<p style="color:var(--text2)">暂无备份</p>';return;}
  el.innerHTML=d.backups.map(p=>`<div class="backup-item"><span>${p.split('/').pop()}</span><button class="btn" onclick="restoreBackup('${p}')">恢复</button></div>`).join('');
}

function restoreBackup(path){
  restoreTarget=path;
  document.getElementById('restore-path').textContent=path;
  document.getElementById('modal-restore').classList.add('show');
}

async function confirmRestore(){
  closeModal('modal-restore');
  const d=await api('/api/restore',{method:'POST',body:JSON.stringify({path:restoreTarget})});
  if(d&&d.ok)toast('已恢复');
}

function closeModal(id){document.getElementById(id).classList.remove('show')}

// init
loadStatus();
startStatsPolling();

// Transparent proxy
async function loadBypass(){
  const d=await api("/api/transparent/bypass");
  if(!d)return;
  document.getElementById("tp-default-cidrs").value=(d.defaults||[]).join("\n");
  document.getElementById("tp-auto-cidrs").value=(d.auto||[]).join("\n");
  document.getElementById("tp-custom-cidrs").value=(d.custom||[]).join("\n");
}
async function tpSaveBypass(){
  const raw=document.getElementById("tp-custom-cidrs").value;
  const cidrs=raw.split("\n").map(s=>s.trim()).filter(s=>s);
  const box=document.getElementById("tp-output");box.style.display="block";box.textContent="Saving bypass rules...";
  const d=await api("/api/transparent/bypass",{method:"POST",body:JSON.stringify({custom:cidrs})});
  if(!d||!d.ok){box.textContent="Failed: "+(d&&d.error||"unknown");return;}
  box.textContent="Bypass rules saved. "+(d.reloaded?"iptables reloaded.":"");
  loadBypass();
}
async function loadTransparent(){
  const d=await api("/api/transparent/status");
  if(!d)return;
  const on=d.enabled&&d.iptables_active;
  document.getElementById("tp-dot").className="dot "+(on?"on":"off");
  document.getElementById("tp-status").innerHTML='<span class="status-pill '+(on?"active":"inactive")+'">'+(on?"已启用":"未启用")+'</span>';
  document.getElementById("tp-port").textContent=d.port||"-";
  document.getElementById("tp-chains").textContent=d.iptables_active?"active":"none";
  const od=await api("/api/outbounds");
  if(od&&od.outbounds){
    const sel=document.getElementById("tp-proxy-tag");
    sel.innerHTML=od.outbounds.filter(ob=>ob.protocol&&ob.protocol!=="freedom"&&ob.protocol!=="blackhole"&&ob.protocol!=="dns").map(ob=>'<option value="'+ob.tag+'">'+ob.tag+'</option>').join("");
  }
  loadBypass();
  loadBalancer();
}
async function tpEnable(){
  const box=document.getElementById("tp-output");box.style.display="block";
  box.textContent="Enabling...";
  const d=await api("/api/transparent/enable",{method:"POST",body:JSON.stringify({port:parseInt(document.getElementById("tp-port-input").value),proxy_tag:document.getElementById("tp-proxy-tag").value})});
  if(!d||!d.ok){box.textContent="Failed: "+(d&&d.error||"unknown")+"\n"+(d&&d.detail||"");return;}
  box.textContent="Enabled! Port: "+d.port;
  loadTransparent();
}
async function tpDisable(){
  if(!confirm("确认关闭透明代理？"))return;
  const box=document.getElementById("tp-output");box.style.display="block";box.textContent="Disabling...";
  const d=await api("/api/transparent/disable",{method:"POST",body:"{}"});
  if(!d||!d.ok){box.textContent="Failed";return;}
  box.textContent="Disabled. iptables cleaned.";
  loadTransparent();
}
async function tpRestore(){
  if(!confirm("确认恢复 iptables 备份？"))return;
  const d=await api("/api/transparent/restore-iptables",{method:"POST",body:"{}"});
  const box=document.getElementById("tp-output");box.style.display="block";
  box.textContent=d&&d.ok?"Restored.":"Failed.";
  loadTransparent();
}
async function loadBalancer(){
  const d=await api("/api/transparent/balancer");
  if(!d)return;
  document.getElementById("tp-bal-enabled").checked=!!d.enabled;
  document.getElementById("tp-bal-strategy").value=d.strategy||"roundRobin";
  const nodes=document.getElementById("tp-bal-nodes");
  const tags=d.available_tags||[];
  const selected=new Set(d.tags||[]);
  if(tags.length===0){
    nodes.innerHTML='<span style="color:var(--text2);font-size:12px">无可用代理节点</span>';
  }else{
    nodes.innerHTML=tags.map(t=>'<label style="display:flex;align-items:center;gap:6px;padding:4px 0;cursor:pointer"><input type="checkbox" name="bal-node" value="'+t+'" '+(selected.has(t)?'checked':'')+'><span style="font-size:13px">'+t+'</span></label>').join("");
  }
  // Update mode hint
  const hint=document.getElementById("tp-mode-hint");
  if(hint){
    if(d.enabled&&d.tags&&d.tags.length>0){
      const strMap={roundRobin:"轮询",leastPing:"最低延迟",random:"随机"};
      hint.style.borderLeftColor="var(--green)";
      hint.innerHTML="✅ 启用时将使用 <b>负载均衡</b>："+d.tags.join(", ")+"（"+(strMap[d.strategy]||d.strategy)+"）";
    }else{
      const sel=document.getElementById("tp-proxy-tag");
      const tag=sel?sel.value:"";
      hint.style.borderLeftColor="var(--border)";
      hint.innerHTML="启用时将使用 <b>单节点</b>："+(tag||"未选择")+"（可在下方配置负载均衡）";
    }
  }
}
async function tpSaveBalancer(){
  const enabled=document.getElementById("tp-bal-enabled").checked;
  const strategy=document.getElementById("tp-bal-strategy").value;
  const tags=Array.from(document.querySelectorAll('input[name="bal-node"]:checked')).map(cb=>cb.value);
  if(enabled&&tags.length===0){
    toast("请至少选择一个节点",false);return;
  }
  const box=document.getElementById("tp-output");box.style.display="block";box.textContent="Saving balancer config...";
  const d=await api("/api/transparent/balancer",{method:"POST",body:JSON.stringify({enabled,tags,strategy})});
  if(!d||!d.ok){box.textContent="Failed: "+(d&&d.error||"unknown");return;}
  box.textContent="Balancer saved. "+(d.reloaded?"Xray restarted.":"");
}

// --- Sysctl ---
async function loadSysctl(){
  const d=await api('/api/sysctl');
  if(!d)return;
  const tbody=document.getElementById('sysctl-tbody');
  tbody.innerHTML=d.params.map(p=>{
    const mismatch=p.recommended&&p.value!==p.recommended;
    const style=mismatch?'color:var(--yellow)':'';
    const rec=p.recommended?`<span style="color:var(--text2)">${p.recommended}</span>`:'<span style="color:var(--text2)">—</span>';
    return `<tr>
      <td style="font-family:monospace;font-size:12px">${p.key}</td>
      <td style="color:var(--text2);font-size:12px">${p.desc}</td>
      <td><input class="sysctl-val" data-key="${p.key}" value="${p.value}" style="width:120px;padding:4px;background:var(--bg);color:var(--text);border:1px solid ${mismatch?'var(--yellow)':'var(--border)'};border-radius:4px;font-family:monospace;font-size:12px"></td>
      <td>${rec}</td>
      <td>${mismatch?`<button class="btn" style="font-size:11px;padding:2px 8px" onclick="applyOne('${p.key}','${p.recommended}')">应用</button>`:''}</td>
    </tr>`;
  }).join('');
}
async function saveSysctl(){
  const changes={};
  document.querySelectorAll('.sysctl-val').forEach(inp=>{
    const key=inp.dataset.key;
    const val=inp.value.trim();
    if(val)changes[key]=val;
  });
  if(!Object.keys(changes).length){toast('无修改',false);return;}
  const d=await api('/api/sysctl',{method:'POST',body:JSON.stringify({changes})});
  if(d&&d.ok){toast('已保存'+(d.applied.length?' ('+d.applied.length+'项)':''));loadSysctl();}
  else toast('保存失败: '+(d&&d.error||'unknown'),false);
}
function applyOne(key,val){
  const inp=document.querySelector(`.sysctl-val[data-key="${key}"]`);
  if(inp)inp.value=val;
}
async function applyRecommended(){
  const d=await api('/api/sysctl');
  if(!d)return;
  const changes={};
  d.params.forEach(p=>{if(p.recommended&&p.value!==p.recommended)changes[p.key]=p.recommended;});
  if(!Object.keys(changes).length){toast('全部已是推荐值');return;}
  const r=await api('/api/sysctl',{method:'POST',body:JSON.stringify({changes})});
  if(r&&r.ok){toast('已应用推荐值 ('+r.applied.length+'项)');loadSysctl();}
  else toast('应用失败',false);
}

// ===================== Connect Mode =====================
let connNodes=[];  // [{tag,protocol,address,port,network,selected}]
let connLatency={}; // {tag: {ping_ms, ping_ok, exit_ip, speed_mbps}}

async function loadConnect(){
  const d=await api('/api/connect/status');
  if(!d)return;
  connNodes=d.nodes||[];
  renderConnNodes();
  updateConnStatus(d);
  // Restore settings
  if(d.balancer_strategy)document.getElementById('conn-strategy').value=d.balancer_strategy;
  if(d.transparent_enabled!==undefined){
    document.getElementById('conn-transparent').checked=!!d.transparent_enabled;
    connToggleTp();
  }
  if(d.inbound_socks_port)document.getElementById('conn-port-socks').value=d.inbound_socks_port;
  if(d.inbound_http_port)document.getElementById('conn-port-http').value=d.inbound_http_port;
  if(d.transparent_port)document.getElementById('conn-port-tp').value=d.transparent_port;
  // Load bypass CIDRs + IP forward status
  loadTpBypass();
  loadTpForward();
}

function renderConnNodes(){
  const list=document.getElementById('conn-node-list');
  if(!connNodes.length){
    list.innerHTML='<div style="padding:20px;text-align:center;color:var(--text2)">无可用节点，请先在"出站" tab 添加</div>';
    updateSelectedCount();
    return;
  }
  list.innerHTML=connNodes.map((n,i)=>{
    const lat=connLatency[n.tag];
    const latStr=lat?(lat.ping_ok?(parseFloat(lat.ping_ms)*1000).toFixed(0)+'ms':'FAIL'):'';
    const latColor=lat?(lat.ping_ok?'var(--green)':'var(--red)'):'var(--text2)';
    const speedStr=lat&&lat.speed_mbps?lat.speed_mbps+' Mbps':'';
    return `<div class="conn-node${n.selected?' selected':''}" onclick="connToggle(${i})">
      <input type="checkbox" class="cb" ${n.selected?'checked':''} onclick="event.stopPropagation();connToggle(${i})">
      <span class="tag-col">${n.tag||'-'}</span>
      <span class="proto-col">${n.protocol||'-'}</span>
      <span class="addr-col" title="${n.address}:${n.port}">${n.address||'-'}:${n.port||'-'}</span>
      <span class="proto-col">${n.network||'tcp'}</span>
      <span class="latency-col" style="color:${latColor}">${latStr}</span>
      <span class="latency-col" style="color:var(--yellow)">${speedStr}</span>
      <span class="ob-actions" onclick="event.stopPropagation()">
        <button class="btn primary" onclick="connTestOne(${i})">延迟</button>
        <button class="btn" onclick="connSpeedOne(${i})">测速</button>
        <button class="btn" onclick="connEditNode(${i})">编辑</button>
        <button class="btn" onclick="connExportNode(${i})">导出</button>
        <button class="btn danger" onclick="connDeleteNode(${i})">删除</button>
      </span>
    </div>`;
  }).join('');
  updateSelectedCount();
}

function connToggle(idx){
  connNodes[idx].selected=!connNodes[idx].selected;
  renderConnNodes();
}

function connSelectAll(){
  connNodes.forEach(n=>n.selected=true);
  renderConnNodes();
}
function connClearAll(){
  connNodes.forEach(n=>n.selected=false);
  renderConnNodes();
}

function updateSelectedCount(){
  const cnt=connNodes.filter(n=>n.selected).length;
  document.getElementById('conn-selected-count').textContent='已选: '+cnt+' 个节点'+(cnt>1?' (负载均衡)':'');
}

function updateConnStatus(state){
  const ind=document.getElementById('conn-indicator');
  const txt=document.getElementById('conn-status-text');
  const ep=document.getElementById('conn-endpoints');
  const btnStart=document.getElementById('btn-conn-start');
  const btnStop=document.getElementById('btn-conn-stop');
  const on=state.active&&state.xray_running;
  ind.className='indicator '+(on?'on':'off');

  // Button state: running → only stop; stopped → only start
  if(btnStart)btnStart.disabled=on;
  if(btnStop)btnStop.disabled=!on;
  if(btnStart)btnStart.style.opacity=on?'0.4':'1';
  if(btnStop)btnStop.style.opacity=on?'1':'0.4';

  // Node list and controls: lock when running
  const nodeEls=document.querySelectorAll('#conn-node-list input,#conn-node-list button');
  nodeEls.forEach(el=>{el.disabled=on;el.style.pointerEvents=on?'none':'auto';});
  const ctrlEls=['conn-strategy','conn-port-socks','conn-port-http','conn-port-tp','conn-transparent'];
  ctrlEls.forEach(id=>{const el=document.getElementById(id);if(el)el.disabled=on;});

  if(on){
    const tags=state.selected_tags||[];
    const stratMap={roundRobin:'轮询',leastPing:'最低延迟',random:'随机'};
    const stratStr=state.balancer_strategy&&tags.length>1?' · '+stratMap[state.balancer_strategy]||state.balancer_strategy:'';
    const tpStr=state.transparent_enabled?' · 透明代理':'';
    const dnsStr=state.dns_actual?' · DNS':'';
    txt.innerHTML='<span style="color:var(--green);font-weight:600">已连接</span> ('+tags.length+'节点'+stratStr+tpStr+dnsStr+')';
    const eps=[];
    eps.push('SOCKS5 → 0.0.0.0:'+(state.inbound_socks_port||10810));
    eps.push('HTTP → 0.0.0.0:'+(state.inbound_http_port||10818));
    if(state.transparent_enabled)eps.push('透明 → 0.0.0.0:'+(state.transparent_port||12345));
    ep.textContent=eps.join('  |  ');
  }else if(state.was_active_but_stopped){
    txt.innerHTML='<span style="color:var(--yellow);font-weight:600">已断开</span> (需重新连接)';
    ep.textContent='';
  }else{
    txt.textContent='未连接';
    ep.textContent='';
  }
}

async function connStart(){
  const tags=connNodes.filter(n=>n.selected).map(n=>n.tag);
  if(!tags.length){toast('请至少选择一个节点',false);return;}
  const strategy=document.getElementById('conn-strategy').value;
  const transparent=document.getElementById('conn-transparent').checked;
  const ports={
    socks:parseInt(document.getElementById('conn-port-socks').value)||10810,
    http:parseInt(document.getElementById('conn-port-http').value)||10818,
    transparent:parseInt(document.getElementById('conn-port-tp').value)||12345,
  };
  const box=document.getElementById('conn-test-output');
  box.style.display='block';
  box.textContent='正在启动连接... ('+tags.length+'节点, '+strategy+(transparent?', 透明代理':'')+')\n';
  const d=await api('/api/connect/start',{method:'POST',body:JSON.stringify({tags,strategy,transparent,ports})});
  if(!d||!d.ok){
    box.textContent+='失败: '+(d&&d.error||'unknown')+'\n'+(d&&d.detail||'');
    return;
  }
  box.textContent+='✅ 连接成功!\n';
  box.textContent+='节点: '+(d.state.selected_tags||[]).join(', ')+'\n';
  box.textContent+='SOCKS5: 0.0.0.0:'+ports.socks+'\n';
  box.textContent+='HTTP: 0.0.0.0:'+ports.http+'\n';
  if(transparent)box.textContent+='透明代理: 0.0.0.0:'+ports.transparent+'\n';
  box.textContent+='Xray 重启: '+(d.restart&&d.restart.success?'成功':'失败')+'\n';
  loadConnect();
}

async function connStop(){
  if(!confirm('确认断开连接？'))return;
  const box=document.getElementById('conn-test-output');
  box.style.display='block';
  box.textContent='正在断开...';
  const d=await api('/api/connect/stop',{method:'POST',body:'{}'});
  if(!d||!d.ok){box.textContent='失败';return;}
  box.textContent='✅ 已断开连接\n';
  box.textContent+='Xray 重启: '+(d.restart&&d.restart.success?'成功':'失败')+'\n';
  loadConnect();
}

async function connTestSelected(){
  const tags=connNodes.filter(n=>n.selected).map(n=>n.tag);
  if(!tags.length){toast('请至少选择一个节点',false);return;}
  await connDoTest(tags);
}

async function connTestAll(){
  const tags=connNodes.map(n=>n.tag);
  if(!tags.length){toast('无可用节点',false);return;}
  await connDoTest(tags);
}

async function connDoTest(tags){
  const box=document.getElementById('conn-test-output');
  box.style.display='block';
  box.textContent='测试 '+tags.length+' 个节点延迟...\n启动临时 Xray...';
  const url=connTestUrl();
  const d=await api('/api/connect/test-selected',{method:'POST',body:JSON.stringify({tags,mode:'ping',url})});
  if(!d||!d.ok){
    box.textContent='失败: '+(d&&d.error||'unknown');
    return;
  }
  let lines=['=== 延迟测试 ('+d.count+' nodes) ===',''];
  for(const r of d.results){
    connLatency[r.tag]={ping_ok:r.ping_ok,ping_ms:r.ping_ms,exit_ip:r.exit_ip,speed_mbps:r.speed_mbps||0};
    const tag=(r.tag||'').padEnd(18);
    const ping=r.ping_ok?(parseFloat(r.ping_ms)*1000).toFixed(0)+'ms':'FAIL';
    const ip=(r.exit_ip||'-').slice(0,20);
    lines.push(tag+ping.padStart(8)+'  '+ip+(r.ping_ok?' ✓':' ✗'));
  }
  box.textContent=lines.join('\n');
  renderConnNodes();
}

// Test URL helpers
function connTestUrl(){
  const custom=(document.getElementById('conn-test-url-custom')?.value||'').trim();
  if(custom)return custom;
  return document.getElementById('conn-test-url-select')?.value||'https://api.ipify.org';
}

async function loadConnTestUrls(){
  const d=await api('/api/test-urls');
  if(!d)return;
  const sel=document.getElementById('conn-test-url-select');
  if(!sel)return;
  sel.innerHTML=(d.urls||[]).map(u=>`<option value="${u.replace(/"/g,'&quot;')}">${u}</option>`).join('');
}

// Single node test
async function connTestOne(idx){
  const n=connNodes[idx];
  if(!n)return;
  const box=document.getElementById('conn-test-output');
  box.style.display='block';
  box.textContent=`测试 ${n.tag} ...\n`;
  const d=await api('/api/connect/test-selected',{method:'POST',body:JSON.stringify({tags:[n.tag],mode:'ping',url:connTestUrl()})});
  if(!d||!d.ok){box.textContent+='失败';return;}
  for(const r of d.results){
    connLatency[r.tag]={ping_ok:r.ping_ok,ping_ms:r.ping_ms,exit_ip:r.exit_ip,speed_mbps:r.speed_mbps||0};
    box.textContent+=`${r.tag}: ${r.ping_ok?(parseFloat(r.ping_ms)*1000).toFixed(0)+'ms':'FAIL'}  ${r.exit_ip||''}\n`;
  }
  renderConnNodes();
}

// Speed test
async function connSpeedTest(){
  const tags=connNodes.filter(n=>n.selected).map(n=>n.tag);
  if(!tags.length){toast('请至少选择一个节点',false);return;}
  const speedUrl=(document.getElementById('conn-speed-url')?.value||'').trim()||'https://speed.cloudflare.com/__down?bytes=10000000';
  const box=document.getElementById('conn-test-output');
  box.style.display='block';
  box.textContent='测速 '+tags.length+' 个节点...\n下载: '+speedUrl+'\n启动临时 Xray...';
  const d=await api('/api/connect/test-selected',{method:'POST',body:JSON.stringify({tags,mode:'speed',url:connTestUrl(),speed_url:speedUrl})});
  if(!d||!d.ok){box.textContent+='失败: '+(d&&d.error||'');return;}
  let lines=['=== 测速 ('+d.count+' nodes) ===',''];
  for(const r of d.results){
    connLatency[r.tag]={ping_ok:r.ping_ok,ping_ms:r.ping_ms,exit_ip:r.exit_ip,speed_mbps:r.speed_mbps||0};
    const tag=(r.tag||'').padEnd(18);
    const speed=r.speed_ok?(r.speed_mbps+' Mbps').padStart(12):'      FAIL';
    const ping=r.ping_ok?(parseFloat(r.ping_ms)*1000).toFixed(0)+'ms':'FAIL';
    lines.push(tag+speed+ping.padStart(10));
  }
  box.textContent=lines.join('\n');
  renderConnNodes();
}

// Edit node (reuse outbounds modal)
function connEditNode(idx){
  const n=connNodes[idx];
  if(!n)return;
  // Find the actual outbound data index
  if(typeof outboundsData!=='undefined'){
    const obIdx=outboundsData.findIndex(ob=>ob.tag===n.tag);
    if(obIdx>=0){editOutbound(obIdx);return;}
  }
  toast('请在出站 tab 编辑',false);
}

// Single node speed test
async function connSpeedOne(idx){
  const n=connNodes[idx];
  if(!n)return;
  const speedUrl=(document.getElementById('conn-speed-url')?.value||'').trim()||'https://speed.cloudflare.com/__down?bytes=10000000';
  const box=document.getElementById('conn-test-output');
  box.style.display='block';
  box.textContent=`测速 ${n.tag} ...\n下载: ${speedUrl}\n`;
  const d=await api('/api/connect/test-selected',{method:'POST',body:JSON.stringify({tags:[n.tag],mode:'speed',url:connTestUrl(),speed_url:speedUrl})});
  if(!d||!d.ok){box.textContent+='失败';return;}
  for(const r of d.results){
    connLatency[r.tag]={ping_ok:r.ping_ok,ping_ms:r.ping_ms,exit_ip:r.exit_ip,speed_mbps:r.speed_mbps||0};
    box.textContent+=`${r.tag}: ${r.speed_ok?r.speed_mbps+' Mbps':'FAIL'}  延迟: ${r.ping_ok?(parseFloat(r.ping_ms)*1000).toFixed(0)+'ms':'FAIL'}\n`;
  }
  renderConnNodes();
}

// Export single node
function connExportNode(idx){
  const n=connNodes[idx];
  if(!n)return;
  // Reuse outbounds export if data available
  if(typeof outboundsData!=='undefined'){
    const obIdx=outboundsData.findIndex(ob=>ob.tag===n.tag);
    if(obIdx>=0&&typeof exportOutbound==='function'){exportOutbound(obIdx);return;}
  }
  toast('请在出站 tab 导出',false);
}

// Delete node
async function connDeleteNode(idx){
  const n=connNodes[idx];
  if(!n||!confirm('删除节点 '+n.tag+' ?'))return;
  // Load fresh outbounds, remove this one, save
  const d=await api('/api/outbounds');
  if(!d)return;
  const obs=(d.outbounds||[]).filter(ob=>ob.tag!==n.tag);
  const r=await api('/api/outbounds',{method:'POST',body:JSON.stringify({outbounds:obs})});
  if(r&&r.ok){toast('已删除 '+n.tag);loadConnect();}
  else toast('删除失败',false);
}

// Quick import links
async function connImportLinks(){
  const text=(document.getElementById('conn-import-links')?.value||'').trim();
  if(!text){toast('请粘贴节点链接',false);return;}
  const tfo=document.getElementById('conn-import-tfo')?.checked||false;
  const links=text.split('\n').map(s=>s.trim()).filter(Boolean);
  if(!links.length){toast('无有效链接',false);return;}

  // Parse all links
  const newObs=[];
  for(const link of links){
    try{
      const r=await api('/api/outbounds/parse-vless',{method:'POST',body:JSON.stringify({link,tfo})});
      if(r&&r.outbound)newObs.push(r.outbound);
      else toast('解析失败: '+link.slice(0,40),false);
    }catch(e){toast('解析异常',false);}
  }
  if(!newObs.length)return;

  // Load existing outbounds, append new ones, save
  const d=await api('/api/outbounds');
  if(!d)return;
  const existing=d.outbounds||[];
  // Deduplicate by tag
  const existingTags=new Set(existing.map(ob=>ob.tag));
  for(const ob of newObs){
    let tag=ob.tag;
    let n=1;
    while(existingTags.has(tag)){tag=ob.tag+'-'+n;n++;}
    ob.tag=tag;
    existingTags.add(tag);
    existing.push(ob);
  }
  const r=await api('/api/outbounds',{method:'POST',body:JSON.stringify({outbounds:existing})});
  if(r&&r.ok){
    toast('导入 '+newObs.length+' 个节点');
    document.getElementById('conn-import-links').value='';
    loadConnect();
  }else toast('保存失败',false);
}

// Init connect mode on page load
loadConnect();
loadConnTestUrls();

// Connect tab: transparent proxy helpers
function connToggleTp(){
  const on=document.getElementById('conn-transparent').checked;
  document.getElementById('conn-tp-details').style.display=on?'block':'none';
}

async function loadTpBypass(){
  const d=await api('/api/transparent/bypass');
  if(!d)return;
  const el1=document.getElementById('tp-default-cidrs');
  const el2=document.getElementById('tp-auto-cidrs');
  const el3=document.getElementById('tp-custom-cidrs');
  if(el1)el1.value=(d.defaults||[]).join('\n');
  if(el2)el2.value=(d.auto||[]).join('\n');
  if(el3)el3.value=(d.custom||[]).join('\n');
}

async function loadTpForward(){
  const d=await api('/api/sysctl');
  if(!d)return;
  const fp=d.params&&d.params.find(p=>p.key==='net.ipv4.ip_forward');
  if(fp){
    const el=document.getElementById('tp-ip-forward');
    const st=document.getElementById('tp-forward-status');
    if(el)el.checked=fp.value==='1'||fp.value===1;
    if(st)st.textContent='当前: '+fp.value+(fp.value==='1'?' ✓':'');
  }
}

async function tpToggleForward(on){
  const v=on?'1':'0';
  const r=await api('/api/sysctl',{method:'POST',body:JSON.stringify({changes:{'net.ipv4.ip_forward':v}})});
  if(r&&r.ok)toast('IP 转发: '+(on?'开启':'关闭'));
  else toast('设置失败',false);
  loadTpForward();
}

async function tpSaveBypass(){
  const custom=(document.getElementById('tp-custom-cidrs').value||'').split('\n').map(s=>s.trim()).filter(Boolean);
  const r=await api('/api/transparent/bypass',{method:'POST',body:JSON.stringify({custom})});
  if(r&&r.ok){toast('绕过规则已保存');loadTpBypass();}
  else toast('保存失败',false);
}
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return Response(HTML, content_type="text/html; charset=utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Xray Manager web panel")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--xray-config", default=DEFAULT_XRAY_CFG)
    parser.add_argument("--xray-binary", default=DEFAULT_XRAY_BIN)
    parser.add_argument("--service", default=DEFAULT_SVC_NAME)
    parser.add_argument("--token", default=DEFAULT_TOKEN)
    parser.add_argument("--test-urls-file", default=DEFAULT_TEST_URLS_FILE)
    args = parser.parse_args()

    XRAY_CFG = args.xray_config
    XRAY_BIN = args.xray_binary
    SVC_NAME = args.service
    AUTH_TOKEN = args.token
    TEST_URLS_FILE = args.test_urls_file

    # Load token from file if exists (overrides default, but --token overrides file)
    if not args.token:
        try:
            with open(f"{BASE_DIR}/state/token") as f:
                saved = f.read().strip()
            if saved:
                AUTH_TOKEN = saved
        except Exception:
            pass

    print(f"Xray Manager starting on http://{args.host}:{args.port}")
    print(f"  Xray config: {XRAY_CFG}")
    print(f"  Xray binary: {XRAY_BIN}")
    print(f"  Service: {SVC_NAME}")
    if AUTH_TOKEN:
        print(f"  Auth: enabled (token required)")
    else:
        print(f"  Auth: disabled (open access)")

    # Create required directories
    _init_dirs()

    # Cleanup stale transparent proxy iptables rules on startup
    _tp_startup_cleanup()

    app.run(host=args.host, port=args.port, debug=False)
