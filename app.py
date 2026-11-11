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
import errno
import json
import ipaddress
import re
import os
import subprocess
import threading
import functools
import time
import shlex
import random
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
import base64 as _b64
import urllib.request
import socket

from flask import Flask, jsonify, request, Response
from txt_endpoints import materialize_config
import conntrack_stats as _ct

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
# Code/binaries live in CODE_DIR (baked into image, never mounted).
# All runtime data lives under BASE_DIR (one host volume).
CODE_DIR = "/opt/derwalld"
BASE_DIR = "/root/xray-manager"
DEFAULT_XRAY_BIN = f"{CODE_DIR}/bin/der"
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
QUIC_REJECT_PORT = 9  # udp "discard": nothing listens there, so the kernel replies port-unreachable
CUSTOM_BYPASS_FILE = f"{BASE_DIR}/state/transparent-bypass.json"
BALANCER_CONFIG_FILE = f"{BASE_DIR}/state/balancer-config.json"
CONNECT_STATE_FILE = f"{BASE_DIR}/state/connect-mode.json"
DNS_STATE_FILE = f"{BASE_DIR}/state/dns-config.json"
CUSTOM_RULES_FILE = f"{BASE_DIR}/state/custom-rules.json"
TOKEN_FILE = f"{BASE_DIR}/state/token"
GEOIP_PATH = f"{BASE_DIR}/data/geoip.dat"
GEOSITE_PATH = f"{BASE_DIR}/data/geosite.dat"
GEO_CDN_PREFIX = "https://hub.543083.xyz/"
GEO_URLS_FILE = f"{BASE_DIR}/state/geo-urls.json"
ACCESS_LOG_FILE = f"{BASE_DIR}/logs/access.log"
ERROR_LOG_FILE = f"{BASE_DIR}/logs/error.log"
XRAY_LOG_FILE = f"{BASE_DIR}/logs/xray.log"
IP_META_CACHE_FILE = f"{BASE_DIR}/state/ip-meta-cache.json"

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
    for d in [f"{BASE_DIR}/data", f"{BASE_DIR}/config",
              f"{BASE_DIR}/backup", f"{BASE_DIR}/state", f"{BASE_DIR}/logs"]:
        Path(d).mkdir(parents=True, exist_ok=True)

XRAY_CFG = DEFAULT_XRAY_CFG
SVC_NAME = DEFAULT_SVC_NAME
AUTH_TOKEN = DEFAULT_TOKEN  # may be overridden by --token or token file
TEST_URLS_FILE = DEFAULT_TEST_URLS_FILE
PANEL_STARTED_AT = time.time()
# Serializes every code path that mutates iptables / resolv.conf / connect state,
# including the background reconcile loop.
_STATE_LOCK = threading.RLock()
RECONCILE_INTERVAL = int(os.environ.get("RECONCILE_INTERVAL", "60") or 0)


def _serialized(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with _STATE_LOCK:
            return fn(*args, **kwargs)
    return wrapper


def _valid_port(value, default):
    try:
        port = int(value if value not in (None, "") else default)
    except (TypeError, ValueError):
        raise ValueError(f"invalid port: {value!r}")
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid port: {value!r}")
    return port


def _normalize_ipv4_cidr(value):
    """Return a canonical IPv4 CIDR string, or None (never passes raw input to a shell)."""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None
    return str(net) if net.version == 4 else None

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


def _ensure_access_log_config(cfg):
    """Ensure Xray logs at info level to xray.log (session-ID based stats)."""
    log = cfg.setdefault("log", {})
    # Remove separate access/error log paths — all output goes to xray.log
    log.pop("access", None)
    log.pop("error", None)
    log["loglevel"] = "info"
    return cfg


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
    resolved_cfg, _ = materialize_config(
        {"outbounds": outbounds},
        f"{BASE_DIR}/state/txt-endpoint-cache.json",
    )
    outbounds = resolved_cfg["outbounds"]
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
        "log": {"access": ACCESS_LOG_FILE, "error": ERROR_LOG_FILE, "loglevel": "warning"},
        # NOTE: temp test configs use separate access/error logs, not production xray.log
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


# Default DNS config (used when no user override persisted)
# NOTE: DoH servers (dns.jianghuxiao.pp.ua, dns.alidns.com) caused socket leaks
# in dns-out outbound (Xray 26.3.27). Using plain UDP DNS until fixed.
# dns inbound forwards directly to upstream via dokodemo-door address, NOT via
# dns-out outbound. Routing rules send dns/transparent-udp53 -> direct.
DNS_INBOUND_SETTINGS = {"address": "223.5.5.5", "port": 53, "network": "udp"}


def _dns_inbound_settings():
    return dict(DNS_INBOUND_SETTINGS)


DEFAULT_DNS_SERVERS = ["223.5.5.5", "119.29.29.29"]
# Written by older versions. Xray parses "udp:IP:53" as a *domain* and the query
# fails; the iptables bypass extractor did not recognise it either.
LEGACY_DEFAULT_DNS_SERVERS = ["udp:223.5.5.5:53", "udp:119.29.29.29:53"]
TP_DEFAULT_DNS_HOSTS = {
    "domain:googleapis.cn": "googleapis.com",
    "geosite:category-ads-all": "127.0.0.1",
    "domain:evil.com": "127.0.0.1",
}

DEFAULT_DNS_CONFIG = {
    "servers": list(DEFAULT_DNS_SERVERS),
    "tag": "dns",
    "hosts": {
        "domain:googleapis.cn": "googleapis.com",
        "geosite:category-ads-all": "127.0.0.1",
    },
}


def _dns_server_ip(server):
    """Literal IP of an Xray dns.servers entry, or None for domains/DoH hostnames.

    Accepts 1.2.3.4, 1.2.3.4:53, udp:1.2.3.4:53, tcp://1.2.3.4:53,
    https://1.2.3.4/dns-query, [2001:db8::1]:53 and {"address": ...}.
    """
    if isinstance(server, dict):
        server = server.get("address", "")
    if not isinstance(server, str):
        return None
    text = server.strip()
    if "://" in text:
        host = urlparse(text).hostname or ""
    else:
        if text[:4].lower() in ("udp:", "tcp:"):
            text = text[4:]
        host = text
        if host.startswith("[") and "]" in host:
            host = host[1:host.index("]")]
        elif host.count(":") == 1:
            host = host.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def _normalize_dns_server(server):
    """Rewrite the legacy "udp:IP[:port]" form into a form Xray understands."""
    if not isinstance(server, str) or server[:4].lower() != "udp:" or "://" in server:
        return server
    ip = _dns_server_ip(server)
    if not ip:
        return server
    rest = server[4:].strip()
    port = 53
    if rest.startswith("[") and "]:" in rest:
        port_s = rest.rsplit("]:", 1)[1]
    elif rest.count(":") == 1:
        port_s = rest.split(":", 1)[1]
    else:
        port_s = ""
    if port_s.isdigit():
        port = int(port_s)
    return ip if port == 53 else {"address": ip, "port": port}


def _normalize_dns_config(dns_cfg):
    dns_cfg = dict(dns_cfg or {})
    servers = dns_cfg.get("servers")
    if isinstance(servers, list):
        dns_cfg["servers"] = [_normalize_dns_server(s) for s in servers]
    return dns_cfg


def _dns_state_load():
    """Load user-persisted DNS config override, or None if never saved."""
    try:
        with open(DNS_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def _dns_state_save(dns_cfg):
    """Persist user's DNS config to state file."""
    Path(DNS_STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(DNS_STATE_FILE, "w") as f:
        json.dump(dns_cfg, f, indent=2, ensure_ascii=False)


def _dns_outbound():
    return {
        "tag": "dns-out", "protocol": "dns",
        "streamSettings": {"sockopt": {"mark": 128}},
    }


def _ensure_dns_outbound(outbounds):
    replaced = False
    result = []
    for outbound in outbounds:
        if outbound.get("tag") == "dns-out":
            if not replaced:
                result.append(_dns_outbound())
                replaced = True
            continue
        result.append(outbound)
    if not replaced:
        result.append(_dns_outbound())
    return result


def _dns_routing_rules(transparent=False):
    # Route DNS queries from the dns inbound to "direct" (freedom) outbound
    # instead of "dns-out". The dns-out outbound (protocol: dns) has a socket
    # leak in Xray 26.3.27 where each query creates an IPv6 UDP socket that
    # never gets closed, exhausting the ephemeral port range. The dns inbound
    # (dokodemo-door) forwards directly to upstream DNS via its settings.address.
    #
    # NOTE: The old "transparent + udp/53 → direct" rule is REMOVED.
    # LAN DNS now goes via DNAT to 127.0.0.1:53 (dns inbound), NOT via REDIRECT
    # to 12345 (transparent). So there's no transparent UDP 53 traffic to route.
    rules = [{"type": "field", "inboundTag": ["dns"], "outboundTag": "direct"}]
    return rules


def _quic_block_rule():
    return {"type": "field", "network": "udp", "port": 443, "outboundTag": "block"}


@_serialized
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
        state.pop("xray_missing_since", None)
        state.pop("recovering", None)
        state.pop("was_active_but_stopped", None)
        # Re-apply on every reconciliation so an older managed resolv.conf is
        # normalized to the current nameserver list. The apply helper backs up
        # only when the file is not already managed, preserving the real original.
        if not dns_active:
            print("[reconcile] DNS hijack missing, applying...")
        _dns_hijack_apply()
        if tp_expected and not tp_has_rules:
            tp_port = state.get("transparent_port", DEFAULT_TRANSPARENT_PORT)
            print(f"[reconcile] iptables missing, applying (port {tp_port})...")
            _iptables_setup_redirect(tp_port)
        elif tp_expected and not _tp_iptables_in_sync(
                tp_port := state.get("transparent_port", DEFAULT_TRANSPARENT_PORT)):
            print(f"[reconcile] iptables out of date (DNS/bypass/port changed), rebuilding (port {tp_port})...")
            _iptables_setup_redirect(tp_port)
        if not tp_expected and tp_has_rules:
            print("[reconcile] Stale iptables, cleaning...")
            _iptables_cleanup()
        _connect_state_write(state)

    # Case 2: active but xray NOT running → keep intent during short restarts.
    # Docker/supervisor restarts can make Xray disappear for a few seconds while
    # DNS is still hijacked to 127.0.0.1. Do NOT mark connect-mode inactive or
    # clean iptables immediately, otherwise the user must manually reconnect.
    elif active_expected and not xray_running:
        now = time.time()
        # A panel/container restart starts Xray and the panel concurrently. Ignore
        # a persisted timestamp from an older process; always grant this process
        # a fresh recovery window before deciding the core is truly gone.
        persisted_missing_since = float(state.get("xray_missing_since") or now)
        missing_since = max(persisted_missing_since, PANEL_STARTED_AT)
        state["xray_missing_since"] = missing_since
        state["recovering"] = True
        state["was_active_but_stopped"] = True
        if now - missing_since < 60:
            print("[reconcile] Active but xray is restarting → preserving connect-mode state")
            _connect_state_write(state)
        else:
            print("[reconcile] Active but xray stopped for >60s → cleaning up")
            state["active"] = False
            state["recovering"] = False
            if dns_active:
                _dns_hijack_restore()
            if tp_has_rules:
                _iptables_cleanup()
            _connect_state_write(state)

    # Case 3: inactive → ensure iptables/DNS are clean (but keep config as-is)
    elif not active_expected:
        standalone_tp = _tp_state_read().get("enabled") and _tp_has_dokodemo_inbound()
        if dns_active and not standalone_tp:
            print("[reconcile] Stale DNS hijack, restoring...")
            _dns_hijack_restore()
        if tp_has_rules and not standalone_tp:
            print("[reconcile] Stale iptables, cleaning...")
            _iptables_cleanup()

    # Active modes need managed inbounds/rules. An inactive panel startup must not
    # rewrite the user's persisted nodes or routing configuration.
    if active_expected:
        _ensure_dns_inbound_in_config()

    state["xray_running"] = xray_running
    state["dns_actual"] = _dns_hijack_is_active()
    state["transparent_actual"] = _tp_has_iptables_rules()
    return state


def _reconcile_loop():
    # First pass soon after start: on boot Xray may not be RUNNING yet when the
    # startup reconcile runs, so rules would otherwise wait a full interval.
    delay = min(10, RECONCILE_INTERVAL)
    while True:
        time.sleep(delay)
        delay = RECONCILE_INTERVAL
        try:
            _reconcile_connect_state()
        except Exception as e:  # keep the loop alive
            print(f"[reconcile] error: {e}", flush=True)


# ---------------------------------------------------------------------------
# User routing rules (direct / proxy / block), kept across connect-mode rebuilds
# ---------------------------------------------------------------------------
USER_RULE_PREFIX = "user:"
PROXY_TARGET = "__proxy__"   # resolved to the active node / balancer when applied
_RULE_MATCH_KEYS = ("domain", "ip", "port", "network", "sourceIP", "protocol", "inboundTag")
_RULE_LIST_KEYS = ("domain", "ip", "sourceIP", "protocol", "inboundTag")


def _normalize_user_rule(rule):
    """Validate one user rule. Bare domains become "domain:x"; returns (rule, error)."""
    if not isinstance(rule, dict):
        return None, "rule must be an object"
    out = {"type": "field"}
    for key in _RULE_LIST_KEYS:
        vals = rule.get(key)
        if vals in (None, "", []):
            continue
        if isinstance(vals, str):
            vals = [v for v in re.split(r"[,\s]+", vals) if v]
        if not isinstance(vals, list) or not all(isinstance(v, str) and v.strip() for v in vals):
            return None, f"{key} must be a list of strings"
        vals = [v.strip() for v in vals]
        if key == "domain":
            vals = [v if ":" in v else f"domain:{v}" for v in vals]
        if key in ("ip", "sourceIP"):
            for v in vals:
                if not v.startswith(("geoip:", "ext:")):
                    try:
                        ipaddress.ip_network(v.lstrip("!"), strict=False)
                    except ValueError:
                        return None, f"invalid IP/CIDR: {v}"
        out[key] = vals
    for key in ("port", "network"):
        val = rule.get(key)
        if val not in (None, ""):
            val = str(val).strip()
            if key == "port" and not re.fullmatch(r"\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*", val):
                return None, f"invalid port: {val}"
            if key == "network" and val not in ("tcp", "udp", "tcp,udp"):
                return None, f"invalid network: {val}"
            out[key] = val
    if not any(k in out for k in _RULE_MATCH_KEYS):
        return None, "rule needs at least one match condition"
    target = rule.get("balancerTag") or rule.get("outboundTag") or ""
    if not isinstance(target, str) or not target:
        return None, "rule needs an outbound (direct / block / proxy / node tag)"
    if rule.get("balancerTag"):
        out["balancerTag"] = target
    else:
        out["outboundTag"] = target
    remark = str(rule.get("remark") or "")[:80]
    if remark:
        out["remark"] = remark
    return out, None


def _custom_rules_load():
    try:
        with open(CUSTOM_RULES_FILE) as f:
            data = json.load(f)
    except Exception:
        return []
    rules = []
    for r in data if isinstance(data, list) else []:
        norm, err = _normalize_user_rule(r)
        if norm:
            rules.append(norm)
    return rules


def _custom_rules_save(rules):
    Path(CUSTOM_RULES_FILE).parent.mkdir(parents=True, exist_ok=True)
    tmp = CUSTOM_RULES_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rules, f, indent=2, ensure_ascii=False)
    os.replace(tmp, CUSTOM_RULES_FILE)


def _is_managed_head_rule(r):
    return r.get("inboundTag") == ["dns"] or (r.get("network") == "udp" and r.get("port") == 443 and r.get("outboundTag") == "block")


def _current_proxy_target(cfg):
    """Where "proxy" rules go: whatever the transparent/socks inbound uses now."""
    rules = cfg.get("routing", {}).get("rules", [])
    for tag in ("transparent", "socks-in", "http-in"):
        for r in rules:
            if r.get("inboundTag") == [tag] and (r.get("balancerTag") or r.get("outboundTag")):
                return ("balancerTag", r["balancerTag"]) if r.get("balancerTag") else ("outboundTag", r["outboundTag"])
    for ob in cfg.get("outbounds", []):
        if ob.get("protocol") not in ("freedom", "blackhole", "dns") and ob.get("tag"):
            return "outboundTag", ob["tag"]
    return "outboundTag", "direct"


def _apply_custom_rules(cfg, rules=None):
    """Insert user rules right after the managed DNS/QUIC head rules (before geo
    direct and the inbound catch-all rules, which would otherwise shadow them)."""
    if rules is None:
        rules = _custom_rules_load()
    routing = cfg.setdefault("routing", {})
    existing = [r for r in routing.get("rules", []) if not str(r.get("ruleTag", "")).startswith(USER_RULE_PREFIX)]
    routing["rules"] = existing
    known = {ob.get("tag") for ob in cfg.get("outbounds", [])}
    balancers = {b.get("tag") for b in routing.get("balancers", [])}
    proxy_key, proxy_tag = _current_proxy_target(cfg)
    materialized = []
    for i, rule in enumerate(rules, 1):
        r = {k: v for k, v in rule.items() if k != "remark"}
        target = r.pop("balancerTag", None) or r.pop("outboundTag", None)
        if target == PROXY_TARGET:
            r[proxy_key] = proxy_tag
        elif target in balancers:
            r["balancerTag"] = target
        elif target in known or target in ("direct", "block"):
            r["outboundTag"] = target
        else:
            continue  # node was deleted; keep the rule stored but skip it
        r["ruleTag"] = f"{USER_RULE_PREFIX}{i}"
        materialized.append(r)
    idx = 0
    while idx < len(existing) and _is_managed_head_rule(existing[idx]):
        idx += 1
    routing["rules"] = existing[:idx] + materialized + existing[idx:]
    if materialized and not any(ob.get("tag") == "block" for ob in cfg.get("outbounds", [])) and \
            any(r.get("outboundTag") == "block" for r in materialized):
        cfg.setdefault("outbounds", []).append({"tag": "block", "protocol": "blackhole"})
    return cfg


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

    # DNS inbound always forwards directly to mainland UDP DNS.
    cfg["inbounds"].append({
        "tag": "dns", "listen": "0.0.0.0", "port": 53,
        "protocol": "dokodemo-door",
        "settings": _dns_inbound_settings(),
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
    if not has_direct:
        outbounds.append({
            "tag": "direct", "protocol": "freedom",
            "settings": {"domainStrategy": "UseIP"},
            "streamSettings": {"sockopt": {"mark": 128}},
        })
    if not has_block:
        outbounds.append({"tag": "block", "protocol": "blackhole", "streamSettings": {"sockopt": {"mark": 128}}})
    outbounds = _ensure_dns_outbound(outbounds)
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

    # Rules (first-match order)
    rules = []

    # 1. DNS hijack → Xray DNS module. dns.servers can be DoH URLs or plain DNS IPs.
    rules.extend(_dns_routing_rules(transparent))

    # 2. Block QUIC before catch-all UDP direct, then bypass CN/private traffic.
    rules.append(_quic_block_rule())
    rules.append({"type": "field", "ip": ["geoip:cn"], "outboundTag": "direct"})
    rules.append({"type": "field", "domain": ["geosite:cn"], "outboundTag": "direct"})
    rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"})

    # 3. User traffic → proxy (must come BEFORE catch-all UDP direct,
    #    otherwise transparent UDP always bypasses proxy)
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

    # 4. Fallback: remaining UDP → direct (after proxy rules so transparent UDP isn't swallowed)
    rules.append({"type": "field", "network": "udp", "outboundTag": "direct"})

    routing["rules"] = rules

    # --- DNS (use user-saved override, otherwise default) ---
    saved_dns = _dns_state_load()
    cfg["dns"] = _normalize_dns_config(saved_dns if saved_dns else DEFAULT_DNS_CONFIG)

    _apply_custom_rules(cfg)
    _ensure_access_log_config(cfg)
    return cfg, None


def _tp_load_custom_bypass():
    """Load user-customized bypass CIDRs from file."""
    try:
        with open(CUSTOM_BYPASS_FILE) as f:
            data = json.load(f)
        if isinstance(data, list):
            return [c for c in (_normalize_ipv4_cidr(x) for x in data) if c]
    except Exception:
        pass
    return []


def _tp_save_custom_bypass(cidrs):
    """Save user-customized bypass CIDRs to file."""
    # Deduplicate and validate
    clean = []
    seen = set()
    for c in cidrs:
        c = _normalize_ipv4_cidr(c)
        if c and c not in seen:
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
        ip = _dns_server_ip(server)
        if ip:
            add_ip(ip)
    return out


def _tp_get_all_bypass_cidrs():
    """Get merged list: default + auto DNS IPs + custom, deduplicated."""
    all_cidrs = list(_BYPASS_CIDRS)
    seen = set(all_cidrs)
    for c in _extract_dns_bypass_cidrs_from_config() + _tp_load_custom_bypass():
        c = _normalize_ipv4_cidr(c)
        if c and c not in seen:
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
        f"iptables -t nat -D PREROUTING -p udp -m udp --dport 53 -j {ch}_PRE 2>/dev/null",
        f"iptables -t nat -D PREROUTING -p udp -m udp --dport 443 -j {ch}_PRE 2>/dev/null",
        f"iptables -t nat -X {ch}_PRE 2>/dev/null",
        f"iptables -t nat -F {ch}_RULE 2>/dev/null",
        f"iptables -t nat -X {ch}_RULE 2>/dev/null",
    ]
    for cmd in cmds:
        _run(cmd, timeout=5)
    _gateway_cleanup()


GATEWAY_COMMENT = "xray-mgr-gw"
# Interfaces that are never a home LAN (container/VPN bridges); their subnets are
# not masqueraded. Matching by name instead of the old "skip 172.*" so a LAN on
# 172.16.0.0/12 still works.
_NON_LAN_IFACE_PREFIXES = ("lo", "docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "tun", "wg", "tailscale", "zt")


def _lan_interfaces():
    """[(iface, ip, cidr)] for LAN-facing IPv4 interfaces."""
    out, _, rc = _run("ip -4 -o addr show", timeout=5)
    found = []
    if rc != 0:
        return found
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] != "inet":
            continue
        iface = parts[1].split("@", 1)[0]
        if iface.startswith(_NON_LAN_IFACE_PREFIXES):
            continue
        try:
            itf = ipaddress.ip_interface(parts[3])
        except ValueError:
            continue
        if itf.network.is_loopback or itf.network.prefixlen == 32:
            continue
        found.append((iface, str(itf.ip), str(itf.network)))
    return found


def _lan_cidrs():
    """IPv4 subnets allowed to use this host as gateway."""
    cidrs = []
    for _, _, cidr in _lan_interfaces():
        if cidr not in cidrs:
            cidrs.append(cidr)
    return cidrs or ["192.168.0.0/16"]


def _nft_forward_backend():
    """Docker on nf_tables hosts often sets FORWARD policy DROP there; legacy ACCEPT
    rules alone cannot override it, so forwarded phone traffic must also be accepted
    in DOCKER-USER (or FORWARD) of the nft backend. Returns (binary, chain) or None."""
    out, _, rc = _run("iptables-nft -S FORWARD 2>/dev/null", timeout=5)
    if rc != 0 or not out.strip():
        return None
    if "-N DOCKER-USER" in _run("iptables-nft -S DOCKER-USER 2>/dev/null", timeout=5)[0]:
        return "iptables-nft", "DOCKER-USER"
    if "-P FORWARD DROP" in out:
        return "iptables-nft", "FORWARD"
    return None


def _gateway_rules():
    """(binary, table, "-A/-I ..." spec) for LAN-gateway mode, all tagged with a comment."""
    c = f'-m comment --comment {GATEWAY_COMMENT}'
    lans = _lan_cidrs()
    rules = []
    for cidr in lans:
        rules.append(("iptables", "nat", f"-A POSTROUTING -s {cidr} ! -o lo {c} -j MASQUERADE"))
    for cidr in lans:
        rules.append(("iptables", "filter", f"-A FORWARD -s {cidr} {c} -j ACCEPT"))
        rules.append(("iptables", "filter", f"-A FORWARD -d {cidr} -m conntrack --ctstate RELATED,ESTABLISHED {c} -j ACCEPT"))
    nft = _nft_forward_backend()
    if nft:
        binary, chain = nft
        for cidr in lans:
            rules.append((binary, "filter", f"-I {chain} -s {cidr} {c} -j ACCEPT"))
            rules.append((binary, "filter", f"-I {chain} -d {cidr} -m conntrack --ctstate RELATED,ESTABLISHED {c} -j ACCEPT"))
    return rules


def _gateway_cleanup():
    for binary in ("iptables", "iptables-nft"):
        for table in ("nat", "filter"):
            out, _, rc = _run(f"{binary} -t {table} -S 2>/dev/null", timeout=5)
            if rc != 0:
                continue
            for line in out.splitlines():
                if line.startswith("-A ") and GATEWAY_COMMENT in line:
                    _run(f"{binary} -t {table} -D " + line[3:], timeout=5)
    # Rules written by versions before the comment tag.
    _run("iptables -D FORWARD -j ACCEPT 2>/dev/null", timeout=5)
    out, _, _ = _run("iptables -t nat -S POSTROUTING 2>/dev/null", timeout=5)
    for line in out.splitlines():
        if line.startswith("-A ") and "MASQUERADE" in line and "! -o lo" in line and "--comment" not in line:
            _run("iptables -t nat -D " + line[3:], timeout=5)


def _gateway_in_sync():
    want = {}
    for binary, table, spec in _gateway_rules():
        want.setdefault((binary, table), []).append(spec.split(" ", 1)[1])
    for (binary, table), specs in want.items():
        out, _, rc = _run(f"{binary} -t {table} -S 2>/dev/null", timeout=5)
        if rc != 0:
            return False
        have = sorted(line[3:] for line in out.splitlines() if line.startswith("-A ") and GATEWAY_COMMENT in line)
        if have != sorted(specs):
            return False
    return True


def _gateway_status():
    """Checks for using this host as a phone's gateway (shown in the UI)."""
    def sysctl(key):
        try:
            return Path("/proc/sys/" + key.replace(".", "/")).read_text().strip()
        except Exception:
            return ""
    nft_out, _, nft_rc = _run("iptables-nft -S FORWARD 2>/dev/null", timeout=5)
    conn = _connect_state_read()
    return {
        "lan": [{"iface": i, "ip": ip, "cidr": c} for i, ip, c in _lan_interfaces()],
        "lan_cidrs": _lan_cidrs(),
        "transparent": bool(conn.get("active") and conn.get("transparent_enabled")) or bool(_tp_state_read().get("enabled")),
        "dns_inbound": any(ib.get("tag") == "dns" and ib.get("port") == 53 for ib in (_parse_config()[0] or {}).get("inbounds", [])),
        "ip_forward": sysctl("net.ipv4.ip_forward") == "1",
        "send_redirects": sysctl("net.ipv4.conf.all.send_redirects"),
        "send_redirects_ifaces": {i: sysctl(f"net.ipv4.conf.{i}.send_redirects") for i, _, _ in _lan_interfaces()},
        "nft_forward_drop": nft_rc == 0 and "-P FORWARD DROP" in nft_out,
        "rules_in_sync": _tp_has_iptables_rules() and _gateway_in_sync(),
    }


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
    """Hijack system DNS to point to Xray's dns inbound (127.0.0.1:53).

    Only backs up the current resolv.conf if it is NOT already hijacked.
    This prevents the original backup from being overwritten with hijacked
    content when apply() is called multiple times (reconnect, reconcile,
    startup restoration, etc.) — which would make restore() a no-op and
    leave the host with a broken 127.0.0.1:53 after Xray stops.
    """
    desired = ("# Xray DNS hijack (xray-manager transparent proxy)\n"
               "nameserver 127.0.0.1\nnameserver 223.5.5.5\nnameserver 119.29.29.29\n")
    try:
        if Path("/etc/resolv.conf").read_text() == desired:
            return True
    except Exception:
        pass
    if not _dns_hijack_is_active():
        _dns_hijack_backup()
    with open("/etc/resolv.conf", "w") as f:
        f.write("# Xray DNS hijack (xray-manager transparent proxy)\n")
        f.write("nameserver 127.0.0.1\n")
        f.write("nameserver 223.5.5.5\n")
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

    # Ensure dns dokodemo-door inbound forwards directly to mainland UDP DNS.
    dns_settings = _dns_inbound_settings()
    existing_dns = next((ib for ib in inbounds if ib.get("tag") == "dns"), None)
    if existing_dns:
        desired = {
            "tag": "dns", "listen": "0.0.0.0", "port": 53,
            "protocol": "dokodemo-door", "settings": dns_settings,
        }
        if existing_dns != desired:
            existing_dns.clear()
            existing_dns.update(desired)
            changed = True
    else:
        inbounds.append({
            "tag": "dns", "listen": "0.0.0.0", "port": 53,
            "protocol": "dokodemo-door",
            "settings": dns_settings,
        })
        changed = True

    new_outbounds = _ensure_dns_outbound(outbounds)
    if new_outbounds != outbounds:
        outbounds = new_outbounds
        changed = True

    # Ensure dns routing rules
    desired_dns_rules = _dns_routing_rules(any(ib.get("tag") == "transparent" for ib in inbounds))
    quic_rule = _quic_block_rule()
    original_rules = list(rules)
    rules = [r for r in rules if r.get("inboundTag") != ["dns"]]
    rules = [r for r in rules if not (r.get("inboundTag") == ["transparent"] and r.get("port") == 53 and r.get("network") == "udp")]
    rules = [r for r in rules if not (r.get("network") == "udp" and r.get("port") == 443)]
    rules = desired_dns_rules + [quic_rule] + rules
    # The managed rules are always stripped and re-added; only a real difference
    # counts (otherwise every reconcile rewrote the config and left a backup file).
    changed = changed or rules != original_rules

    if changed:
        cfg["inbounds"] = inbounds
        cfg["outbounds"] = outbounds
        routing["rules"] = rules
        _save_config_object(cfg)
        print("[dns-config] Added missing dokodemo/dns inbound to config")


def _iptables_rule_specs(port, bypass_cidrs):
    """Exact XRAY_MGR_RULE lines as printed by `iptables -t nat -S` (used for setup and drift checks)."""
    ch = f"{CHAIN_PREFIX}_RULE"
    specs = [f"-A {ch} -d {cidr} -j RETURN" for cidr in bypass_cidrs]
    specs.append(f"-A {ch} -m mark --mark 0x80/0x80 -j RETURN")
    specs.append(f"-A {ch} -p tcp -j REDIRECT --to-ports {port}")
    # UDP 53 from LAN/Docker bridges -> Xray's DNS inbound (0.0.0.0:53), which forwards
    # to mainland UDP DNS. REDIRECT targets the receiving interface address; the old
    # "DNAT --to-destination 127.0.0.1:53" is dropped as a martian for any non-local
    # source unless route_localnet=1, which broke DNS for every bridge container.
    specs.append(f"-A {ch} -p udp -m udp --dport 53 -j REDIRECT --to-ports 53")
    # QUIC (udp/443) is not proxied (only TCP is). Send it to a closed local port so the
    # box answers "port unreachable" at once and browsers fall back to TCP, which is
    # proxied. A FORWARD REJECT does not work reliably: the packet is first routed back
    # out the LAN port, the ICMP redirect emitted there shares the per-host ICMP rate
    # limit, and the REJECT's error was suppressed (seen on kernel 4.18). Bypassed
    # destinations (LAN, DNS servers, custom bypass) RETURN above and keep working.
    specs.append(f"-A {ch} -p udp -m udp --dport 443 -j REDIRECT --to-ports {QUIC_REJECT_PORT}")
    return specs


def _iptables_hook_specs():
    ch = CHAIN_PREFIX
    return [
        f"PREROUTING -p tcp -j {ch}_PRE",
        f"PREROUTING -p udp -m udp --dport 53 -j {ch}_PRE",
        f"PREROUTING -p udp -m udp --dport 443 -j {ch}_PRE",
        f"OUTPUT -p tcp -j {ch}_OUT",
        f"{ch}_PRE -j {ch}_RULE",
        f"{ch}_OUT -j {ch}_RULE",
    ]


def _tp_iptables_in_sync(port, bypass_cidrs=None):
    """True when the live rules equal what _iptables_setup_redirect would install now.

    Existence alone is not enough: DNS servers, hosts or custom bypass entries may
    have changed since the rules were built.
    """
    if bypass_cidrs is None:
        bypass_cidrs = _tp_get_all_bypass_cidrs()
    out, _, rc = _run(f"iptables -t nat -S {CHAIN_PREFIX}_RULE", timeout=5)
    if rc != 0:
        return False
    actual = [line.strip() for line in out.splitlines() if line.startswith("-A ")]
    if actual != _iptables_rule_specs(port, bypass_cidrs):
        return False
    for spec in _iptables_hook_specs():
        _, _, rc = _run(f"iptables -t nat -C {spec}", timeout=5)
        if rc != 0:
            return False
    return _gateway_in_sync()


def _active_tp_port():
    conn = _connect_state_read()
    if conn.get("active") and conn.get("transparent_enabled"):
        return conn.get("transparent_port", DEFAULT_TRANSPARENT_PORT)
    return _tp_state_read().get("port", DEFAULT_TRANSPARENT_PORT)


def _tp_rebuild_if_active():
    """Rebuild transparent-proxy rules (new bypass list) if they are installed. Returns (rebuilt, error)."""
    if not _tp_has_iptables_rules():
        return False, ""
    ok, msg = _iptables_setup_redirect(_active_tp_port())
    return ok, "" if ok else msg


def _iptables_setup_redirect(port, bypass_cidrs=None):
    """(Re)build all XRAY_MGR rules. Idempotent: always starts from a clean slate."""
    ch = CHAIN_PREFIX
    try:
        port = _valid_port(port, DEFAULT_TRANSPARENT_PORT)
    except ValueError as e:
        return False, str(e)
    if bypass_cidrs is None:
        bypass_cidrs = _tp_get_all_bypass_cidrs()
    bypass_cidrs = [c for c in (_normalize_ipv4_cidr(x) for x in bypass_cidrs) if c]
    _iptables_cleanup()
    setup = [
        f"iptables -t nat -N {ch}_OUT",
        f"iptables -t nat -N {ch}_PRE",
        f"iptables -t nat -N {ch}_RULE",
    ]
    setup.extend(f"iptables -t nat {spec}" for spec in _iptables_rule_specs(port, bypass_cidrs))
    setup.append(f"iptables -t nat -I PREROUTING -p tcp -j {ch}_PRE")
    setup.append(f"iptables -t nat -I PREROUTING -p udp -m udp --dport 53 -j {ch}_PRE")
    setup.append(f"iptables -t nat -I PREROUTING -p udp -m udp --dport 443 -j {ch}_PRE")
    setup.append(f"iptables -t nat -I OUTPUT -p tcp -j {ch}_OUT")
    setup.append(f"iptables -t nat -A {ch}_PRE -j {ch}_RULE")
    setup.append(f"iptables -t nat -A {ch}_OUT -j {ch}_RULE")
    # LAN gateway support (phone sets its gateway to this host): see _gateway_rules().
    for backend, table, spec in _gateway_rules():
        setup.append(f"{backend} -t {table} {spec}")
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

    # -- Inbound: DNS (port 53), forwarded directly to mainland UDP DNS --
    has_dns_ib = any(ib.get("tag") == "dns" for ib in cfg.get("inbounds", []))
    dns_settings = _dns_inbound_settings()
    if not has_dns_ib:
        cfg.setdefault("inbounds", []).append({
            "tag": "dns", "listen": "0.0.0.0", "port": 53,
            "protocol": "dokodemo-door",
            "settings": dns_settings,
        })
    else:
        for ib in cfg.get("inbounds", []):
            if ib.get("tag") == "dns":
                if ib.get("settings") != dns_settings:
                    ib["settings"] = dns_settings
                break

    # -- Outbound: dns-out --
    outbounds = cfg.get("outbounds", [])
    outbounds = _ensure_dns_outbound(outbounds)

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
    # Extract and remove geo/dns/transparent rules from wherever they are,
    # then rebuild in correct order: geo → dns → transparent → other
    old_rules = cfg.get("routing", {}).get("rules", [])

    # Classify existing rules
    geo_keys = ("geoip:cn", "geosite:cn", "geoip:private")
    geo_rules = []
    tp_rule = None
    other_rules = []
    for r in old_rules:
        if str(r.get("ruleTag", "")).startswith(USER_RULE_PREFIX):
            continue  # re-inserted by _apply_custom_rules
        dump = json.dumps(r)
        is_geo = any(k in dump for k in geo_keys)
        is_udp_direct = r.get("network") == "udp" and r.get("outboundTag") == "direct"
        # Catch-all "udp -> direct" must stay LAST (re-added below); placing it with the
        # geo rules (before the transparent rule) sent all transparent UDP direct.
        match_keys = ("ip", "domain", "port", "sourcePort", "source", "inboundTag", "protocol", "user", "attrs")
        is_udp_fallback = is_udp_direct and not any(k in r for k in match_keys)
        is_dns = r.get("inboundTag") == ["dns"]
        is_tp_dns = r.get("inboundTag") == ["transparent"] and r.get("port") == 53 and r.get("network") == "udp"
        is_quic_block = r.get("network") == "udp" and r.get("port") == 443
        is_tp = r.get("inboundTag") == ["transparent"]
        if is_dns or is_tp_dns or is_quic_block or is_udp_fallback:
            continue
        if is_geo or (is_udp_direct and not is_udp_fallback):
            geo_rules.append(r)
        elif is_tp:
            tp_rule = r
        else:
            other_rules.append(r)

    # Ensure geo rules exist (NO catch-all UDP direct here — moved after tp_rule)
    if not any("geoip:cn" in json.dumps(r) for r in geo_rules):
        geo_rules.append({"type": "field", "ip": ["geoip:cn"], "outboundTag": "direct"})
    if not any("geosite:cn" in json.dumps(r) for r in geo_rules):
        geo_rules.append({"type": "field", "domain": ["geosite:cn"], "outboundTag": "direct"})
    if not any("geoip:private" in json.dumps(r) for r in geo_rules):
        geo_rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"})

    # Ensure dns rules exist
    dns_rules = _dns_routing_rules(True)

    # Ensure transparent rule exists
    if not tp_rule:
        default_tag = None
        for ob in outbounds:
            if ob.get("protocol") not in ("freedom", "blackhole", "dns"):
                default_tag = ob.get("tag")
                break
        if not default_tag:
            return None, "no proxy outbound found"

        if balancer_cfg and balancer_cfg.get("enabled") and balancer_cfg.get("tags"):
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
            balancers = cfg.get("routing", {}).get("balancers", [])
            balancers = [b for b in balancers if b.get("tag") != bal_tag]
            balancers.append(balancer)
            cfg.setdefault("routing", {})["balancers"] = balancers
            tp_rule = {"type": "field", "inboundTag": ["transparent"], "balancerTag": bal_tag}
        else:
            tp_rule = {"type": "field", "inboundTag": ["transparent"], "outboundTag": default_tag}

    # Final order: dns → QUIC block → geo direct → transparent → other → UDP fallback
    udp_fallback = {"type": "field", "network": "udp", "outboundTag": "direct"}
    cfg["routing"]["rules"] = dns_rules + [_quic_block_rule()] + geo_rules + [tp_rule] + other_rules + [udp_fallback]

    # -- DNS config --
    cfg.setdefault("dns", {})
    if not cfg["dns"].get("servers"):
        cfg["dns"]["servers"] = list(DEFAULT_DNS_SERVERS)
    if not cfg["dns"].get("hosts"):
        cfg["dns"]["hosts"] = dict(TP_DEFAULT_DNS_HOSTS)
    cfg["dns"] = _normalize_dns_config(cfg["dns"])

    _apply_custom_rules(cfg)
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
    if (dns.get("servers") in (DEFAULT_DNS_SERVERS, LEGACY_DEFAULT_DNS_SERVERS)
            and (not dns.get("hosts") or dns.get("hosts") == TP_DEFAULT_DNS_HOSTS)):
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
        out, _, rc = _run("pgrep -x der")
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


def _runtime_config_path():
    return str(Path(XRAY_CFG).with_name("xray-runtime.json"))


def _materialize_runtime_config(cfg=None):
    if cfg is None:
        cfg, err = _parse_config()
        if err:
            return None, [], err
    if cfg is None:
        return None, [], "empty Xray config"
    runtime, resolved = materialize_config(
        cfg,
        f"{BASE_DIR}/state/txt-endpoint-cache.json",
    )
    target = Path(_runtime_config_path())
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(json.dumps(runtime, ensure_ascii=False, indent=2) + "\n")
    os.replace(temp, target)
    return str(target), resolved, None


def _test_config():
    """Resolve TXT endpoints and run xray -test on the runtime config."""
    runtime_path, resolved, materialize_error = _materialize_runtime_config()
    if materialize_error:
        return {"ok": False, "output": materialize_error, "exit_code": -1, "txt_endpoints": []}
    out, err, rc = _run(f"{shlex.quote(XRAY_BIN)} run -test -config {shlex.quote(runtime_path)}")
    combined = (out + err).strip()
    ok = "Configuration OK" in combined
    return {"ok": ok, "output": combined, "exit_code": rc, "txt_endpoints": resolved,
            "runtime_config": runtime_path}


def _xray_version():
    out, _, _ = _run(f"{XRAY_BIN} version")
    return out.strip().split("\n")[0] if out.strip() else "unknown"


CONFIG_BACKUP_KEEP = max(1, int(os.environ.get("CONFIG_BACKUP_KEEP", "3") or 3))


def _prune_config_backups(keep=None):
    """Keep only the newest `keep` config backups (backup/config-*.json.bak and the
    config/<name>.bak.* files written by restore). Each config save creates one."""
    keep = CONFIG_BACKUP_KEEP if keep is None else keep
    groups = [list(Path(f"{BASE_DIR}/backup").glob("config-*.json.bak")),
              list(Path(XRAY_CFG).parent.glob(Path(XRAY_CFG).name + ".bak.*"))]
    removed = 0
    for files in groups:
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        for old in files[keep:]:
            try:
                old.unlink()
                removed += 1
            except OSError:
                pass
    return removed


def _backup_config():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = f"{BASE_DIR}/backup"
    Path(backup_dir).mkdir(parents=True, exist_ok=True)
    backup = f"{backup_dir}/config-{ts}.json.bak"
    try:
        raw, _ = _read_config()
        with open(backup, "w") as f:
            f.write(raw)
        _prune_config_backups()
        return backup
    except Exception:
        return ""


def _save_config_object(cfg):
    _ensure_access_log_config(cfg)
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
    """Materialize TXT endpoints, restart Xray service, and return restart result."""
    runtime_path, resolved, materialize_error = _materialize_runtime_config()
    if materialize_error:
        return {"active": "error", "success": False, "error": materialize_error}
    if _has_systemd():
        _run(f"systemctl --no-block restart {SVC_NAME}")
        time.sleep(1.5)
        out, _, rc = _run(f"systemctl is-active {SVC_NAME}")
        return {"active": out.strip(), "success": out.strip() == "active",
                "runtime_config": runtime_path, "txt_endpoints": resolved}
    elif _has_supervisord():
        _run("supervisorctl restart xray-all:xray")
        time.sleep(1.5)
        out, _, _ = _run("supervisorctl status xray-all:xray")
        active = "active" if "RUNNING" in out else "inactive"
        return {"active": active, "success": "RUNNING" in out,
                "runtime_config": runtime_path, "txt_endpoints": resolved}
    else:
        return {"active": "unknown", "success": False}


def _bool_param(qs, *names, default=False):
    for name in names:
        if name in qs:
            v = qs[name][0].lower()
            return v in ("1", "true", "yes")
    return default


def _share_qs(query):
    """parse_qs that keeps a literal "+" (ECH values look like "cloudflare-ech.com+https://...")."""
    return parse_qs(query.replace("+", "%2B"), keep_blank_values=False)


def _apply_stream_settings(outbound, qs, address, default_network="tcp"):
    """Apply transport/security settings from share-link query params.

    Follows the Xray share-link conventions: type=tcp|raw|ws|grpc|xhttp|httpupgrade|kcp,
    security=none|tls|reality, sni, fp, alpn, ech, pbk/sid/spx/pqv, host, path,
    mode (xhttp mode / grpc multi), extra (xhttp JSON), serviceName, authority,
    headerType, seed.
    """
    def q(*names, default=""):
        for name in names:
            if qs.get(name) and qs[name][0] != "":
                return qs[name][0]
        return default

    network = q("type", "network", default=default_network) or default_network
    if network == "h2":
        network = "http"
    security = q("security", default="none") or "none"
    stream = {"network": network, "security": security}

    if security == "tls":
        # Xray 26.x removed allowInsecure=true (the whole config then fails to load, taking
        # every node down); certificate pinning via pinnedPeerCertSha256 replaces it.
        tls = {"serverName": q("sni", "serverName", "peer", default=address), "allowInsecure": False}
        if q("fp", "fingerprint"):
            tls["fingerprint"] = q("fp", "fingerprint")
        if q("alpn"):
            tls["alpn"] = [x for x in q("alpn").split(",") if x]
        if q("ech"):
            tls["echConfigList"] = q("ech")
            tls["echForceQuery"] = q("echForceQuery", default="full")
        if q("pcs", "pinnedPeerCertSha256"):
            tls["pinnedPeerCertSha256"] = q("pcs", "pinnedPeerCertSha256")
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality = {
            "serverName": q("sni", "serverName", default=address),
            "fingerprint": q("fp", default="chrome"),
            "publicKey": q("pbk", "publicKey"),
            "shortId": q("sid", "shortId"),
            "spiderX": q("spx", "spiderX"),
            "mldsa65Verify": q("pqv"),
        }
        stream["realitySettings"] = {k: v for k, v in reality.items() if v}

    host, path = q("host"), q("path")
    if network == "ws":
        ws = {"path": path or "/"}
        if host:
            ws["host"] = host
        stream["wsSettings"] = ws
    elif network == "httpupgrade":
        hu = {"path": path or "/"}
        if host:
            hu["host"] = host
        stream["httpupgradeSettings"] = hu
    elif network == "grpc":
        grpc = {"serviceName": q("serviceName", default=path)}
        if q("mode") == "multi":
            grpc["multiMode"] = True
        if q("authority"):
            grpc["authority"] = q("authority")
        stream["grpcSettings"] = grpc
    elif network == "xhttp":
        xh = {"path": path or "/"}
        if host:
            xh["host"] = host
        if q("mode"):
            xh["mode"] = q("mode")
        if q("extra"):
            try:
                extra = json.loads(q("extra"))
            except ValueError:
                raise ValueError("xhttp extra must be JSON")
            if isinstance(extra, dict) and extra:
                xh["extra"] = extra
        stream["xhttpSettings"] = xh
    elif network == "http":
        h = {"path": path or "/"}
        if host:
            h["host"] = [x for x in host.split(",") if x]
        stream["httpSettings"] = h
    elif network == "kcp":
        kcp = {"header": {"type": q("headerType", default="none")}}
        if q("seed"):
            kcp["seed"] = q("seed")
        stream["kcpSettings"] = kcp
    elif network in ("tcp", "raw") and q("headerType") == "http":
        req = {"path": [path or "/"]}
        if host:
            req["headers"] = {"Host": [x for x in host.split(",") if x]}
        stream["tcpSettings"] = {"header": {"type": "http", "request": req}}

    outbound["streamSettings"] = stream


def _parse_vless_link(link):
    parsed = urlparse(link.strip())
    uuid = parsed.username
    if not uuid:
        raise ValueError("missing UUID in vless link")
    address = parsed.hostname
    port = parsed.port or 443
    qs = _share_qs(parsed.query)
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
        data = json.loads(_b64.b64decode(b64).decode("utf-8"))
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

    stream = {"network": net, "security": data.get("tls", "") or "none"}
    if stream["security"] == "tls":
        tls = {"serverName": data.get("sni", address)}
        fp = data.get("fp", "")
        if fp:
            tls["fingerprint"] = fp
        alpn = data.get("alpn", "")
        if alpn:
            tls["alpn"] = [x for x in str(alpn).split(",") if x]
        # allowInsecure=true is rejected by Xray 26.x; ignore the share-link flag.
        stream["tlsSettings"] = tls

    if net == "ws":
        ws = {"path": data.get("path", "/") or "/"}
        host = data.get("host", "")
        if host:
            ws["host"] = host
        stream["wsSettings"] = ws
    elif net in ("xhttp", "httpupgrade"):
        settings = {"path": data.get("path", "/") or "/"}
        if data.get("host"):
            settings["host"] = data["host"]
        if net == "xhttp" and data.get("mode"):
            settings["mode"] = data["mode"]
        if net == "xhttp" and data.get("extra"):
            extra = data["extra"]
            if isinstance(extra, str):
                extra = json.loads(extra)
            settings["extra"] = extra
        stream[f"{net}Settings"] = settings
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
        std = unquote(userinfo).replace("-", "+").replace("_", "/")
        padded = std + "=" * (-len(std) % 4)
        decoded = None
        try:
            decoded = _b64.b64decode(padded, validate=True).decode("utf-8")
        except Exception:
            decoded = None
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
        qs = _share_qs(remaining)
    else:
        qs = _share_qs(raw_query)

    outbound = {
        "tag": tag, "protocol": "shadowsocks",
        "settings": {"servers": [{"address": address, "port": port, "method": method, "password": password}]},
    }

    # Parse plugin (v2ray-plugin / obfs-local)
    if plugin_str:
        parts = [x.replace("\\;", ";") for x in re.split(r"(?<!\\);", plugin_str)]  # SIP003 escapes ";" as "\\;"
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
                    ws["host"] = host
                ws["path"] = path
                stream = {"network": "ws", "security": "none", "wsSettings": ws}
                if "tls" in plugin_args:
                    stream["security"] = "tls"
                    tls = {"serverName": plugin_args.get("sni") or host or address}
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
    elif qs.get("type") or qs.get("security"):
        # Xray-style SIP002 extension: ss://...?type=ws&host=...&path=...&security=tls
        _apply_stream_settings(outbound, qs, address)

    return outbound


def _parse_trojan_link(link):
    """Parse trojan:// link."""
    parsed = urlparse(link.strip())
    password = unquote(parsed.username or "")
    if not password:
        raise ValueError("missing password in trojan link")
    address = parsed.hostname
    port = parsed.port or 443
    qs = _share_qs(parsed.query)
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
@_serialized
def api_dns_post():
    data = request.json or {}
    dns = data.get("dns")
    if not isinstance(dns, dict):
        return jsonify({"error": "dns must be an object"}), 400
    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500
    dns = _normalize_dns_config(dns)
    cfg["dns"] = dns
    backup, test = _save_config_object(cfg)
    if not test["ok"]:
        return jsonify({"error": "config test failed, rolled back", "detail": test["output"]}), 400
    _dns_state_save(dns)
    restart = _restart_xray()
    # Rebuild iptables bypass if transparent proxy is active (picks up new DNS IPs)
    iptables_rebuilt, rebuild_error = _tp_rebuild_if_active()
    result = {"ok": not rebuild_error, "backup": backup, "test": test, "restart": restart,
              "iptables_rebuilt": iptables_rebuilt}
    if rebuild_error:
        result["error"] = "iptables rebuild failed: " + rebuild_error
    return jsonify(result), (500 if rebuild_error else 200)


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
@_serialized
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
    cfg["dns"] = _normalize_dns_config(cfg.get("dns"))
    cfg["dns"]["hosts"] = hosts
    backup, test = _save_config_object(cfg)
    if not test["ok"]:
        return jsonify({"error": "config test failed, rolled back", "detail": test["output"]}), 400
    _dns_state_save(cfg["dns"])
    restart = _restart_xray()
    # If transparent proxy iptables rules are active, rebuild them to pick up
    # new DNS hosts IPs in the bypass list.
    iptables_rebuilt, rebuild_error = _tp_rebuild_if_active()
    result = {"ok": not rebuild_error, "hosts": hosts, "backup": backup, "test": test,
              "restart": restart, "iptables_rebuilt": iptables_rebuilt}
    if rebuild_error:
        result["error"] = "iptables rebuild failed: " + rebuild_error
    return jsonify(result), (500 if rebuild_error else 200)


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
            link_path = f"{CODE_DIR}/bin/{gf['name']}"
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
@_serialized
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

    backup = _backup_config()

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
@_serialized
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

    backup = _backup_config()

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
@_serialized
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
@_serialized
def api_routing_post():
    data = request.json
    if not data or "routing" not in data:
        return jsonify({"error": "missing 'routing' field"}), 400

    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500

    cfg["routing"] = data["routing"]
    new_raw = json.dumps(cfg, ensure_ascii=False, indent=2)

    backup = _backup_config()

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


@app.route("/api/routing/custom")
def api_routing_custom_get():
    return jsonify({"rules": _custom_rules_load(), "proxy_target": PROXY_TARGET})


@app.route("/api/routing/custom", methods=["POST"])
@_serialized
def api_routing_custom_post():
    data = request.json or {}
    raw = data.get("rules")
    if not isinstance(raw, list):
        return jsonify({"error": "rules must be a list"}), 400
    rules = []
    for i, r in enumerate(raw, 1):
        norm, err = _normalize_user_rule(r)
        if err:
            return jsonify({"error": f"第 {i} 条规则: {err}"}), 400
        rules.append(norm)
    cfg, err = _parse_config()
    if err:
        return jsonify({"error": err}), 500
    _apply_custom_rules(cfg, rules)
    backup, test = _save_config_object(cfg)
    if not test["ok"]:
        return jsonify({"error": "config test failed, rolled back", "detail": test["output"]}), 400
    _custom_rules_save(rules)
    restart = _restart_xray()
    return jsonify({"ok": True, "rules": rules, "test": test, "restart": restart})


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
    runtime_outbound = next(
        (item for item in temp_cfg["outbounds"] if item.get("tag") == outbound.get("tag")),
        outbound,
    )
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
            v = runtime_outbound.get("settings", {}).get("vnext", [{}])[0]
            s = runtime_outbound.get("settings", {}).get("servers", [{}])[0]
            src = v or s
            result["outbound_addr"] = str(src.get("address", "?")) + ":" + str(src.get("port", "?"))
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
    runtime_by_tag = {ob.get("tag", ""): ob for ob in temp_cfg["outbounds"]}
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
                runtime_ob = runtime_by_tag.get(tag, ob)
                v = runtime_ob.get("settings", {}).get("vnext", [{}])[0]
                s = runtime_ob.get("settings", {}).get("servers", [{}])[0]
                src = v or s
                addr = str(src.get("address", "?")) + ":" + str(src.get("port", "?"))
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
@_serialized
def api_transparent_bypass_post():
    data = request.json or {}
    cidrs = data.get("custom", [])
    if not isinstance(cidrs, list):
        return jsonify({"error": "custom must be a list of CIDR strings"}), 400
    invalid = [c for c in cidrs if not _normalize_ipv4_cidr(c)]
    if invalid:
        return jsonify({"error": "invalid IPv4 CIDR: " + ", ".join(map(str, invalid[:5]))}), 400
    saved = _tp_save_custom_bypass(cidrs)
    # If transparent proxy is currently active, rebuild iptables rules
    reloaded, rebuild_error = _tp_rebuild_if_active()
    if rebuild_error:
        return jsonify({"error": "iptables rebuild failed: " + rebuild_error, "custom": saved}), 400
    return jsonify({"ok": True, "custom": saved, "reloaded": reloaded})


@app.route("/api/gateway/status")
def api_gateway_status():
    return jsonify(_gateway_status())


@app.route("/api/transparent/status")
def api_transparent_status():
    state = _tp_state_read()
    out, _, rc = _run("iptables -t nat -L " + CHAIN_PREFIX + "_RULE -n 2>/dev/null")
    state["iptables_active"] = rc == 0 and CHAIN_PREFIX in out
    state["port"] = state.get("port", DEFAULT_TRANSPARENT_PORT)
    return jsonify(state)


@app.route("/api/transparent/enable", methods=["POST"])
@_serialized
def api_transparent_enable():
    data = request.json or {}
    try:
        port = _valid_port(data.get("port"), DEFAULT_TRANSPARENT_PORT)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
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
        rollback_cfg, _ = _tp_remove_dokodemo_from_config()
        if rollback_cfg:
            _save_config_object(rollback_cfg)
        return jsonify({"error": msg}), 400
    restart = _restart_xray()
    _dns_hijack_apply()
    _tp_state_write({"enabled": True, "port": port, "proxy_tag": proxy_tag})
    return jsonify({"ok": True, "port": port, "restart": restart})


@app.route("/api/transparent/disable", methods=["POST"])
@_serialized
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
@_serialized
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
@_serialized
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
@_serialized
def api_connect_start():
    """One-click start: apply selected nodes, routing, optional transparent proxy."""
    data = request.json or {}
    tags = data.get("tags", [])
    strategy = data.get("strategy", "roundRobin")
    transparent = bool(data.get("transparent", False))
    raw_ports = data.get("ports") or {}
    if not isinstance(raw_ports, dict):
        return jsonify({"error": "ports must be an object"}), 400
    try:
        ports = {key: _valid_port(raw_ports.get(key), default)
                 for key, default in (("socks", 10810), ("http", 10818), ("transparent", 12345))}
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

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
@_serialized
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
    runtime_by_tag = {ob.get("tag", ""): ob for ob in temp_cfg["outbounds"]}
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
                runtime_ob = runtime_by_tag.get(tag, ob)
                v = runtime_ob.get("settings", {}).get("vnext", [{}])[0]
                s = runtime_ob.get("settings", {}).get("servers", [{}])[0]
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


# ---------------------------------------------------------------------------
# Host traffic history (vnstat-like): samples /proc/net/dev of the host netns
# (the container runs with --network host) into hourly buckets per interface.
# Covers all traffic of the machine, not only the proxy core.
# ---------------------------------------------------------------------------
TRAFFIC_DB = f"{BASE_DIR}/state/traffic.db"
TRAFFIC_SAMPLE_INTERVAL = int(os.environ.get("TRAFFIC_SAMPLE_INTERVAL", "60") or 0)
TRAFFIC_KEEP_DAYS = int(os.environ.get("TRAFFIC_KEEP_DAYS", "400") or 400)
_TRAFFIC_SKIP_PREFIXES = ("lo", "docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "vxlan", "kube")
_TRAFFIC_LOCK = threading.Lock()


def _traffic_conn():
    import sqlite3
    Path(TRAFFIC_DB).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(TRAFFIC_DB, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS last_sample(iface TEXT PRIMARY KEY, boot_id TEXT, rx INTEGER, tx INTEGER, ts INTEGER);"
        "CREATE TABLE IF NOT EXISTS hourly(iface TEXT, hour INTEGER, rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(iface, hour));"
        "CREATE TABLE IF NOT EXISTS iface_info(iface TEXT PRIMARY KEY, ips TEXT, first_seen INTEGER, last_seen INTEGER);"
    )
    return conn


def _boot_info():
    boot_id, btime = "", 0
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        pass
    try:
        for line in Path("/proc/stat").read_text().splitlines():
            if line.startswith("btime "):
                btime = int(line.split()[1])
    except (OSError, ValueError):
        pass
    return boot_id, btime


def _iface_ipv4():
    out, _, rc = _run("ip -4 -o addr show", timeout=5)
    res = {}
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "inet":
                res.setdefault(parts[1].split("@", 1)[0], []).append(parts[3].split("/", 1)[0])
    return res


def _traffic_spread(conn, iface, start, end, rx, tx):
    """Add rx/tx to hourly buckets, split proportionally over [start, end]."""
    if rx <= 0 and tx <= 0:
        return
    start = min(start, end)
    span = end - start
    hours = []
    h = start - start % 3600
    while h <= end:
        lo, hi = max(h, start), min(h + 3600, end)
        hours.append((h, (hi - lo) if span > 0 else 1))
        h += 3600
    total = sum(w for _, w in hours) or 1
    rx_left, tx_left = rx, tx
    for i, (h, w) in enumerate(hours):
        if i == len(hours) - 1:
            r, t = rx_left, tx_left
        else:
            r, t = rx * w // total, tx * w // total
        rx_left -= r
        tx_left -= t
        if r or t:
            conn.execute("INSERT INTO hourly(iface,hour,rx,tx) VALUES(?,?,?,?) "
                         "ON CONFLICT(iface,hour) DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx",
                         (iface, h, r, t))


def _traffic_sample(now=None, counters=None, boot=None, ips=None):
    """One sampling pass. Deltas since the previous sample (also across panel
    restarts within the same boot) go into hourly buckets."""
    now = int(now if now is not None else time.time())
    counters = _read_net_dev() if counters is None else counters
    boot_id, btime = _boot_info() if boot is None else boot
    ips = _iface_ipv4() if ips is None else ips
    with _TRAFFIC_LOCK:
        conn = _traffic_conn()
        try:
            last = {r[0]: r[1:] for r in conn.execute("SELECT iface, boot_id, rx, tx, ts FROM last_sample")}
            for iface, (rx, tx) in counters.items():
                if iface.startswith(_TRAFFIC_SKIP_PREFIXES):
                    continue
                prev = last.get(iface)
                if prev is None:
                    pass  # first sight: baseline only
                elif prev[0] == boot_id and rx >= prev[1] and tx >= prev[2]:
                    _traffic_spread(conn, iface, prev[3], now, rx - prev[1], tx - prev[2])
                else:
                    # reboot or interface counter reset: counters restart from 0
                    start = max(prev[3], btime) if prev[0] != boot_id else prev[3]
                    _traffic_spread(conn, iface, start, now, rx, tx)
                conn.execute("INSERT OR REPLACE INTO last_sample VALUES(?,?,?,?,?)", (iface, boot_id, rx, tx, now))
                conn.execute("INSERT INTO iface_info(iface, ips, first_seen, last_seen) VALUES(?,?,?,?) "
                             "ON CONFLICT(iface) DO UPDATE SET ips=CASE WHEN excluded.ips!='' THEN excluded.ips ELSE ips END, last_seen=excluded.last_seen",
                             (iface, ",".join(ips.get(iface, [])), now, now))
            conn.commit()
        finally:
            conn.close()


def _traffic_prune(now=None):
    now = int(now if now is not None else time.time())
    with _TRAFFIC_LOCK:
        conn = _traffic_conn()
        try:
            conn.execute("DELETE FROM hourly WHERE hour < ?", (now - TRAFFIC_KEEP_DAYS * 86400,))
            conn.commit()
        finally:
            conn.close()


def _traffic_loop():
    last_prune = 0
    while True:
        try:
            _traffic_sample()
            if time.time() - last_prune > 86400:
                _traffic_prune()
                last_prune = time.time()
        except Exception as e:  # keep sampling even if one pass fails
            print(f"[traffic] sample failed: {e}", flush=True)
        time.sleep(TRAFFIC_SAMPLE_INTERVAL)


def _traffic_history(range_name="24h", now=None):
    now = int(now if now is not None else time.time())
    lt = time.localtime(now)
    if range_name == "30d":
        day0 = int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1)))
        starts = []
        d = datetime.fromtimestamp(day0)
        for i in range(29, -1, -1):
            x = d - timedelta(days=i)
            starts.append(int(time.mktime(x.timetuple())))
        label = lambda t: time.strftime("%m-%d", time.localtime(t))
        end = int(time.mktime((datetime.fromtimestamp(day0) + timedelta(days=1)).timetuple()))
    elif range_name == "12m":
        y, m = lt.tm_year, lt.tm_mon
        months = []
        for _ in range(12):
            months.append((y, m))
            y, m = (y - 1, 12) if m == 1 else (y, m - 1)
        months.reverse()
        starts = [int(time.mktime((y, m, 1, 0, 0, 0, 0, 0, -1))) for y, m in months]
        ny, nm = (lt.tm_year + 1, 1) if lt.tm_mon == 12 else (lt.tm_year, lt.tm_mon + 1)
        end = int(time.mktime((ny, nm, 1, 0, 0, 0, 0, 0, -1)))
        label = lambda t: time.strftime("%Y-%m", time.localtime(t))
    else:
        range_name = "24h"
        h0 = now - now % 3600
        starts = [h0 - 3600 * i for i in range(23, -1, -1)]
        end = h0 + 3600
        label = lambda t: time.strftime("%H:00", time.localtime(t))

    day_start = int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1)))
    month_start = int(time.mktime((lt.tm_year, lt.tm_mon, 1, 0, 0, 0, 0, 0, -1)))
    with _TRAFFIC_LOCK:
        conn = _traffic_conn()
        try:
            rows = conn.execute("SELECT iface, hour, rx, tx FROM hourly WHERE hour >= ? AND hour < ?",
                                (min(starts[0], month_start), end)).fetchall()
            totals = {r[0]: (r[1], r[2], r[3]) for r in conn.execute(
                "SELECT iface, SUM(rx), SUM(tx), MIN(hour) FROM hourly GROUP BY iface")}
            info = {r[0]: (r[1], r[2], r[3]) for r in conn.execute("SELECT iface, ips, first_seen, last_seen FROM iface_info")}
        finally:
            conn.close()

    import bisect
    buckets = [{"start": t, "label": label(t), "data": {}} for t in starts]
    ifaces = {}
    for iface, hour, rx, tx in rows:
        st = ifaces.setdefault(iface, {"today": [0, 0], "month": [0, 0]})
        if hour >= day_start:
            st["today"][0] += rx; st["today"][1] += tx
        if hour >= month_start:
            st["month"][0] += rx; st["month"][1] += tx
        i = bisect.bisect_right(starts, hour) - 1
        if 0 <= i < len(buckets) and hour < end:
            cell = buckets[i]["data"].setdefault(iface, [0, 0])
            cell[0] += rx; cell[1] += tx
    out_ifaces = []
    for iface in sorted(set(totals) | set(info)):
        ips, first_seen, last_seen = info.get(iface, ("", None, None))
        t = totals.get(iface, (0, 0, None))
        st = ifaces.get(iface, {"today": [0, 0], "month": [0, 0]})
        out_ifaces.append({
            "name": iface, "ips": [x for x in (ips or "").split(",") if x],
            "today": {"rx": st["today"][0], "tx": st["today"][1]},
            "month": {"rx": st["month"][0], "tx": st["month"][1]},
            "total": {"rx": t[0] or 0, "tx": t[1] or 0},
            "since": min(x for x in (first_seen, t[2]) if x) if (first_seen or t[2]) else None,
            "last_seen": last_seen,
            "active": bool(last_seen and now - last_seen < max(3 * TRAFFIC_SAMPLE_INTERVAL, 300)),
        })
    for b in buckets:
        b["data"] = {k: {"rx": v[0], "tx": v[1]} for k, v in b["data"].items()}
    return {"ok": True, "range": range_name, "interval": TRAFFIC_SAMPLE_INTERVAL,
            "interfaces": out_ifaces, "buckets": buckets}


@app.route("/api/traffic/history")
def api_traffic_history():
    try:
        return jsonify(_traffic_history(request.args.get("range", "24h")))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500



# ---------------------------------------------------------------------------
# Per-remote-IP traffic (conntrack accounting, whole host incl. LAN/docker)
# ---------------------------------------------------------------------------
PEER_STATS_ENABLED = os.environ.get("PEER_STATS", "1") not in ("0", "false", "no")
PEER_KEEP_DAYS = int(os.environ.get("PEER_KEEP_DAYS", "30") or 30)
_ct_acc = None
_PEER_NODE_CACHE = {"t": 0, "ips": {}}
_PEER_DOMAIN_CACHE = {"t": 0, "map": {}}
PEER_KIND_LABELS = {"core": "经核心", "node": "代理节点", "direct": "直连", "internal": "内网", "inbound": "入站"}


def _conntrack_acct_enabled():
    try:
        return Path("/proc/sys/net/netfilter/nf_conntrack_acct").read_text().strip() == "1"
    except OSError:
        return None


def _peer_node_ips():
    """{ip: tag} of proxy node servers (domains resolved, cached 10 min)."""
    now = time.time()
    if now - _PEER_NODE_CACHE["t"] < 600 and _PEER_NODE_CACHE["ips"]:
        return _PEER_NODE_CACHE["ips"]
    cfg = None
    for path in (_runtime_config_path(), XRAY_CFG):
        try:
            with open(path) as f:
                cfg = json.load(f)
            break
        except Exception:
            continue
    ips = {}
    for ob in (cfg or {}).get("outbounds", []):
        if ob.get("protocol") in ("freedom", "blackhole", "dns", "loopback"):
            continue
        addr = _extract_node_info(ob).get("address", "")
        if not addr:
            continue
        if _is_ip(addr):
            ips.setdefault(addr, ob.get("tag", ""))
            continue
        try:
            for info in socket.getaddrinfo(addr, None, proto=socket.IPPROTO_TCP):
                ips.setdefault(info[4][0], ob.get("tag", ""))
        except OSError:
            pass
    _PEER_NODE_CACHE.update(t=now, ips=ips)
    return ips


def _peer_context():
    local = {"127.0.0.1", "::1"}
    for addrs in _iface_ipv4().values():
        local.update(addrs)
    out, _, rc = _run("ip -6 -o addr show", timeout=5)
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "inet6":
                local.add(parts[3].split("/", 1)[0])
    return {"local_ips": local, "node_ips": set(_peer_node_ips())}


_PEER_RX_RECV = re.compile(r"\[(\d+)\] proxy/dokodemo: received request for (\S+)")
_PEER_RX_SNIFF = re.compile(r"\[(\d+)\] app/dispatcher: sniffed domain: (\S+)")
_PEER_RX_ACCEPT = re.compile(r" from (\S+) accepted (?:tcp|udp):(\[[^\]]+\]|[0-9.]+):\d+ \[[^\]]*?(?:->|>>)\s*([^\]\s]+)\]")


def _peer_domain_map():
    """({ip: [domain, ...]}, {ip: outbound_tag}) from the core log of the last 24h
    (cached 60s). Transparent connections are linked by the client endpoint:
    "[sid] dokodemo: received request for C" + "[sid] sniffed domain: D" +
    "from C accepted tcp:IP:443 [in -> out]". DNS answers and freedom
    "connection opened" lines add more IP -> domain pairs."""
    now = time.time()
    if now - _PEER_DOMAIN_CACHE["t"] < 60:
        return _PEER_DOMAIN_CACHE["map"], _PEER_DOMAIN_CACHE.get("routes", {})
    import collections
    m = collections.defaultdict(collections.Counter)
    routes = {}
    sid_by_client, domain_by_sid = {}, {}
    for line in _read_log_window(datetime.now() - timedelta(hours=24)):
        if "accepted" in line:
            g = _PEER_RX_ACCEPT.search(line)
            if g:
                client, ip, out = g.group(1), g.group(2).strip("[]"), g.group(3)
                routes[ip] = out
                d = domain_by_sid.get(sid_by_client.get(client, ""))
                if d and d != ip:
                    m[ip][d] += 3
                continue
        if "dokodemo: received request" in line:
            g = _PEER_RX_RECV.search(line)
            if g:
                sid_by_client[g.group(2)] = g.group(1)
            continue
        if "sniffed domain" in line:
            g = _PEER_RX_SNIFF.search(line)
            if g:
                domain_by_sid[g.group(1)] = g.group(2).rstrip(".")
            continue
        a = _parse_dns_answer_line(line) or _parse_connection_opened_line(line)
        if a:
            for ip in a[1]:
                m[ip][a[0]] += 1
    res = {ip: [d for d, _ in cnt.most_common(3)] for ip, cnt in m.items() if ip}
    _PEER_DOMAIN_CACHE.update(t=now, map=res, routes=routes)
    return res, routes


def _peer_stats_start():
    global _ct_acc
    if not PEER_STATS_ENABLED or _ct_acc is not None:
        return
    _ct_acc = _ct.ConntrackAccounting(TRAFFIC_DB, _peer_context, dump_interval=60, keep_days=PEER_KEEP_DAYS)
    _ct_acc.start()


@app.route("/api/traffic/peers")
def api_traffic_peers():
    hours = max(1, min(request.args.get("hours", 1, type=int) or 1, 24 * PEER_KEEP_DAYS))
    kind = (request.args.get("kind") or "").strip()
    q = (request.args.get("q") or "").strip().lower()
    limit = max(1, min(request.args.get("limit", 200, type=int) or 200, 2000))
    status = {"enabled": PEER_STATS_ENABLED, "acct": _conntrack_acct_enabled()}
    if _ct_acc is None:
        return jsonify({"ok": True, "status": status, "rows": [], "totals": {}, "total_rows": 0})
    status.update({k: _ct_acc.stats.get(k) for k in ("events", "dropped", "dumps", "last_dump", "flows",
                                                      "started_at", "error", "no_counters")})
    try:
        rows, totals, n = _ct_acc.query(hours=hours)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "status": status}), 500
    domains, routes = _peer_domain_map()
    nodes = _peer_node_ips()
    wire_direct = {r["ip"] for r in rows if r["kind"] == "direct"}
    for r in rows:
        r["domains"] = domains.get(r["ip"], [])
        if r["kind"] == "node":
            r["node"] = nodes.get(r["ip"], "")
        if r["kind"] == "core":
            tag = routes.get(r["ip"], "")
            r["outbound"] = tag
            if tag:
                r["route"] = {"direct": "direct", "blocked": "block"}.get(_classify_outbound(tag), "proxy")
            else:
                r["route"] = "direct" if r["ip"] in wire_direct else "proxy"
        r["label"] = PEER_KIND_LABELS.get(r["kind"], r["kind"])
    if kind == "wire":
        rows = [r for r in rows if r["kind"] != "core"]
    elif kind:
        rows = [r for r in rows if r["kind"] == kind]
    if q:
        rows = [r for r in rows if q in r["ip"].lower() or any(q in d.lower() for d in r["domains"])
                or q in (r.get("node") or "").lower()]
    matched = len(rows)
    rows = rows[:limit]
    if request.args.get("enrich", "1") != "0":
        meta = _enrich_ip_meta([r["ip"] for r in rows[:100] if not _ct._is_private(r["ip"])])
        for r in rows:
            if r["ip"] in meta:
                m = meta[r["ip"]]
                r["meta"] = {"asn": m.get("asn"), "country": m.get("country"), "as_name": m.get("as_name")}
    wire = {"rx": 0, "tx": 0}
    for k, t in totals.items():
        if k != "core":
            wire["rx"] += t["rx"]
            wire["tx"] += t["tx"]
    return jsonify({"ok": True, "status": status, "hours": hours, "rows": rows, "matched": matched,
                    "total_rows": n, "totals": totals, "wire": wire})


def _classify_outbound(tag):
    if tag == "direct":
        return "direct"
    if tag == "block":
        return "blocked"
    return "proxy"


def _parse_endpoint(endpoint):
    """Parse Xray endpoint like tcp:host:443, //host:443, DNS, or udp:[::1]:53."""
    endpoint = (endpoint or "").strip()
    if endpoint == "DNS":
        return "dns", "DNS", None
    network = ""
    rest = endpoint
    if endpoint.startswith("//"):
        rest = endpoint[2:]
    elif ":" in endpoint:
        first, tail = endpoint.split(":", 1)
        if first in ("tcp", "udp"):
            network = first
            rest = tail

    host = rest
    port = None
    if rest.startswith("[") and "]:" in rest:
        host, port_s = rest.rsplit("]:", 1)
        host = host + "]"
        if port_s.isdigit():
            port = int(port_s)
    elif ":" in rest:
        host_s, port_s = rest.rsplit(":", 1)
        # IPv6 without brackets has multiple colons and no reliable port separator.
        if port_s.isdigit() and host_s.count(":") <= 1:
            host = host_s
            port = int(port_s)
    return network, host, port


def _parse_access_time(ts):
    for fmt in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except Exception:
            pass
    return None


def _parse_route_tag(route):
    # Newer Xray logs use "inbound -> outbound"; older logs may only have outbound.
    parts = [p.strip() for p in (route or "").split("->") if p.strip()]
    return parts[-1] if parts else (route or "").strip()


def _parse_access_line(line):
    line = line.rstrip("\n")
    if " accepted " not in line or "[" not in line or "]" not in line:
        return None
    m = re.match(
        r'^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
        r'(?:from\s+)?(?P<src>.+?)\s+accepted\s+(?P<dest>\S+)\s+'
        r'\[(?P<route>[^\]]+)\]',
        line,
    )
    if not m:
        return None
    src_network, client, _src_port = _parse_endpoint(m.group("src"))
    network, target, port = _parse_endpoint(m.group("dest"))
    route = m.group("route")
    outbound = _parse_route_tag(route)
    ts = m.group("ts")
    # Keep seconds in API output so sorting/filtering remains readable.
    display_ts = ts.split(".", 1)[0]
    return {
        "time": display_ts,
        "client": client,
        "source_network": src_network,
        "network": network,
        "target": target,
        "port": port,
        "route": route,
        "outbound": outbound,
        "route_type": _classify_outbound(outbound),
        "raw": line,
    }


def _is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip("[]"))
        return True
    except Exception:
        return False


def _read_last_lines(path, max_lines=50000):
    try:
        with open(path) as f:
            return f.readlines()[-max_lines:]
    except Exception:
        return []


def _parse_dns_answer_line(line):
    """Parse Xray info log: got answer: domain. TypeA -> [ip ip]."""
    if " got answer: " not in line or " -> [" not in line:
        return None
    m = re.search(r'got answer:\s+(?P<domain>\S+)\s+Type(?:A|AAAA)\s+->\s+\[(?P<ips>[^\]]*)\]', line)
    if not m:
        return None
    domain = m.group("domain").rstrip(".")
    ips = [x.strip().strip(",") for x in m.group("ips").split() if x.strip()]
    ips = [ip.strip("[]") for ip in ips if _is_ip(ip)]
    if not domain or not ips:
        return None
    return domain, ips


def _parse_connection_opened_line(line):
    """Parse freedom info log: connection opened to tcp:domain:443 ... remote endpoint ip:443."""
    if "connection opened to" not in line or "remote endpoint" not in line:
        return None
    m = re.search(r'connection opened to\s+(?:tcp|udp):(?P<domain>\S+?):(?P<dport>\d+),.*?remote endpoint\s+(?P<ip>\[[^\]]+\]|[0-9a-fA-F:.]+):(?P<rport>\d+)', line)
    if not m:
        return None
    domain = m.group("domain").strip("[]").rstrip(".")
    ip = m.group("ip").strip("[]")
    if not domain or _is_ip(domain) or not _is_ip(ip):
        return None
    return domain, [ip]


def _parse_sniffed_domain_line(line):
    if "sniffed domain:" not in line:
        return None
    m = re.search(r'^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\[Info\]\s+\[(?P<id>\d+)\].*?sniffed domain:\s+(?P<domain>\S+)', line)
    if not m:
        return None
    domain = m.group("domain").rstrip(".")
    if not domain or _is_ip(domain):
        return None
    return {"time": m.group("ts").split(".", 1)[0], "id": m.group("id"), "domain": domain}


# ---------------------------------------------------------------------------
# Session-ID based log parsing (xray.log at info level)
# ---------------------------------------------------------------------------

def _parse_session_line(line):
    """Parse one xray.log line into a structured event with session_id."""
    line = line.rstrip("\n")

    # Extract session ID [NNNN] — format: "2026/06/07 01:40:36.445864 [Info] [NNNN]"
    sid_m = re.search(r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\[Info\]\s+\[(\d+)\]', line)
    if not sid_m:
        return None

    ts = sid_m.group(1)
    session_id = sid_m.group(2)
    display_ts = ts.split(".", 1)[0]

    # 1. sniffed domain
    m = re.search(r'app/dispatcher: sniffed domain:\s+(\S+)', line)
    if m:
        domain = m.group(1).rstrip(".")
        if domain and not _is_ip(domain):
            return {"_type": "sniffed", "_sid": session_id, "_ts": display_ts, "domain": domain}

    # 2. taking detour
    m = re.search(r'app/dispatcher: taking detour\s+\[([^\]]+)\]\s+for\s+\[(\S+)\]', line)
    if m:
        route_tag = m.group(1)
        target_proto = m.group(2)
        return {"_type": "detour", "_sid": session_id, "_ts": display_ts,
                "route_tag": route_tag, "target_proto": target_proto}

    # 3. connection opened
    m = re.search(r'proxy/freedom: connection opened to\s+(\S+?),.*?remote endpoint\s+(\S+):(\d+)', line)
    if m:
        return {"_type": "opened", "_sid": session_id, "_ts": display_ts,
                "target_proto": m.group(1), "remote_ip": m.group(2).strip("[]"), "remote_port": m.group(3)}

    # 4. shadowsocks tunneling
    m = re.search(r'proxy/shadowsocks: tunneling request to\s+(\S+?)\s+via\s+(\S+)', line)
    if m:
        return {"_type": "tunneled", "_sid": session_id, "_ts": display_ts,
                "target_proto": m.group(1), "via": m.group(2)}

    # 5. connection failed
    if "failed to" in line and ("process outbound" in line or "open connection" in line):
        return {"_type": "failed", "_sid": session_id, "_ts": display_ts}

    return None


_LOG_TS_RE = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")


def _read_log_window(cutoff=None, max_lines=50000):
    """Tail of xray.log; also reads the rotated xray.log.1 when the current file
    starts after `cutoff` (supervisor rotates xray.log every 10MB)."""
    lines = _read_last_lines(XRAY_LOG_FILE, max_lines=max_lines)
    if cutoff is None or len(lines) >= max_lines:
        return lines
    first = None
    for line in lines[:200]:
        m = _LOG_TS_RE.match(line)
        if m:
            first = _parse_access_time(m.group(1))
            break
    if first is None or first > cutoff:
        lines = _read_last_lines(XRAY_LOG_FILE + ".1", max_lines=max_lines - len(lines)) + lines
    return lines


def _build_sessions(max_lines=50000, cutoff=None):
    """Read xray.log, group by session ID, build per-connection records."""
    grouped = {}
    for line in _read_log_window(cutoff, max_lines=max_lines):
        ev = _parse_session_line(line)
        if ev and ev.get("_sid"):
            grouped.setdefault(ev["_sid"], []).append(ev)

    sessions = []
    for sid, events in grouped.items():
        domain = ""
        route_tag = ""
        target_ip = ""
        target_port = ""
        client = ""
        failed = False
        ts = ""

        for ev in events:
            if not ts:
                ts = ev.get("_ts", "")
            if ev["_type"] == "sniffed" and not domain:
                domain = ev["domain"]
            elif ev["_type"] == "detour":
                if not route_tag:
                    route_tag = ev["route_tag"]
                # Extract domain from detour target if no sniffed domain
                if not domain:
                    proto_target = ev.get("target_proto", "")
                    _, detour_domain, _ = _parse_endpoint(proto_target)
                    if detour_domain and not _is_ip(detour_domain):
                        domain = detour_domain
            elif ev["_type"] == "opened":
                target_ip = ev.get("remote_ip", "")
                target_port = ev.get("remote_port", "")
            elif ev["_type"] == "failed":
                failed = True

        if not target_ip and not domain:
            continue

        route_type = _classify_outbound(route_tag)
        # Prefer domain as target, IP as connection detail
        target = domain or target_ip
        domains = [domain] if domain else []
        display = domain if domain and target_ip and domain != target_ip else target
        sessions.append({
            "time": ts,
            "client": client,
            "target": target,
            "display_target": _target_display(display, domains) if domain else target_ip,
            "domains": domains,
            "ip": target_ip,
            "ip_meta": None,
            "port": target_port,
            "route_type": route_type,
            "outbound": route_tag,
            "route": route_tag,
            "network": "",
            "source_network": "",
            "raw": "",
            "failed": failed,
        })

    return sessions


def _load_ip_meta_cache():
    try:
        with open(IP_META_CACHE_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_ip_meta_cache(cache):
    try:
        Path(IP_META_CACHE_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(IP_META_CACHE_FILE, "w") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _query_team_cymru(ips, timeout=4):
    """Batch query Team Cymru whois. Returns ip -> ASN metadata. Best-effort."""
    ips = [ip for ip in ips if _is_ip(ip) and not ipaddress.ip_address(ip.strip("[]")).is_private]
    if not ips:
        return {}
    query = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    result = {}
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(query.encode())
            chunks = []
            while True:
                try:
                    b = sock.recv(4096)
                except socket.timeout:
                    break
                if not b:
                    break
                chunks.append(b)
        text = b"".join(chunks).decode("utf-8", "replace")
    except Exception:
        return result
    for line in text.splitlines():
        if not line.strip() or line.lower().startswith("as"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        asn, ip, bgp_prefix, cc, registry, allocated = parts[:6]
        as_name = " | ".join(parts[6:]).strip()
        if not _is_ip(ip):
            continue
        result[ip] = {
            "asn": asn,
            "prefix": bgp_prefix,
            "country": cc,
            "registry": registry,
            "allocated": allocated,
            "as_name": as_name,
            "updated_at": int(time.time()),
            "source": "team-cymru",
        }
    return result


def _enrich_ip_meta(ips):
    cache = _load_ip_meta_cache()
    now = int(time.time())
    ttl = 7 * 24 * 3600
    missing = []
    for ip in sorted(set(ips)):
        if not _is_ip(ip):
            continue
        meta = cache.get(ip)
        if not meta or now - int(meta.get("updated_at", 0) or 0) > ttl:
            missing.append(ip)
    if missing:
        queried = _query_team_cymru(missing[:100])
        if queried:
            cache.update(queried)
            _save_ip_meta_cache(cache)
    return {ip: cache.get(ip) for ip in ips if cache.get(ip)}


def _target_display(target, domains):
    if domains and domains[0] != target:
        return f"{domains[0]} / {target}"
    return target


@app.route("/api/access-stats")
def api_access_stats():
    minutes = request.args.get("minutes", 5, type=int) or 5
    q = (request.args.get("q") or "").strip().lower()
    route_type = request.args.get("type", "all") or "all"
    limit = request.args.get("limit", 100, type=int) or 100
    enrich = request.args.get("enrich", "1") != "0"
    minutes = max(1, min(minutes, 24 * 60))
    limit = max(1, min(limit, 1000))
    cutoff = datetime.now() - timedelta(minutes=minutes)

    try:
        all_sessions = _build_sessions(cutoff=cutoff)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e),
                        "hint": f"xray.log not found or parse error: {XRAY_LOG_FILE}"})

    # Time window filter
    records = []
    for rec in all_sessions:
        ts = _parse_access_time(rec["time"])
        if not ts or ts < cutoff:
            continue
        if route_type != "all" and rec["route_type"] != route_type:
            continue
        records.append(rec)

    # Search filter
    if q:
        filtered = []
        for rec in records:
            domains = rec.get("domains") or []
            hay = " ".join(str(rec.get(k) or "") for k in ("client", "target", "display_target", "outbound", "route_type"))
            hay += " " + " ".join(domains)
            if q in hay.lower():
                filtered.append(rec)
        records = filtered

    # IP metadata enrichment
    if enrich:
        target_ips = sorted({r["target"].strip("[]") for r in records if _is_ip(r.get("target", ""))})
        ip_meta = _enrich_ip_meta(target_ips)
        for rec in records:
            meta = ip_meta.get((rec.get("target") or "").strip("[]"))
            if meta:
                rec["ip_meta"] = meta

    # Aggregation
    by_target = {}
    by_outbound = {}
    by_client = {}
    for rec in records:
        target = rec["target"] or "(unknown)"
        domains = rec.get("domains") or []
        item = by_target.setdefault(target, {
            "target": target,
            "display_target": _target_display(target, domains),
            "domains": domains,
            "ip_meta": rec.get("ip_meta"),
            "count": 0, "proxy": 0, "direct": 0, "blocked": 0,
            "outbounds": {},
            "last_seen": rec["time"],
        })
        if domains and not item.get("domains"):
            item["domains"] = domains
            item["display_target"] = _target_display(target, domains)
        if rec.get("ip_meta") and not item.get("ip_meta"):
            item["ip_meta"] = rec.get("ip_meta")
        item["count"] += 1
        item[rec["route_type"]] += 1
        item["outbounds"][rec["outbound"]] = item["outbounds"].get(rec["outbound"], 0) + 1
        if rec["time"] > item["last_seen"]:
            item["last_seen"] = rec["time"]
        by_outbound[rec["outbound"]] = by_outbound.get(rec["outbound"], 0) + 1
        by_client[rec["client"]] = by_client.get(rec["client"], 0) + 1

    return jsonify({
        "ok": True,
        "log_file": XRAY_LOG_FILE,
        "window_minutes": minutes,
        "total": len(records),
        "proxy": sum(1 for r in records if r["route_type"] == "proxy"),
        "direct": sum(1 for r in records if r["route_type"] == "direct"),
        "blocked": sum(1 for r in records if r["route_type"] == "blocked"),
        "enriched_targets": sum(1 for x in by_target.values() if x.get("domains") or x.get("ip_meta")),
        "by_target": sorted(by_target.values(), key=lambda x: x["count"], reverse=True)[:200],
        "by_outbound": [{"outbound": k, "count": v} for k, v in sorted(by_outbound.items(), key=lambda x: x[1], reverse=True)],
        "by_client": [{"client": k, "count": v} for k, v in sorted(by_client.items(), key=lambda x: x[1], reverse=True)[:100]],
        "records": list(reversed(records[-limit:])),
    })


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


@app.route("/api/logs/clear", methods=["POST"])
def api_logs_clear():
    cleared = []
    errors = []
    log_files = [
        XRAY_LOG_FILE,
        ERROR_LOG_FILE,
        ACCESS_LOG_FILE,
        f"{BASE_DIR}/logs/xray.log",
        f"{BASE_DIR}/logs/xray.err",
        f"{BASE_DIR}/logs/panel.log",
        f"{BASE_DIR}/logs/panel.err",
    ]
    for path in dict.fromkeys(log_files):
        try:
            p = Path(path)
            if p.exists() and p.is_file():
                p.write_text("")
                cleared.append(str(p))
        except Exception as e:
            errors.append({"path": path, "error": str(e)})
    try:
        if Path(IP_META_CACHE_FILE).exists():
            Path(IP_META_CACHE_FILE).write_text("{}\n")
            cleared.append(IP_META_CACHE_FILE)
    except Exception as e:
        errors.append({"path": IP_META_CACHE_FILE, "error": str(e)})

    restart = _restart_xray()
    return jsonify({"ok": not errors and restart.get("success", False), "cleared": cleared, "errors": errors, "restart": restart})


@app.route("/api/backups")
def api_backups():
    cfg_dir = Path(XRAY_CFG).parent
    cfg_name = Path(XRAY_CFG).name
    found = list(cfg_dir.glob(f"{cfg_name}.bak.*")) + list(Path(f"{BASE_DIR}/backup").glob("config-*.json.bak"))
    backups = [str(p) for p in sorted(found, key=lambda p: p.stat().st_mtime, reverse=True)][:20]
    return jsonify({"backups": backups})


@app.route("/api/restore", methods=["POST"])
@_serialized
def api_restore():
    data = request.json
    if not data or "path" not in data:
        return jsonify({"error": "missing 'path' field"}), 400
    path = os.path.realpath(str(data["path"]))
    allowed_dirs = {os.path.realpath(str(Path(XRAY_CFG).parent)), os.path.realpath(f"{BASE_DIR}/backup")}
    if os.path.dirname(path) not in allowed_dirs:
        return jsonify({"error": "path must be a backup under config/ or backup/"}), 400
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
        _prune_config_backups()
    except Exception:
        pass

    with open(XRAY_CFG, "w") as f:
        f.write(content)
    test = _test_config()
    if not test["ok"]:
        with open(XRAY_CFG, "w") as f:
            f.write(raw)
        return jsonify({"error": "backup failed config test, not restored", "detail": test["output"]}), 400

    return jsonify({"ok": True, "restored_from": path, "test": test})


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
    ("net.netfilter.nf_conntrack_acct", "nf_conntrack_acct", "连接跟踪字节计数 (0/1)，「外部 IP 流量」统计需要；只对之后新建的连接生效", "1"),
]

# The container's own /proc/sys is read-only. Mount the host's net sysctls and
# sysctl.d to make changes apply immediately and survive reboots:
#   -v /proc/sys/net:/host/proc/sys/net -v /etc/sysctl.d:/host/etc/sysctl.d
SYSCTL_HOST_ROOT = os.environ.get("SYSCTL_HOST_ROOT", "/host/proc/sys")
SYSCTL_PERSIST_FILE = os.environ.get("SYSCTL_PERSIST_FILE", "/host/etc/sysctl.d/90-derwalld.conf")
_SYSCTL_VALUE_RE = re.compile(r"^[A-Za-z0-9_.\- ]{1,64}$")


def _sysctl_path(key):
    rel = key.replace(".", "/")
    host = Path(SYSCTL_HOST_ROOT) / rel
    if host.exists():
        return host, True
    return Path("/proc/sys") / rel, False


def _sysctl_writable(path):
    return os.access(str(path), os.W_OK) and "ro" not in _mount_opts_for(str(path))


def _mount_opts_for(path):
    best, opts = "", ""
    try:
        for line in Path("/proc/mounts").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 4 and (path == parts[1] or path.startswith(parts[1].rstrip("/") + "/")) and len(parts[1]) > len(best):
                best, opts = parts[1], parts[3]
    except OSError:
        pass
    return opts.split(",")


def _sysctl_persist(values):
    """Merge key=value lines into the host sysctl.d file owned by the panel."""
    path = Path(SYSCTL_PERSIST_FILE)
    if not path.parent.is_dir():
        return None, "宿主机 /etc/sysctl.d 未挂载，未持久化（重启后失效）"
    lines = path.read_text().splitlines() if path.exists() else [f"# managed by {PANEL_TITLE} panel"]
    for k, v in values.items():
        for i, line in enumerate(lines):
            if line.split("=", 1)[0].strip() == k:
                lines[i] = f"{k} = {v}"
                break
        else:
            lines.append(f"{k} = {v}")
    path.write_text("\n".join(lines) + "\n")
    return str(path).replace("/host", "", 1), None


@app.route("/api/sysctl")
def api_sysctl_get():
    result = []
    writable_any = False
    for full_key, short, desc, recommended in SYSCTL_PARAMS:
        path, on_host = _sysctl_path(full_key)
        try:
            val = " ".join(path.read_text().split())
        except Exception:
            val = "(unavailable)"
        writable = path.exists() and _sysctl_writable(path)
        writable_any = writable_any or writable
        result.append({"key": full_key, "short": short, "value": val, "desc": desc, "recommended": recommended,
                       "writable": writable})
    persist_dir = Path(SYSCTL_PERSIST_FILE).parent
    return jsonify({"params": result, "writable": writable_any,
                    "persist": str(SYSCTL_PERSIST_FILE).replace("/host", "", 1) if persist_dir.is_dir() else ""})


@app.route("/api/sysctl", methods=["POST"])
def api_sysctl_set():
    data = request.json or {}
    changes = data.get("changes", {})
    if not changes:
        return jsonify({"error": "no changes"}), 400
    if not isinstance(changes, dict):
        return jsonify({"error": "changes must be an object"}), 400
    applied, errors, done = [], [], {}
    for key, val in changes.items():
        if not any(key == p[0] for p in SYSCTL_PARAMS):
            errors.append(f"{key}: not allowed")
            continue
        val = " ".join(str(val).split())
        if not _SYSCTL_VALUE_RE.match(val):
            errors.append(f"{key}: invalid value")
            continue
        path, _ = _sysctl_path(key)
        try:
            cur = " ".join(path.read_text().split())
            if cur != val:
                path.write_text(val)
            if " ".join(path.read_text().split()) != val:
                raise OSError("value not accepted by kernel")
            applied.append(f"{key}={val}")
            done[key] = val
        except OSError as e:
            hint = "（容器内只读，需挂载 -v /proc/sys/net:/host/proc/sys/net）" if e.errno == errno.EROFS else ""
            errors.append(f"{key}: {e.strerror or e}{hint}")
    persisted = None
    if done:
        try:
            persisted, perr = _sysctl_persist(done)
            if perr:
                errors.append(perr)
        except OSError as e:
            errors.append(f"persist: {e}")
    return jsonify({"ok": not errors, "applied": applied, "errors": errors, "persisted": persisted}), (200 if applied or not errors else 400)


# ---------------------------------------------------------------------------
# HTML UI (single page, embedded)
# ---------------------------------------------------------------------------

HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__PANEL_TITLE__</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#f5f7fa;--bg2:#ffffff;--bg3:#f2f3f5;--border:#e5e6eb;--border2:#c9cdd4;
  --text:#1d2129;--text2:#86909c;--text3:#4e5969;
  --accent:#165dff;--accent-hover:#4080ff;--accent-soft:#e8f3ff;
  --green:#00b42a;--green-soft:#e8ffea;--red:#f53f3f;--red-soft:#ffece8;
  --yellow:#ff7d00;--yellow-soft:#fff7e8;--orange:#f77234;
  --sidebar:#1d2129;--sidebar-text:#c9cdd4;
  --radius:6px;--shadow:0 1px 2px rgba(0,0,0,.04),0 2px 8px rgba(29,33,41,.04);
  --mono:'JetBrains Mono','SF Mono',SFMono-Regular,Menlo,Consolas,monospace;
}
html,body{height:100%}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Hiragino Sans GB','Microsoft YaHei','Noto Sans CJK SC','Source Han Sans SC','WenQuanYi Micro Hei',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.57;font-size:14px;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
input,select,textarea,button{font:inherit}
input:not([type=checkbox]):not([type=radio]),select,textarea{background:var(--bg2)!important;color:var(--text)!important;border:1px solid var(--border)!important;border-radius:4px!important;transition:border-color .15s,box-shadow .15s;outline:none}
input:not([type=checkbox]):not([type=radio]):hover,select:hover,textarea:hover{border-color:var(--border2)!important}
input:not([type=checkbox]):not([type=radio]):focus,select:focus,textarea:focus{border-color:var(--accent)!important;box-shadow:0 0 0 2px var(--accent-soft)}
input[type=checkbox],input[type=radio]{accent-color:var(--accent);width:14px;height:14px;vertical-align:middle}
input[readonly],textarea[readonly]{background:var(--bg3)!important;color:var(--text3)!important}

/* ---------- top bar ---------- */
.header{background:var(--bg2);border-bottom:1px solid var(--border);height:56px;padding:0 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.header h1{font-size:16px;font-weight:600;display:flex;align-items:center;gap:10px;letter-spacing:.2px}
.header h1 svg{width:28px;height:28px;padding:5px;border-radius:6px;background:var(--accent);color:#fff;stroke:#fff}
.header .version{color:var(--text3);font-size:12px;background:var(--bg3);padding:2px 10px;border-radius:10px;font-family:var(--mono)}
#header-stats{background:var(--bg3);padding:3px 10px;border-radius:4px;color:var(--text3)!important}

/* ---------- layout: sidebar + content ---------- */
.container{display:grid;grid-template-columns:200px minmax(0,1fr);gap:0;min-height:calc(100vh - 56px);background:linear-gradient(to right,var(--bg2) 199px,var(--border) 199px,var(--border) 200px,transparent 200px)}
.tabs{grid-column:1;grid-row:1 / span 40;background:var(--bg2);border-right:1px solid var(--border);padding:12px 8px;display:flex;flex-direction:column;gap:2px;position:sticky;top:56px;height:calc(100vh - 56px);overflow-y:auto}
.tabs .tab{display:flex;align-items:center;gap:10px;padding:9px 14px;border-radius:4px;color:var(--text3);font-size:14px;cursor:pointer;border:none;transition:background .15s,color .15s;user-select:none}
.tabs .tab svg{width:16px;height:16px;flex-shrink:0;stroke:currentColor;fill:none;stroke-width:1.8}
.tabs .tab:hover{background:var(--bg3);color:var(--text)}
.tabs .tab.active{background:var(--accent-soft);color:var(--accent);font-weight:500}
.tabs .nav-group{font-size:12px;color:var(--text2);padding:14px 14px 6px;letter-spacing:.5px}
.tabs .nav-group:first-child{padding-top:4px}
.tab-content{display:none;grid-column:2;padding:20px 24px 40px;min-width:0}
.tab-content.active{display:block}

/* modal-internal tab strips keep a horizontal underline style */
.modal .tab{display:inline-block;padding:8px 16px;cursor:pointer;border-bottom:2px solid transparent;color:var(--text3);font-size:14px;transition:all .15s}
.modal .tab:hover{color:var(--text)}
.modal .tab.active{color:var(--accent);border-bottom-color:var(--accent);font-weight:500}

/* ---------- cards ---------- */
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:20px 24px;margin-bottom:16px;box-shadow:var(--shadow);overflow-x:auto;min-width:0}
.card h2{font-size:16px;font-weight:600;margin:-4px 0 16px;display:flex;align-items:center;gap:8px;color:var(--text)}
.card h2::before{content:"";width:3px;height:14px;border-radius:2px;background:var(--accent);display:inline-block}
.card h2 .dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.card > p:first-of-type{color:var(--text2)!important}
.dot.on{background:var(--green);box-shadow:0 0 0 3px var(--green-soft)}
.dot.off{background:var(--red);box-shadow:0 0 0 3px var(--red-soft)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.stat{background:var(--bg2);border:1px solid var(--border);padding:14px 16px;border-radius:var(--radius)}
.stat .label{color:var(--text2);font-size:12px;margin-bottom:6px}
.stat .value{font-size:20px;font-weight:600;font-family:var(--mono);color:var(--text)}

/* ---------- buttons ---------- */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:4px;height:32px;padding:0 15px;border-radius:4px;border:1px solid var(--border2);background:var(--bg2);color:var(--text);cursor:pointer;font-size:14px;line-height:1;white-space:nowrap;transition:all .15s}
.btn:hover{color:var(--accent);border-color:var(--accent)}
.btn:active{background:var(--accent-soft)}
.btn:disabled{cursor:not-allowed;opacity:.45;color:var(--text2);border-color:var(--border)}
.btn.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.seg{display:inline-flex;border:1px solid var(--border2);border-radius:4px;overflow:hidden}
.seg button{height:30px;padding:0 14px;border:0;border-right:1px solid var(--border2);background:var(--bg2);color:var(--text3);cursor:pointer;font-size:13px}
.seg button:last-child{border-right:0}
.seg button.on{background:var(--accent-soft);color:var(--accent);font-weight:500}
.tr-chart{width:100%;height:200px;display:block}
.tr-share{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--bg3);min-width:80px}
.tr-legend{display:flex;gap:14px;font-size:12px;color:var(--text2);align-items:center}
.tr-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
.btn.primary:hover{background:var(--accent-hover);border-color:var(--accent-hover);color:#fff}
.btn.danger{background:var(--bg2);color:var(--red);border-color:#fbaca3}
.btn.danger:hover{background:var(--red);color:#fff;border-color:var(--red)}
.btn.success{background:var(--green);color:#fff;border-color:var(--green)}
.btn.success:hover{background:#23c343;border-color:#23c343;color:#fff}
.btn.ghost{border-color:transparent;background:transparent;color:var(--accent)}
.btn.ghost:hover{background:var(--accent-soft)}
.btn.sm,.ob-actions .btn{height:24px;padding:0 8px;font-size:12px;border-radius:3px}
.btn-group{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;align-items:center}

/* ---------- connect page ---------- */
.conn-node-list{max-height:440px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg2)}
.conn-node{display:flex;align-items:center;gap:12px;padding:10px 14px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s;font-size:13px}
.conn-node:last-child{border-bottom:none}
.conn-node:hover{background:var(--bg3)}
.conn-node.selected{background:var(--accent-soft);box-shadow:inset 3px 0 0 var(--accent)}
.conn-node .cb{flex-shrink:0}
.conn-node .tag-col{min-width:140px;font-weight:500;font-family:var(--mono);color:var(--text)}
.conn-node .proto-col{min-width:96px;color:var(--text3);font-size:12px}
.conn-node .addr-col{flex:1;min-width:0;color:var(--text2);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono)}
.conn-node .latency-col{min-width:70px;text-align:right;font-family:var(--mono);font-size:12px}
.conn-ctrl{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-top:16px}
.conn-ctrl .card-inner{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px}
.conn-ctrl .card-inner > label:first-child{font-weight:500;color:var(--text)!important;font-size:13px!important}
.conn-status-bar{display:flex;align-items:center;gap:12px;padding:12px 16px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);margin-top:14px;font-size:13px}
.conn-status-bar .indicator{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.conn-status-bar .indicator.on{background:var(--green);box-shadow:0 0 0 4px var(--green-soft)}
.conn-status-bar .indicator.off{background:var(--border2)}

/* ---------- gateway panel ---------- */
.gw-panel{border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;margin-bottom:10px;background:var(--bg2)}
.gw-setup{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font-size:13px;margin:6px 0 10px}
.gw-setup b{font-family:var(--mono);color:var(--text)}
.gw-setup span{color:var(--text2)}
.gw-checks{display:flex;flex-wrap:wrap;gap:6px}
.check{display:inline-flex;align-items:center;gap:5px;font-size:12px;padding:2px 8px;border-radius:10px;background:var(--bg3);color:var(--text3)}
.check::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--border2)}
.check.ok{background:var(--green-soft);color:#009a29}.check.ok::before{background:var(--green)}
.check.warn{background:var(--yellow-soft);color:#d25f00}.check.warn::before{background:var(--yellow)}
.check.bad{background:var(--red-soft);color:#cb2634}.check.bad::before{background:var(--red)}

/* ---------- editors / tables ---------- */
textarea.config-editor{width:100%;min-height:500px;background:#fafbfc!important;color:var(--text);border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;font-family:var(--mono);font-size:12.5px;line-height:1.6;resize:vertical;tab-size:2;white-space:pre;overflow:auto}
table{width:100%;border-collapse:separate;border-spacing:0;border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}
th{background:var(--bg3);color:var(--text3);font-weight:500;font-size:13px;white-space:nowrap}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:#f7f8fa}
td{font-family:var(--mono);font-size:12.5px;color:var(--text)}
.ob-addr{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr.ob-system td{color:var(--text2)}
.tag{display:inline-block;padding:0 8px;line-height:22px;border-radius:3px;font-size:12px;font-weight:500;font-family:inherit;white-space:nowrap}
.tag.us{background:var(--accent-soft);color:var(--accent)}
.tag.kr{background:var(--green-soft);color:#009a29}
.tag.jp{background:var(--yellow-soft);color:#d25f00}
.tag.hk{background:#fff3e8;color:#e65b1c}
.tag.red{background:var(--red-soft);color:#cb2634}
.tag.default{background:var(--bg3);color:var(--text3)}
.log-box{background:#fafbfc;border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;font-family:var(--mono);font-size:12px;line-height:1.65;max-height:500px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;color:var(--text3)}

/* ---------- feedback ---------- */
.toast{position:fixed;top:68px;left:50%;transform:translateX(-50%);padding:10px 16px;border-radius:4px;font-size:14px;z-index:999;animation:slideIn .2s;max-width:480px;background:var(--bg2);color:var(--text);box-shadow:0 4px 12px rgba(0,0,0,.12);border:1px solid var(--border);display:flex;align-items:center;gap:8px}
.toast::before{content:"";width:8px;height:8px;border-radius:50%;flex-shrink:0}
.toast.ok::before{background:var(--green)}
.toast.err::before{background:var(--red)}
.toast.err{border-color:#fbaca3}
@keyframes slideIn{from{transform:translate(-50%,-8px);opacity:0}to{transform:translate(-50%,0);opacity:1}}

/* ---------- forms ---------- */
.edit-row{display:grid;grid-template-columns:120px 1fr;gap:10px;align-items:center;margin-bottom:10px}
.edit-row label{color:var(--text3);font-size:13px;text-align:right;white-space:nowrap}
.edit-row input,.edit-row select{width:100%}
.edit-row input,.edit-row select,.edit-row textarea{height:32px;padding:0 10px;font-size:13px}
.form-section{border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px 4px;margin-bottom:12px}
.form-section > h4{font-size:13px;font-weight:600;color:var(--text);margin:-2px 0 12px}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 16px}
.field{display:flex;flex-direction:column;gap:4px;margin-bottom:12px;min-width:0}
.field.full{grid-column:1 / -1}
.field > label{font-size:12px;color:var(--text3)}
.field > label em{font-style:normal;color:var(--text2);margin-left:4px}
.field input:not([type=checkbox]),.field select{height:32px;padding:0 10px;font-size:13px;width:100%}
.field textarea{padding:8px 10px;font-family:var(--mono);font-size:12px;min-height:72px;width:100%;resize:vertical}
.field .hint{font-size:12px;color:var(--text2)}
.field.inline{flex-direction:row;align-items:center;gap:8px}
.hidden{display:none!important}

/* ---------- routing ---------- */
.rule-builder{display:grid;grid-template-columns:180px minmax(0,1fr) 220px;gap:12px;align-items:start}
.rule-builder textarea{min-height:76px;padding:8px 10px;font-family:var(--mono);font-size:12px;width:100%;resize:vertical}
.rule-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;align-items:center}
.chips{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:12px}
.chips > span{font-size:12px;color:var(--text2);margin-right:2px}
.chip{display:inline-flex;align-items:center;gap:4px;height:26px;padding:0 10px;border-radius:13px;border:1px solid var(--border);background:var(--bg2);color:var(--text3);cursor:pointer;font-size:12px;transition:all .15s}
.chip:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-soft)}
.chip .x{color:var(--text2);margin-left:2px}
.chip .x:hover{color:var(--red)}
.match-vals{display:flex;flex-wrap:wrap;gap:4px}
.match-vals code{font-family:var(--mono);font-size:12px;background:var(--bg3);padding:0 6px;border-radius:3px;line-height:20px}
.dirty-flag{color:var(--yellow);font-size:12px}
.empty{padding:28px;text-align:center;color:var(--text2);font-size:13px}

.modal-overlay{position:fixed;inset:0;background:rgba(29,33,41,.45);z-index:200;display:none;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:var(--bg2);border-radius:8px;padding:20px 24px;width:92%;max-width:880px;max-height:88vh;overflow-y:auto;box-shadow:0 12px 32px rgba(0,0,0,.18)}
.modal h3{margin-bottom:16px;font-size:16px;font-weight:600}
.modal-footer{display:flex;justify-content:flex-end;gap:8px;margin-top:16px;padding-top:12px;border-top:1px solid var(--border)}
.modal-footer .btn-group{margin-top:0}
.ob-actions{display:flex;gap:4px;flex-wrap:nowrap;align-items:center;white-space:nowrap}
.backup-item{display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border);font-size:12px;font-family:var(--mono)}
.status-pill{display:inline-block;padding:0 10px;line-height:22px;border-radius:11px;font-size:12px;font-weight:500}
.status-pill.active{background:var(--green-soft);color:#009a29}
.status-pill.inactive{background:var(--red-soft);color:#cb2634}
details > summary{cursor:pointer;color:var(--text3)!important}
::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-thumb{background:#d9dbe0;border-radius:4px}::-webkit-scrollbar-track{background:transparent}

@media(max-width:900px){
  .header{padding:0 14px;height:52px}
  .header h1{font-size:15px}
  .header .version,#header-stats{display:none}
  .header h1{white-space:nowrap}
  .container{display:block;background:none}
  .tab-content div[style*="justify-content:space-between"]{flex-wrap:wrap;gap:8px}
  .tab-content div[style*="display:flex;gap:6px"]{flex-wrap:wrap}
  .tab-content span[id$="selected-count"]{white-space:nowrap}
  .conn-node{flex-wrap:wrap;gap:6px 10px}
  .conn-node .addr-col{flex-basis:100%;order:5}
  .conn-node .ob-actions{flex-wrap:wrap}
  .tabs{position:sticky;top:52px;z-index:90;height:auto;flex-direction:row;overflow-x:auto;border-right:none;border-bottom:1px solid var(--border);padding:6px 8px;scrollbar-width:none}
  .tabs::-webkit-scrollbar{display:none}
  .tabs .nav-group{display:none}
  .tabs .tab{padding:6px 12px;white-space:nowrap;font-size:13px}
  .tabs .tab svg{display:none}
  .tab-content{padding:12px}
  .card{padding:14px}
  .grid{grid-template-columns:repeat(2,1fr);gap:8px}
  .stat .value{font-size:15px}
  .form-grid,.rule-builder{grid-template-columns:1fr}
  .edit-row label{text-align:left;white-space:normal;line-height:1.4}
  table{display:block;overflow-x:auto}
  th,td{padding:8px 10px;font-size:12px}
  .modal{width:96%;padding:14px;max-height:92vh}
  .edit-row{grid-template-columns:96px 1fr}
  textarea.config-editor{min-height:300px;font-size:11px}
  .toast{left:12px;right:12px;transform:none;max-width:none}
  #ob-test-url-select,#ob-test-url-custom,#ob-speed-url,#conn-test-url-select,#conn-test-url-custom,#conn-speed-url,#conn-import-links{min-width:100%!important;flex:1}
}
</style>
</head>
<body>

<!-- Login Overlay -->
<div id="login-overlay" style="position:fixed;inset:0;background:var(--bg);z-index:9999;display:flex;align-items:center;justify-content:center">
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:32px;width:360px;text-align:center">
    <svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" style="width:40px;height:40px;margin-bottom:12px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    <h2 style="margin-bottom:20px;font-size:18px;color:var(--text)">__PANEL_TITLE__</h2>
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
    __PANEL_TITLE__
  </h1>
  <div style="display:flex;align-items:center;gap:10px">
    <span id="header-stats" style="font-size:11px;color:var(--text2);font-family:monospace">↓ - ↑ -</span>
    <span class="version" id="version">-</span>
    <button onclick="doLogout()" style="padding:4px 10px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;color:var(--text2);font-size:12px;cursor:pointer">退出</button>
  </div>
</div>

<div class="container">
  <div class="tabs">
    <div class="nav-group">代理</div>
    <div class="tab active" data-tab="connect" onclick="switchTab('connect')"><svg viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg>连接</div>
    <div class="tab" data-tab="outbounds" onclick="switchTab('outbounds')"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/></svg>节点</div>
    <div class="tab" data-tab="routing" onclick="switchTab('routing')"><svg viewBox="0 0 24 24"><path d="M6 3v12a3 3 0 0 0 3 3h9M15 15l3 3-3 3M6 3l3 3M6 3 3 6"/></svg>路由规则</div>
    <div class="tab" data-tab="inbounds" onclick="switchTab('inbounds')"><svg viewBox="0 0 24 24"><path d="M12 3v12M7 10l5 5 5-5M4 21h16"/></svg>入站</div>
    <div class="tab" data-tab="dns" onclick="switchTab('dns')"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>DNS</div>
    <div class="nav-group">运维</div>
    <div class="tab" data-tab="status" onclick="switchTab('status')"><svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>状态</div>
    <div class="tab" data-tab="logs" onclick="switchTab('logs')"><svg viewBox="0 0 24 24"><path d="M5 4h14v16H5zM9 8h6M9 12h6M9 16h4"/></svg>日志与访问</div>
    <div class="tab" data-tab="config" onclick="switchTab('config')"><svg viewBox="0 0 24 24"><path d="M8 6 3 12l5 6M16 6l5 6-5 6"/></svg>配置文件</div>
    <div class="tab" data-tab="system" onclick="switchTab('system')"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9 7 7M17 17l2.1 2.1M4.9 19.1 7 17M17 7l2.1-2.1"/></svg>系统</div>
    <div class="tab" data-tab="backups" onclick="switchTab('backups')"><svg viewBox="0 0 24 24"><path d="M4 7h16v13H4zM8 3h8v4H8zM9 13h6"/></svg>备份</div>
  </div>

  <!-- Connect Mode -->
  <div class="tab-content active" id="tab-connect">
    <div class="card">
      <h2>连接模式</h2>
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
        <select id="conn-test-url-select" style="min-width:min(240px,100%);padding:5px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-size:12px"></select>
        <input id="conn-test-url-custom" placeholder="自定义" style="min-width:min(200px,100%);padding:5px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace;font-size:12px">
        <label style="color:var(--text2);font-size:12px">测速URL</label>
        <input id="conn-speed-url" value="https://speed.cloudflare.com/__down?bytes=10000000" style="min-width:min(300px,100%);padding:5px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace;font-size:12px">
      </div>
      <div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:10px;flex-wrap:wrap">
        <textarea id="conn-import-links" placeholder="快速导入：vless:// vmess:// ss:// trojan://（支持多行）" style="flex:1;min-width:min(350px,100%);min-height:50px;padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace;font-size:12px;resize:vertical"></textarea>
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
            <div class="gw-panel" id="gw-panel">
              <div style="font-size:13px;font-weight:500">局域网网关</div>
              <div class="hint" style="font-size:12px;color:var(--text2)">手机、电视等设备手动设置 IP，把网关指向本机即可全局代理。</div>
              <div id="gw-body" style="font-size:12px;color:var(--text2);margin-top:6px">检测中...</div>
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
        <button class="btn success" onclick="connStart()" id="btn-conn-start">启动连接</button>
        <button class="btn danger" onclick="connStop()" id="btn-conn-stop">断开连接</button>
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
      <h2>流量统计（本机）</h2>
      <p style="font-size:13px;margin:-6px 0 12px">按网卡统计整台机器的收发字节（读取宿主机 /proc/net/dev，含代理以外的全部流量），每分钟采样一次，按小时存储，保留 400 天。</p>
      <div style="overflow-x:auto"><table style="white-space:nowrap">
        <thead><tr><th>网卡</th><th>IP</th><th>今日 ↓ / ↑</th><th>本月 ↓ / ↑</th><th>本月占比</th><th>累计 ↓ / ↑</th><th>记录起始</th></tr></thead>
        <tbody id="tr-iface-tbody"><tr><td colspan="7" style="color:var(--text2)">加载中…</td></tr></tbody>
      </table></div>
      <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:16px 0 8px">
        <div class="seg" id="tr-range">
          <button data-r="24h" class="on" onclick="setTrafficRange('24h')">24 小时</button>
          <button data-r="30d" onclick="setTrafficRange('30d')">30 天</button>
          <button data-r="12m" onclick="setTrafficRange('12m')">12 个月</button>
        </div>
        <select id="tr-iface" onchange="renderTraffic()" style="height:30px;padding:0 8px;border:1px solid var(--border2);border-radius:4px;background:var(--bg2);color:var(--text)"></select>
        <span class="tr-legend"><span><i style="background:var(--green)"></i>下载 ↓</span><span><i style="background:var(--yellow)"></i>上传 ↑</span></span>
        <span id="tr-sum" style="font-size:12px;color:var(--text2);margin-left:auto"></span>
      </div>
      <svg class="tr-chart" id="tr-chart" preserveAspectRatio="none"></svg>
    </div>
    <div class="card">
      <h2>外部 IP 流量</h2>
      <p style="font-size:13px;margin:-6px 0 12px">按对端 IP 统计整台机器（含局域网转发和 docker）的连接与字节，来自内核连接跟踪（nf_conntrack_acct）。「经核心」是应用要访问的原始目标 IP（如 kiro.dev 解析出的地址），其线上流量实际流向「代理节点」或「直连」，合计时不重复计入。</p>
      <div id="pr-status" style="font-size:12px;color:var(--text2);margin-bottom:10px"></div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px">
        <div class="seg" id="pr-range">
          <button data-h="1" class="on" onclick="setPeerRange(1)">1 小时</button>
          <button data-h="24" onclick="setPeerRange(24)">24 小时</button>
          <button data-h="168" onclick="setPeerRange(168)">7 天</button>
        </div>
        <select id="pr-kind" onchange="loadPeers()" style="height:30px;padding:0 8px;border:1px solid var(--border2);border-radius:4px;background:var(--bg2);color:var(--text)">
          <option value="">全部类型</option><option value="core">经核心（应用目标）</option><option value="wire">仅线上（不含经核心）</option>
          <option value="node">代理节点</option><option value="direct">直连</option><option value="internal">内网</option><option value="inbound">入站</option>
        </select>
        <input id="pr-q" placeholder="搜索 IP / 域名 / 节点" onkeydown="if(event.key==='Enter')loadPeers()" style="height:30px;flex:1;min-width:min(200px,100%);padding:0 10px;border:1px solid var(--border2);border-radius:4px">
        <button class="btn" onclick="loadPeers()">刷新</button>
      </div>
      <div id="pr-sum" style="font-size:13px;color:var(--text3);margin-bottom:10px"></div>
      <div style="overflow-x:auto"><table style="white-space:nowrap">
        <thead><tr><th>对端 IP</th><th>域名 / 节点</th><th>归属</th><th>类型</th><th>协议:端口</th><th>↓ 下载</th><th>↑ 上传</th><th>连接</th><th>最后</th></tr></thead>
        <tbody id="pr-tbody"><tr><td colspan="9" style="color:var(--text2)">加载中…</td></tr></tbody>
      </table></div>
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
        <select id="test-url-select" style="min-width:min(260px,100%);padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px"></select>
        <input id="test-url-custom" placeholder="自定义测试 URL" style="min-width:min(360px,100%);padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace">
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
        <select id="ob-test-url-select" style="min-width:min(260px,100%);padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px"></select>
        <input id="ob-test-url-custom" placeholder="自定义 URL" style="min-width:min(320px,100%);padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace">
      </div>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap">
        <label style="color:var(--text2);font-size:13px">测速 URL</label>
        <input id="ob-speed-url" value="https://speed.cloudflare.com/__down?bytes=10000000" style="min-width:min(460px,100%);padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace">
        <button class="btn primary" onclick="batchTestSelected('ping')">批量测延迟</button>
        <button class="btn" onclick="batchTestSelected('speed')">批量测速</button>
        <button class="btn" onclick="batchExportOutbounds()">批量导出</button>
      </div>
      <div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:12px;flex-wrap:wrap">
        <textarea id="quick-import-links" placeholder="快速导入：粘贴 vless:// vmess:// ss:// trojan:// 链接（支持多行）" style="flex:1;min-width:min(400px,100%);min-height:60px;padding:6px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:monospace;font-size:12px;resize:vertical"></textarea>
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
      <h2>添加规则</h2>
      <p style="font-size:13px;margin-bottom:14px">自定义规则排在系统规则之前，优先匹配；重新连接、切换节点或开关透明代理后仍然保留。“走代理”默认跟随当前连接的节点或负载均衡。</p>
      <div class="rule-builder">
        <div class="field">
          <label>匹配类型</label>
          <select id="rt-cond-type" onchange="routingTypeHint()">
            <option value="domain">域名（含子域名）</option>
            <option value="full">完整域名</option>
            <option value="keyword">域名关键词</option>
            <option value="geosite">域名集 geosite</option>
            <option value="ip">IP / CIDR</option>
            <option value="geoip">IP 集 geoip</option>
            <option value="port">目标端口</option>
            <option value="sourceIP">来源设备 IP</option>
          </select>
        </div>
        <div class="field">
          <label>匹配值<em id="rt-hint">每行或逗号分隔，如 openai.com</em></label>
          <textarea id="rt-cond-value" spellcheck="false" placeholder="openai.com&#10;chatgpt.com"></textarea>
        </div>
        <div class="field">
          <label>代理节点<em>“走代理”时使用</em></label>
          <select id="rt-outbound"></select>
          <label style="margin-top:8px">备注</label>
          <input id="rt-remark" placeholder="可选">
        </div>
      </div>
      <div class="rule-actions">
        <button class="btn" onclick="routingAdd('direct')">直连</button>
        <button class="btn primary" onclick="routingAdd('proxy')">走代理</button>
        <button class="btn danger" onclick="routingAdd('block')">阻断</button>
        <button class="btn" id="rt-bypass-btn" onclick="routingAddBypass()" title="IP/CIDR 在 iptables 层直接放行，不经过代理核心（局域网服务、游戏、内网段）">透明代理绕过</button>
      </div>
      <div class="chips">
        <span>常用：</span>
        <button class="chip" onclick="routingPreset('ads')">广告拦截</button>
        <button class="chip" onclick="routingPreset('ai')">OpenAI / Claude / Gemini 走代理</button>
        <button class="chip" onclick="routingPreset('kiro')">Kiro / AWS 走代理</button>
        <button class="chip" onclick="routingPreset('google')">Google / YouTube 走代理</button>
        <button class="chip" onclick="routingPreset('github')">GitHub 走代理</button>
        <button class="chip" onclick="routingPreset('apple')">Apple 服务直连</button>
        <button class="chip" onclick="routingPreset('bt')">BT 下载直连</button>
      </div>
    </div>

    <div class="card">
      <h2>自定义规则 <span class="dirty-flag" id="rt-dirty" style="display:none">有未保存的修改</span></h2>
      <table>
        <thead><tr><th style="width:44px">#</th><th style="width:110px">类型</th><th>匹配值</th><th style="width:150px">动作</th><th style="width:140px">备注</th><th style="width:170px">操作</th></tr></thead>
        <tbody id="rt-custom-tbody"></tbody>
      </table>
      <div class="btn-group">
        <button class="btn primary" onclick="routingSaveCustom()">保存并生效</button>
        <button class="btn" onclick="loadRouting()">放弃修改</button>
        <span style="font-size:12px;color:var(--text2)">保存会重启代理核心，已有连接会断开重连</span>
      </div>
      <div class="log-box" id="routing-output" style="display:none;margin-top:10px;max-height:150px"></div>
    </div>

    <div class="card">
      <h2>透明代理绕过</h2>
      <p style="font-size:13px;margin-bottom:10px">这些目标 IP 不进入代理核心，直接由本机转发。私有网段、保留地址和 DNS 服务器已默认绕过。</p>
      <div class="chips" id="rt-bypass-list" style="margin-top:0"></div>
    </div>

    <div class="card">
      <h2>系统规则</h2>
      <p style="font-size:13px;margin-bottom:10px">由连接模式自动生成（DNS、QUIC 阻断、国内直连、入站默认出口），只读；如需调整请在“配置文件”中编辑。</p>
      <table>
        <thead><tr><th style="width:44px">#</th><th style="width:110px">条件</th><th>匹配值</th><th style="width:180px">出口</th></tr></thead>
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
      <p style="color:var(--text2);font-size:12px;margin-bottom:12px">编辑 <code>dns</code> 配置。常见 DoH：<code>https://dns.alidns.com/dns-query</code>、<code>https://doh.pub/dns-query</code>、<code>https://cloudflare-dns.com/dns-query</code>、<code>https://dns.google/dns-query</code></p>
      <div class="edit-row"><label>服务器（每行一个）</label><textarea id="dns-servers" style="min-height:140px"></textarea></div>
      <div class="edit-row"><label>clientIp</label><input id="dns-client-ip" placeholder="可选，如 1.1.1.1"></div>
      <div class="btn-group"><button class="btn primary" onclick="saveDns()">保存 DNS</button></div>
    </div>
    <div class="card" style="margin-top:16px">
      <h2>DNS Hosts</h2>
      <p style="color:var(--text2);font-size:12px;margin-bottom:12px">自定义域名解析，类似 /etc/hosts。每行一条：<code>域名 IP</code>。支持 <code>#</code> 注释。可选前缀：<code>domain:</code>、<code>geosite:</code>、<code>full:</code></p>
      <div style="padding:8px 12px;background:var(--bg);border:1px solid var(--info);border-radius:4px;margin-bottom:12px;font-size:11px;color:var(--text2)">
        Hosts 中的 IP 会<strong>自动加入 iptables bypass</strong>，避免透明代理拦截 DoH/DNS 服务器连接。保存后如透明代理正在运行，iptables 规则会自动重建。
      </div>
      <textarea id="dns-hosts-editor" style="width:100%;min-height:180px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:8px;font-family:monospace;font-size:12px;resize:vertical" placeholder="googleapis.cn 203.208.41.96&#10;domain:google.com 8.8.8.8&#10;full:ads.example.com 127.0.0.1&#10;# 这是注释"></textarea>
      <div class="btn-group" style="margin-top:8px"><button class="btn primary" onclick="saveDnsHosts()">保存 Hosts</button></div>
    </div>
  </div>

  <!-- Transparent Proxy -->
  <!-- Logs -->
  <div class="tab-content" id="tab-logs">
    <div class="card">
      <h2>访问统计</h2>
      <p style="color:var(--text2);font-size:12px;margin-bottom:12px">基于核心日志解析，统计最近窗口内的访问域名、直连/代理/拦截和出口节点。需确保日志级别为 info。</p>
      <div class="btn-group" style="margin-bottom:12px">
        <button class="btn" onclick="loadAccessStats(5)">最近5分钟</button>
        <button class="btn" onclick="loadAccessStats(10)">最近10分钟</button>
        <button class="btn" onclick="loadAccessStats(30)">最近30分钟</button>
        <button class="btn" onclick="loadAccessStats(60)">最近1小时</button>
        <select id="access-type" onchange="loadAccessStats()" style="padding:4px 8px;background:var(--bg);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px">
          <option value="all">全部</option>
          <option value="proxy">代理</option>
          <option value="direct">直连</option>
          <option value="blocked">拦截</option>
        </select>
        <input id="access-search" placeholder="搜索域名/IP/节点/客户端" style="flex:1;min-width:min(220px,100%);padding:4px 8px;background:var(--bg);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px" oninput="loadAccessStatsDebounced()">
        <button class="btn danger" onclick="clearLogs()">清理统计和日志</button>
      </div>
      <div id="access-summary" style="margin-bottom:12px;color:var(--text2)">加载中...</div>
      <h3 style="margin:12px 0 8px">目标排行</h3>
      <table><thead><tr><th>目标域名/IP</th><th>归属</th><th>总数</th><th>代理</th><th>直连</th><th>拦截</th><th>出口分布</th><th>最后访问</th></tr></thead><tbody id="access-targets"></tbody></table>
      <h3 style="margin:16px 0 8px">最近记录</h3>
      <table><thead><tr><th>时间</th><th>客户端</th><th>目标</th><th>归属</th><th>端口</th><th>类型</th><th>出口</th></tr></thead><tbody id="access-records"></tbody></table>
    </div>
    <div class="card">
      <h2>服务日志</h2>
      <div class="btn-group" style="margin-bottom:12px">
        <button class="btn" onclick="loadLogs(50)">50行</button>
        <button class="btn" onclick="loadLogs(200)">200行</button>
        <button class="btn" onclick="loadLogs(500)">500行</button>
        <button class="btn primary" onclick="loadLogs(200)">刷新</button>
        <input id="log-filter" placeholder="过滤关键词 (如: direct, telegram, error)" style="flex:1;min-width:min(200px,100%);padding:4px 8px;background:var(--bg);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px" oninput="filterLogs()">
      </div>
      <div class="log-box" id="log-box">加载中...</div>
    </div>
  </div>

  <!-- System / Sysctl -->
  <div class="tab-content" id="tab-system">
    <div class="card">
      <h2>内核参数调优</h2>
      <p style="color:var(--text2);font-size:12px;margin-bottom:12px">修改宿主机网络内核参数，保存后立即生效，并写入宿主机 sysctl.d 以便重启后保持。标黄的值与推荐值不一致。</p>
      <div id="sysctl-hint" style="font-size:12px;margin-bottom:12px"></div>
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
      <p style="color:var(--text2);font-size:12px;margin-top:8px">支持 vless / vmess / ss / trojan，含 REALITY、XHTTP（mode、extra）、gRPC、HTTPUpgrade、ECH，可粘贴多行批量添加。</p>
      <label style="display:flex;align-items:center;gap:4px;font-size:12px;color:var(--text2);margin-top:6px;cursor:pointer"><input type="checkbox" id="modal-tfo"> TCP Fast Open</label>
      <div class="btn-group" style="margin-top:12px">
        <button class="btn primary" onclick="parseAndAddVless()">解析并新增</button>
      </div>
    </div>
    <div id="mob-pane-form" style="display:none">
      <div class="form-section">
        <h4>基本信息</h4>
        <div class="form-grid">
          <div class="field"><label>名称 (tag)</label><input id="of-tag" autocomplete="off" placeholder="us-xhttp-01"></div>
          <div class="field"><label>协议</label><select id="of-protocol" onchange="ofRefresh()"><option value="vless">VLESS</option><option value="vmess">VMess</option><option value="trojan">Trojan</option><option value="shadowsocks">Shadowsocks</option></select></div>
          <div class="field"><label>服务器地址<em>域名 / IP / TXT 端点</em></label><input id="of-address" placeholder="example.com"></div>
          <div class="field"><label>端口</label><input id="of-port" type="number" min="1" max="65535" placeholder="443"></div>
        </div>
      </div>
      <div class="form-section">
        <h4>认证</h4>
        <div class="form-grid">
          <div class="field"><label id="of-id-label">UUID</label><input id="of-id" autocomplete="off"></div>
          <div class="field" data-proto="vless vmess shadowsocks"><label id="of-security-label">加密</label><input id="of-security" list="of-security-list"><datalist id="of-security-list"></datalist></div>
          <div class="field" data-proto="vless"><label>流控 (flow)</label><select id="of-flow"><option value="">无</option><option value="xtls-rprx-vision">xtls-rprx-vision</option><option value="xtls-rprx-vision-udp443">xtls-rprx-vision-udp443</option></select></div>
        </div>
      </div>
      <div class="form-section">
        <h4>传输</h4>
        <div class="form-grid">
          <div class="field"><label>传输方式 (network)</label><select id="of-network" onchange="ofRefresh()"><option value="tcp">TCP / RAW</option><option value="ws">WebSocket</option><option value="xhttp">XHTTP</option><option value="grpc">gRPC</option><option value="httpupgrade">HTTPUpgrade</option></select></div>
          <div class="field" data-net="ws xhttp httpupgrade"><label>Host<em>伪装域名</em></label><input id="of-host"></div>
          <div class="field" data-net="ws xhttp httpupgrade grpc"><label id="of-path-label">Path</label><input id="of-path" placeholder="/"></div>
          <div class="field" data-net="xhttp"><label>XHTTP 模式</label><select id="of-xhttp-mode"><option value="">auto (默认)</option><option value="packet-up">packet-up</option><option value="stream-up">stream-up</option><option value="stream-one">stream-one</option></select></div>
          <div class="field" data-net="grpc"><label>gRPC 模式</label><select id="of-grpc-multi"><option value="false">gun (默认)</option><option value="true">multi</option></select></div>
          <div class="field full" data-net="xhttp"><label>XHTTP extra<em>JSON，可选：xPadding*、xmux、headers 等</em></label><textarea id="of-xhttp-extra" spellcheck="false" placeholder='{"xmux":{"maxConnections":3}}'></textarea></div>
        </div>
      </div>
      <div class="form-section">
        <h4>传输层安全</h4>
        <div class="form-grid">
          <div class="field"><label>安全 (security)</label><select id="of-tls-mode" onchange="ofRefresh()"><option value="none">无</option><option value="tls">TLS</option><option value="reality">REALITY</option></select></div>
          <div class="field" data-sec="tls reality"><label>SNI (serverName)</label><input id="of-sni"></div>
          <div class="field" data-sec="tls reality"><label>指纹 (fingerprint)</label><select id="of-fp"><option value="">不设置</option><option>chrome</option><option>firefox</option><option>safari</option><option>ios</option><option>android</option><option>edge</option><option>360</option><option>qq</option><option>random</option><option>randomized</option></select></div>
          <div class="field" data-sec="tls"><label>ALPN</label><input id="of-alpn" list="of-alpn-list" placeholder="h2,http/1.1"><datalist id="of-alpn-list"><option value="h2"><option value="http/1.1"><option value="h2,http/1.1"><option value="h3"></datalist></div>
          <div class="field" data-sec="tls"><label>证书指纹 (pinnedPeerCertSha256)<em>自签证书时填，替代已移除的 allowInsecure</em></label><input id="of-pcs" placeholder="SHA256 十六进制，多个用逗号分隔"></div>
          <div class="field" data-sec="tls"><label>ECH 强制查询</label><select id="of-ech-force"><option value="full">full</option><option value="half">half</option><option value="none">none</option></select></div>
          <div class="field full" data-sec="tls"><label>ECH (echConfigList)<em>Base64 配置，或 "域名+DoH 地址" 动态查询</em></label><input id="of-ech" placeholder="cloudflare-ech.com+https://dns.alidns.com/dns-query"></div>
          <div class="field full" data-sec="reality"><label>公钥 (publicKey / pbk)</label><input id="of-pbk" autocomplete="off"></div>
          <div class="field" data-sec="reality"><label>shortId (sid)</label><input id="of-sid" autocomplete="off"></div>
          <div class="field" data-sec="reality"><label>spiderX (spx)</label><input id="of-spx" placeholder="/"></div>
        </div>
      </div>
      <div class="form-section">
        <h4>高级</h4>
        <div class="form-grid">
          <div class="field"><label>多路复用 (mux)</label><select id="of-mux" onchange="ofRefresh()"><option value="off">关闭</option><option value="on">开启</option></select></div>
          <div class="field" id="of-mux-conc-field"><label>mux 并发</label><input id="of-mux-conc" type="number" placeholder="8"></div>
          <div class="field inline"><input type="checkbox" id="of-tfo"><label for="of-tfo" style="font-size:13px;color:var(--text)">TCP Fast Open</label></div>
        </div>
        <p class="hint" style="font-size:12px;color:var(--text2);margin-bottom:10px">表单未覆盖的字段（sockopt、_delay、xmux 以外的自定义项等）保存时原样保留。</p>
      </div>
      <div class="btn-group" style="margin-top:4px">
        <button class="btn primary" onclick="saveFormOutboundDirect()">保存节点</button>
        <button class="btn" onclick="saveFormOutbound()">生成 JSON 预览</button>
      </div>
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
  document.querySelectorAll('.tabs .tab').forEach(t=>t.classList.toggle('active',t.dataset.tab===name));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  if(name==='connect')loadConnect();
  if(name==='status'){loadStatus();startStatsPolling();loadTraffic();loadPeers();}else{stopStatsPolling();}
  if(name==='inbounds'){loadInbounds();loadTestUrls();}
  if(name==='outbounds'){loadOutbounds();loadObTestUrls();}
  if(name==='routing')loadRouting();
  if(name==='config'){loadConfig();loadGeoInfo();}
  if(name==='dns'){loadDns();loadDnsHosts();}
  if(name==='logs'){loadAccessStats(5);loadLogs(200);}
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
  document.getElementById('version').textContent=(m=>m?'核心 v'+m[0]:'-')(String(d.xray_version||'').match(/\d+\.\d+\.\d+/));
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
let trafficRange='24h', trafficData=null;
const TR_COLORS=['#165dff','#00b42a','#ff7d00','#722ed1','#f53f3f','#14c9c9','#86909c'];
function setTrafficRange(r){
  trafficRange=r;
  document.querySelectorAll('#tr-range button').forEach(b=>b.classList.toggle('on',b.dataset.r===r));
  loadTraffic();
}
async function loadTraffic(){
  const d=await api('/api/traffic/history?range='+encodeURIComponent(trafficRange));
  if(!d||!d.ok){document.getElementById('tr-iface-tbody').innerHTML='<tr><td colspan="7" style="color:var(--red)">'+escapeHtml((d&&d.error)||'加载失败')+'</td></tr>';return;}
  trafficData=d;
  const sel=document.getElementById('tr-iface'), cur=sel.value||'__all__';
  sel.innerHTML='<option value="__all__">全部网卡</option>'+d.interfaces.map(i=>'<option value="'+escapeHtml(i.name)+'">'+escapeHtml(i.name)+(i.ips.length?' '+escapeHtml(i.ips[0]):'')+'</option>').join('');
  sel.value=[...sel.options].some(o=>o.value===cur)?cur:'__all__';
  const monthTotal=d.interfaces.reduce((a,i)=>a+i.month.rx+i.month.tx,0)||0;
  const pair=x=>fmtBytes(x.rx)+' / '+fmtBytes(x.tx);
  document.getElementById('tr-iface-tbody').innerHTML=d.interfaces.length?d.interfaces.map((i,k)=>{
    const m=i.month.rx+i.month.tx, pct=monthTotal?m*100/monthTotal:0;
    const since=i.since?new Date(i.since*1000).toLocaleString('zh-CN',{hour12:false}):'-';
    return '<tr'+(i.active?'':' style="color:var(--text2)"')+'><td>'+escapeHtml(i.name)+(i.active?'':' <span style="font-size:11px;color:var(--text2)">(已不在)</span>')+'</td><td>'+escapeHtml(i.ips.join(', ')||'-')+'</td><td>'+pair(i.today)+'</td><td>'+pair(i.month)+'</td>'+
      '<td><div style="display:flex;align-items:center;gap:8px"><div class="tr-share" style="width:90px"><div style="width:'+pct.toFixed(1)+'%;background:'+TR_COLORS[k%TR_COLORS.length]+'"></div></div><span>'+pct.toFixed(1)+'%</span></div></td>'+
      '<td>'+pair(i.total)+'</td><td style="font-size:12px;color:var(--text2)">'+since+'</td></tr>';
  }).join(''):'<tr><td colspan="7" style="color:var(--text2)">暂无数据，采样开始后约 1 分钟出现</td></tr>';
  renderTraffic();
}
function renderTraffic(){
  const d=trafficData; if(!d)return;
  const iface=document.getElementById('tr-iface').value||'__all__';
  const pts=d.buckets.map(b=>{let rx=0,tx=0;for(const [k,v] of Object.entries(b.data)){if(iface==='__all__'||k===iface){rx+=v.rx;tx+=v.tx;}}return {label:b.label,rx,tx};});
  const svg=document.getElementById('tr-chart');
  const W=Math.max(svg.clientWidth||800,320), H=200, padL=64, padB=22, padT=8, plotW=W-padL-8, plotH=H-padB-padT;
  svg.setAttribute('viewBox','0 0 '+W+' '+H);
  const max=Math.max(1,...pts.map(p=>Math.max(p.rx,p.tx)));
  const n=pts.length, bw=plotW/n, barW=Math.max(2,Math.min(14,bw*0.36));
  let g='';
  for(let i=0;i<=4;i++){const y=padT+plotH-plotH*i/4;g+='<line x1="'+padL+'" x2="'+(W-8)+'" y1="'+y+'" y2="'+y+'" stroke="#e5e6eb"/><text x="'+(padL-6)+'" y="'+(y+4)+'" text-anchor="end" font-size="11" fill="#86909c">'+fmtBytes(Math.round(max*i/4))+'</text>';}
  const step=Math.ceil(n/Math.max(4,Math.min(12,Math.floor(plotW/52))));
  pts.forEach((p,i)=>{
    const x=padL+bw*i+bw/2, hr=plotH*p.rx/max, ht=plotH*p.tx/max, tip=escapeHtml(p.label)+'  ↓ '+fmtBytes(p.rx)+'  ↑ '+fmtBytes(p.tx);
    g+='<g><title>'+tip+'</title><rect x="'+(x-barW-1)+'" y="'+(padT+plotH-hr)+'" width="'+barW+'" height="'+hr+'" fill="#00b42a" rx="1"/><rect x="'+(x+1)+'" y="'+(padT+plotH-ht)+'" width="'+barW+'" height="'+ht+'" fill="#ff7d00" rx="1"/><rect x="'+(padL+bw*i)+'" y="'+padT+'" width="'+bw+'" height="'+plotH+'" fill="transparent"/></g>';
    if(i%step===0||i===n-1)g+='<text x="'+x+'" y="'+(H-6)+'" text-anchor="middle" font-size="11" fill="#86909c">'+escapeHtml(p.label)+'</text>';
  });
  svg.innerHTML=g;
  const srx=pts.reduce((a,p)=>a+p.rx,0), stx=pts.reduce((a,p)=>a+p.tx,0);
  document.getElementById('tr-sum').textContent='区间合计 ↓ '+fmtBytes(srx)+'  ↑ '+fmtBytes(stx);
}
window.addEventListener('resize',()=>{if(document.getElementById('tab-status').classList.contains('active'))renderTraffic();});

let peerHours=1;
function setPeerRange(h){
  peerHours=h;
  document.querySelectorAll('#pr-range button').forEach(b=>b.classList.toggle('on',+b.dataset.h===h));
  loadPeers();
}
async function loadPeers(){
  const kind=document.getElementById('pr-kind').value, q=document.getElementById('pr-q').value.trim();
  const d=await api('/api/traffic/peers?hours='+peerHours+'&kind='+encodeURIComponent(kind)+'&q='+encodeURIComponent(q)+'&limit=300');
  const tb=document.getElementById('pr-tbody'), st=document.getElementById('pr-status');
  if(!d||!d.ok){tb.innerHTML='<tr><td colspan="9" style="color:var(--red)">'+escapeHtml((d&&d.error)||'加载失败')+'</td></tr>';return;}
  const s=d.status||{};
  let msg=[];
  if(!s.enabled)msg.push('<span style="color:var(--yellow)">已通过 PEER_STATS=0 关闭</span>');
  else if(s.acct===false)msg.push('<span style="color:var(--yellow)">宿主机未开启 net.netfilter.nf_conntrack_acct，开启后新连接才有字节计数：sysctl -w net.netfilter.nf_conntrack_acct=1</span>');
  if(s.error)msg.push('<span style="color:var(--red)">'+escapeHtml(s.error)+'</span>');
  if(s.enabled)msg.push('跟踪中连接 '+(s.flows||0)+'，已处理关闭事件 '+(s.events||0)+(s.dropped?'，<span style="color:var(--yellow)">事件丢失 '+s.dropped+' 次（短连接可能少算）</span>':'')+(s.last_dump?'，上次全量读取 '+new Date(s.last_dump*1000).toLocaleTimeString('zh-CN',{hour12:false}):''));
  st.innerHTML=msg.join('；');
  const t=d.totals||{}, g=k=>t[k]||{rx:0,tx:0,peers:0};
  document.getElementById('pr-sum').innerHTML='线上合计 ↓ <b>'+fmtBytes((d.wire||{}).rx||0)+'</b> ↑ <b>'+fmtBytes((d.wire||{}).tx||0)+'</b>'+
    '　代理节点 '+fmtBytes(g('node').rx+g('node').tx)+'　直连 '+fmtBytes(g('direct').rx+g('direct').tx)+'　内网 '+fmtBytes(g('internal').rx+g('internal').tx)+'　入站 '+fmtBytes(g('inbound').rx+g('inbound').tx)+
    '　<span style="color:var(--text2)">经核心目标 '+g('core').peers+' 个</span>';
  const kindTag=r=>{
    const c={core:'var(--accent)',node:'#722ed1',direct:'var(--green)',internal:'var(--text3)',inbound:'var(--yellow)'}[r.kind]||'var(--text3)';
    let l=r.label; if(r.kind==='core')l+=r.route==='direct'?' → 直连':r.route==='block'?' → 拦截':' → '+(r.outbound||'代理');
    return '<span style="color:'+c+'">'+escapeHtml(l)+'</span>';
  };
  tb.innerHTML=(d.rows||[]).length?d.rows.map(r=>{
    const name=r.kind==='node'?('节点 '+escapeHtml(r.node||'')):escapeHtml((r.domains||[]).join(', ')||'-');
    const meta=r.meta?('AS'+escapeHtml(r.meta.asn||'')+' '+escapeHtml(r.meta.country||'')+'<div style="font-size:11px;color:var(--text2);max-width:220px;overflow:hidden;text-overflow:ellipsis">'+escapeHtml(r.meta.as_name||'')+'</div>'):'-';
    const last=r.last_seen?new Date(r.last_seen*1000).toLocaleString('zh-CN',{hour12:false,month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}):'-';
    return '<tr><td>'+escapeHtml(r.ip)+'</td><td style="max-width:280px;overflow:hidden;text-overflow:ellipsis">'+name+'</td><td>'+meta+'</td><td>'+kindTag(r)+'</td><td>'+escapeHtml((r.proto||'')+':'+(r.port||''))+'</td><td>'+fmtBytes(r.rx)+'</td><td>'+fmtBytes(r.tx)+'</td><td>'+r.conns+'</td><td style="font-size:12px;color:var(--text2)">'+last+'</td></tr>';
  }).join('')+(d.matched>d.rows.length?'<tr><td colspan="9" style="color:var(--text2)">仅显示前 '+d.rows.length+' 条，共 '+d.matched+' 条</td></tr>':''):'<tr><td colspan="9" style="color:var(--text2)">暂无数据（每分钟全量读取一次，新连接关闭时实时计入）</td></tr>';
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
      opts+=`<option value="bal:${b.tag}">${b.tag} (${(b.selector||[]).join(', ')})</option>`;
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
  if(d&&d.ok){toast('入站已保存'+(d.restart&&d.restart.success?'，核心已重启':''));}
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
  box.textContent='Batch '+(doSpeed?'speedtest':'latency')+' ('+tags.length+' nodes)...\nStarting temp core...';
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
  box.textContent=`Testing ${ob.tag} (${addr}) ...\nStarting temp core...`;
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
  box.textContent=`Speedtest ${ob.tag} (${addr}) ...\nDownloading: ${speedUrl}\nStarting temp core...`;
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

// ==== node-form:begin ====
const OF_NET_KEYS={tcp:['tcpSettings','rawSettings'],raw:['tcpSettings','rawSettings'],ws:['wsSettings'],grpc:['grpcSettings'],xhttp:['xhttpSettings','splithttpSettings'],httpupgrade:['httpupgradeSettings'],kcp:['kcpSettings'],http:['httpSettings'],h2:['httpSettings']};
const OF_ALL_NET_KEYS=['tcpSettings','rawSettings','wsSettings','grpcSettings','xhttpSettings','splithttpSettings','httpupgradeSettings','kcpSettings','httpSettings'];
const OF_SS_METHODS=['aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305','xchacha20-ietf-poly1305','2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305','none'];
let editingOutboundBase=null;
function ofEl(id){return document.getElementById(id);}
function ofv(id){const e=ofEl(id);if(!e)return '';return e.type==='checkbox'?!!e.checked:String(e.value??'').trim();}
function ofset(id,v){const e=ofEl(id);if(!e)return;if(e.type==='checkbox'){e.checked=!!v;return;}
  const val=(v===undefined||v===null)?'':String(v);
  // keep values the select does not list (e.g. kcp, randomizednoalpn) instead of silently dropping them
  if(e.tagName==='SELECT'&&val!==''&&![...e.options].some(o=>o.value===val)){const o=document.createElement('option');o.value=val;o.textContent=val;o.dataset.extra='1';e.appendChild(o);}
  e.value=val;}
function ofClone(o){return o===undefined?undefined:JSON.parse(JSON.stringify(o));}
function ofSetOrDel(obj,key,val){if(val===''||val===undefined||val===null||(Array.isArray(val)&&!val.length))delete obj[key];else obj[key]=val;}

function ofRefresh(){
  const proto=ofv('of-protocol'),net=ofv('of-network'),sec=ofv('of-tls-mode');
  if(!document.querySelectorAll)return;
  document.querySelectorAll('#mob-pane-form [data-proto],#mob-pane-form [data-net],#mob-pane-form [data-sec]').forEach(el=>{
    const ok=(!el.dataset.proto||el.dataset.proto.split(' ').includes(proto))&&(!el.dataset.net||el.dataset.net.split(' ').includes(net))&&(!el.dataset.sec||el.dataset.sec.split(' ').includes(sec));
    el.classList.toggle('hidden',!ok);
  });
  const idLabel={vless:'UUID',vmess:'UUID',trojan:'密码',shadowsocks:'密码'}[proto]||'UUID';
  ofEl('of-id-label').textContent=idLabel;
  ofEl('of-security-label').textContent={vless:'加密 (encryption)',vmess:'加密 (security)',shadowsocks:'加密方法 (method)'}[proto]||'加密';
  const list={vless:['none'],vmess:['auto','aes-128-gcm','chacha20-poly1305','none','zero'],shadowsocks:OF_SS_METHODS}[proto]||[];
  ofEl('of-security-list').innerHTML=list.map(x=>`<option value="${x}">`).join('');
  ofEl('of-path-label').textContent=net==='grpc'?'serviceName':'Path';
  ofEl('of-mux-conc-field').classList.toggle('hidden',ofv('of-mux')!=='on');
}

function outboundToForm(ob){
  ob=ob||{};
  const p=ob.protocol||'vless';
  ofset('of-tag',ob.tag||'');
  ofset('of-protocol',p);
  let address='',port='',ident='',sec='',flow='';
  try{
    if(p==='shadowsocks'||p==='trojan'){
      const s=(ob.settings&&ob.settings.servers&&ob.settings.servers[0])||{};
      address=s.address||'';port=s.port||'';ident=s.password||'';sec=p==='shadowsocks'?(s.method||''):'';flow=s.flow||'';
    }else{
      const v=(ob.settings&&ob.settings.vnext&&ob.settings.vnext[0])||{};const u=(v.users&&v.users[0])||{};
      address=v.address||'';port=v.port||'';ident=u.id||'';sec=p==='vmess'?(u.security||''):(u.encryption||'');flow=u.flow||'';
    }
  }catch(e){}
  ofset('of-address',address);ofset('of-port',port);ofset('of-id',ident);ofset('of-security',sec);ofset('of-flow',flow);
  const ss=ob.streamSettings||{};
  let net=ss.network||'tcp'; if(net==='raw')net='tcp'; if(net==='splithttp')net='xhttp';
  ofset('of-network',net);
  ofset('of-tls-mode',ss.security||'none');
  const tls=ss.tlsSettings||{},rl=ss.realitySettings||{};
  const t=ss.security==='reality'?rl:tls;
  ofset('of-sni',t.serverName||'');
  ofset('of-fp',t.fingerprint||'');
  ofset('of-alpn',Array.isArray(tls.alpn)?tls.alpn.join(','):'');
  ofset('of-pcs',tls.pinnedPeerCertSha256||'');
  ofset('of-ech',tls.echConfigList||'');
  ofset('of-ech-force',tls.echForceQuery||'full');
  ofset('of-pbk',rl.publicKey||'');ofset('of-sid',rl.shortId||'');ofset('of-spx',rl.spiderX||'');
  let host='',path='',mode='',extra='',multi='false';
  if(net==='ws'){const w=ss.wsSettings||{};host=w.host||(w.headers&&w.headers.Host)||'';path=w.path||'';}
  else if(net==='httpupgrade'){const h=ss.httpupgradeSettings||{};host=h.host||'';path=h.path||'';}
  else if(net==='xhttp'){const x=ss.xhttpSettings||ss.splithttpSettings||{};host=x.host||'';path=x.path||'';mode=x.mode||'';extra=x.extra&&Object.keys(x.extra).length?JSON.stringify(x.extra,null,2):'';}
  else if(net==='grpc'){const g=ss.grpcSettings||{};path=g.serviceName||'';multi=g.multiMode?'true':'false';}
  ofset('of-host',host);ofset('of-path',path);ofset('of-xhttp-mode',mode==='auto'?'':mode);ofset('of-xhttp-extra',extra);ofset('of-grpc-multi',multi);
  const mux=ob.mux||{};
  ofset('of-mux',mux.enabled?'on':'off');ofset('of-mux-conc',mux.enabled&&mux.concurrency!==undefined?mux.concurrency:'');
  ofset('of-tfo',!!(ss.sockopt&&ss.sockopt.tcpFastOpen));
  ofRefresh();
}

// Builds the outbound from the form on top of `base` (the node being edited), so
// every field the form does not know about is preserved unchanged.
function formToOutbound(base){
  const protocol=ofv('of-protocol');
  const sameProto=!!(base&&base.protocol===protocol);
  const ob=sameProto?ofClone(base):(base?Object.fromEntries(Object.entries(ofClone(base)).filter(([k])=>!['settings','protocol'].includes(k))):{});
  ob.tag=ofv('of-tag')||'new-node';
  ob.protocol=protocol;
  const address=ofv('of-address');
  const port=parseInt(ofv('of-port')||'0',10);
  if(!address)throw new Error('请填写服务器地址');
  if(!(port>=1&&port<=65535))throw new Error('端口无效');
  const ident=ofv('of-id'),sec=ofv('of-security'),flow=ofv('of-flow');
  const settings=sameProto&&ob.settings?ob.settings:{};
  if(protocol==='shadowsocks'||protocol==='trojan'){
    const servers=Array.isArray(settings.servers)&&settings.servers.length?settings.servers:[{}];
    const s=servers[0];s.address=address;s.port=port;s.password=ident;
    if(protocol==='shadowsocks'){s.method=sec||'aes-128-gcm';if(!sameProto){s.ota=false;s.level=1;}}
    else ofSetOrDel(s,'flow',flow);
    settings.servers=servers;delete settings.vnext;
  }else{
    const vnext=Array.isArray(settings.vnext)&&settings.vnext.length?settings.vnext:[{}];
    const v=vnext[0];v.address=address;v.port=port;
    const users=Array.isArray(v.users)&&v.users.length?v.users:[{}];const u=users[0];u.id=ident;
    if(protocol==='vmess'){u.security=sec||'auto';if(u.alterId===undefined)u.alterId=0;delete u.encryption;delete u.flow;}
    else{u.encryption=sec||'none';ofSetOrDel(u,'flow',flow);}
    v.users=users;settings.vnext=vnext;delete settings.servers;
  }
  ob.settings=settings;

  const ss=ofClone(ob.streamSettings)||{};
  const net=ofv('of-network');
  const keepNet=(ss.network==='raw'&&net==='tcp')?'raw':(ss.network==='splithttp'&&net==='xhttp'?'splithttp':net);
  ss.network=keepNet;
  const own=OF_NET_KEYS[net]||[];
  for(const k of OF_ALL_NET_KEYS){if(!own.includes(k))delete ss[k];}
  const host=ofv('of-host'),path=ofv('of-path');
  if(net==='ws'){
    const w=ss.wsSettings||{};w.path=path||'/';ofSetOrDel(w,'host',host);
    if(w.headers&&w.headers.Host!==undefined){delete w.headers.Host;}
    ss.wsSettings=w;
  }else if(net==='httpupgrade'){
    const h=ss.httpupgradeSettings||{};h.path=path||'/';ofSetOrDel(h,'host',host);ss.httpupgradeSettings=h;
  }else if(net==='xhttp'){
    const key=ss.splithttpSettings&&!ss.xhttpSettings?'splithttpSettings':'xhttpSettings';
    const x=ss[key]||{};x.path=path||'/';ofSetOrDel(x,'host',host);ofSetOrDel(x,'mode',ofv('of-xhttp-mode'));
    const extraRaw=ofv('of-xhttp-extra');
    if(extraRaw){let e;try{e=JSON.parse(extraRaw);}catch(err){throw new Error('XHTTP extra 不是合法 JSON: '+err.message);}
      if(!e||typeof e!=='object'||Array.isArray(e))throw new Error('XHTTP extra 必须是 JSON 对象');x.extra=e;}
    else delete x.extra;
    ss[key]=x;
  }else if(net==='grpc'){
    const g=ss.grpcSettings||{};g.serviceName=path==='/'?'':path;
    if(ofv('of-grpc-multi')==='true')g.multiMode=true;else delete g.multiMode;ss.grpcSettings=g;
  }
  const mode=ofv('of-tls-mode');
  ss.security=mode;
  const sni=ofv('of-sni'),fp=ofv('of-fp');
  if(mode==='tls'){
    const t=ss.tlsSettings||{};
    ofSetOrDel(t,'serverName',sni||host||(t.serverName?'':address));
    ofSetOrDel(t,'fingerprint',fp);
    ofSetOrDel(t,'alpn',ofv('of-alpn').split(',').map(s=>s.trim()).filter(Boolean));
    ofSetOrDel(t,'pinnedPeerCertSha256',ofv('of-pcs'));
    const ech=ofv('of-ech');
    if(ech){t.echConfigList=ech;t.echForceQuery=ofv('of-ech-force')||'full';}else{delete t.echConfigList;delete t.echForceQuery;}
    ss.tlsSettings=t;delete ss.realitySettings;
  }else if(mode==='reality'){
    const r=ss.realitySettings||{};
    ofSetOrDel(r,'serverName',sni||address);ofSetOrDel(r,'fingerprint',fp||'chrome');
    ofSetOrDel(r,'publicKey',ofv('of-pbk'));ofSetOrDel(r,'shortId',ofv('of-sid'));ofSetOrDel(r,'spiderX',ofv('of-spx'));
    if(!r.publicKey)throw new Error('REALITY 需要公钥 (pbk)');
    ss.realitySettings=r;delete ss.tlsSettings;
  }else{delete ss.tlsSettings;delete ss.realitySettings;}
  const sock=ss.sockopt||{};
  if(ofv('of-tfo'))sock.tcpFastOpen=true;else delete sock.tcpFastOpen;
  if(Object.keys(sock).length)ss.sockopt=sock;else delete ss.sockopt;
  ob.streamSettings=ss;
  if(ofv('of-mux')==='on'){
    const c=parseInt(ofv('of-mux-conc')||'8',10);
    ob.mux=Object.assign({},ob.mux||{},{enabled:true,concurrency:Number.isFinite(c)?c:8});
  }else if(ob.mux){ob.mux=Object.assign({},ob.mux,{enabled:false});}
  return ob;
}

function _shareQuery(params){
  return Object.entries(params).filter(([,v])=>v!==undefined&&v!==null&&v!=='').map(([k,v])=>k+'='+encodeURIComponent(String(v))).join('&');
}
function _b64utf8(s){return btoa(unescape(encodeURIComponent(s)));}

// Transport + security params shared by vless / trojan / ss(Xray style) links.
function _streamShareParams(ss){
  const p={};
  const net0=ss.network||'tcp';
  const net=net0==='raw'?'tcp':(net0==='splithttp'?'xhttp':net0);
  const sec=ss.security||'none';
  if(net!=='tcp')p.type=net;
  if(sec!=='none')p.security=sec;
  if(sec==='tls'){
    const t=ss.tlsSettings||{};
    p.sni=t.serverName;p.fp=t.fingerprint;
    if(Array.isArray(t.alpn)&&t.alpn.length)p.alpn=t.alpn.join(',');

    if(t.echConfigList){p.ech=t.echConfigList;if(t.echForceQuery&&t.echForceQuery!=='full')p.echForceQuery=t.echForceQuery;}
    if(t.pinnedPeerCertSha256)p.pcs=t.pinnedPeerCertSha256;
  }else if(sec==='reality'){
    const r=ss.realitySettings||{};
    p.sni=r.serverName;p.fp=r.fingerprint;p.pbk=r.publicKey;p.sid=r.shortId;p.spx=r.spiderX;p.pqv=r.mldsa65Verify;
  }
  if(net==='ws'){const w=ss.wsSettings||{};p.host=w.host||(w.headers&&w.headers.Host);p.path=w.path;}
  else if(net==='httpupgrade'){const h=ss.httpupgradeSettings||{};p.host=h.host;p.path=h.path;}
  else if(net==='xhttp'){const x=ss.xhttpSettings||ss.splithttpSettings||{};p.host=x.host;p.path=x.path;p.mode=x.mode;
    if(x.extra&&Object.keys(x.extra).length)p.extra=JSON.stringify(x.extra);}
  else if(net==='grpc'){const g=ss.grpcSettings||{};p.serviceName=g.serviceName;if(g.multiMode)p.mode='multi';p.authority=g.authority;}
  else if(net==='tcp'){const h=((ss.tcpSettings||ss.rawSettings||{}).header)||{};
    if(h.type==='http'){p.headerType='http';const rq=h.request||{};const hh=(rq.headers&&(rq.headers.Host||rq.headers.host))||[];
      p.host=Array.isArray(hh)?hh.join(','):hh;p.path=Array.isArray(rq.path)?rq.path[0]:rq.path;}}
  else if(net==='kcp'){const k=ss.kcpSettings||{};p.headerType=k.header&&k.header.type;p.seed=k.seed;}
  return p;
}

function outboundToShareLink(ob){
  const p=ob.protocol||'';
  const ss=ob.streamSettings||{};
  const frag='#'+encodeURIComponent(ob.tag||'');
  try{
    if(p==='vless'){
      const v=ob.settings.vnext[0];const u=v.users[0];
      const params=Object.assign({encryption:u.encryption||'none',flow:u.flow},_streamShareParams(ss));
      return 'vless://'+encodeURIComponent(u.id)+'@'+v.address+':'+v.port+'?'+_shareQuery(params)+frag;
    }
    if(p==='trojan'){
      const s=ob.settings.servers[0];
      const params=Object.assign({flow:s.flow},_streamShareParams(ss));
      const q=_shareQuery(params);
      return 'trojan://'+encodeURIComponent(s.password)+'@'+s.address+':'+s.port+(q?'?'+q:'')+frag;
    }
    if(p==='vmess'){
      const v=ob.settings.vnext[0];const u=v.users[0];
      const sp=_streamShareParams(ss);
      const obj={v:'2',ps:ob.tag||'',add:String(v.address),port:String(v.port),id:u.id,aid:String(u.alterId||0),scy:u.security||'auto',
        net:sp.type||'tcp',type:sp.headerType||'none',host:sp.host||'',path:(sp.type==='grpc'?sp.serviceName:sp.path)||'',tls:sp.security||'',sni:sp.sni||''};
      if(sp.fp)obj.fp=sp.fp;if(sp.alpn)obj.alpn=sp.alpn;
      if(sp.mode&&sp.type==='xhttp')obj.mode=sp.mode;if(sp.extra)obj.extra=sp.extra;
      return 'vmess://'+_b64utf8(JSON.stringify(obj));
    }
    if(p==='shadowsocks'){
      const s=ob.settings.servers[0];
      const user=_b64utf8(s.method+':'+s.password).replace(/=+$/,'');
      const base='ss://'+user+'@'+s.address+':'+s.port;
      const net=ss.network||'tcp';
      if(net==='tcp'||net==='raw'){
        return base+frag;
      }
      if(net==='ws'&&(ss.security||'none')!=='reality'){
        // v2ray-plugin form: understood by v2rayN / Shadowrocket / Clash. SIP003: escape \ ; = in values.
        const w=ss.wsSettings||{};const esc=x=>String(x).replace(/[\\;=]/g,c=>'\\'+c);
        const parts=['v2ray-plugin','mode=websocket'];
        const host=w.host||(w.headers&&w.headers.Host);
        if(ss.security==='tls'){parts.push('tls');const sni=(ss.tlsSettings||{}).serverName;if(sni&&sni!==host)parts.push('sni='+esc(sni));}
        if(host)parts.push('host='+esc(host));
        if(w.path)parts.push('path='+esc(w.path));
        return base+'/?plugin='+encodeURIComponent(parts.join(';'))+frag;
      }
      return base+'?'+_shareQuery(_streamShareParams(ss))+frag;
    }
  }catch(e){console.error('export error:',e);}
  return null;
}
// ==== node-form:end ====

function saveFormOutbound(){
  try{
    const ob=formToOutbound(editingOutboundBase);
    document.getElementById('eo-json').value=JSON.stringify(ob,null,2);
    switchObModalTab('json');
    toast('已根据表单生成 JSON，确认后保存');
  }catch(e){ toast('表单校验失败: '+e.message,false); }
}

function saveFormOutboundDirect(){
  let ob;
  try{ ob=formToOutbound(editingOutboundBase); }catch(e){ toast('表单校验失败: '+e.message,false); return; }
  const dup=outboundsData.findIndex((x,i)=>x.tag===ob.tag&&i!==editingOutboundIdx);
  if(dup>=0){toast('名称已存在: '+ob.tag,false);return;}
  const oldTag=editingOutboundIdx>=0?outboundsData[editingOutboundIdx].tag:null;
  if(editingOutboundIdx>=0) outboundsData[editingOutboundIdx]=ob; else outboundsData.push(ob);
  closeModal('modal-outbound');
  renderOutbounds();
  saveOutbounds().then(()=>{ if(typeof loadConnect==='function'&&document.getElementById('tab-connect').classList.contains('active')) loadConnect(); });
  if(oldTag&&oldTag!==ob.tag) toast('节点已改名，引用旧名称的路由规则需要同步修改',false);
}

function showAddOutboundModal(){
  editingOutboundIdx=-1;
  editingOutboundBase=null;
  document.getElementById('modal-ob-title').textContent='新增节点';
  document.getElementById('vless-link').value='';
  document.getElementById('eo-json').value=JSON.stringify({tag:'new-proxy',protocol:'vless',settings:{vnext:[{address:'example.com',port:443,users:[{id:'UUID',encryption:'none'}]}]},streamSettings:{network:'ws',security:'tls',tlsSettings:{serverName:'example.com',allowInsecure:false},wsSettings:{host:'example.com',path:'/'}}}, null, 2);
  outboundToForm(JSON.parse(document.getElementById('eo-json').value));
  switchObModalTab('link');
  document.getElementById('modal-outbound').classList.add('show');
}

function editOutbound(idx){
  editingOutboundIdx=idx;
  document.getElementById('modal-ob-title').textContent='编辑节点 · '+(outboundsData[idx].tag||'');
  editingOutboundBase=outboundsData[idx];
  document.getElementById('eo-json').value=JSON.stringify(outboundsData[idx], null, 2);
  outboundToForm(outboundsData[idx]);
  switchObModalTab('form');
  document.getElementById('modal-outbound').classList.add('show');
}

function switchObModalTab(tab){
  const isLink=tab==='link';
  const isForm=tab==='form';
  if(isForm){
    // keep the form in sync with hand edits made in the JSON tab
    try{ const ob=JSON.parse(document.getElementById('eo-json').value); if(ob&&typeof ob==='object'){ editingOutboundBase=ob; outboundToForm(ob);} }catch(e){}
  }
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
  if(s&&s.ok) toast('已添加 '+added+' 个节点并保存'+(s.restart&&s.restart.success?'，核心已重启':''));
  else toast('已解析但保存失败，请手动点保存',false);
}

async function saveOutbounds(){
  const d=await api('/api/outbounds',{method:'POST',body:JSON.stringify({outbounds:outboundsData})});
  if(d&&d.ok)toast('出站已保存'+(d.restart&&d.restart.success?'，核心已重启':''));
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
  if(s&&s.ok) toast('已导入 '+added+' 个节点并保存'+(s.restart&&s.restart.success?'，核心已重启':''));
  else toast('已解析但保存失败，请手动点保存',false);
}

let routingCustom=[];
let routingProxyTarget='__proxy__';
let routingBypass=[];
const RT_TYPE_LABEL={domain:'域名',full:'完整域名',keyword:'关键词',geosite:'域名集',regexp:'正则',ip:'IP',geoip:'IP 集',port:'端口',sourceIP:'来源 IP',network:'网络',protocol:'协议',inboundTag:'入站'};
const RT_HINTS={domain:'每行或逗号分隔，如 openai.com',full:'精确匹配，如 api.openai.com',keyword:'包含即匹配，如 google',geosite:'如 openai、google、category-ads-all、cn',ip:'如 1.2.3.4、10.0.0.0/8',geoip:'如 cn、private、telegram',port:'如 443、8000-9000',sourceIP:'局域网设备，如 192.168.1.23'};
const RT_PRESETS={
  ads:{type:'geosite',vals:['category-ads-all'],act:'block',remark:'广告拦截'},
  ai:{type:'geosite',vals:['openai','anthropic','google-gemini'],act:'proxy',remark:'AI 服务'},
  kiro:{type:'domain',vals:['kiro.dev','amazonaws.com','aws.dev','awsstatic.com'],act:'proxy',remark:'Kiro / AWS'},
  google:{type:'geosite',vals:['google','youtube'],act:'proxy',remark:'Google / YouTube'},
  github:{type:'geosite',vals:['github'],act:'proxy',remark:'GitHub'},
  apple:{type:'geosite',vals:['apple-cn'],act:'direct',remark:'Apple 国内服务'},
  bt:{type:'protocol',vals:['bittorrent'],act:'direct',remark:'BT 下载'},
};

function routingTypeHint(){
  const t=document.getElementById('rt-cond-type').value;
  document.getElementById('rt-hint').textContent=RT_HINTS[t]||'';
  document.getElementById('rt-bypass-btn').disabled=!['ip','sourceIP'].includes(t)||t==='sourceIP';
}

function rtSplit(s){return String(s||'').split(/[\s,，;；]+/).map(x=>x.trim()).filter(Boolean);}

// UI type + values -> Xray rule match fields
function rtBuildMatch(type,vals){
  const m={};
  if(type==='domain')m.domain=vals.map(v=>/^(domain|full|keyword|regexp|geosite|ext):/.test(v)?v:'domain:'+v.replace(/^\*?\./,''));
  else if(type==='full')m.domain=vals.map(v=>v.startsWith('full:')?v:'full:'+v);
  else if(type==='keyword')m.domain=vals.map(v=>v.startsWith('keyword:')?v:'keyword:'+v);
  else if(type==='geosite')m.domain=vals.map(v=>v.startsWith('geosite:')?v:'geosite:'+v);
  else if(type==='ip')m.ip=vals;
  else if(type==='geoip')m.ip=vals.map(v=>v.startsWith('geoip:')?v:'geoip:'+v);
  else if(type==='port')m.port=vals.join(',');
  else if(type==='sourceIP')m.sourceIP=vals;
  else if(type==='protocol')m.protocol=vals;
  return m;
}

function rtDescribe(r){
  const out=[];
  for(const [k,label] of [['domain',null],['ip',null],['sourceIP','来源 IP'],['port','端口'],['network','网络'],['protocol','协议'],['inboundTag','入站']]){
    if(r[k]===undefined)continue;
    const vals=Array.isArray(r[k])?r[k]:[r[k]];
    let type=label;
    if(k==='domain'){const p=String(vals[0]).split(':')[0];type=RT_TYPE_LABEL[p]||'域名';}
    if(k==='ip'){type=String(vals[0]).startsWith('geoip:')?'IP 集':'IP';}
    out.push({type,vals});
  }
  return out;
}

function rtTargetLabel(r){
  const t=r.balancerTag||r.outboundTag||'';
  if(t===routingProxyTarget)return '<span class="tag us">走代理（当前节点）</span>';
  if(t==='direct')return '<span class="tag kr">直连</span>';
  if(t==='block')return '<span class="tag red">阻断</span>';
  return `<span class="tag us">代理 · ${escapeHtml(t)}</span>`;
}

function routingRenderCustom(){
  const tb=document.getElementById('rt-custom-tbody');
  if(!routingCustom.length){tb.innerHTML='<tr><td colspan="6" class="empty">暂无自定义规则，可在上方添加或点常用模板</td></tr>';return;}
  tb.innerHTML=routingCustom.map((r,i)=>{
    const d=rtDescribe(r);
    const type=d.map(x=>`<span class="tag default">${x.type}</span>`).join(' ');
    const vals=d.map(x=>x.vals.map(v=>`<code>${escapeHtml(String(v).replace(/^(domain|full|keyword|geosite|geoip):/,''))}</code>`).join('')).join('');
    return `<tr>
      <td style="color:var(--text2)">${i+1}</td><td>${type}</td><td><div class="match-vals">${vals}</div></td>
      <td>${rtTargetLabel(r)}</td><td style="font-family:inherit;color:var(--text3)">${escapeHtml(r.remark||'')}</td>
      <td><div class="ob-actions">
        <button class="btn sm" onclick="routingMove(${i},-1)" ${i===0?'disabled':''}>上移</button>
        <button class="btn sm" onclick="routingMove(${i},1)" ${i>=routingCustom.length-1?'disabled':''}>下移</button>
        <button class="btn sm danger" onclick="routingDelete(${i})">删除</button></div></td></tr>`;
  }).join('');
}

function routingRenderRules(){
  const rules=(routingData.rules||[]).filter(r=>!String(r.ruleTag||'').startsWith('user:'));
  const tb=document.getElementById('routing-tbody');
  if(!rules.length){tb.innerHTML='<tr><td colspan="4" class="empty">尚未连接，暂无系统规则</td></tr>';return;}
  tb.innerHTML=rules.map((r,i)=>{
    const d=rtDescribe(r);
    const type=d.length?d.map(x=>`<span class="tag default">${x.type}</span>`).join(' '):'<span class="tag default">全部</span>';
    const vals=d.map(x=>x.vals.map(v=>`<code>${escapeHtml(v)}</code>`).join('')).join('');
    const ob=r.outboundTag||(r.balancerTag?r.balancerTag+'（负载均衡）':'-');
    const cls=ob==='direct'?'tag kr':ob==='block'?'tag red':'tag us';
    return `<tr class="ob-system"><td>${i+1}</td><td>${type}</td><td><div class="match-vals">${vals}</div></td><td><span class="${cls}">${escapeHtml(ob)}</span></td></tr>`;
  }).join('');
}

function routingRenderBypass(){
  const el=document.getElementById('rt-bypass-list');
  el.innerHTML=routingBypass.length?routingBypass.map((c,i)=>`<span class="chip">${escapeHtml(c)}<span class="x" onclick="routingRemoveBypass(${i})" title="删除">✕</span></span>`).join(''):'<span>暂无自定义绕过</span>';
}

function routingSetDirty(on){document.getElementById('rt-dirty').style.display=on?'inline':'none';}

async function loadRouting(){
  const [d,c,b]=await Promise.all([api('/api/routing'),api('/api/routing/custom'),api('/api/transparent/bypass')]);
  if(d)routingData=d.routing||{};
  if(c){routingCustom=c.rules||[];routingProxyTarget=c.proxy_target||'__proxy__';}
  if(b)routingBypass=b.custom||[];
  routingRenderRules();routingRenderCustom();routingRenderBypass();routingSetDirty(false);routingTypeHint();
  routingLoadOutbounds();
}

async function routingLoadOutbounds(){
  const d=await api('/api/outbounds');
  if(!d)return;
  const sel=document.getElementById('rt-outbound');
  let opts=`<option value="${routingProxyTarget}">当前连接的节点（推荐）</option>`;
  for(const ob of (d.outbounds||[])){
    if(['freedom','blackhole','dns'].includes(ob.protocol))continue;
    opts+=`<option value="${escapeHtml(ob.tag)}">${escapeHtml(ob.tag)} (${ob.protocol})</option>`;
  }
  for(const b of (routingData.balancers||[]))opts+=`<option value="bal:${escapeHtml(b.tag)}">${escapeHtml(b.tag)}（负载均衡）</option>`;
  sel.innerHTML=opts;
}

function routingPushRule(match,act,remark){
  const rule=Object.assign({type:'field'},match);
  if(act==='direct'||act==='block')rule.outboundTag=act;
  else{const t=document.getElementById('rt-outbound').value||routingProxyTarget;
    if(t.startsWith('bal:'))rule.balancerTag=t.slice(4);else rule.outboundTag=t;}
  if(remark)rule.remark=remark;
  routingCustom.push(rule);
  routingRenderCustom();routingSetDirty(true);
}

function routingAdd(act){
  const type=document.getElementById('rt-cond-type').value;
  const vals=rtSplit(document.getElementById('rt-cond-value').value);
  if(!vals.length){toast('请填写匹配值',false);return;}
  if(type==='ip'||type==='sourceIP'){
    const bad=vals.filter(v=>!/^!?[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(v));
    if(bad.length){toast('IP 格式不正确: '+bad.join(', '),false);return;}
  }
  if(type==='port'&&!vals.every(v=>/^\d{1,5}(-\d{1,5})?$/.test(v))){toast('端口格式不正确',false);return;}
  routingPushRule(rtBuildMatch(type,vals),act,document.getElementById('rt-remark').value.trim());
  document.getElementById('rt-cond-value').value='';document.getElementById('rt-remark').value='';
  toast('已添加，点击“保存并生效”应用');
}

function routingPreset(key){
  const p=RT_PRESETS[key];if(!p)return;
  routingPushRule(rtBuildMatch(p.type,p.vals),p.act,p.remark);
  toast('已添加“'+p.remark+'”，点击“保存并生效”应用');
}

function routingMove(i,delta){
  const j=i+delta;if(j<0||j>=routingCustom.length)return;
  [routingCustom[i],routingCustom[j]]=[routingCustom[j],routingCustom[i]];
  routingRenderCustom();routingSetDirty(true);
}
function routingDelete(i){routingCustom.splice(i,1);routingRenderCustom();routingSetDirty(true);}

async function routingSaveCustom(){
  const box=document.getElementById('routing-output');
  box.style.display='block';box.textContent='保存中...';
  const d=await api('/api/routing/custom',{method:'POST',body:JSON.stringify({rules:routingCustom})});
  if(d&&d.ok){box.textContent='已保存并生效'+(d.restart&&d.restart.success?'，核心已重启':'');toast('路由规则已生效');loadRouting();}
  else box.textContent='保存失败: '+(d&&d.error||'unknown')+(d&&d.detail?'\n'+d.detail:'');
}

async function routingSaveBypass(list){
  const r=await api('/api/transparent/bypass',{method:'POST',body:JSON.stringify({custom:list})});
  if(r&&r.ok){routingBypass=r.custom||[];routingRenderBypass();toast('绕过列表已更新'+(r.reloaded?'，iptables 已重建':''));return true;}
  toast('保存失败: '+(r&&r.error||''),false);return false;
}
async function routingAddBypass(){
  const vals=rtSplit(document.getElementById('rt-cond-value').value);
  if(!vals.length){toast('请填写 IP / CIDR',false);return;}
  if(await routingSaveBypass([...new Set([...routingBypass,...vals])]))document.getElementById('rt-cond-value').value='';
}
function routingRemoveBypass(i){const l=routingBypass.slice();l.splice(i,1);routingSaveBypass(l);}

async function loadDns(){
  const d=await api('/api/dns');
  if(!d)return;
  const dns=d.dns||{};
  const servers=Array.isArray(dns.servers)?dns.servers:[];
  document.getElementById('dns-servers').value=servers.map(s=>typeof s==='string'?s:JSON.stringify(s)).join('\n');
  document.getElementById('dns-client-ip').value=dns.clientIp||'';
  dnsLoaded=dns;
}
let dnsLoaded=null;

async function saveDns(){
  if(!dnsLoaded){toast('DNS 配置尚未加载',false);return;}
  const servers=document.getElementById('dns-servers').value.split('\n').map(s=>s.trim()).filter(Boolean).map(s=>{
    if(s.startsWith('{')){ try{return JSON.parse(s);}catch(e){ return s; } }
    return s;
  });
  // keep hosts (edited in the Hosts card) and any other fields of the current dns block
  const dns=Object.assign({},dnsLoaded,{servers});
  const cip=document.getElementById('dns-client-ip').value.trim();
  if(cip) dns.clientIp=cip; else delete dns.clientIp;
  const d=await api('/api/dns',{method:'POST',body:JSON.stringify({dns})});
  if(d&&d.ok) toast('DNS 已保存'+(d.restart&&d.restart.success?'，核心已重启':'')+(d.iptables_rebuilt?'，iptables 已重建':''));
  else if(d&&d.error) toast(d.error,false);
}

async function loadDnsHosts(){
  const d=await api('/api/dns/hosts');
  if(!d)return;
  document.getElementById('dns-hosts-editor').value=d.text||'';
}

async function saveDnsHosts(){
  const text=document.getElementById('dns-hosts-editor').value;
  const d=await api('/api/dns/hosts',{method:'POST',body:JSON.stringify({text})});
  if(d&&d.ok) toast('Hosts 已保存'+(d.restart&&d.restart.success?'，核心已重启':'')+(d.iptables_rebuilt?'，iptables 已重建':''));
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
  if(d&&d.ok)toast('配置已保存'+(d&&d.restart&&d.restart.success?'，核心已重启':''));
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


let accessMinutes=5;
let accessTimer=null;
function escapeHtml(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function routeTypeLabel(t){return ({proxy:'代理',direct:'直连',blocked:'拦截'}[t]||t||'');}
function asInfo(meta){
  if(!meta)return '<span style="color:var(--text2)">-</span>';
  const asn=meta.asn?('AS'+meta.asn):'';
  const name=meta.as_name||'';
  const cc=meta.country||'';
  return '<div style="font-size:12px">'+escapeHtml([asn,cc].filter(Boolean).join(' '))+'</div><div style="font-size:11px;color:var(--text2);max-width:220px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="'+escapeHtml(name)+'">'+escapeHtml(name)+'</div>';
}
function targetCell(x){
  const domains=x.domains||[];
  if(domains.length){
    return '<div><code>'+escapeHtml(domains[0])+'</code></div><div style="font-size:11px;color:var(--text2)">'+escapeHtml(x.target||'')+'</div>';
  }
  return '<code>'+escapeHtml(x.target||'')+'</code>';
}
async function loadAccessStats(minutes){
  if(minutes)accessMinutes=minutes;
  const type=document.getElementById('access-type')?.value||'all';
  const q=document.getElementById('access-search')?.value||'';
  const d=await api('/api/access-stats?minutes='+accessMinutes+'&type='+encodeURIComponent(type)+'&q='+encodeURIComponent(q));
  if(!d)return;
  const summary=document.getElementById('access-summary');
  if(!d.ok){
    summary.innerHTML='<span style="color:var(--red)">访问日志不可用：'+escapeHtml(d.error||d.hint||'unknown')+'</span>';
    document.getElementById('access-targets').innerHTML='';
    document.getElementById('access-records').innerHTML='';
    return;
  }
  summary.innerHTML='最近 <b>'+d.window_minutes+'</b> 分钟：总计 <b>'+d.total+'</b>，代理 <b style="color:var(--green)">'+d.proxy+'</b>，直连 <b>'+d.direct+'</b>，拦截 <b style="color:var(--red)">'+d.blocked+'</b>，补全 <b>'+((d.enriched_targets)||0)+'</b> 个目标 <span style="color:var(--text2);font-size:11px">('+escapeHtml(d.log_file)+')</span>';
  document.getElementById('access-targets').innerHTML=(d.by_target||[]).map(x=>{
    const obs=Object.entries(x.outbounds||{}).map(([k,v])=>k+':'+v).join(', ');
    return '<tr><td>'+targetCell(x)+'</td><td>'+asInfo(x.ip_meta)+'</td><td>'+x.count+'</td><td>'+x.proxy+'</td><td>'+x.direct+'</td><td>'+x.blocked+'</td><td>'+escapeHtml(obs)+'</td><td>'+escapeHtml(x.last_seen)+'</td></tr>';
  }).join('')||'<tr><td colspan="8" style="color:var(--text2)">暂无记录</td></tr>';
  document.getElementById('access-records').innerHTML=(d.records||[]).map(r=>'<tr><td>'+escapeHtml(r.time)+'</td><td>'+escapeHtml(r.client)+'</td><td>'+targetCell(r)+'</td><td>'+asInfo(r.ip_meta)+'</td><td>'+escapeHtml(r.port||'')+'</td><td>'+escapeHtml(routeTypeLabel(r.route_type))+'</td><td>'+escapeHtml(r.outbound)+'</td></tr>').join('')||'<tr><td colspan="7" style="color:var(--text2)">暂无记录</td></tr>';
}
function loadAccessStatsDebounced(){clearTimeout(accessTimer);accessTimer=setTimeout(()=>loadAccessStats(),300);}

async function clearLogs(){
  if(!confirm('确认清理访问统计、核心/面板日志和 IP 归属缓存？此操作不可恢复。'))return;
  const d=await api('/api/logs/clear',{method:'POST'});
  if(!d)return;
  if(d.ok){
    toast('已清理统计和日志');
    await loadAccessStats();
    await loadLogs(200);
  }else{
    toast('清理部分失败: '+JSON.stringify(d.errors||[]));
  }
}

let _rawLogs='';
async function loadLogs(n){
  const d=await api('/api/logs?lines='+n);
  if(!d)return;
  _rawLogs=d.logs;
  filterLogs();
  const box=document.getElementById('log-box');
  box.scrollTop=box.scrollHeight;
}
function filterLogs(){
  const q=(document.getElementById('log-filter').value||'').trim().toLowerCase();
  const box=document.getElementById('log-box');
  if(!q){box.textContent=_rawLogs;box.scrollTop=box.scrollHeight;return;}
  const lines=_rawLogs.split('\n');
  const matched=lines.filter(l=>l.toLowerCase().includes(q));
  box.textContent=matched.join('\n')||'(无匹配)';
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
      hint.innerHTML="启用时将使用 <b>负载均衡</b>："+d.tags.join(", ")+"（"+(strMap[d.strategy]||d.strategy)+"）";
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
  box.textContent="Balancer saved. "+(d.reloaded?"core restarted.":"");
}

// --- Sysctl ---
async function loadSysctl(){
  const d=await api('/api/sysctl');
  if(!d)return;
  const tbody=document.getElementById('sysctl-tbody');
  document.getElementById('sysctl-hint').innerHTML=d.writable
    ?'<span style="color:var(--green)">可直接修改宿主机参数</span>'+(d.persist?'，持久化到 '+escapeHtml(d.persist):'，<span style="color:var(--yellow)">未挂载宿主机 /etc/sysctl.d，重启后失效</span>')
    :'<span style="color:var(--yellow)">当前容器内 /proc/sys 只读，保存不会生效。启动容器时加上 -v /proc/sys/net:/host/proc/sys/net -v /etc/sysctl.d:/host/etc/sysctl.d</span>';
  tbody.innerHTML=d.params.map(p=>{
    const mismatch=p.recommended&&p.value!==p.recommended&&p.value!=='(unavailable)';
    const rec=p.recommended?`<span style="color:var(--text2)">${escapeHtml(p.recommended)}</span>`:'<span style="color:var(--text2)">—</span>';
    return `<tr>
      <td style="font-family:monospace;font-size:12px">${escapeHtml(p.key)}</td>
      <td style="color:var(--text2);font-size:12px;white-space:normal;min-width:180px">${escapeHtml(p.desc)}</td>
      <td><input class="sysctl-val" data-key="${escapeHtml(p.key)}" data-orig="${escapeHtml(p.value)}" value="${escapeHtml(p.value)}" style="width:120px;padding:4px;background:var(--bg);color:var(--text);border:1px solid ${mismatch?'var(--yellow)':'var(--border)'};border-radius:4px;font-family:monospace;font-size:12px"></td>
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
    if(val&&val!==inp.dataset.orig)changes[key]=val;
  });
  if(!Object.keys(changes).length){toast('无修改',false);return;}
  const d=await api('/api/sysctl',{method:'POST',body:JSON.stringify({changes})});
  if(d&&d.ok){toast('已生效 '+d.applied.length+' 项'+(d.persisted?'，已写入 '+d.persisted:''));}
  else toast('部分失败: '+((d&&d.errors)||[d&&d.error||'unknown']).join('；'),false);
  loadSysctl();
}
function applyOne(key,val){
  const inp=document.querySelector(`.sysctl-val[data-key="${key}"]`);
  if(inp)inp.value=val;
}
async function applyRecommended(){
  const d=await api('/api/sysctl');
  if(!d)return;
  const changes={};
  d.params.forEach(p=>{if(p.recommended&&p.value!==p.recommended&&p.writable)changes[p.key]=p.recommended;});
  if(!Object.keys(changes).length){toast('全部已是推荐值');return;}
  const r=await api('/api/sysctl',{method:'POST',body:JSON.stringify({changes})});
  if(r&&r.ok){toast('已应用推荐值 ('+r.applied.length+'项)');}
  else toast('部分失败: '+((r&&r.errors)||[r&&r.error||'unknown']).join('；'),false);
  loadSysctl();
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
  box.textContent+='连接成功\n';
  box.textContent+='节点: '+(d.state.selected_tags||[]).join(', ')+'\n';
  box.textContent+='SOCKS5: 0.0.0.0:'+ports.socks+'\n';
  box.textContent+='HTTP: 0.0.0.0:'+ports.http+'\n';
  if(transparent)box.textContent+='透明代理: 0.0.0.0:'+ports.transparent+'\n';
  box.textContent+='核心重启: '+(d.restart&&d.restart.success?'成功':'失败')+'\n';
  loadConnect();
}

async function connStop(){
  if(!confirm('确认断开连接？'))return;
  const box=document.getElementById('conn-test-output');
  box.style.display='block';
  box.textContent='正在断开...';
  const d=await api('/api/connect/stop',{method:'POST',body:'{}'});
  if(!d||!d.ok){box.textContent='失败';return;}
  box.textContent='已断开连接\n';
  box.textContent+='核心重启: '+(d.restart&&d.restart.success?'成功':'失败')+'\n';
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
  box.textContent='测试 '+tags.length+' 个节点延迟...\n启动临时核心...';
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
  box.textContent='测速 '+tags.length+' 个节点...\n下载: '+speedUrl+'\n启动临时核心...';
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
  const d=await api('/api/gateway/status');
  const el=document.getElementById('gw-body');
  if(!d||!el)return;
  const lan=(d.lan||[]);
  const ip=lan.length?lan[0].ip:'本机局域网 IP';
  const ifs=d.send_redirects_ifaces||{};
  const redirOff=d.send_redirects==='0'&&Object.values(ifs).every(v=>v==='0');
  const redirCmd='sysctl -w net.ipv4.conf.all.send_redirects=0'+Object.keys(ifs).map(i=>' net.ipv4.conf.'+i+'.send_redirects=0').join('');
  const chk=(cls,txt,title)=>`<span class="check ${cls}" title="${escapeHtml(title||'')}">${txt}</span>`;
  const checks=[
    d.transparent?chk('ok','透明代理已启用'):chk('bad','透明代理未启用','勾选上方“启用”后重新连接'),
    d.ip_forward?chk('ok','IP 转发已开启'):chk('bad','IP 转发未开启','宿主机执行 sysctl -w net.ipv4.ip_forward=1'),
    d.dns_inbound?chk('ok','DNS 入站 :53'):chk('warn','DNS 入站未就绪'),
    d.rules_in_sync?chk('ok','iptables 规则最新'):chk(d.transparent?'warn':'','iptables 规则未生效'),
    redirOff?chk('ok','ICMP 重定向已关闭'):'',
    d.nft_forward_drop?chk('ok','已放行 Docker FORWARD DROP','宿主机 nftables FORWARD 默认丢弃，已在 DOCKER-USER 放行局域网'):'',
  ].join('');
  const rows=lan.length?lan.map(x=>`<span>${escapeHtml(x.iface)} · ${escapeHtml(x.cidr)}</span><b>网关 / DNS 填 ${escapeHtml(x.ip)}</b>`).join(''):'<span>网关 / DNS</span><b>本机局域网 IP</b>';
  el.innerHTML=`<div class="gw-setup">${rows}
      <span>手机 IP</span><b>同网段未占用的地址，子网掩码与网段一致</b>
    </div><div class="gw-checks">${checks}</div>
    ${redirOff?'':`<details style="margin-top:8px"><summary style="font-size:12px">可选：关闭 ICMP 重定向</summary><div class="log-box" style="margin-top:6px;padding:8px 10px;white-space:normal">不影响正常使用。旁路由接法下，本机给 UDP 等直连流量转发时会顺带告诉设备“这个目标可以直接找路由器”，部分系统会自动记下，之后访问同一 IP 的 TCP 也绕过代理。宿主机执行可避免：<br><code>${escapeHtml(redirCmd)}</code></div></details>`}
    <p style="font-size:12px;color:var(--text2);margin-top:8px">TCP 全部经过代理；DNS 可以填本机或任意公共 DNS（都会被接管）；QUIC 被拒绝后浏览器自动改用 TCP；其他 UDP（游戏、语音）直连。IPv6 不经过本机，若路由器下发了 IPv6，建议在手机或路由器上关闭。</p>`;
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

PANEL_TITLE = (os.environ.get("PANEL_TITLE") or "Derwalld").strip()[:40] or "Derwalld"


@app.route("/")
def index():
    import html as _html
    return Response(HTML.replace("__PANEL_TITLE__", _html.escape(PANEL_TITLE)), content_type="text/html; charset=utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Derwalld web panel")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--xray-config", default=DEFAULT_XRAY_CFG)
    parser.add_argument("--xray-binary", default=DEFAULT_XRAY_BIN)
    parser.add_argument("--service", default=DEFAULT_SVC_NAME)
    parser.add_argument("--token", default=None,
                        help="auth token; default: state/token file, else 123456; empty string disables auth")
    parser.add_argument("--test-urls-file", default=DEFAULT_TEST_URLS_FILE)
    args = parser.parse_args()

    XRAY_CFG = args.xray_config
    XRAY_BIN = args.xray_binary
    SVC_NAME = args.service
    AUTH_TOKEN = args.token if args.token is not None else DEFAULT_TOKEN
    TEST_URLS_FILE = args.test_urls_file

    # Load token from file if exists (overrides default, but --token overrides file)
    if args.token is None:
        try:
            with open(f"{BASE_DIR}/state/token") as f:
                saved = f.read().strip()
            if saved:
                AUTH_TOKEN = saved
        except Exception:
            pass

    print(f"{PANEL_TITLE} panel starting on http://{args.host}:{args.port}")
    print(f"  Xray config: {XRAY_CFG}")
    print(f"  Xray binary: {XRAY_BIN}")
    print(f"  Service: {SVC_NAME}")
    if AUTH_TOKEN:
        print(f"  Auth: enabled (token required)")
    else:
        print(f"  Auth: disabled (open access)")

    # Create required directories
    _init_dirs()
    pruned = _prune_config_backups()
    if pruned:
        print(f"  Pruned {pruned} old config backups (keep {CONFIG_BACKUP_KEEP})")

    # Cleanup stale transparent proxy iptables rules on startup
    with _STATE_LOCK:
        _tp_startup_cleanup()
    if RECONCILE_INTERVAL > 0:
        threading.Thread(target=_reconcile_loop, name="reconcile", daemon=True).start()
        print(f"  Reconcile: every {RECONCILE_INTERVAL}s")
    if TRAFFIC_SAMPLE_INTERVAL > 0:
        threading.Thread(target=_traffic_loop, name="traffic", daemon=True).start()
        print(f"  Traffic history: every {TRAFFIC_SAMPLE_INTERVAL}s -> {TRAFFIC_DB}")
    if PEER_STATS_ENABLED:
        _peer_stats_start()
        print(f"  Peer traffic (conntrack): acct={_conntrack_acct_enabled()} keep {PEER_KEEP_DAYS}d")

    app.run(host=args.host, port=args.port, debug=False)
