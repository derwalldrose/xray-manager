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
import ip_asn as _ipasn

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
IP_ASN_PATH = f"{BASE_DIR}/data/ip2asn-v4.tsv.gz"
LEASTPING_PROBE_URL = "https://www.gstatic.com/generate_204"
_asn_db = _ipasn.AsnDB(IP_ASN_PATH, [u for u in (os.environ.get("IP_ASN_URL") or "").split(",") if u] or (_ipasn.DEFAULT_URL, _ipasn.FALLBACK_URL))
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
    # leastPing needs an observatory, otherwise the core refuses to start
    # ("not all dependencies are resolved").
    if is_multi and strategy == "leastPing":
        cfg["observatory"] = {"subjectSelector": list(selected_tags), "probeURL": LEASTPING_PROBE_URL,
                              "probeInterval": "1m", "enableConcurrency": True}
    elif (cfg.get("observatory") or {}).get("probeURL") == LEASTPING_PROBE_URL:
        cfg.pop("observatory", None)

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

    # Save original inbounds for restoration on stop. When switching nodes while
    # already connected, keep the inbounds saved by the first connect; the current
    # ones are connect-mode inbounds and would otherwise survive "stop".
    _prev = _connect_state_read()
    if _prev.get("active") and "original_inbounds" in _prev:
        original_inbounds = _prev["original_inbounds"]
    else:
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


_PEER_DOMAIN_LOCK = threading.Lock()


def _peer_domain_map(wait=False):
    """({ip: [domain, ...]}, {ip: outbound_tag}) from the core log of the last 24h
    (cached 60s). Transparent connections are linked by the client endpoint:
    "[sid] dokodemo: received request for C" + "[sid] sniffed domain: D" +
    "from C accepted tcp:IP:443 [in -> out]". DNS answers and freedom
    "connection opened" lines add more IP -> domain pairs."""
    now = time.time()
    if now - _PEER_DOMAIN_CACHE["t"] < 60:
        return _PEER_DOMAIN_CACHE["map"], _PEER_DOMAIN_CACHE.get("routes", {})
    if _PEER_DOMAIN_CACHE["t"] and not wait:
        # Stale-while-revalidate: answer from the previous map, rebuild in background.
        if _PEER_DOMAIN_LOCK.acquire(blocking=False):
            def _bg():
                try:
                    _peer_domain_map_build()
                finally:
                    _PEER_DOMAIN_LOCK.release()
            threading.Thread(target=_bg, daemon=True).start()
        return _PEER_DOMAIN_CACHE["map"], _PEER_DOMAIN_CACHE.get("routes", {})
    with _PEER_DOMAIN_LOCK:
        if time.time() - _PEER_DOMAIN_CACHE["t"] < 60:
            return _PEER_DOMAIN_CACHE["map"], _PEER_DOMAIN_CACHE.get("routes", {})
        return _peer_domain_map_build()


def _peer_domain_map_build():
    now = time.time()
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


@app.route("/api/ip-meta")
def api_ip_meta():
    ips = [x.strip() for x in (request.args.get("ips") or "").split(",") if x.strip()][:100]
    ips = [ip for ip in ips if _is_ip(ip) and not _ct._is_private(ip)]
    meta = _enrich_ip_meta(ips) if ips else {}
    return jsonify({"ok": True, "db": _asn_db.status(), "meta": {ip: {"asn": m.get("asn"), "country": m.get("country"),
                                              "as_name": m.get("as_name")} for ip, m in meta.items()}})


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


IP_META_MISS_TTL = 3600


def _enrich_ip_meta(ips):
    out = {}
    rest = []
    cache = None
    for ip in set(ips):
        m = _asn_db.lookup(ip) if _asn_db.rows else None
        if m:
            if not m.get("country"):
                cache = cache if cache is not None else _load_ip_meta_cache()
                m["country"] = (cache.get(ip) or {}).get("country", "")
            out[ip] = m
        else:
            rest.append(ip)
    if not rest:
        return out
    cache = cache if cache is not None else _load_ip_meta_cache()
    now = int(time.time())
    ttl = 7 * 24 * 3600
    missing = []
    for ip in sorted(rest):
        if not _is_ip(ip):
            continue
        meta = cache.get(ip)
        age = now - int((meta or {}).get("updated_at", 0) or 0)
        if not meta or age > (IP_META_MISS_TTL if meta.get("miss") else ttl):
            missing.append(ip)
    if missing:
        batch = missing[:100]
        queried = _query_team_cymru(batch)
        # Remember IPs whois could not answer (or a failed query) for a while,
        # so every page view does not wait for the 4s whois timeout again.
        for ip in batch:
            if ip not in queried and not _ct._is_private(ip):
                queried[ip] = {"miss": True, "updated_at": now}
        if queried:
            cache.update(queried)
            _save_ip_meta_cache(cache)
    out.update({ip: cache[ip] for ip in rest if cache.get(ip) and not cache[ip].get("miss")})
    return out


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

UI_FILE = Path(__file__).with_name("ui.html")
try:
    HTML = UI_FILE.read_text(encoding="utf-8")
except OSError as _e:  # keep the API usable even if the UI file is missing
    import html as _h
    HTML = f"<!doctype html><title>__PANEL_TITLE__</title><p>ui.html not found: {_h.escape(str(_e))}</p>"

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
    if os.environ.get("IP_ASN_DB", "1") != "0":
        _asn_db.start()
        print(f"  IP ASN db: {IP_ASN_PATH} (weekly refresh)")

    app.run(host=args.host, port=args.port, debug=False)
