"""Resolve Xray outbound dial endpoints from DNS TXT ``IP:port`` records.

The source Xray config remains unchanged. ``materialize_config`` deep-copies it
and changes only outbound server address/port fields, preserving SNI, Host,
credentials, and every transport option.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import random
import socket
import struct
import threading
import time
from pathlib import Path

_RESOLVERS = ("223.5.5.5", "119.29.29.29")
_DNS_PORT = 53
_TIMEOUT = 2.0
_CACHE_LOCK = threading.Lock()


def parse_endpoint(value: str):
    value = str(value).strip()
    while len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1].strip()
    try:
        if value.startswith("["):
            close = value.find("]")
            if close <= 1 or value[close + 1 : close + 2] != ":":
                return None
            address, port_text = value[1:close], value[close + 2 :]
            if ipaddress.ip_address(address).version != 6:
                return None
        else:
            if value.count(":") != 1:
                return None
            address, port_text = value.rsplit(":", 1)
            if ipaddress.ip_address(address).version != 4:
                return None
        port = int(port_text)
        if not 1 <= port <= 65535:
            return None
        return address, port
    except (ValueError, TypeError):
        return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
        return True
    except ValueError:
        return False


def _encode_name(name: str) -> bytes:
    labels = name.rstrip(".").encode("idna").split(b".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid DNS name")
    return b"".join(bytes((len(label),)) + label for label in labels) + b"\0"


def _skip_name(packet: bytes, offset: int) -> int:
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            return offset + 2
        offset += 1
        if size == 0:
            return offset
        offset += size
        if offset > len(packet):
            raise ValueError("truncated DNS label")


def _parse_txt_response(packet: bytes):
    if len(packet) < 12:
        raise ValueError("short DNS response")
    flags, qdcount, ancount = struct.unpack("!HHH", packet[2:8])
    if flags & 0x000F:
        return [], 0
    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(packet, offset) + 4
    records = []
    ttls = []
    for _ in range(ancount):
        offset = _skip_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated DNS answer")
        rtype, _rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        end = offset + rdlength
        if end > len(packet):
            raise ValueError("truncated DNS rdata")
        if rtype == 16:
            parts = []
            pos = offset
            while pos < end:
                size = packet[pos]
                pos += 1
                if pos + size > end:
                    raise ValueError("truncated TXT chunk")
                parts.append(packet[pos : pos + size])
                pos += size
            records.append(b"".join(parts).decode("utf-8", "replace"))
            ttls.append(int(ttl))
        offset = end
    return records, min(ttls) if ttls else 0


def query_txt(host: str, resolvers=_RESOLVERS, timeout=_TIMEOUT):
    txid = random.SystemRandom().randrange(0, 65536)
    query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _encode_name(host) + struct.pack("!HH", 16, 1)
    last_error = None
    for resolver in resolvers:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(query, (resolver, _DNS_PORT))
            packet, _ = sock.recvfrom(4096)
            if len(packet) < 2 or struct.unpack("!H", packet[:2])[0] != txid:
                raise ValueError("DNS transaction mismatch")
            return _parse_txt_response(packet)
        except (OSError, ValueError) as exc:
            last_error = exc
        finally:
            sock.close()
    if last_error:
        raise last_error
    return [], 0


def _load_cache(path: str):
    try:
        data = json.loads(Path(path).read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_cache(path: str, cache: dict):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(json.dumps(cache, ensure_ascii=False, indent=2) + "\n")
    os.replace(temp, target)


def resolve_endpoint(host: str, cache_path: str, now=None, query=query_txt):
    host = str(host or "").strip().rstrip(".").lower()
    if not host or _is_ip(host):
        return None
    now = time.time() if now is None else float(now)
    with _CACHE_LOCK:
        cache = _load_cache(cache_path)
        cached = cache.get(host, {})
        if float(cached.get("expires_at", 0)) > now:
            endpoint = parse_endpoint(cached.get("endpoint", ""))
            if endpoint:
                return endpoint
        cache.pop(host, None)

    try:
        records, ttl = query(host)
    except Exception:
        return None
    endpoints = list(dict.fromkeys(filter(None, (parse_endpoint(record) for record in records))))
    if not endpoints:
        return None
    endpoint = random.SystemRandom().choice(endpoints)
    if int(ttl) > 0:
        address = f"[{endpoint[0]}]" if ":" in endpoint[0] else endpoint[0]
        with _CACHE_LOCK:
            cache = _load_cache(cache_path)
            cache[host] = {"endpoint": f"{address}:{endpoint[1]}", "expires_at": now + int(ttl)}
            _save_cache(cache_path, cache)
    return endpoint


def _targets(outbound: dict):
    settings = outbound.get("settings") or {}
    for key in ("vnext", "servers"):
        values = settings.get(key) or []
        if isinstance(values, list):
            for value in values:
                if isinstance(value, dict) and "address" in value and "port" in value:
                    yield value


def materialize_config(config: dict, cache_path: str, resolver=resolve_endpoint):
    runtime = copy.deepcopy(config)
    resolved = []
    for outbound in runtime.get("outbounds") or []:
        if not isinstance(outbound, dict):
            continue
        for target in _targets(outbound):
            original_host = str(target.get("address") or "").strip()
            endpoint = resolver(original_host, cache_path)
            if endpoint is None:
                continue
            target["address"], target["port"] = endpoint
            resolved.append({
                "tag": outbound.get("tag", ""),
                "host": original_host,
                "address": endpoint[0],
                "port": endpoint[1],
            })
    return runtime, resolved
