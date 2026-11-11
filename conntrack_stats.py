"""Per-remote-IP traffic accounting from the kernel conntrack table.

Requires net.netfilter.nf_conntrack_acct=1 on the host (counters are attached
to connections created after it is enabled) and CAP_NET_ADMIN in the host
network namespace. Two netlink sockets are used:

* an event socket subscribed to NFNLGRP_CONNTRACK_DESTROY, which delivers the
  final byte counters of every closed connection;
* a periodic dump (IPCTNL_MSG_CT_GET + NLM_F_DUMP) that picks up the growth of
  long-lived connections between dumps.

Only deltas are added, so a connection is counted once no matter how many
dumps it appears in. Results go into hourly buckets in SQLite.
"""
import errno
import ipaddress
import socket
import sqlite3
import struct
import threading
import time
from pathlib import Path

NETLINK_NETFILTER = 12
NFNL_SUBSYS_CTNETLINK = 1
IPCTNL_MSG_CT_NEW, IPCTNL_MSG_CT_GET, IPCTNL_MSG_CT_DELETE = 0, 1, 2
NFNLGRP_CONNTRACK_DESTROY = 3
NLM_F_REQUEST, NLM_F_DUMP = 0x1, 0x300
NLMSG_ERROR, NLMSG_DONE = 2, 3
NLA_TYPE_MASK = 0x3FFF

CTA_TUPLE_ORIG, CTA_TUPLE_REPLY, CTA_MARK, CTA_COUNTERS_ORIG, CTA_COUNTERS_REPLY, CTA_ID = 1, 2, 8, 9, 10, 12
CTA_TUPLE_IP, CTA_TUPLE_PROTO = 1, 2
CTA_IP_V4_SRC, CTA_IP_V4_DST, CTA_IP_V6_SRC, CTA_IP_V6_DST = 1, 2, 3, 4
CTA_PROTO_NUM, CTA_PROTO_SRC_PORT, CTA_PROTO_DST_PORT = 1, 2, 3
CTA_COUNTERS_BYTES = 2

PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}

# kinds, from the host's point of view
KIND_CORE = "core"                  # app connection redirected into the proxy core (original destination)
KIND_NODE = "node"                  # proxy core -> proxy node server (real wire traffic of proxied flows)
KIND_DIRECT = "direct"              # outbound to a public IP, not proxied
KIND_INTERNAL = "internal"          # outbound to a private / internal IP
KIND_INBOUND = "inbound"            # connection opened by the remote side towards this host
KINDS = (KIND_CORE, KIND_NODE, KIND_DIRECT, KIND_INTERNAL, KIND_INBOUND)


def _attrs(buf, off, end):
    out = {}
    while off + 4 <= end:
        ln, typ = struct.unpack_from("=HH", buf, off)
        if ln < 4:
            break
        out[typ & NLA_TYPE_MASK] = (off + 4, off + ln)
        off += (ln + 3) & ~3
    return out


def _tuple(buf, span):
    a = _attrs(buf, *span)
    ip = _attrs(buf, *a[CTA_TUPLE_IP]) if CTA_TUPLE_IP in a else {}
    pr = _attrs(buf, *a[CTA_TUPLE_PROTO]) if CTA_TUPLE_PROTO in a else {}
    src = dst = None
    if CTA_IP_V4_SRC in ip:
        src = socket.inet_ntop(socket.AF_INET, bytes(buf[ip[CTA_IP_V4_SRC][0]:ip[CTA_IP_V4_SRC][0] + 4]))
        dst = socket.inet_ntop(socket.AF_INET, bytes(buf[ip[CTA_IP_V4_DST][0]:ip[CTA_IP_V4_DST][0] + 4]))
    elif CTA_IP_V6_SRC in ip:
        src = socket.inet_ntop(socket.AF_INET6, bytes(buf[ip[CTA_IP_V6_SRC][0]:ip[CTA_IP_V6_SRC][0] + 16]))
        dst = socket.inet_ntop(socket.AF_INET6, bytes(buf[ip[CTA_IP_V6_DST][0]:ip[CTA_IP_V6_DST][0] + 16]))
    proto = buf[pr[CTA_PROTO_NUM][0]] if CTA_PROTO_NUM in pr else 0
    sport = struct.unpack_from("!H", buf, pr[CTA_PROTO_SRC_PORT][0])[0] if CTA_PROTO_SRC_PORT in pr else 0
    dport = struct.unpack_from("!H", buf, pr[CTA_PROTO_DST_PORT][0])[0] if CTA_PROTO_DST_PORT in pr else 0
    return src, dst, proto, sport, dport


def _counter_bytes(buf, span):
    a = _attrs(buf, *span)
    if CTA_COUNTERS_BYTES not in a:
        return None
    return struct.unpack_from("!Q", buf, a[CTA_COUNTERS_BYTES][0])[0]


def parse_messages(buf):
    """Yield (msg_type, flow_dict) for ctnetlink messages in one netlink datagram."""
    off, n = 0, len(buf)
    while off + 16 <= n:
        ln, typ, _flags, _seq, _pid = struct.unpack_from("=IHHII", buf, off)
        if ln < 16 or off + ln > n:
            break
        if typ in (NLMSG_DONE, NLMSG_ERROR):
            yield typ, None
        elif (typ >> 8) == NFNL_SUBSYS_CTNETLINK:
            a = _attrs(buf, off + 20, off + ln)
            if CTA_TUPLE_ORIG in a and CTA_TUPLE_REPLY in a:
                o = _tuple(buf, a[CTA_TUPLE_ORIG])
                r = _tuple(buf, a[CTA_TUPLE_REPLY])
                flow = {
                    "id": struct.unpack_from("!I", buf, a[CTA_ID][0])[0] if CTA_ID in a else 0,
                    "orig": o, "reply": r,
                    "mark": struct.unpack_from("!I", buf, a[CTA_MARK][0])[0] if CTA_MARK in a else 0,
                    "ob": _counter_bytes(buf, a[CTA_COUNTERS_ORIG]) if CTA_COUNTERS_ORIG in a else None,
                    "rb": _counter_bytes(buf, a[CTA_COUNTERS_REPLY]) if CTA_COUNTERS_REPLY in a else None,
                }
                yield typ & 0xFF, flow
        off += (ln + 3) & ~3


def _dump_request(seq, family):
    nfgen = struct.pack("=BBH", family, 0, 0)
    hdr = struct.pack("=IHHII", 16 + len(nfgen), (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET,
                      NLM_F_REQUEST | NLM_F_DUMP, seq, 0)
    return hdr + nfgen


def _is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return not a.is_global


class FlowClassifier:
    """Decide, for one conntrack entry, which remote IP the traffic belongs to,
    the kind, and which counter is upload (tx) / download (rx) for this host."""

    def __init__(self, local_ips=(), node_ips=(), proxy_mark=0x80, tp_ports=()):
        self.local_ips = set(local_ips)
        self.node_ips = set(node_ips)
        self.proxy_mark = proxy_mark
        self.tp_ports = set(tp_ports)

    def _local(self, ip):
        if ip in self.local_ips:
            return True
        try:
            return ipaddress.ip_address(ip).is_loopback
        except ValueError:
            return False

    def classify(self, flow):
        """Return (remote_ip, kind, port, proto, orig_is_tx) or None to skip."""
        osrc, odst, proto, _osport, odport = flow["orig"]
        rsrc, _rdst, _rp, rsport, _rdport = flow["reply"]
        if not osrc or not odst:
            return None
        # NAT REDIRECT into the transparent proxy: reply comes from a local
        # address on the dokodemo / DNS port, the original destination is the
        # app's real target (e.g. kiro.dev's IP).
        if rsrc != odst and self._local(rsrc) and not self._local(odst):
            return odst, KIND_CORE, odport, proto, True
        src_local, dst_local = self._local(osrc), self._local(odst)
        if src_local and dst_local:
            return None
        if not dst_local:
            # outbound: from this host, or forwarded for a LAN client. The core's
            # SO_MARK is a packet mark, not a conntrack mark, so node traffic is
            # recognised by the node server addresses.
            if odst in self.node_ips:
                kind = KIND_NODE
            elif _is_private(odst):
                kind = KIND_INTERNAL
            else:
                kind = KIND_DIRECT
            return odst, kind, odport, proto, True
        # inbound: remote opened a connection to this host
        return osrc, KIND_INBOUND, odport, proto, False


class ConntrackAccounting:
    def __init__(self, db_path, context, dump_interval=60, keep_days=30):
        """context(): returns dict(local_ips, node_ips, tp_ports, proxy_mark)."""
        self.db_path = db_path
        self.context = context
        self.dump_interval = dump_interval
        self.keep_days = keep_days
        self.lock = threading.Lock()
        self.seen = {}          # flow key -> (orig_bytes, reply_bytes)
        self.pending = {}       # (hour, ip, kind) -> [rx, tx, conns, port, proto]
        self.classifier = FlowClassifier()
        self.stats = {"events": 0, "dropped": 0, "dumps": 0, "last_dump": 0, "flows": 0,
                      "started_at": int(time.time()), "error": "", "no_counters": 0}
        self._seq = int(time.time()) & 0xFFFF

    # -- storage ----------------------------------------------------------
    def _conn(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(
            "CREATE TABLE IF NOT EXISTS peer_hourly(hour INTEGER, ip TEXT, kind TEXT, rx INTEGER NOT NULL DEFAULT 0,"
            " tx INTEGER NOT NULL DEFAULT 0, conns INTEGER NOT NULL DEFAULT 0, port INTEGER, proto INTEGER,"
            " last_seen INTEGER, PRIMARY KEY(hour, ip, kind));"
            "CREATE INDEX IF NOT EXISTS peer_hourly_ip ON peer_hourly(ip);"
        )
        return conn

    def flush(self, now=None):
        now = int(now if now is not None else time.time())
        with self.lock:
            pending, self.pending = self.pending, {}
        if not pending:
            return 0
        conn = self._conn()
        try:
            for (hour, ip, kind), (rx, tx, conns, port, proto) in pending.items():
                conn.execute(
                    "INSERT INTO peer_hourly(hour,ip,kind,rx,tx,conns,port,proto,last_seen) VALUES(?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(hour,ip,kind) DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx, "
                    "conns=conns+excluded.conns, port=excluded.port, proto=excluded.proto, last_seen=excluded.last_seen",
                    (hour, ip, kind, rx, tx, conns, port, proto, now))
            conn.commit()
        finally:
            conn.close()
        return len(pending)

    def prune(self, now=None):
        now = int(now if now is not None else time.time())
        conn = self._conn()
        try:
            conn.execute("DELETE FROM peer_hourly WHERE hour < ?", (now - self.keep_days * 86400,))
            conn.commit()
        finally:
            conn.close()

    # -- accounting -------------------------------------------------------
    def account(self, flow, final, now=None):
        """Add the counter growth of one flow. final=True for destroy events."""
        ob, rb = flow.get("ob"), flow.get("rb")
        if ob is None or rb is None:
            self.stats["no_counters"] += 1
            return
        key = (flow["id"], flow["orig"])
        now = int(now if now is not None else time.time())
        with self.lock:
            prev = self.seen.pop(key, None) if final else self.seen.get(key)
            if not final:
                self.seen[key] = (ob, rb)
            first = prev is None
            if prev is None:
                prev = (0, 0)
            dob, drb = max(0, ob - prev[0]), max(0, rb - prev[1])
            if not dob and not drb and not first:
                return
            c = self.classifier.classify(flow)
            if not c:
                return
            ip, kind, port, proto, orig_is_tx = c
            tx, rx = (dob, drb) if orig_is_tx else (drb, dob)
            hour = now - now % 3600
            cell = self.pending.setdefault((hour, ip, kind), [0, 0, 0, port, proto])
            cell[0] += rx
            cell[1] += tx
            cell[2] += 1 if first else 0
            cell[3], cell[4] = port, proto

    def _refresh_context(self):
        try:
            ctx = self.context() or {}
            self.classifier = FlowClassifier(ctx.get("local_ips", ()), ctx.get("node_ips", ()),
                                             ctx.get("proxy_mark", 0x80), ctx.get("tp_ports", ()))
        except Exception as e:  # keep the previous classifier
            self.stats["error"] = f"context: {e}"

    def dump_once(self):
        self._refresh_context()
        alive = set()
        for family in (socket.AF_INET, socket.AF_INET6):
            s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
            try:
                s.settimeout(10)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
                s.bind((0, 0))
                self._seq = (self._seq + 1) & 0xFFFFFFFF
                s.send(_dump_request(self._seq, family))
                done = False
                while not done:
                    data = s.recv(1 << 20)
                    for typ, flow in parse_messages(data):
                        if flow is None:
                            done = True
                            break
                        alive.add((flow["id"], flow["orig"]))
                        self.account(flow, final=False)
            finally:
                s.close()
        with self.lock:
            # forget flows whose destroy event was lost
            for key in [k for k in self.seen if k not in alive]:
                del self.seen[key]
            self.stats["flows"] = len(self.seen)
        self.stats["dumps"] += 1
        self.stats["last_dump"] = int(time.time())

    def _event_loop(self):
        while True:
            s = None
            try:
                s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
                try:
                    s.setsockopt(socket.SOL_SOCKET, 33, 8 << 20)  # SO_RCVBUFFORCE (CAP_NET_ADMIN)
                except OSError:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
                s.bind((0, 1 << (NFNLGRP_CONNTRACK_DESTROY - 1)))
                while True:
                    try:
                        data = s.recv(1 << 20)
                    except OSError as e:
                        if e.errno == errno.ENOBUFS:
                            self.stats["dropped"] += 1
                            continue
                        raise
                    for typ, flow in parse_messages(data):
                        if flow is not None and typ == IPCTNL_MSG_CT_DELETE:
                            self.stats["events"] += 1
                            self.account(flow, final=True)
            except Exception as e:
                self.stats["error"] = f"events: {e}"
                time.sleep(5)
            finally:
                if s is not None:
                    s.close()

    def _dump_loop(self):
        last_prune = 0
        while True:
            try:
                self.dump_once()
                self.flush()
                if time.time() - last_prune > 86400:
                    self.prune()
                    last_prune = time.time()
                if self.stats["error"].startswith("dump"):
                    self.stats["error"] = ""
            except Exception as e:
                self.stats["error"] = f"dump: {e}"
            time.sleep(self.dump_interval)

    def start(self):
        threading.Thread(target=self._event_loop, name="ct-events", daemon=True).start()
        threading.Thread(target=self._dump_loop, name="ct-dump", daemon=True).start()

    # -- query ------------------------------------------------------------
    def query(self, hours=24, kind="", now=None):
        now = int(now if now is not None else time.time())
        self.flush(now)
        since = now - now % 3600 - (max(1, hours) - 1) * 3600
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT ip, kind, SUM(rx), SUM(tx), SUM(conns), MAX(last_seen), "
                "(SELECT port FROM peer_hourly p2 WHERE p2.ip=p.ip AND p2.kind=p.kind ORDER BY hour DESC LIMIT 1), "
                "(SELECT proto FROM peer_hourly p2 WHERE p2.ip=p.ip AND p2.kind=p.kind ORDER BY hour DESC LIMIT 1) "
                "FROM peer_hourly p WHERE hour >= ? GROUP BY ip, kind", (since,)).fetchall()
        finally:
            conn.close()
        totals = {k: {"rx": 0, "tx": 0, "conns": 0, "peers": 0} for k in KINDS}
        out = []
        for ip, k, rx, tx, conns, last_seen, port, proto in rows:
            t = totals.setdefault(k, {"rx": 0, "tx": 0, "conns": 0, "peers": 0})
            t["rx"] += rx or 0
            t["tx"] += tx or 0
            t["conns"] += conns or 0
            t["peers"] += 1
            out.append({"ip": ip, "kind": k, "rx": rx or 0, "tx": tx or 0, "conns": conns or 0,
                        "last_seen": last_seen, "port": port, "proto": PROTO_NAMES.get(proto, str(proto or ""))})
        if kind:
            out = [r for r in out if r["kind"] == kind]
        out.sort(key=lambda r: r["rx"] + r["tx"], reverse=True)
        return out, totals, len(rows)
