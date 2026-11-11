import socket
import struct
import tempfile
import unittest
from pathlib import Path

import conntrack_stats as ct


def nla(typ, payload, nested=False):
    ln = 4 + len(payload)
    return struct.pack("=HH", ln, typ | (0x8000 if nested else 0)) + payload + b"\0" * ((4 - ln % 4) % 4)


def tup(src, dst, proto, sport, dport):
    ip = nla(ct.CTA_IP_V4_SRC, socket.inet_aton(src)) + nla(ct.CTA_IP_V4_DST, socket.inet_aton(dst))
    pr = (nla(ct.CTA_PROTO_NUM, bytes([proto])) + nla(ct.CTA_PROTO_SRC_PORT, struct.pack("!H", sport))
          + nla(ct.CTA_PROTO_DST_PORT, struct.pack("!H", dport)))
    return nla(ct.CTA_TUPLE_IP, ip, True) + nla(ct.CTA_TUPLE_PROTO, pr, True)


def msg(msg_type, cid, orig, reply, ob, rb):
    body = struct.pack("=BBH", socket.AF_INET, 0, 0)
    body += nla(ct.CTA_TUPLE_ORIG, tup(*orig), True) + nla(ct.CTA_TUPLE_REPLY, tup(*reply), True)
    body += nla(ct.CTA_ID, struct.pack("!I", cid))
    if ob is not None:
        body += nla(ct.CTA_COUNTERS_ORIG, nla(1, struct.pack("!Q", 1)) + nla(ct.CTA_COUNTERS_BYTES, struct.pack("!Q", ob)), True)
        body += nla(ct.CTA_COUNTERS_REPLY, nla(1, struct.pack("!Q", 1)) + nla(ct.CTA_COUNTERS_BYTES, struct.pack("!Q", rb)), True)
    return struct.pack("=IHHII", 16 + len(body), (ct.NFNL_SUBSYS_CTNETLINK << 8) | msg_type, 0, 1, 0) + body


LOCAL = "172.21.2.67"
KIRO = "65.8.76.19"
NODE = "23.80.90.243"


class ConntrackTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.acc = ct.ConntrackAccounting(str(Path(self.tmp.name) / "t.db"),
                                          lambda: {"local_ips": {LOCAL, "127.0.0.1"}, "node_ips": {NODE}})
        self.acc._refresh_context()

    def tearDown(self):
        self.tmp.cleanup()

    def feed(self, data, final):
        for typ, flow in ct.parse_messages(data):
            self.acc.account(flow, final=final, now=1_800_000_000)

    def rows(self):
        rows, totals, _ = self.acc.query(hours=24 * 365 * 10, now=1_800_000_000)
        return {(r["ip"], r["kind"]): (r["rx"], r["tx"], r["conns"]) for r in rows}, totals

    def test_parse_and_classify_kinds(self):
        data = b"".join([
            # app -> kiro.dev, REDIRECTed into the core (reply from 127.0.0.1:12345)
            msg(0, 1, (LOCAL, KIRO, 6, 40000, 443), ("127.0.0.1", LOCAL, 6, 12345, 40000), 1000, 50000),
            # core -> node
            msg(0, 2, (LOCAL, NODE, 6, 40001, 443), (NODE, LOCAL, 6, 443, 40001), 1200, 52000),
            # LAN phone -> baidu, masqueraded direct
            msg(0, 3, ("192.168.1.20", "110.242.68.66", 6, 5000, 443), ("110.242.68.66", LOCAL, 6, 443, 5000), 300, 9000),
            # host -> internal 10.x
            msg(0, 4, (LOCAL, "10.19.98.142", 6, 40002, 443), ("10.19.98.142", LOCAL, 6, 443, 40002), 10, 20),
            # remote opens the panel port
            msg(0, 5, ("10.18.216.5", LOCAL, 6, 6000, 54321), (LOCAL, "10.18.216.5", 6, 54321, 6000), 700, 90000),
            # loopback only -> ignored
            msg(0, 6, ("127.0.0.1", "127.0.0.1", 6, 7000, 54321), ("127.0.0.1", "127.0.0.1", 6, 54321, 7000), 5, 5),
        ])
        self.feed(data, final=False)
        r, totals = self.rows()
        self.assertEqual(r[(KIRO, "core")], (50000, 1000, 1))
        self.assertEqual(r[(NODE, "node")], (52000, 1200, 1))
        self.assertEqual(r[("110.242.68.66", "direct")], (9000, 300, 1))
        self.assertEqual(r[("10.19.98.142", "internal")], (20, 10, 1))
        self.assertEqual(r[("10.18.216.5", "inbound")], (700, 90000, 1))
        self.assertNotIn(("127.0.0.1", "inbound"), r)
        self.assertEqual(len(r), 5)

    def test_deltas_between_dump_and_destroy(self):
        o, rp = (LOCAL, NODE, 6, 40001, 443), (NODE, LOCAL, 6, 443, 40001)
        self.feed(msg(0, 9, o, rp, 100, 1000), final=False)   # dump 1
        self.feed(msg(0, 9, o, rp, 150, 3000), final=False)   # dump 2: +50/+2000
        self.feed(msg(2, 9, o, rp, 160, 3500), final=True)    # destroy: +10/+500
        self.feed(msg(2, 9, o, rp, 160, 3500), final=True)    # duplicate destroy for a forgotten flow counts again only if unseen
        r, _ = self.rows()
        rx, tx, conns = r[(NODE, "node")]
        self.assertEqual((rx, tx), (3500 + 3500, 160 + 160))
        self.assertEqual(conns, 2)
        self.assertEqual(self.acc.seen, {})

    def test_short_flow_only_destroy_and_no_counters(self):
        self.feed(msg(2, 11, (LOCAL, KIRO, 6, 1, 443), ("127.0.0.1", LOCAL, 6, 12345, 1), 10, 20), final=True)
        self.feed(msg(2, 12, (LOCAL, KIRO, 6, 2, 443), ("127.0.0.1", LOCAL, 6, 12345, 2), None, None), final=True)
        r, _ = self.rows()
        self.assertEqual(r[(KIRO, "core")], (20, 10, 1))
        self.assertEqual(self.acc.stats["no_counters"], 1)


if __name__ == "__main__":
    unittest.main()
