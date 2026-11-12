import json, os, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app

NODES = [{"tag": t, "protocol": "vless", "settings": {"vnext": [{"address": "a", "port": 1}]}} for t in ("n1", "n2", "n3")]

class HotSwitch(unittest.TestCase):
    def build(self, tags, strategy="roundRobin", transparent=False, nodes=NODES):
        cfg = {"inbounds": [], "outbounds": json.loads(json.dumps(nodes)), "routing": {"rules": []}}
        with mock.patch.object(app, "_parse_config", return_value=(cfg, None)), \
             mock.patch.object(app, "_dns_state_load", return_value=None), \
             mock.patch.object(app, "_custom_rules_load", return_value=[]), \
             mock.patch.object(app, "_pick_api_listen", return_value="127.0.0.1:10085"):
            out, err = app._build_connect_config(tags, strategy, transparent, {"socks": 10810, "http": 10818, "transparent": 12345})
        self.assertIsNone(err)
        return out

    def test_single_node_uses_balancer_and_api(self):
        c = self.build(["n2"], transparent=True)
        self.assertEqual(c["routing"]["balancers"], [{"tag": "proxy-balancer", "selector": ["n2"], "strategy": {"type": "random"}}])
        tp = [r for r in c["routing"]["rules"] if r.get("inboundTag") == ["transparent"]]
        self.assertEqual(tp[0].get("balancerTag"), "proxy-balancer")
        self.assertEqual(c["api"]["listen"], "127.0.0.1:10085")
        self.assertIn("RoutingService", c["api"]["services"])

    def test_fingerprint_ignores_only_node_choice(self):
        fp = app._connect_fingerprint
        self.assertEqual(fp(self.build(["n1"])), fp(self.build(["n2"])))
        self.assertEqual(fp(self.build(["n1", "n2"], "leastPing")), fp(self.build(["n3"])))
        self.assertNotEqual(fp(self.build(["n1"])), fp(self.build(["n1"], transparent=True)))

    def test_prefix_tag_falls_back_to_outbound(self):
        nodes = NODES + [{"tag": "n1-b", "protocol": "vless"}]
        c = self.build(["n1"], nodes=nodes)
        self.assertEqual(c["routing"]["balancers"], [])
        socks = [r for r in c["routing"]["rules"] if r.get("inboundTag") == ["socks-in"]][0]
        self.assertEqual(socks.get("outboundTag"), "n1")

    def test_api_listen_kept(self):
        cfg = {"api": {"tag": "api", "listen": "127.0.0.1:10090", "services": ["StatsService"]}}
        app._ensure_routing_api(cfg)
        self.assertEqual(cfg["api"]["listen"], "127.0.0.1:10090")
        self.assertEqual(cfg["api"]["services"], ["StatsService", "RoutingService"])

if __name__ == "__main__":
    unittest.main()
