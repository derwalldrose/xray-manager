import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import app


class DnsServerParsingTest(unittest.TestCase):
    def test_dns_server_ip_forms(self):
        cases = {
            "223.5.5.5": "223.5.5.5",
            "223.5.5.5:53": "223.5.5.5",
            "udp:223.5.5.5:53": "223.5.5.5",
            "udp:119.29.29.29": "119.29.29.29",
            "tcp://8.8.8.8:53": "8.8.8.8",
            "https://1.1.1.1/dns-query": "1.1.1.1",
            "https://dns.alidns.com/dns-query": None,
            "udp:[2001:db8::1]:53": "2001:db8::1",
            "localhost": None,
            "fakedns": None,
        }
        for raw, want in cases.items():
            self.assertEqual(app._dns_server_ip(raw), want, raw)
        self.assertEqual(app._dns_server_ip({"address": "9.9.9.9", "port": 53}), "9.9.9.9")

    def test_legacy_udp_servers_normalized(self):
        dns = app._normalize_dns_config({"servers": ["udp:223.5.5.5:53", "udp:1.2.3.4:5353",
                                                      "https://dns.alidns.com/dns-query", {"address": "8.8.8.8"}],
                                         "tag": "dns"})
        self.assertEqual(dns["servers"], ["223.5.5.5", {"address": "1.2.3.4", "port": 5353},
                                          "https://dns.alidns.com/dns-query", {"address": "8.8.8.8"}])
        self.assertNotIn("udp:", json.dumps(app.DEFAULT_DNS_CONFIG))


class TempConfigMixin:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.cfg_path = base / "xray.json"
        patches = {
            "XRAY_CFG": str(self.cfg_path),
            "CUSTOM_BYPASS_FILE": str(base / "bypass.json"),
            "CONNECT_STATE_FILE": str(base / "connect.json"),
            "TRANSPARENT_STATE_FILE": str(base / "tp.json"),
            "DNS_STATE_FILE": str(base / "dns.json"),
        }
        self.patchers = [mock.patch.object(app, k, v) for k, v in patches.items()]
        for p in self.patchers:
            p.start()

    def tearDown(self):
        for p in self.patchers:
            p.stop()
        self.tmp.cleanup()

    def write_cfg(self, cfg):
        self.cfg_path.write_text(json.dumps(cfg))


class BypassTest(TempConfigMixin, unittest.TestCase):
    def test_bypass_includes_legacy_udp_dns_servers(self):
        self.write_cfg({"dns": {"servers": ["udp:223.5.5.5:53", "udp:119.29.29.29:53"]}})
        cidrs = app._tp_get_all_bypass_cidrs()
        self.assertIn("223.5.5.5/32", cidrs)
        self.assertIn("119.29.29.29/32", cidrs)

    def test_custom_bypass_rejects_shell_metacharacters(self):
        saved = app._tp_save_custom_bypass(["1.2.3.4/32; touch /tmp/pwn", "10.1.2.3", "8.8.8.0/24", "::1/128", "x"])
        self.assertEqual(saved, ["10.1.2.3/32", "8.8.8.0/24"])
        Path(app.CUSTOM_BYPASS_FILE).write_text(json.dumps(["1.1.1.1/32 -j ACCEPT", "1.0.0.1"]))
        self.assertEqual(app._tp_load_custom_bypass(), ["1.0.0.1/32"])

    def test_bypass_api_rejects_invalid_cidr(self):
        client = app.app.test_client()
        with mock.patch.object(app, "AUTH_TOKEN", ""):
            r = client.post("/api/transparent/bypass", json={"custom": ["1.2.3.4/32;id"]})
        self.assertEqual(r.status_code, 400)


class IptablesSyncTest(TempConfigMixin, unittest.TestCase):
    def test_in_sync_detects_missing_dns_bypass(self):
        self.write_cfg({"dns": {"servers": ["223.5.5.5"]}})
        bypass = app._tp_get_all_bypass_cidrs()
        live_without = [x for x in app._iptables_rule_specs(12345, bypass) if "223.5.5.5" not in x]
        live_with = app._iptables_rule_specs(12345, bypass)

        def fake_run(lines):
            def run(cmd, timeout=15):
                if " -S " in cmd:
                    return "-N XRAY_MGR_RULE\n" + "\n".join(lines) + "\n", "", 0
                return "", "", 0
            return run

        with mock.patch.object(app, "_run", fake_run(live_without)):
            self.assertFalse(app._tp_iptables_in_sync(12345))
        with mock.patch.object(app, "_run", fake_run(live_with)):
            self.assertTrue(app._tp_iptables_in_sync(12345))
        with mock.patch.object(app, "_run", fake_run(live_with)):
            self.assertFalse(app._tp_iptables_in_sync(12346))

    def test_setup_rejects_bad_port_without_running_commands(self):
        with mock.patch.object(app, "_run") as run:
            ok, msg = app._iptables_setup_redirect("12345; reboot")
        self.assertFalse(ok)
        run.assert_not_called()

    def test_connect_start_rejects_bad_port(self):
        self.write_cfg({"outbounds": [{"tag": "p", "protocol": "freedom"}]})
        client = app.app.test_client()
        with mock.patch.object(app, "AUTH_TOKEN", ""), mock.patch.object(app, "_run") as run:
            r = client.post("/api/connect/start", json={"tags": ["p"], "ports": {"transparent": "1;id"}})
        self.assertEqual(r.status_code, 400)
        run.assert_not_called()


class ReconcileTest(TempConfigMixin, unittest.TestCase):
    def _patch(self, **kw):
        base = dict(_service_status=lambda: {"running": True}, _dns_hijack_is_active=lambda: True,
                    _dns_hijack_apply=lambda: True, _ensure_dns_inbound_in_config=lambda: None)
        base.update(kw)
        return [mock.patch.object(app, k, v) for k, v in base.items()]

    def test_active_rebuilds_drifted_rules(self):
        Path(app.CONNECT_STATE_FILE).write_text(json.dumps(
            {"active": True, "transparent_enabled": True, "transparent_port": 12345}))
        setup = mock.Mock(return_value=(True, "ok"))
        ps = self._patch(_tp_has_iptables_rules=lambda: True, _tp_iptables_in_sync=lambda port: False,
                         _iptables_setup_redirect=setup)
        for p in ps:
            p.start()
        try:
            app._reconcile_connect_state()
        finally:
            for p in ps:
                p.stop()
        setup.assert_called_once_with(12345)

    def test_inactive_keeps_standalone_transparent_mode(self):
        Path(app.CONNECT_STATE_FILE).write_text(json.dumps({"active": False}))
        Path(app.TRANSPARENT_STATE_FILE).write_text(json.dumps({"enabled": True, "port": 12345}))
        cleanup = mock.Mock()
        ps = self._patch(_tp_has_iptables_rules=lambda: True, _tp_has_dokodemo_inbound=lambda: True,
                         _iptables_cleanup=cleanup, _dns_hijack_restore=mock.Mock())
        for p in ps:
            p.start()
        try:
            app._reconcile_connect_state()
        finally:
            for p in ps:
                p.stop()
        cleanup.assert_not_called()


class RoutingAndParsingTest(TempConfigMixin, unittest.TestCase):
    def test_udp_fallback_stays_last_and_single(self):
        self.write_cfg({
            "outbounds": [{"tag": "proxy", "protocol": "vless"}, {"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [
                {"type": "field", "network": "udp", "outboundTag": "direct"},
                {"type": "field", "ip": ["geoip:cn"], "outboundTag": "direct"},
                {"type": "field", "inboundTag": ["transparent"], "outboundTag": "proxy"},
            ]},
            "dns": {"servers": ["udp:223.5.5.5:53"]},
        })
        cfg, err = app._tp_add_dokodemo_to_config(12345)
        self.assertIsNone(err)
        rules = cfg["routing"]["rules"]
        fallback = {"type": "field", "network": "udp", "outboundTag": "direct"}
        self.assertEqual(rules.count(fallback), 1)
        self.assertEqual(rules[-1], fallback)
        tp_index = next(i for i, r in enumerate(rules) if r.get("inboundTag") == ["transparent"])
        self.assertLess(tp_index, len(rules) - 1)
        self.assertEqual(cfg["dns"]["servers"], ["223.5.5.5"])

    def test_vmess_link_parses(self):
        import base64
        link = "vmess://" + base64.b64encode(json.dumps(
            {"add": "example.com", "port": "443", "id": "00000000-0000-0000-0000-000000000000",
             "net": "ws", "tls": "tls", "ps": "n1"}).encode()).decode()
        ob = app._parse_share_link(link)
        self.assertEqual(ob["protocol"], "vmess")
        self.assertEqual(ob["tag"], "n1")


if __name__ == "__main__":
    unittest.main()
