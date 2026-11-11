import base64
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

        gw = mock.patch.object(app, "_gateway_in_sync", return_value=True)
        gw.start(); self.addCleanup(gw.stop)
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
    def test_ensure_dns_inbound_is_idempotent(self):
        self.write_cfg({"outbounds": [{"tag": "proxy", "protocol": "vless"}], "routing": {"rules": [
            {"type": "field", "inboundTag": ["socks-in"], "outboundTag": "proxy"}]}})
        with mock.patch.object(app, "_test_config", return_value={"ok": True}), \
                mock.patch.object(app, "_backup_config", return_value=""):
            with mock.patch.object(app, "_save_config_object", wraps=app._save_config_object) as save:
                app._ensure_dns_inbound_in_config()
                self.assertEqual(save.call_count, 1)
                app._ensure_dns_inbound_in_config()
                self.assertEqual(save.call_count, 1)

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



class ShareLinkParseTest(unittest.TestCase):
    def test_vless_xhttp_ech_extra(self):
        extra = {"xPaddingBytes": "100-1000", "xmux": {"maxConnections": 3}}
        from urllib.parse import quote
        link = ("vless://00000000-0000-0000-0000-000000000001@a.example.com:443?encryption=none&security=tls"
                "&sni=s.example.com&fp=chrome&alpn=h2&ech=" + quote("cloudflare-ech.com+https://dns.alidns.com/dns-query", safe="")
                + "&type=xhttp&host=h.example.com&path=%2Fx&mode=stream-one&extra=" + quote(json.dumps(extra), safe="") + "#n1")
        ob = app._parse_share_link(link)
        ss = ob["streamSettings"]
        self.assertEqual(ss["network"], "xhttp")
        self.assertEqual(ss["xhttpSettings"], {"path": "/x", "host": "h.example.com", "mode": "stream-one", "extra": extra})
        self.assertEqual(ss["tlsSettings"]["echConfigList"], "cloudflare-ech.com+https://dns.alidns.com/dns-query")
        self.assertEqual(ss["tlsSettings"]["alpn"], ["h2"])

    def test_unencoded_plus_in_ech_is_kept(self):
        ob = app._parse_share_link("vless://u@a.com:443?security=tls&ech=cloudflare-ech.com+https://1.1.1.1/dns-query&type=ws&host=a.com#x")
        self.assertEqual(ob["streamSettings"]["tlsSettings"]["echConfigList"], "cloudflare-ech.com+https://1.1.1.1/dns-query")
        self.assertEqual(ob["streamSettings"]["wsSettings"], {"path": "/", "host": "a.com"})

    def test_reality_and_grpc_multi(self):
        ob = app._parse_share_link("vless://u@1.2.3.4:443?security=reality&sni=www.apple.com&fp=safari&pbk=PUB&sid=ab12&spx=%2F"
                                   "&type=grpc&serviceName=svc&mode=multi&flow=xtls-rprx-vision#r")
        ss = ob["streamSettings"]
        self.assertEqual(ss["realitySettings"], {"serverName": "www.apple.com", "fingerprint": "safari", "publicKey": "PUB",
                                                 "shortId": "ab12", "spiderX": "/"})
        self.assertEqual(ss["grpcSettings"], {"serviceName": "svc", "multiMode": True})
        self.assertEqual(ob["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")

    def test_ss_v2ray_plugin_path_with_escapes(self):
        from urllib.parse import quote
        plugin = "v2ray-plugin;mode=websocket;tls;host=w.example.com;path=/?enc\\=aes-128-gcm&proxyip\\=p.example.com"
        user = base64.urlsafe_b64encode(b"aes-128-gcm:p@ss/w+rd").decode().rstrip("=")
        ob = app._parse_share_link(f"ss://{user}@1.2.3.4:8880/?plugin={quote(plugin, safe='')}#s")
        srv = ob["settings"]["servers"][0]
        self.assertEqual((srv["method"], srv["password"]), ("aes-128-gcm", "p@ss/w+rd"))
        self.assertEqual(ob["streamSettings"]["wsSettings"], {"host": "w.example.com", "path": "/?enc=aes-128-gcm&proxyip=p.example.com"})
        self.assertEqual(ob["streamSettings"]["security"], "tls")


class CustomRulesTest(TempConfigMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        p = mock.patch.object(app, "CUSTOM_RULES_FILE", str(Path(self.tmp.name) / "rules.json"))
        p.start(); self.patchers.append(p)

    def test_normalize(self):
        r, err = app._normalize_user_rule({"domain": "openai.com, geosite:google", "outboundTag": "__proxy__", "remark": "ai"})
        self.assertIsNone(err)
        self.assertEqual(r["domain"], ["domain:openai.com", "geosite:google"])
        self.assertEqual(app._normalize_user_rule({"ip": ["1.2.3.4;id"], "outboundTag": "direct"})[1], "invalid IP/CIDR: 1.2.3.4;id")
        self.assertIsNotNone(app._normalize_user_rule({"outboundTag": "direct"})[1])
        self.assertIsNotNone(app._normalize_user_rule({"port": "443;x", "outboundTag": "direct"})[1])

    def test_user_rules_go_before_geo_and_catch_all_and_survive_reconnect(self):
        self.write_cfg({"outbounds": [{"tag": "n1", "protocol": "vless"}, {"tag": "n2", "protocol": "vless"},
                                      {"tag": "direct", "protocol": "freedom"}], "routing": {"rules": []}})
        app._custom_rules_save([
            {"type": "field", "domain": ["domain:openai.com"], "outboundTag": "__proxy__"},
            {"type": "field", "ip": ["10.9.0.0/16"], "outboundTag": "direct"},
            {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
            {"type": "field", "domain": ["domain:x.com"], "outboundTag": "deleted-node"},
        ])
        for tags, want in ((["n2"], ("outboundTag", "n2")), (["n1", "n2"], ("balancerTag", "proxy-balancer"))):
            cfg, err = app._build_connect_config(tags, "roundRobin", True, {"socks": 1, "http": 2, "transparent": 3})
            self.assertIsNone(err)
            rules = cfg["routing"]["rules"]
            user = [i for i, r in enumerate(rules) if str(r.get("ruleTag", "")).startswith("user:")]
            self.assertEqual(len(user), 3)  # rule for a deleted node is skipped
            geo = next(i for i, r in enumerate(rules) if r.get("ip") == ["geoip:cn"])
            catch_all = next(i for i, r in enumerate(rules) if r.get("inboundTag") == ["transparent"])
            self.assertLess(max(user), geo)
            self.assertLess(max(user), catch_all)
            self.assertEqual(rules[0]["inboundTag"], ["dns"])
            self.assertEqual(rules[user[0]].get(want[0]), want[1])
            self.assertTrue(any(o["tag"] == "block" for o in cfg["outbounds"]))

    def test_transparent_builder_keeps_user_rules_in_front(self):
        self.write_cfg({"outbounds": [{"tag": "n1", "protocol": "vless"}, {"tag": "direct", "protocol": "freedom"}],
                        "routing": {"rules": [{"type": "field", "ruleTag": "user:1", "domain": ["domain:old.com"], "outboundTag": "direct"}]}})
        app._custom_rules_save([{"type": "field", "domain": ["domain:new.com"], "outboundTag": "direct"}])
        cfg, err = app._tp_add_dokodemo_to_config(12345)
        self.assertIsNone(err)
        rules = cfg["routing"]["rules"]
        doms = [r.get("domain") for r in rules if str(r.get("ruleTag", "")).startswith("user:")]
        self.assertEqual(doms, [["domain:new.com"]])
        tp = next(i for i, r in enumerate(rules) if r.get("inboundTag") == ["transparent"])
        self.assertLess(next(i for i, r in enumerate(rules) if r.get("domain") == ["domain:new.com"]), tp)


class GatewayTest(unittest.TestCase):
    IP_OUT = """1: lo    inet 127.0.0.1/8 scope host lo
2: ens3    inet 172.21.2.67/24 brd 172.21.2.255 scope global ens3
3: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0
4: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
5: br-9eca    inet 172.28.0.1/16 scope global br-9eca
6: wg0    inet 10.8.0.1/24 scope global wg0
"""

    def fake_run(self, nft_forward="", docker_user=False):
        def run(cmd, timeout=15):
            if cmd.startswith("ip -4 -o addr"):
                return self.IP_OUT, "", 0
            if cmd.startswith("iptables-nft -S FORWARD"):
                return (nft_forward, "", 0) if nft_forward else ("", "", 1)
            if cmd.startswith("iptables-nft -S DOCKER-USER"):
                return ("-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n", "", 0) if docker_user else ("", "", 1)
            return "", "", 0
        return run

    def test_lan_detection_by_interface_name(self):
        with mock.patch.object(app, "_run", self.fake_run()):
            self.assertEqual(app._lan_cidrs(), ["172.21.2.0/24", "192.168.1.0/24"])

    def test_rules_cover_masquerade_quic_redirects_and_nft_drop(self):
        with mock.patch.object(app, "_run", self.fake_run("-P FORWARD DROP\n-A FORWARD -j DOCKER-USER\n", True)):
            rules = app._gateway_rules()
        specs = [f"{b} {t} {s}" for b, t, s in rules]
        self.assertIn("iptables nat -A POSTROUTING -s 192.168.1.0/24 ! -o lo -m comment --comment xray-mgr-gw -j MASQUERADE", specs)
        quic = app._iptables_rule_specs(12345, ["192.168.0.0/16"])
        self.assertEqual(quic[-1], "-A XRAY_MGR_RULE -p udp -m udp --dport 443 -j REDIRECT --to-ports 9")
        self.assertLess(quic.index("-A XRAY_MGR_RULE -d 192.168.0.0/16 -j RETURN"), len(quic) - 1)
        self.assertTrue(any(x.startswith("iptables-nft filter -I DOCKER-USER -s 192.168.1.0/24") for x in specs))
        self.assertFalse(any("172.17." in x or "172.28." in x or "10.8.0." in x for x in specs))
        self.assertTrue(all("xray-mgr-gw" in x for x in specs))

    def test_no_nft_rules_when_nft_forward_accepts(self):
        with mock.patch.object(app, "_run", self.fake_run("-P FORWARD ACCEPT\n")):
            self.assertFalse(any(b == "iptables-nft" for b, _, _ in app._gateway_rules()))



class HousekeepingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        (base / "backup").mkdir(); (base / "config").mkdir()
        self.cfg = base / "config" / "x.json"; self.cfg.write_text("{}")
        self.ps = [mock.patch.object(app, "BASE_DIR", str(base)), mock.patch.object(app, "XRAY_CFG", str(self.cfg)),
                   mock.patch.object(app, "XRAY_LOG_FILE", str(base / "xray.log"))]
        for p in self.ps: p.start()
        self.base = base

    def tearDown(self):
        for p in self.ps: p.stop()
        self.tmp.cleanup()

    def test_backups_pruned_to_newest_three(self):
        import os
        for i in range(6):
            f = self.base / "backup" / f"config-2026010{i}_000000.json.bak"; f.write_text(str(i)); os.utime(f, (1000 + i, 1000 + i))
        newest = app._backup_config()
        left = sorted(p.name for p in (self.base / "backup").glob("config-*.json.bak"))
        self.assertEqual(len(left), 3)
        self.assertIn(Path(newest).name, left)
        self.assertNotIn("config-20260100_000000.json.bak", left)
        self.assertEqual((self.base / "backup" / Path(newest).name).read_text(), "{}")

    def test_access_window_reads_rotated_file(self):
        old = "2026/11/11 01:00:00.1 [Info] [11] app/dispatcher: sniffed domain: old.example.com\n"
        new = "2026/11/11 03:00:00.1 [Info] [22] app/dispatcher: sniffed domain: new.example.com\n"
        (self.base / "xray.log.1").write_text(old)
        (self.base / "xray.log").write_text(new)
        from datetime import datetime as dt
        both = app._read_log_window(dt(2026, 11, 11, 0, 30))
        self.assertEqual(both, [old, new])
        only_new = app._read_log_window(dt(2026, 11, 11, 2, 30, 0).replace(hour=3, minute=0, second=0))
        self.assertEqual(only_new, [new])


if __name__ == "__main__":
    unittest.main()
