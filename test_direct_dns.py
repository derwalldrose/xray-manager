import unittest
from pathlib import Path

import app


class DirectDnsTest(unittest.TestCase):
    def test_dns_inbound_is_direct_mainland_udp(self):
        self.assertEqual(
            app._dns_inbound_settings(),
            {"address": "223.5.5.5", "port": 53, "network": "udp"},
        )

    def test_dnscrypt_feature_is_removed(self):
        source = Path(app.__file__).read_text()
        for marker in ("dnscrypt", "5300", "/api/dnscrypt", "loadDnscrypt"):
            self.assertNotIn(marker, source)

    def test_dns_capture_redirects_to_dns_inbound_not_transparent_port(self):
        # DNAT to 127.0.0.1 is dropped as martian for bridge/LAN sources
        # (route_localnet=0), so udp/53 is REDIRECTed to the dns inbound on :53.
        specs = app._iptables_rule_specs(12345, ["10.0.0.0/8"])
        self.assertIn("-A XRAY_MGR_RULE -p udp -m udp --dport 53 -j REDIRECT --to-ports 53", specs)
        self.assertFalse(any("127.0.0.1:53" in x for x in specs))
        self.assertFalse(any("udp" in x and "--to-ports 12345" in x for x in specs))
        source = Path(app.__file__).read_text()
        self.assertIn("is_udp_fallback", source)
        self.assertNotIn("if is_geo or is_udp_direct:", source)

    def test_inactive_start_does_not_rewrite_config(self):
        source = Path(app.__file__).read_text()
        self.assertIn("if active_expected:\n        _ensure_dns_inbound_in_config()", source)

    def test_restart_grants_fresh_recovery_window(self):
        source = Path(app.__file__).read_text()
        self.assertIn("missing_since = max(persisted_missing_since, PANEL_STARTED_AT)", source)
        self.assertIn("_iptables_cleanup()\n        _connect_state_write(state)", source)

    def test_connect_dns_is_explicit_and_restorable(self):
        source = Path(app.__file__).read_text()
        self.assertIn("_dns_hijack_backup()", source)
        self.assertIn("_dns_hijack_restore()", source)
        self.assertIn("        _dns_hijack_apply()\n        if tp_expected", source)
        localhost = source.index('f.write("nameserver 127.0.0.1\\n")')
        alidns = source.index('f.write("nameserver 223.5.5.5\\n")')
        dnspod = source.index('f.write("nameserver 119.29.29.29\\n")')
        self.assertLess(localhost, alidns)
        self.assertLess(alidns, dnspod)


if __name__ == "__main__":
    unittest.main()
