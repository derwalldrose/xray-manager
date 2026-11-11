import json
import tempfile
import unittest
from pathlib import Path

from txt_endpoints import materialize_config, parse_endpoint, resolve_endpoint


class TxtEndpointsTest(unittest.TestCase):
    def test_parse_endpoint_is_strict(self):
        self.assertEqual(parse_endpoint("192.0.2.10:10000"), ("192.0.2.10", 10000))
        self.assertEqual(parse_endpoint('"[2001:db8::1]:443"'), ("2001:db8::1", 443))
        for value in ("example.com:443", "192.0.2.1:0", "192.0.2.1:65536", "2001:db8::1:443", "v=spf1 -all"):
            self.assertIsNone(parse_endpoint(value), value)

    def test_ttl_cache_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = str(Path(tmp) / "cache.json")
            calls = []

            def query(host):
                calls.append(host)
                return ["192.0.2.10:10000"], 60

            self.assertEqual(resolve_endpoint("entry.example", cache, now=1000, query=query), ("192.0.2.10", 10000))
            self.assertEqual(resolve_endpoint("entry.example", cache, now=1059, query=query), ("192.0.2.10", 10000))
            self.assertEqual(resolve_endpoint("entry.example", cache, now=1060, query=query), ("192.0.2.10", 10000))
            self.assertEqual(calls, ["entry.example", "entry.example"])

    def test_materialize_changes_only_dial_target(self):
        source = {
            "outbounds": [{
                "tag": "txt-node",
                "protocol": "vless",
                "settings": {"vnext": [{"address": "entry.example", "port": 443, "users": [{"id": "id"}]}]},
                "streamSettings": {
                    "security": "tls",
                    "tlsSettings": {"serverName": "origin.example"},
                    "wsSettings": {"headers": {"Host": "origin.example"}, "path": "/ws"},
                },
            }],
        }

        def resolver(host, _cache_path):
            return ("192.0.2.10", 10000) if host == "entry.example" else None

        runtime, report = materialize_config(source, "/unused", resolver=resolver)
        target = runtime["outbounds"][0]
        self.assertEqual(target["settings"]["vnext"][0]["address"], "192.0.2.10")
        self.assertEqual(target["settings"]["vnext"][0]["port"], 10000)
        self.assertEqual(target["streamSettings"]["tlsSettings"]["serverName"], "origin.example")
        self.assertEqual(target["streamSettings"]["wsSettings"]["headers"]["Host"], "origin.example")
        self.assertEqual(source["outbounds"][0]["settings"]["vnext"][0]["address"], "entry.example")
        self.assertEqual(report[0]["tag"], "txt-node")

    def test_ip_and_no_txt_fall_back_unchanged(self):
        source = {"outbounds": [{"tag": "ip", "settings": {"servers": [{"address": "192.0.2.20", "port": 443}]}},
                                {"tag": "domain", "settings": {"servers": [{"address": "normal.example", "port": 8443}]}}]}
        runtime, report = materialize_config(source, "/unused", resolver=lambda _host, _cache: None)
        self.assertEqual(runtime, source)
        self.assertEqual(report, [])


if __name__ == "__main__":
    unittest.main()
