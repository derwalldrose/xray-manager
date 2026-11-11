#!/usr/bin/env python3
"""Static checks for xray-manager access stats feature."""
from pathlib import Path
import importlib.util

p = Path('/mnt/code/hermes/workspace/xray-manager/app.py')
s = p.read_text()
required = [
    'ACCESS_LOG_FILE',
    'ERROR_LOG_FILE',
    'IP_META_CACHE_FILE',
    '_ensure_access_log_config',
    '_build_sessions',
    '_query_team_cymru',
    '@app.route("/api/access-stats")',
    'function loadAccessStats',
    'function asInfo',
    'id="access-search"',
    '访问统计',
]
missing = [x for x in required if x not in s]
if missing:
    raise SystemExit('missing: ' + ', '.join(missing))

spec = importlib.util.spec_from_file_location('xray_manager_app', p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
old_line = '2026/06/06 12:00:01 tcp:192.168.1.10:53211 accepted tcp:google.com:443 [proxy-hk]'
rec = mod._parse_access_line(old_line)
assert rec['client'] == '192.168.1.10', rec
assert rec['target'] == 'google.com', rec
assert rec['port'] == 443, rec
assert rec['outbound'] == 'proxy-hk', rec
assert rec['route_type'] == 'proxy', rec
new_line = '2026/06/06 09:59:41.081681 from tcp:127.0.0.1:45176 accepted tcp:api.ipify.org:443 [socks-in -> ss-notls1]'
rec = mod._parse_access_line(new_line)
assert rec['time'] == '2026/06/06 09:59:41', rec
assert rec['client'] == '127.0.0.1', rec
assert rec['target'] == 'api.ipify.org', rec
assert rec['outbound'] == 'ss-notls1', rec
assert rec['route_type'] == 'proxy', rec
http_line = '2026/06/06 09:59:46.453018 from 127.0.0.1:55918 accepted //www.qq.com:443 [http-in -> direct]'
rec = mod._parse_access_line(http_line)
assert rec['client'] == '127.0.0.1', rec
assert rec['target'] == 'www.qq.com', rec
assert rec['port'] == 443, rec
assert rec['outbound'] == 'direct', rec
assert rec['route_type'] == 'direct', rec
dns_line = '2026/06/06 09:59:46.350055 from DNS accepted udp:119.29.29.29:53 [dns -> direct]'
rec = mod._parse_access_line(dns_line)
assert rec['client'] == 'DNS', rec
assert rec['network'] == 'udp', rec
assert rec['target'] == '119.29.29.29', rec
assert rec['outbound'] == 'direct', rec
answer = '2026/06/06 12:48:32.182080 [Info] app/dns: UDP:119.29.29.29:53 got answer: minorshort.weixin.qq.com. TypeA -> [223.109.215.124 117.185.24.162], rtt: 26ms'
parsed = mod._parse_dns_answer_line(answer)
assert parsed == ('minorshort.weixin.qq.com', ['223.109.215.124', '117.185.24.162']), parsed
opened = '2026/06/06 13:05:26.163036 [Info] [2794661860] proxy/freedom: connection opened to tcp:minorshort.weixin.qq.com:80, local endpoint 192.168.0.200:53070, remote endpoint 223.109.215.124:80'
parsed = mod._parse_connection_opened_line(opened)
assert parsed == ('minorshort.weixin.qq.com', ['223.109.215.124']), parsed
sniffed = '2026/06/06 13:06:36.178193 [Info] [3934350317] app/dispatcher: sniffed domain: linux.do'
parsed = mod._parse_sniffed_domain_line(sniffed)
assert parsed == {'time': '2026/06/06 13:06:36', 'id': '3934350317', 'domain': 'linux.do'}, parsed
print('access stats feature markers, parser, enrichment helpers ok')
