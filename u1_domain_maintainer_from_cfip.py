#!/usr/bin/env python3
from __future__ import annotations

"""
以 cfip 的 D1 数据为唯一基准，直接执行多域名维护。

功能：
1. 直接读取 Cloudflare D1 中的 cfip records 作为唯一数据源
2. 按各域名规则选择 wanted TXT/A
3. 读取当前 Cloudflare TXT/A 记录
4. 用 probe4 校验当前记录是否仍有效
5. 仅当当前记录失效或与 wanted 不一致时才更新
6. 支持 dry-run / Telegram 通知 / 输出 JSON 结果

当前已按原脚本整理出的默认规则（都可直接改 CONFIG）:

1) hk.270376.xyz
   - 参考原脚本: /root/hw_proxyip_inputs/run_hk_record.py
   - ASN 优先顺序: 3258 -> 979 -> 906 -> 25820
   - 国家/地区: 香港
   - 城市: Hong Kong / 香港
   - 仅使用端口: 443
   - TXT: 取前 3 个唯一 IP:port
   - A: 取同批前 3 个唯一 IP

2) jp.270376.xyz
   - 参考原脚本: /root/hw_proxyip_inputs/run_jp_record.py
   - ASN 优先顺序: 3258 -> 979 -> 906 -> 25820
   - 国家/地区: 日本
   - 城市: Tokyo / Osaka / 东京 / 大阪
   - 仅使用端口: 443
   - TXT: 取前 3 个唯一 IP:port
   - A: 取同批前 3 个唯一 IP

3) tw.270376.xyz
   - 参考原脚本: /root/hw_proxyip_inputs/tw-geo-maintainer.py
   - 国家/地区: 台湾
   - 城市: Taipei / Kaohsiung City / 台北 / 高雄
   - ASN: 3462
   - 仅使用端口: 443
   - TXT: 取前 3 个唯一 IP:port
   - A: 取同批前 3 个唯一 IP

4) sg.270376.xyz
   - 参考原脚本: /root/hw_proxyip_inputs/sg-geo-maintainer.py
   - 国家/地区: 新加坡
   - 城市: Singapore / 新加坡
   - ASN: 38136
   - 仅使用端口: 443
   - TXT: 取前 3 个唯一 IP:port
   - A: 取同批前 3 个唯一 IP

5) us.270376.xyz
   - 参考原脚本: /root/hw_proxyip_inputs/u1-us-maintainer.py + /root/masscan-asn-runner/u1-success-pool-iptest.csv
   - 国家/地区: 美国
   - 城市: Los Angeles / 洛杉矶
   - ASN 约束（按原成功池归纳）: 25820, 906, 979, 1054, 3257
   - ASN 优先顺序: 25820 -> 906 -> 979 -> 1054 -> 3257
   - A: 仅端口 443，取前 3 个唯一 IP
   - TXT: 优先非 443；不足时回退任意端口；取前 3 个唯一 IP:port

6) kr.270376.xyz
   - 参考原脚本: /root/hw_proxyip_inputs/kr_txt_maintainer.py + /root/masscan-asn-runner/o1-success-pool-iptest.csv
   - 出站国家要求: South Korea / Korea, Republic of / KR / 韩国
   - ASN 约束（按原成功池归纳）: 4766, 9318, 17857, 17858, 17849, 17864, 17597, 23563, 3786, 9845, 9697, 138195
   - ASN 优先顺序: 4766 -> 9318 -> 17857 -> 17858 -> 17849 -> 17864 -> 17597 -> 23563 -> 3786 -> 9845 -> 9697 -> 138195
   - TXT 目标数: 3
   - A 目标数: 3
   - A 端口规则: 10000
   - TXT 端口规则: 不限端口，但优先按输入顺序选择前 3 个成功候选

7) kr1.270376.xyz
   - 参考原脚本: /root/hw_proxyip_inputs/kr_txt_maintainer.py + run_o1_kr1_maintainer.sh
   - 出站国家要求: South Korea / Korea, Republic of / KR / 韩国
   - TXT 目标数: 3
   - A 目标数: 3
   - A 端口规则: 12345
   - TXT 端口规则: 12345
   - ASN 约束: 4766（按原 kr1 独立脚本语义保留）

支持修改:
- 直接编辑 CONFIG['domains']
- 可修改 ASN 优先级、国家/城市匹配、端口策略、目标数量
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path

ACCOUNT = '9b8556f8dc27cf344651a218c901e406'
DB_ID = '161169cf-ace5-48be-ac0c-e21a1736d822'
EMAIL = 'yonflee2025@gmail.com'
GLOBAL_KEY = '718eb09f456ca26c7f3692ef2d28fcff3816d'
URL = f'https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/d1/database/{DB_ID}/query'
HEADERS = {'X-Auth-Email': EMAIL, 'X-Auth-Key': GLOBAL_KEY, 'Content-Type': 'application/json'}
KR_COUNTRIES = {'South Korea', 'Korea, Republic of', 'KR', '韩国'}


@dataclass
class DomainRule:
    hostname: str
    countries: list[str]
    cities: list[str]
    asn_priority: list[str]
    asn_allow: list[str]
    ip_prefix_priority: list[str]
    txt_port_mode: str  # fixed | prefer_non_443 | any_ordered
    txt_port: str | None
    a_port: str | None
    txt_count: int = 3
    a_count: int = 3


CONFIG = {
    'telegram': {
        'token': '',
        'chat_id': '',
    },
    'cloudflare': {
        'zone': '270376.xyz',
        'ttl': 60,
    },
    'domains': [
        DomainRule('hk.270376.xyz', ['香港', 'HK'], ['Hong Kong', '香港'], ['4760', '906', '25820', '3258', '979'], ['4760', '906', '25820', '3258', '979'], ['1.', '219.'], 'fixed', '443', '443'),
        DomainRule('jp.270376.xyz', ['日本', 'JP'], ['Tokyo', 'Osaka', '东京', '大阪'], ['3258', '979', '906', '25820'], ['3258', '979', '906', '25820'], [], 'fixed', '443', '443'),
        DomainRule('tw.270376.xyz', ['台湾', 'TW'], ['Taipei', 'Kaohsiung City', '台北', '高雄'], ['3462'], ['3462'], [], 'fixed', '443', '443'),
        DomainRule('sg.270376.xyz', ['新加坡', 'SG'], ['Singapore', '新加坡'], ['38136'], ['38136'], [], 'fixed', '443', '443'),
        DomainRule('us.270376.xyz', ['美国', 'US'], ['Los Angeles', '洛杉矶'], ['906', '979', '1054', '3257', '6233', '967', '213136', '25820'], ['25820', '906', '979', '1054', '3257', '6233', '967', '213136'], [], 'prefer_non_443', None, '443'),
        DomainRule('kr.270376.xyz', list(KR_COUNTRIES), [], ['4766', '9318', '17857', '17858', '17849', '17864', '17597', '23563', '3786', '9845', '9697', '138195'], ['4766', '9318', '17857', '17858', '17849', '17864', '17597', '23563', '3786', '9845', '9697', '138195'], [], 'any_ordered', None, '10000'),
        DomainRule('kr1.270376.xyz', list(KR_COUNTRIES), [], ['4766'], ['4766'], [], 'fixed', '12345', '12345'),
    ]
}


def d1_query(sql: str) -> list[dict]:
    req = urllib.request.Request(URL, data=json.dumps({'sql': sql}).encode(), headers=HEADERS, method='POST')
    with urllib.request.urlopen(req, timeout=600) as resp:
        data = json.loads(resp.read().decode('utf-8', 'replace'))
    if data.get('errors'):
        raise RuntimeError(data['errors'])
    result = data.get('result') or []
    if not result:
        return []
    return result[0].get('results') or []


def fetch_rows() -> list[dict]:
    sql = 'SELECT * FROM records ORDER BY updated_at DESC LIMIT 15000'
    return d1_query(sql)


def norm(v: str | None) -> str:
    return (v or '').strip()


def row_country(row: dict) -> str:
    return norm(row.get('exit_location') or row.get('ip_location') or '')


def row_city_values(row: dict) -> list[str]:
    return [norm(row.get('city')), norm(row.get('city_zh')), norm(row.get('region')), norm(row.get('region_zh'))]


def row_ip(row: dict) -> str:
    return norm(row.get('ip'))


def row_port(row: dict) -> str:
    return norm(row.get('port'))


def row_asn(row: dict) -> str:
    return norm(row.get('asn'))


def row_ip_port(row: dict) -> str:
    return f"{row_ip(row)}:{row_port(row)}"


def matches_geo(row: dict, rule: DomainRule) -> bool:
    country = row_country(row)
    if rule.countries and country not in rule.countries:
        return False
    if rule.cities:
        row_cities = set(v for v in row_city_values(row) if v)
        if not any(city in row_cities for city in rule.cities):
            return False
    return True


def matches_asn(row: dict, rule: DomainRule) -> bool:
    if not rule.asn_allow:
        return True
    return row_asn(row) in set(rule.asn_allow)


def ip_prefix_rank(ip: str, prefixes: list[str]) -> int:
    for i, prefix in enumerate(prefixes or []):
        if ip.startswith(prefix):
            return i
    return 999


def sort_rows_for_rule(rows: list[dict], rule: DomainRule) -> list[dict]:
    asn_rank = {asn: i for i, asn in enumerate(rule.asn_priority)}
    asn_fallback = len(asn_rank) + 100
    return sorted(rows, key=lambda r: (ip_prefix_rank(row_ip(r), rule.ip_prefix_priority), asn_rank.get(row_asn(r), asn_fallback)))


def unique_ip_ports(rows: list[dict], count: int, port: str | None = None) -> list[str]:
    seen = set()
    out = []
    for row in rows:
        if port is not None and row_port(row) != port:
            continue
        ip = row_ip(row)
        rp = row_port(row)
        item = f'{ip}:{rp}'
        if not ip or not rp or item in seen:
            continue
        seen.add(item)
        out.append(item)
        if len(out) >= count:
            break
    return out


def unique_ips_from_candidates(candidates: list[str], count: int) -> list[str]:
    seen = set()
    out = []
    for cand in candidates:
        ip = cand.split(':', 1)[0]
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
        if len(out) >= count:
            break
    return out


class TelegramNotifier:
    def __init__(self, token: str = '', chat_id: str = ''):
        self.token = token or ''
        self.chat_id = chat_id or ''

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def send(self, text: str) -> None:
        if not self.enabled:
            return
        data = urllib.parse.urlencode({'chat_id': self.chat_id, 'text': text, 'disable_web_page_preview': 'true'}).encode()
        req = urllib.request.Request(
            f'https://api.telegram.org/bot{self.token}/sendMessage',
            data=data,
            headers={'User-Agent': 'cfip-domain-maintainer/1.0', 'Content-Type': 'application/x-www-form-urlencoded'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read().decode('utf-8', 'replace'))
        if not body.get('ok'):
            raise RuntimeError(body)


class CloudflareClient:
    def __init__(self, email: str, global_api_key: str, zone: str, ttl: int = 60):
        self.email = email
        self.global_api_key = global_api_key
        self.zone_name = zone
        self.ttl = ttl
        self.base = 'https://api.cloudflare.com/client/v4'
        self.zone_id = self._get_zone_id(zone)

    def _headers(self) -> dict[str, str]:
        return {
            'X-Auth-Email': self.email,
            'X-Auth-Key': self.global_api_key,
            'Content-Type': 'application/json',
            'User-Agent': 'cfip-domain-maintainer/1.0',
        }

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(self.base + path, data=data, headers=self._headers(), method=method)
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode('utf-8', 'replace'))
        if not body.get('success'):
            raise RuntimeError(body)
        return body

    def _get_zone_id(self, zone_name: str) -> str:
        body = self._request('GET', f'/zones?name={urllib.parse.quote(zone_name)}')
        result = body.get('result') or []
        if not result:
            raise RuntimeError(f'zone not found: {zone_name}')
        return result[0]['id']

    def list_records(self, name: str, record_type: str) -> list[dict]:
        body = self._request('GET', f'/zones/{self.zone_id}/dns_records?type={record_type}&name={urllib.parse.quote(name)}')
        return body.get('result') or []

    def delete_record(self, record_id: str) -> None:
        self._request('DELETE', f'/zones/{self.zone_id}/dns_records/{record_id}')

    def create_record(self, name: str, record_type: str, content: str) -> None:
        self._request('POST', f'/zones/{self.zone_id}/dns_records', {
            'type': record_type,
            'name': name,
            'content': content,
            'ttl': self.ttl,
            'proxied': False if record_type == 'A' else None,
        })

    def replace_txt(self, name: str, values: list[str]) -> None:
        current = self.list_records(name, 'TXT')
        for rec in current:
            self.delete_record(rec['id'])
        for value in values:
            self.create_record(name, 'TXT', value)

    def replace_a(self, name: str, values: list[str]) -> None:
        current = self.list_records(name, 'A')
        for rec in current:
            self.delete_record(rec['id'])
        for value in values:
            self.create_record(name, 'A', value)


def select_for_rule(rows: list[dict], rule: DomainRule) -> dict:
    matched = [row for row in rows if matches_geo(row, rule) and matches_asn(row, rule)]
    ordered = sort_rows_for_rule(matched, rule)

    if rule.txt_port_mode == 'fixed':
        txt_candidates = unique_ip_ports(ordered, rule.txt_count, rule.txt_port)
    elif rule.txt_port_mode == 'prefer_non_443':
        txt_candidates = unique_ip_ports([r for r in ordered if row_port(r) != '443'], rule.txt_count)
        if len(txt_candidates) < rule.txt_count:
            seen = set(txt_candidates)
            for cand in unique_ip_ports(ordered, rule.txt_count * 10):
                if cand not in seen:
                    txt_candidates.append(cand)
                    seen.add(cand)
                if len(txt_candidates) >= rule.txt_count:
                    break
    else:
        txt_candidates = unique_ip_ports(ordered, rule.txt_count)

    if rule.a_port:
        a_source = [cand for cand in txt_candidates if cand.endswith(':' + rule.a_port)]
        if len(a_source) < rule.a_count:
            extra = unique_ip_ports(ordered, rule.a_count * 20, rule.a_port)
            seen = set(a_source)
            for cand in extra:
                if cand not in seen:
                    a_source.append(cand)
                    seen.add(cand)
                if len(a_source) >= rule.a_count * 5:
                    break
    else:
        a_source = txt_candidates[:]

    a_candidates = unique_ips_from_candidates(a_source, rule.a_count)
    return {
        'hostname': rule.hostname,
        'rule': asdict(rule),
        'matched_rows': len(matched),
        'txt_selected': txt_candidates,
        'a_selected': a_candidates,
    }


def probe_candidates(candidates: list[str]) -> dict[str, dict]:
    if not candidates:
        return {}
    req = urllib.request.Request(
        'https://ck.batch10p.workers.dev/probe',
        data=json.dumps({'candidates': candidates}).encode(),
        headers={'Content-Type': 'application/json', 'User-Agent': 'cfip-domain-maintainer/1.0'},
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=600) as resp:
        body = json.loads(resp.read().decode('utf-8', 'replace'))
    if isinstance(body, list):
        items = body
    else:
        items = body.get('results') or []
    normalized = {}
    for item in items:
        if isinstance(item, dict) and item.get('candidate'):
            normalized[item['candidate']] = item
    for cand in candidates:
        normalized.setdefault(cand, {'ok': False, 'raw': None})
    return normalized


def filter_valid_wanted(selection: dict, batch_size: int = 200) -> dict:
    txt_selected = selection['txt_selected']
    txt_probe_results = {}
    txt_valid = []
    txt_probe_count = 0
    for i in range(0, len(txt_selected), batch_size):
        batch = txt_selected[i:i + batch_size]
        txt_probe_count += len(batch)
        result = probe_candidates(batch)
        txt_probe_results.update(result)
        for cand in batch:
            if result.get(cand, {}).get('ok'):
                txt_valid.append(cand)
    txt_valid = txt_valid[:selection['rule']['txt_count']]

    a_port = selection['rule']['a_port']
    a_candidates_raw = selection['a_selected']
    a_probe_input = [f'{ip}:{a_port}' if a_port else ip for ip in a_candidates_raw]
    a_probe_results = {}
    a_valid = []
    a_probe_count = 0
    for i in range(0, len(a_probe_input), batch_size):
        batch = a_probe_input[i:i + batch_size]
        a_probe_count += len(batch)
        result = probe_candidates(batch)
        a_probe_results.update(result)
        for item in batch:
            if result.get(item, {}).get('ok'):
                a_valid.append(item.split(':', 1)[0])
    seen_ip = set()
    a_valid_unique = []
    for ip in a_valid:
        if ip in seen_ip:
            continue
        seen_ip.add(ip)
        a_valid_unique.append(ip)
        if len(a_valid_unique) >= selection['rule']['a_count']:
            break

    return {
        'hostname': selection['hostname'],
        'txt_selected': txt_valid,
        'a_selected': a_valid_unique,
        'txt_probe_results': txt_probe_results,
        'a_probe_results': a_probe_results,
        'candidate_txt_probe_count': txt_probe_count,
        'candidate_a_probe_count': a_probe_count,
        'rule': selection['rule'],
        'matched_rows': selection.get('matched_rows', 0),
    }


def current_txt_contents(cf: CloudflareClient, name: str) -> list[str]:
    records = cf.list_records(name, 'TXT')
    out = []
    seen = set()
    for rec in records:
        content = str(rec.get('content', '')).strip()
        if not content:
            continue
        parts = [part.strip() for part in content.split(',') if part.strip()]
        for part in parts:
            if part in seen:
                continue
            seen.add(part)
            out.append(part)
    return out


def current_a_contents(cf: CloudflareClient, name: str) -> list[str]:
    records = cf.list_records(name, 'A')
    return [str(rec.get('content', '')) for rec in records]


def check_current_state(cf: CloudflareClient, selection: dict) -> dict:
    current_txt = current_txt_contents(cf, selection['hostname'])
    current_a = current_a_contents(cf, selection['hostname'])
    wanted_txt = selection['txt_selected']
    wanted_a = selection['a_selected']
    a_probe_port = selection['rule']['a_port'] or '443'
    txt_probe = probe_candidates(current_txt)
    a_probe_input = [f'{ip}:{a_probe_port}' for ip in current_a]
    a_probe = probe_candidates(a_probe_input)
    txt_valid = [cand for cand in current_txt if txt_probe.get(cand, {}).get('ok')]
    a_valid = [ip for ip in current_a if a_probe.get(f'{ip}:{a_probe_port}', {}).get('ok')]
    txt_ok = len(current_txt) == len(wanted_txt) and set(current_txt) == set(wanted_txt) and len(txt_valid) == len(wanted_txt)
    a_ok = len(current_a) == len(wanted_a) and set(current_a) == set(wanted_a) and len(a_valid) == len(wanted_a)
    return {
        'current_txt': current_txt,
        'current_a': current_a,
        'txt_ok': txt_ok,
        'a_ok': a_ok,
        'probe_count': len(txt_probe) + len(a_probe),
        'txt_probe_results': txt_probe,
        'a_probe_results': a_probe,
    }


def apply_updates(cf: CloudflareClient, selection: dict, current: dict, dry_run: bool) -> dict:
    updated = {
        'txt_updated': False,
        'a_updated': False,
        'txt_deleted_first': False,
        'a_deleted_first': False,
    }
    if dry_run:
        return updated

    need_fix_txt = (not current['txt_ok']) or any(not item.get('ok') for item in current.get('txt_probe_results', {}).values())
    need_fix_a = (not current['current_a']) or any(not item.get('ok') for item in current.get('a_probe_results', {}).values())

    if need_fix_txt:
        if len(selection['txt_selected']) < selection['rule']['txt_count']:
            updated['txt_skipped_reason'] = 'not enough probe-validated wanted TXT candidates'
        else:
            cf.replace_txt(selection['hostname'], selection['txt_selected'])
            updated['txt_updated'] = True

    if need_fix_a:
        cf.replace_a(selection['hostname'], [])
        updated['a_deleted_first'] = True
        if len(selection['a_selected']) < selection['rule']['a_count']:
            updated['a_skipped_reason'] = 'not enough probe-validated wanted A candidates'
        else:
            cf.replace_a(selection['hostname'], selection['a_selected'])
            updated['a_updated'] = True

    return updated


def format_notify(entry: dict) -> str:
    txt_lines = entry['selection']['txt_selected'] or ['(empty)']
    a_lines = entry['selection']['a_selected'] or ['(empty)']
    txt_block = ['txt=' + txt_lines[0], *txt_lines[1:]]
    a_block = ['a=' + a_lines[0], *a_lines[1:]]

    txt_probe_bad = [cand for cand, info in (entry['current'].get('txt_probe_results') or {}).items() if not info.get('ok')]
    a_probe_bad = [cand for cand, info in (entry['current'].get('a_probe_results') or {}).items() if not info.get('ok')]
    txt_missing = [cand for cand in txt_lines if cand not in (entry['current'].get('current_txt') or [])]
    a_missing = [ip for ip in a_lines if ip not in (entry['current'].get('current_a') or [])]
    probe_false_block = []
    if txt_probe_bad:
        probe_false_block.append('txt_probe_false=' + txt_probe_bad[0])
        probe_false_block.extend(txt_probe_bad[1:])
    if a_probe_bad:
        probe_false_block.append('a_probe_false=' + a_probe_bad[0])
        probe_false_block.extend(a_probe_bad[1:])
    if txt_missing:
        probe_false_block.append('txt_current_missing=' + txt_missing[0])
        probe_false_block.extend(txt_missing[1:])
    if a_missing:
        probe_false_block.append('a_current_missing=' + a_missing[0])
        probe_false_block.extend(a_missing[1:])

    return '\n'.join([
        f"{entry['hostname']} maintain",
        f"txt_ok={entry['current']['txt_ok']} a_ok={entry['current']['a_ok']}",
        'current_txt=' + (', '.join(entry['current'].get('current_txt') or ['(empty)'])),
        'current_a=' + (', '.join(entry['current'].get('current_a') or ['(empty)'])),
        *txt_block,
        *a_block,
        *probe_false_block,
    ])


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Maintain multiple domain records directly from cfip D1 data')
    p.add_argument('--dump-json', default='')
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--tg-token', default=CONFIG['telegram']['token'])
    p.add_argument('--tg-chat-id', default=CONFIG['telegram']['chat_id'])
    return p.parse_args()


def main() -> int:
    args = parse_args()
    rows = fetch_rows()
    notifier = TelegramNotifier(args.tg_token, args.tg_chat_id)
    cf = CloudflareClient(email=EMAIL, global_api_key=GLOBAL_KEY, zone=CONFIG['cloudflare']['zone'], ttl=CONFIG['cloudflare']['ttl'])
    entries = []
    for rule in CONFIG['domains']:
        selection = select_for_rule(rows, rule)
        selection = filter_valid_wanted(selection)
        current = check_current_state(cf, selection)
        updated = apply_updates(cf, selection, current, args.dry_run)
        entry = {
            'hostname': rule.hostname,
            'selection': selection,
            'current': current,
            'updated': updated,
        }
        entries.append(entry)
        try:
            notifier.send(format_notify(entry))
        except Exception as e:
            entry['notify_error'] = repr(e)

    result = {
        'success': True,
        'source': 'cloudflare-d1-direct',
        'dry_run': args.dry_run,
        'row_count': len(rows),
        'domains': entries,
    }
    if args.dump_json:
        out = Path(args.dump_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('Interrupted', file=sys.stderr)
        raise SystemExit(130)
