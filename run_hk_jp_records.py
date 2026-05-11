#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

RULES = {
    'jp': {'record': 'jp.270376.xyz', 'countries': {'日本'}, 'cities': {'Tokyo', 'Osaka', '东京', '大阪'}},
    'hk': {'record': 'hk.270376.xyz', 'countries': {'香港'}, 'cities': {'Hong Kong', '香港'}},
}

CSV_SPECS = [
    ('3258', Path('/root/masscan-asn-runner/as3258-iptest.csv')),
    ('979', Path('/root/masscan-asn-runner/as979-iptest.csv')),
    ('906', Path('/root/masscan-asn-runner/as906-iptest.csv')),
    ('25820', Path('/root/masscan-asn-runner/as25820-iptest.csv')),
]
SCAN_SH = Path('/root/scan-asn.sh')
CF_CONFIG = Path('/root/hw_proxyip_inputs/cf-2025-270376.json')
USER_AGENT = 'Mozilla/5.0'
TARGET_COUNT = 3
TARGET_PORT = '443'
PROBE_URL = 'https://ck.batch10p.workers.dev/probe'


def parse_args(argv=None):
    p = argparse.ArgumentParser(description='Maintain hk/jp records from merged iptest rows with probe4 validation of current records.')
    p.add_argument('--geo', choices=sorted(RULES.keys()) + ['all'], default='all')
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--check-a', action='store_true')
    p.add_argument('--tg-token', default=None)
    p.add_argument('--tg-chat-id', default=None)
    return p.parse_args(argv)


def notify(text: str, tg_token: str | None, tg_chat_id: str | None) -> None:
    if not tg_token or not tg_chat_id:
        print('telegram notify skipped: missing tg token or chat id', flush=True)
        return
    data = urllib.parse.urlencode({'chat_id': tg_chat_id, 'text': text, 'disable_web_page_preview': 'true'}).encode()
    req = urllib.request.Request(
        f'https://api.telegram.org/bot{tg_token}/sendMessage',
        data=data,
        headers={'User-Agent': USER_AGENT, 'Content-Type': 'application/x-www-form-urlencoded'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            print('telegram notify response: ' + resp.read().decode('utf-8', 'replace'), flush=True)
    except Exception as e:
        body = e.read().decode('utf-8', 'replace') if hasattr(e, 'read') else ''
        print(f'telegram notify exception: {e!r}; body={body}', flush=True)


def cf_request(method, url, headers, payload=None):
    data = None
    h = dict(headers)
    if payload is not None:
        h['Content-Type'] = 'application/json'
        data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        out = json.loads(resp.read().decode())
    if not out.get('success', False):
        raise RuntimeError(out)
    return out


def ensure_csv(asn: str, path: Path) -> None:
    if path.exists() and path.stat().st_size > 0:
        return
    subprocess.run([
        str(SCAN_SH), 'start', '--asn', asn, '--ports', '443,8443', '--rate', '30k',
        '--iptest-speedtest', '0', '--workdir', '/root/masscan-asn-runner'
    ], check=True)
    while True:
        status = subprocess.run([str(SCAN_SH), 'status'], capture_output=True, text=True, check=False)
        out = (status.stdout or '') + (status.stderr or '')
        if 'not running' in out:
            break
    if not path.exists() or path.stat().st_size == 0:
        raise SystemExit(f'expected csv not generated: {path}')


def load_rows(path: Path) -> list[dict]:
    return list(csv.DictReader(path.read_text(encoding='utf-8-sig').splitlines()))


def matches_geo(row: dict, geo: str) -> bool:
    country = (row.get('出站IP位置') or '').strip()
    city = (row.get('城市') or '').strip()
    city_cn = (row.get('城市(中文)') or '').strip()
    rule = RULES[geo]
    return country in rule['countries'] and (city in rule['cities'] or city_cn in rule['cities'])


def top_for_geo(rows: list[dict], geo: str, count: int = TARGET_COUNT) -> list[dict]:
    seen, top = set(), []
    for r in rows:
        port = (r.get('端口号') or r.get('端口') or '').strip()
        if port != TARGET_PORT:
            continue
        if not matches_geo(r, geo):
            continue
        ip = (r.get('IP地址') or '').strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        top.append(r)
        if len(top) >= count:
            break
    return top


def probe_candidates(candidates: list[str]) -> dict[str, dict]:
    if not candidates:
        return {}
    payload = json.dumps({'candidates': candidates}).encode()
    req = urllib.request.Request(
        PROBE_URL,
        data=payload,
        headers={'User-Agent': USER_AGENT, 'Content-Type': 'application/json'},
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode())
    items = data if isinstance(data, list) else (data.get('results') or [])
    results = {}
    for item in items:
        results[item.get('candidate')] = item
    return results


def cf_context(cf_cfg: Path):
    cfg = json.loads(cf_cfg.read_text(encoding='utf-8'))
    headers = {'User-Agent': USER_AGENT, 'X-Auth-Email': cfg['email'], 'X-Auth-Key': cfg['globalApiKey']}
    zone_name = urllib.parse.quote(cfg['zone'])
    zone_data = cf_request('GET', 'https://api.cloudflare.com/client/v4/zones?name=' + zone_name, headers)
    zone_id = zone_data['result'][0]['id']
    return headers, zone_id


def list_record_set(cf_cfg: Path, record: str):
    headers, zone_id = cf_context(cf_cfg)
    qname = urllib.parse.quote(record)
    txt_records = cf_request('GET', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=TXT&name={qname}', headers)['result']
    a_records = cf_request('GET', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={qname}', headers)['result']
    txt_candidates = []
    if txt_records:
        txt_candidates = [x.strip() for x in txt_records[0].get('content', '').split(',') if x.strip()]
    a_ips = [r['content'].strip() for r in a_records if r.get('content')]
    return headers, zone_id, txt_records, a_records, txt_candidates, a_ips


def replace_record(cf_cfg: Path, record: str, selected_rows: list[dict]) -> dict:
    a_ips, selected = [], []
    for r in selected_rows:
        ip = (r.get('IP地址') or '').strip()
        port = (r.get('端口号') or r.get('端口') or '').strip()
        a_ips.append(ip)
        selected.append(f'{ip}:{port}')
    txt_content = ','.join(selected)

    headers, zone_id, txt_existing, a_existing, _, _ = list_record_set(cf_cfg, record)
    txt_payload = {'type': 'TXT', 'name': record, 'content': txt_content, 'ttl': 60}
    if txt_existing:
        txt_id = txt_existing[0]['id']
        cf_request('PUT', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{txt_id}', headers, txt_payload)
        for extra in txt_existing[1:]:
            cf_request('DELETE', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{extra["id"]}', headers)
    else:
        cf_request('POST', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records', headers, txt_payload)

    for rec in a_existing:
        cf_request('DELETE', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec["id"]}', headers)
    created = []
    for ip in a_ips:
        created.append(cf_request('POST', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records', headers, {'type': 'A', 'name': record, 'content': ip, 'ttl': 60, 'proxied': False})['result'])
    return {'record': record, 'txt_content': txt_content, 'a_ips': a_ips, 'record_ids': [r['id'] for r in created], 'selected': selected}


def check_and_replace(cf_cfg: Path, record: str, selected_rows: list[dict], dry_run: bool) -> dict:
    _, _, _, _, txt_candidates, a_ips = list_record_set(cf_cfg, record)
    wanted_txt = []
    wanted_a = []
    for r in selected_rows:
        ip = (r.get('IP地址') or '').strip()
        port = (r.get('端口号') or r.get('端口') or '').strip()
        wanted_txt.append(f'{ip}:{port}')
        wanted_a.append(ip)

    current_probe = probe_candidates(list(dict.fromkeys(txt_candidates + [f'{ip}:443' for ip in a_ips]))) if (txt_candidates or a_ips) else {}
    txt_valid = [cand for cand in txt_candidates if current_probe.get(cand, {}).get('ok')]
    a_valid = [ip for ip in a_ips if current_probe.get(f'{ip}:443', {}).get('ok')]
    txt_ok = len(txt_candidates) == TARGET_COUNT and txt_candidates == wanted_txt and len(txt_valid) == TARGET_COUNT
    a_ok = len(a_ips) == TARGET_COUNT and set(a_ips) == set(wanted_a) and len(a_valid) == TARGET_COUNT
    result = {
        'record': record,
        'current_txt': txt_candidates,
        'current_a': a_ips,
        'wanted_txt': wanted_txt,
        'wanted_a': wanted_a,
        'txt_valid': txt_valid,
        'a_valid': a_valid,
        'txt_ok': txt_ok,
        'a_ok': a_ok,
    }
    if not dry_run and not (txt_ok and a_ok):
        result['replaced'] = replace_record(cf_cfg, record, selected_rows)
    return result


def compact_message(results: dict, errors: dict) -> str:
    lines = []
    for geo in ['hk', 'jp']:
        if geo in errors:
            lines.append(f'{geo.upper()} maintain')
            lines.append(f"error={errors[geo].get('error')}")
            continue
        r = results.get(geo)
        if not r:
            continue
        txt = ','.join(r.get('wanted_txt', []))
        a = ','.join(r.get('wanted_a', []))
        lines.append(f'{geo.upper()} maintain')
        lines.append(f"txt_ok={r.get('txt_ok')} a_ok={r.get('a_ok')}")
        lines.append(f'txt={txt}')
        lines.append(f'a={a}')
    return '\n'.join(lines)


def main(argv=None):
    args = parse_args(argv)

    for asn, path in CSV_SPECS:
        ensure_csv(asn, path)

    combined_rows = []
    for _, path in CSV_SPECS:
        combined_rows.extend(load_rows(path))

    targets = [args.geo] if args.geo != 'all' else ['hk', 'jp']
    results = {}
    errors = {}
    for geo in targets:
        top = top_for_geo(combined_rows, geo)
        if len(top) < TARGET_COUNT:
            errors[geo] = {'error': f'not enough unique {geo.upper()} {TARGET_PORT} IPs from merged iptest rows: {len(top)}'}
            continue
        results[geo] = check_and_replace(CF_CONFIG, RULES[geo]['record'], top, args.dry_run)

    message = compact_message(results, errors)
    print(json.dumps({'results': results, 'errors': errors}, ensure_ascii=False, indent=2))
    notify(message, args.tg_token, args.tg_chat_id)
    return 0 if not errors else 1


if __name__ == '__main__':
    raise SystemExit(main())
