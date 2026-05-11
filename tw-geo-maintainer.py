#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

USER_AGENT = 'Mozilla/5.0'
TARGET_COUNT = 3
TARGET_PORT = '443'
PROBE_URL = 'https://ck.batch10p.workers.dev/probe'


def log(msg: str) -> None:
    print(msg, flush=True)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8'))


def save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


def load_pool(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def save_pool(path: Path, candidates: list[str]) -> None:
    unique = list(dict.fromkeys(candidates))
    path.write_text('\n'.join(unique) + ('\n' if unique else ''), encoding='utf-8')


def unique_ip_count(candidates: list[str]) -> int:
    return len({cand.split(':', 1)[0] for cand in candidates if ':' in cand})


def backup_pool_with_timestamp(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_name(f"{path.stem}.bak-{time.strftime('%Y%m%d-%H%M%S')}{path.suffix}")
    backup.write_text(path.read_text(encoding='utf-8'), encoding='utf-8')
    return backup


class TelegramNotifier:
    def __init__(self, *, token: str | None, chat_id: str | None):
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
            headers={'User-Agent': USER_AGENT, 'Content-Type': 'application/x-www-form-urlencoded'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = resp.read().decode('utf-8', 'replace')
            parsed = json.loads(body)
            if not parsed.get('ok', False):
                log(f'telegram notify failed: {parsed}')
            else:
                log(f'telegram notify response: {body}')
        except Exception as e:
            log(f'telegram notify exception: {e!r}')


class CloudflareClient:
    def __init__(self, *, email: str, global_api_key: str):
        self.email = email
        self.global_api_key = global_api_key

    def _request(self, method: str, url: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {'User-Agent': USER_AGENT, 'X-Auth-Email': self.email, 'X-Auth-Key': self.global_api_key}
        data = None
        if payload is not None:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode('utf-8', 'replace')
        parsed = json.loads(body)
        if not parsed.get('success', False):
            raise RuntimeError(f'Cloudflare API failed: {parsed}')
        return parsed

    def get_zone_id(self, zone_name: str) -> str:
        q = urllib.parse.quote(zone_name)
        data = self._request('GET', f'https://api.cloudflare.com/client/v4/zones?name={q}')
        results = data.get('result') or []
        if not results:
            raise RuntimeError(f'zone not found: {zone_name}')
        return results[0]['id']

    def list_txt_records(self, zone_id: str, name: str) -> list[dict[str, Any]]:
        qname = urllib.parse.quote(name)
        data = self._request('GET', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=TXT&name={qname}')
        return data.get('result') or []

    def list_a_records(self, zone_id: str, name: str) -> list[dict[str, Any]]:
        qname = urllib.parse.quote(name)
        data = self._request('GET', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={qname}')
        return data.get('result') or []

    def upsert_single_txt_record(self, zone_id: str, name: str, content: str, ttl: int = 60) -> dict[str, Any]:
        existing = self.list_txt_records(zone_id, name)
        payload = {'type': 'TXT', 'name': name, 'content': content, 'ttl': ttl}
        if existing:
            primary = existing[0]
            data = self._request('PUT', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{primary["id"]}', payload)
            for extra in existing[1:]:
                self._request('DELETE', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{extra["id"]}')
            return data['result']
        data = self._request('POST', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records', payload)
        return data['result']

    def replace_a_records(self, zone_id: str, name: str, ips: list[str], ttl: int = 60) -> list[dict[str, Any]]:
        existing = self.list_a_records(zone_id, name)
        for rec in existing:
            self._request('DELETE', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec["id"]}')
        created = []
        for ip in ips:
            data = self._request('POST', f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records', {
                'type': 'A', 'name': name, 'content': ip, 'ttl': ttl, 'proxied': False
            })
            created.append(data['result'])
        return created


def probe_candidates(candidates: list[str]) -> dict[str, dict[str, Any]]:
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
    return {item.get('candidate'): item for item in items}


def write_results(prefix: Path, results: list[dict[str, Any]]) -> dict[str, Any]:
    prefix.parent.mkdir(parents=True, exist_ok=True)
    summary_path = prefix.with_suffix('.summary.json')
    final = {
        'tested_candidates': len(results),
        'ok_total': sum(1 for r in results if r.get('ok')),
        'timestamp': int(time.time()),
        'candidates': [r.get('candidate') for r in results],
    }
    save_json(summary_path, final)
    return final


def current_a_candidates(cf: CloudflareClient, zone: str, record_name: str) -> list[str]:
    zone_id = cf.get_zone_id(zone)
    recs = cf.list_a_records(zone_id, record_name)
    return [rec['content'].strip() for rec in recs if rec.get('content')]


def current_txt_candidates(cf: CloudflareClient, zone: str, record_name: str) -> list[str]:
    zone_id = cf.get_zone_id(zone)
    records = cf.list_txt_records(zone_id, record_name)
    if not records:
        return []
    return [part.strip() for part in records[0].get('content', '').split(',') if part.strip()]


def select_from_pool(pool: list[str], target_count: int) -> tuple[list[str], list[str]]:
    selected_txt: list[str] = []
    selected_a: list[str] = []
    seen_ips: set[str] = set()
    for cand in pool:
        if ':' not in cand:
            continue
        ip, port = cand.rsplit(':', 1)
        if port != TARGET_PORT:
            continue
        if cand not in selected_txt and len(selected_txt) < target_count:
            selected_txt.append(cand)
        if ip not in seen_ips and len(selected_a) < target_count:
            seen_ips.add(ip)
            selected_a.append(ip)
        if len(selected_txt) >= target_count and len(selected_a) >= target_count:
            break
    return selected_txt, selected_a


def ensure_txt_updated(cf: CloudflareClient, zone: str, record_name: str, selected: list[str]) -> dict[str, Any]:
    zone_id = cf.get_zone_id(zone)
    content = ','.join(selected)
    result = cf.upsert_single_txt_record(zone_id, record_name, content, ttl=60)
    return {'zone_id': zone_id, 'content': content, 'record_id': result['id']}


def ensure_a_updated(cf: CloudflareClient, zone: str, record_name: str, ips: list[str]) -> dict[str, Any]:
    zone_id = cf.get_zone_id(zone)
    records = cf.replace_a_records(zone_id, record_name, ips, ttl=60)
    return {'zone_id': zone_id, 'ips': ips, 'record_ids': [r['id'] for r in records]}


def parse_args(argv=None):
    p = argparse.ArgumentParser(description='Maintain TW A/TXT from success pool with probe4 validation of current records.')
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--pool', type=Path, required=True)
    p.add_argument('--csv', type=Path, required=False)
    p.add_argument('--state-dir', type=Path, default=Path('./state'))
    p.add_argument('--record', default='tw.270376.xyz')
    p.add_argument('--target-count', type=int, default=TARGET_COUNT)
    p.add_argument('--tg-token', default=None)
    p.add_argument('--tg-chat-id', default=None)
    p.add_argument('--dry-run', action='store_true')
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    config = load_json(args.config)
    state_dir = args.state_dir.resolve(); state_dir.mkdir(parents=True, exist_ok=True)
    pool_path = args.pool.resolve()
    pool = load_pool(pool_path)
    notifier = TelegramNotifier(token=args.tg_token, chat_id=args.tg_chat_id)
    cf = CloudflareClient(email=config['email'], global_api_key=config['globalApiKey'])
    zone = config['zone']
    record = args.record
    if not pool:
        raise SystemExit(f'empty pool: {args.pool}')
    try:
        current_txt = current_txt_candidates(cf, zone, record)
        current_a = current_a_candidates(cf, zone, record)
        log(f'current TXT candidates: {current_txt}')
        log(f'current A candidates: {current_a}')
        log(f'using success-only pool: {pool_path} ({len(pool)} candidates)')
        desired_txt, desired_a = select_from_pool(pool, args.target_count)
        if len(desired_txt) < args.target_count:
            raise SystemExit(f'not enough :443 TXT candidates in pool: {len(desired_txt)} < {args.target_count}')
        if len(desired_a) < args.target_count:
            raise SystemExit(f'not enough unique :443 A candidates in pool: {len(desired_a)} < {args.target_count}')

        current_probe = probe_candidates(list(dict.fromkeys(current_txt + [f'{ip}:{TARGET_PORT}' for ip in current_a]))) if (current_txt or current_a) else {}
        txt_valid = [cand for cand in current_txt if current_probe.get(cand, {}).get('ok')]
        a_valid = [ip for ip in current_a if current_probe.get(f'{ip}:{TARGET_PORT}', {}).get('ok')]
        txt_ok = len(current_txt) == args.target_count and current_txt == desired_txt and len(txt_valid) == args.target_count
        a_ok = len(current_a) == args.target_count and set(current_a) == set(desired_a) and len(a_valid) == args.target_count

        checked = [current_probe[k] for k in current_probe]
        outputs = write_results(state_dir / 'maintain-tw', checked)
        failed_tested = sorted({item['candidate'] for item in checked if not item.get('ok')})
        if failed_tested and not args.dry_run:
            failed_set = set(failed_tested)
            pruned_pool = [cand for cand in pool if cand not in failed_set]
            backup_path = backup_pool_with_timestamp(pool_path)
            save_pool(pool_path, pruned_pool)
            pool = pruned_pool
            outputs['success_pool_backup'] = str(backup_path) if backup_path else None
            outputs['success_pool_removed'] = sorted(failed_set)

        update_txt = {'dry_run': True, 'content': ','.join(desired_txt)}
        update_a = {'dry_run': True, 'ips': desired_a}
        if not args.dry_run and not (txt_ok and a_ok):
            update_txt = ensure_txt_updated(cf, zone, record, desired_txt)
            update_a = ensure_a_updated(cf, zone, record, desired_a)
        final_summary = {
            'record': record,
            'selected_txt': desired_txt,
            'selected_a': desired_a,
            'current_txt': current_txt,
            'current_a': current_a,
            'txt_ok': txt_ok,
            'a_ok': a_ok,
            'txt_valid': txt_valid,
            'a_valid': a_valid,
            'update_txt': update_txt,
            'update_a': update_a,
            'state_dir': str(state_dir),
            'success_pool_candidates': len(pool),
            'success_pool_unique_ips': unique_ip_count(pool),
            'outputs_summary': outputs,
        }
        save_json(state_dir / 'maintain-tw-final.json', final_summary)
        notifier.send(
            f'TW maintain\n'
            f'txt_ok={txt_ok} a_ok={a_ok}\n'
            f'txt={",".join(desired_txt)}\n'
            f'a={",".join(desired_a)}'
        )
        print(json.dumps(final_summary, ensure_ascii=False, indent=2))
        return 0
    except Exception as e:
        notifier.send(f'TW maintain failed\n{type(e).__name__}: {e}')
        raise


if __name__ == '__main__':
    raise SystemExit(main())
