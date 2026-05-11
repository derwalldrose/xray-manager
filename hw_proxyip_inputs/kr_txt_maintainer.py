#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

PROBE_URL = 'https://ck.batch10p.workers.dev/probe'
USER_AGENT = 'Mozilla/5.0'
TARGET_COUNT = 3
DEFAULT_WORKERS = 32
DEFAULT_TIMEOUT = 15
DEFAULT_RETRIES = 2


def log(msg: str) -> None:
    print(msg, flush=True)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding='utf-8'))


def save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


def load_pool(path: Path) -> list[str]:
    return sorted({line.strip() for line in path.read_text(encoding='utf-8').splitlines() if line.strip()})


def save_pool(path: Path, candidates: list[str]) -> None:
    path.write_text('\n'.join(candidates) + ('\n' if candidates else ''), encoding='utf-8')


def unique_ip_count(candidates: list[str]) -> int:
    return len({cand.split(':', 1)[0] for cand in candidates if ':' in cand})


def backup_pool_with_timestamp(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_name(f"{path.stem}.bak-{time.strftime('%Y%m%d-%H%M%S')}{path.suffix}")
    backup.write_text(path.read_text(encoding='utf-8'), encoding='utf-8')
    return backup


def parse_txt_candidates(content: str) -> list[str]:
    return [part.strip() for part in content.split(',') if part.strip()]


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
        data = urllib.parse.urlencode({
            'chat_id': self.chat_id,
            'text': text,
            'disable_web_page_preview': 'true',
        }).encode()
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
        except Exception as e:
            log(f'telegram notify exception: {e!r}')


class CloudflareClient:
    def __init__(self, *, email: str, global_api_key: str):
        self.email = email
        self.global_api_key = global_api_key

    def _request(self, method: str, url: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {
            'User-Agent': USER_AGENT,
            'X-Auth-Email': self.email,
            'X-Auth-Key': self.global_api_key,
        }
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


class Batch4Probe:
    def __init__(self, *, timeout: int, retries: int):
        self.timeout = timeout
        self.retries = retries

    def probe_one(self, candidate: str) -> dict[str, Any]:
        payload = json.dumps({'candidates': [candidate]}).encode()
        last_err = None
        for attempt in range(1, self.retries + 1):
            req = urllib.request.Request(
                PROBE_URL,
                data=payload,
                headers={'Content-Type': 'application/json', 'User-Agent': USER_AGENT},
                method='POST',
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read().decode('utf-8', 'replace')
                data = json.loads(body)
                if isinstance(data, dict):
                    data = [data]
                if data:
                    item = data[0]
                    if item.get('candidate') != candidate:
                        item['candidate'] = candidate
                    return item
            except Exception as e:
                last_err = repr(e)
                time.sleep(1.0 * attempt)
        return {'candidate': candidate, 'ok': False, 'batch_error': last_err, 'probe_results': []}


def is_kr_success(item: dict[str, Any]) -> bool:
    if not item.get('ok'):
        return False
    probe_results = item.get('probe_results') or []
    for pr in probe_results:
        country = pr.get('exit_country')
        if country in ('South Korea', 'Korea, Republic of', 'KR', '韩国'):
            return True
    return False


def write_results(prefix: Path, results: list[dict[str, Any]]) -> dict[str, Any]:
    prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = prefix.with_suffix('.results.json')
    csv_path = prefix.with_suffix('.summary.csv')
    ok_path = prefix.with_suffix('.ok-kr.txt')
    ips_path = prefix.with_suffix('.ok-kr-ips.txt')
    ports_path = prefix.with_suffix('.port-top20.csv')
    summary_path = prefix.with_suffix('.summary.json')

    json_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')

    ok_kr: list[str] = []
    port_counter: Counter[str] = Counter()
    with csv_path.open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f)
        w.writerow([
            'candidate', 'ok', 'is_kr_exit', 'inferred_stack', 'supports_ipv4', 'supports_ipv6',
            'dual_stack', 'has_status_200', 'first_exit_country', 'first_exit_city', 'first_exit_asn',
            'first_exit_org', 'batch_error', 'probe_errors'
        ])
        for item in results:
            prs = item.get('probe_results') or []
            first = prs[0] if prs else {}
            status200 = any(pr.get('status_code') == 200 for pr in prs if isinstance(pr, dict))
            kr = is_kr_success(item)
            if kr:
                ok_kr.append(item['candidate'])
                try:
                    port_counter[item['candidate'].rsplit(':', 1)[1]] += 1
                except Exception:
                    pass
            probe_errors = ' | '.join(sorted({str(pr.get('error')) for pr in prs if isinstance(pr, dict) and pr.get('error')}))
            w.writerow([
                item.get('candidate'), item.get('ok'), kr, item.get('inferred_stack'), item.get('supports_ipv4'),
                item.get('supports_ipv6'), item.get('dual_stack'), status200, first.get('exit_country'),
                first.get('exit_city'), first.get('exit_asn'), first.get('exit_org'), item.get('batch_error', ''),
                probe_errors,
            ])

    ok_path.write_text('\n'.join(ok_kr) + ('\n' if ok_kr else ''), encoding='utf-8')
    unique_ips = sorted({cand.split(':', 1)[0] for cand in ok_kr})
    ips_path.write_text('\n'.join(unique_ips) + ('\n' if unique_ips else ''), encoding='utf-8')

    port_top20 = port_counter.most_common(20)
    with ports_path.open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f)
        w.writerow(['rank', 'port', 'count'])
        for i, (port, count) in enumerate(port_top20, start=1):
            w.writerow([i, port, count])

    summary = {
        'tested_candidates': len(results),
        'ok_total': sum(1 for r in results if r.get('ok')),
        'ok_kr_total': len(ok_kr),
        'ok_unique_ips': len(unique_ips),
        'success_rate': round(sum(1 for r in results if r.get('ok')) / len(results), 6) if results else 0,
        'kr_success_rate': round(len(ok_kr) / len(results), 6) if results else 0,
        'port_top20': [{'port': port, 'count': count} for port, count in port_top20],
        'output_files': {
            'results_json': str(json_path),
            'summary_csv': str(csv_path),
            'ok_kr_txt': str(ok_path),
            'ok_kr_ips': str(ips_path),
            'port_top20_csv': str(ports_path),
        },
        'ok_kr_examples': ok_kr[:20],
    }
    save_json(summary_path, summary)
    return {'summary': summary, 'ok_kr': ok_kr}


def full_refresh(*, pool: list[str], probe: Batch4Probe, workers: int, state_dir: Path) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_map = {ex.submit(probe.probe_one, candidate): candidate for candidate in pool}
        for idx, fut in enumerate(as_completed(future_map), start=1):
            results.append(fut.result())
            if idx % 100 == 0 or idx == len(pool):
                log(f'full-refresh: completed {idx}/{len(pool)}')
    results.sort(key=lambda item: item.get('candidate', ''))
    outputs = write_results(state_dir / 'full-refresh', results)
    success_pool = sorted(outputs['ok_kr'])
    save_pool(state_dir / 'success-pool.txt', success_pool)
    outputs['results'] = results
    outputs['success_pool'] = success_pool
    return outputs


def maintain(*, current_txt: list[str], pool: list[str], probe: Batch4Probe, target_count: int, state_dir: Path) -> dict[str, Any]:
    kept: list[str] = []
    checked_results: list[dict[str, Any]] = []
    seen = set()
    failed_current_txt: list[str] = []
    failed_tested_candidates: list[str] = []

    for candidate in current_txt:
        if candidate in seen:
            continue
        seen.add(candidate)
        item = probe.probe_one(candidate)
        checked_results.append(item)
        if is_kr_success(item):
            kept.append(candidate)
        else:
            failed_current_txt.append(candidate)
            failed_tested_candidates.append(candidate)

    if len(kept) < target_count:
        for candidate in pool:
            if candidate in seen or candidate in kept:
                continue
            item = probe.probe_one(candidate)
            checked_results.append(item)
            seen.add(candidate)
            if is_kr_success(item):
                kept.append(candidate)
            else:
                failed_tested_candidates.append(candidate)
            if len(kept) >= target_count:
                break

    outputs = write_results(state_dir / 'maintain', checked_results)
    outputs['selected'] = kept[:target_count]
    outputs['failed_current_txt'] = failed_current_txt
    outputs['failed_tested_candidates'] = sorted(set(failed_tested_candidates))
    return outputs


def ensure_txt_updated(cf: CloudflareClient, zone: str, record_name: str, selected: list[str]) -> dict[str, Any]:
    zone_id = cf.get_zone_id(zone)
    content = ','.join(selected)
    result = cf.upsert_single_txt_record(zone_id, record_name, content, ttl=60)
    return {'zone_id': zone_id, 'content': content, 'record_id': result['id']}


def get_current_txt(cf: CloudflareClient, zone: str, record_name: str) -> list[str]:
    zone_id = cf.get_zone_id(zone)
    records = cf.list_txt_records(zone_id, record_name)
    if not records:
        return []
    return parse_txt_candidates(records[0].get('content', ''))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Probe KR proxy pool and maintain Cloudflare TXT record.')
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--pool', type=Path, required=True)
    p.add_argument('--state-dir', type=Path, default=Path('./kr-txt-maintainer-state'))
    p.add_argument('--success-pool', type=Path, default=None, help='optional success-only pool file; if omitted, defaults to <state-dir>/success-pool.txt')
    p.add_argument('--mode', choices=['full-refresh', 'maintain'], required=True)
    p.add_argument('--target-count', type=int, default=TARGET_COUNT)
    p.add_argument('--workers', type=int, default=DEFAULT_WORKERS)
    p.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT)
    p.add_argument('--retries', type=int, default=DEFAULT_RETRIES)
    p.add_argument('--tg-token', default=None)
    p.add_argument('--tg-chat-id', default=None)
    p.add_argument('--dry-run', action='store_true')
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config = load_json(args.config)
    pool = load_pool(args.pool)
    state_dir = args.state_dir.resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    success_pool_path = args.success_pool.resolve() if args.success_pool else (state_dir / 'success-pool.txt')

    probe = Batch4Probe(timeout=args.timeout, retries=args.retries)
    notifier = TelegramNotifier(token=args.tg_token, chat_id=args.tg_chat_id)
    cf = CloudflareClient(email=config['email'], global_api_key=config['globalApiKey'])
    zone = config['zone']
    record_name = config['recordName']

    try:
        if args.mode == 'full-refresh':
            outputs = full_refresh(pool=pool, probe=probe, workers=args.workers, state_dir=state_dir)
            if success_pool_path != state_dir / 'success-pool.txt':
                save_pool(success_pool_path, outputs['success_pool'])
            selected = outputs['ok_kr'][:args.target_count]
            if len(selected) < args.target_count:
                raise SystemExit(f'not enough successful KR candidates to fill TXT record: {len(selected)} < {args.target_count}')
        else:
            current_txt = get_current_txt(cf, zone, record_name)
            log(f'current TXT candidates: {current_txt}')
            if success_pool_path.exists():
                effective_pool = load_pool(success_pool_path)
                log(f'using success-only pool: {success_pool_path} ({len(effective_pool)} candidates)')
            else:
                effective_pool = pool
                log(f'success-only pool missing, falling back to full pool ({len(effective_pool)} candidates)')
            outputs = maintain(current_txt=current_txt, pool=effective_pool, probe=probe, target_count=args.target_count, state_dir=state_dir)
            selected = outputs['selected']
            if outputs['failed_tested_candidates'] and success_pool_path.exists():
                failed_set = set(outputs['failed_tested_candidates'])
                pruned_pool = [cand for cand in effective_pool if cand not in failed_set]
                backup_path = backup_pool_with_timestamp(success_pool_path)
                save_pool(success_pool_path, pruned_pool)
                outputs['success_pool_backup'] = str(backup_path) if backup_path else None
                outputs['success_pool_removed'] = sorted(failed_set)
                outputs['success_pool_size_before'] = len(effective_pool)
                outputs['success_pool_size_after'] = len(pruned_pool)
            if len(selected) < args.target_count:
                raise SystemExit(f'not enough valid KR candidates after maintain run: {len(selected)} < {args.target_count}')

        update_info = {'dry_run': True, 'content': ','.join(selected)}
        if not args.dry_run:
            update_info = ensure_txt_updated(cf, zone, record_name, selected)

        current_success_pool = load_pool(success_pool_path) if success_pool_path.exists() else []
        final_summary = {
            'mode': args.mode,
            'selected': selected,
            'update': update_info,
            'state_dir': str(state_dir),
            'success_pool_candidates': len(current_success_pool),
            'success_pool_unique_ips': unique_ip_count(current_success_pool),
            'outputs_summary': outputs['summary'],
        }
        save_json(state_dir / f'{args.mode}-final.json', final_summary)
        notifier.send(
            f"KR TXT {args.mode} 完成\n"
            f"selected: {', '.join(selected)}\n"
            f"tested: {outputs['summary']['tested_candidates']}\n"
            f"ok_kr: {outputs['summary']['ok_kr_total']}\n"
            f"pool_candidates: {len(current_success_pool)}\n"
            f"pool_ips: {unique_ip_count(current_success_pool)}\n"
            f"txt: {update_info.get('content', '')}\n"
            f"removed: {len(outputs.get('success_pool_removed', []))}"
        )
        print(json.dumps(final_summary, ensure_ascii=False, indent=2))
        return 0
    except Exception as e:
        notifier.send(f"KR TXT {args.mode} 失败\n{type(e).__name__}: {e}")
        raise


if __name__ == '__main__':
    raise SystemExit(main())
