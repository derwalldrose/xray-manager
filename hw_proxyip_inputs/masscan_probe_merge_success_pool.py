#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import time
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

PROBE_URL = 'https://ck.batch10p.workers.dev/probe'
USER_AGENT = 'Mozilla/5.0'


def log(msg: str) -> None:
    print(msg, flush=True)


def load_candidates(path: Path) -> list[str]:
    return sorted({line.strip() for line in path.read_text(encoding='utf-8').splitlines() if line.strip()})


def save_pool(path: Path, candidates: list[str]) -> None:
    path.write_text('\n'.join(candidates) + ('\n' if candidates else ''), encoding='utf-8')


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


def is_kr_success(item: dict[str, Any]) -> bool:
    if not item.get('ok'):
        return False
    for pr in item.get('probe_results') or []:
        if pr.get('exit_country') in ('South Korea', 'Korea, Republic of', 'KR', '韩国'):
            return True
    return False


def do_batch(batch: list[str], timeout: int, retries: int) -> list[dict[str, Any]]:
    payload = json.dumps({'candidates': batch}).encode()
    last_err = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(
            PROBE_URL,
            data=payload,
            headers={'Content-Type': 'application/json', 'User-Agent': USER_AGENT},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode('utf-8', 'replace')
            data = json.loads(body)
            if isinstance(data, dict):
                data = [data]
            got = {item.get('candidate') for item in data if isinstance(item, dict)}
            for cand in batch:
                if cand not in got:
                    data.append({'candidate': cand, 'ok': False, 'batch_error': 'missing result in response', 'probe_results': []})
            return data
        except Exception as e:
            last_err = repr(e)
            time.sleep(1.0 * attempt)
    return [{'candidate': cand, 'ok': False, 'batch_error': last_err, 'probe_results': []} for cand in batch]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='Probe masscan-open candidates and merge KR successes into success-pool.')
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--success-pool', type=Path, required=True)
    p.add_argument('--state-dir', type=Path, required=True)
    p.add_argument('--batch-size', type=int, default=2)
    p.add_argument('--workers', type=int, default=24)
    p.add_argument('--timeout', type=int, default=15)
    p.add_argument('--retries', type=int, default=2)
    p.add_argument('--tg-token', default=None)
    p.add_argument('--tg-chat-id', default=None)
    args = p.parse_args(argv)

    notifier = TelegramNotifier(token=args.tg_token, chat_id=args.tg_chat_id)
    state_dir = args.state_dir.resolve()
    state_dir.mkdir(parents=True, exist_ok=True)

    candidates = load_candidates(args.input)
    existing_pool = load_candidates(args.success_pool) if args.success_pool.exists() else []
    batches = [candidates[i:i+args.batch_size] for i in range(0, len(candidates), args.batch_size)]
    results: list[dict[str, Any]] = []
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(do_batch, batch, args.timeout, args.retries): batch for batch in batches}
            for idx, fut in enumerate(as_completed(futs), start=1):
                results.extend(fut.result())
                if idx % 50 == 0 or idx == len(batches):
                    log(f'masscan-probe: completed {idx}/{len(batches)} batches')

        by_candidate = {}
        for item in results:
            cand = item.get('candidate')
            if cand and cand not in by_candidate:
                by_candidate[cand] = item
        for cand in candidates:
            by_candidate.setdefault(cand, {'candidate': cand, 'ok': False, 'batch_error': 'no result recorded', 'probe_results': []})
        final_results = [by_candidate[c] for c in candidates]
        ok_kr = [item['candidate'] for item in final_results if is_kr_success(item)]
        merged_pool = sorted(set(existing_pool) | set(ok_kr))
        save_pool(args.success_pool, merged_pool)

        # outputs
        (state_dir / 'masscan-probe.results.json').write_text(json.dumps(final_results, ensure_ascii=False, indent=2), encoding='utf-8')
        (state_dir / 'masscan-probe.ok-kr.txt').write_text('\n'.join(ok_kr) + ('\n' if ok_kr else ''), encoding='utf-8')
        port_counter = Counter(c.rsplit(':', 1)[1] for c in ok_kr if ':' in c)
        with (state_dir / 'masscan-probe.port-top20.csv').open('w', encoding='utf-8-sig', newline='') as f:
            w = csv.writer(f)
            w.writerow(['rank', 'port', 'count'])
            for i, (port, count) in enumerate(port_counter.most_common(20), start=1):
                w.writerow([i, port, count])

        summary = {
            'tested_candidates': len(candidates),
            'ok_kr_total': len(ok_kr),
            'existing_success_pool': len(existing_pool),
            'merged_success_pool': len(merged_pool),
            'new_additions': len(set(ok_kr) - set(existing_pool)),
            'top20_ports': [{'port': p, 'count': c} for p, c in port_counter.most_common(20)],
        }
        (state_dir / 'masscan-probe.summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
        notifier.send(
            f"masscan补池完成\ninput: {len(candidates)}\nnew_ok_kr: {len(ok_kr)}\nnew_additions: {summary['new_additions']}\nmerged_pool: {len(merged_pool)}"
        )
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    except Exception as e:
        notifier.send(f"masscan补池失败\n{type(e).__name__}: {e}")
        raise


if __name__ == '__main__':
    raise SystemExit(main())
