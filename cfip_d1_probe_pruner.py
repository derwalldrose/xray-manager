#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import time
import urllib.request
from pathlib import Path

ACCOUNT = '9b8556f8dc27cf344651a218c901e406'
DB_ID = '161169cf-ace5-48be-ac0c-e21a1736d822'
EMAIL = 'yonflee2025@gmail.com'
GLOBAL_KEY = '718eb09f456ca26c7f3692ef2d28fcff3816d'
D1_URL = f'https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/d1/database/{DB_ID}/query'
D1_HEADERS = {'X-Auth-Email': EMAIL, 'X-Auth-Key': GLOBAL_KEY, 'Content-Type': 'application/json'}
PROBE_URL = 'https://ck.batch10p.workers.dev/probe'
UA = 'cfip-record-pruner/1.0'


def d1_query(sql: str) -> list[dict]:
    req = urllib.request.Request(D1_URL, data=json.dumps({'sql': sql}).encode(), headers=D1_HEADERS, method='POST')
    with urllib.request.urlopen(req, timeout=600) as resp:
        data = json.loads(resp.read().decode('utf-8', 'replace'))
    if data.get('errors'):
        raise RuntimeError(data['errors'])
    result = data.get('result') or []
    if not result:
        return []
    return result[0].get('results') or []


def d1_exec(sql: str) -> dict:
    req = urllib.request.Request(D1_URL, data=json.dumps({'sql': sql}).encode(), headers=D1_HEADERS, method='POST')
    with urllib.request.urlopen(req, timeout=600) as resp:
        data = json.loads(resp.read().decode('utf-8', 'replace'))
    if data.get('errors'):
        raise RuntimeError(data['errors'])
    return data


def q(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def fetch_rows(limit: int) -> list[dict]:
    sql = (
        'SELECT id, ip, port, updated_at FROM records '
        f'ORDER BY updated_at DESC, id ASC LIMIT {int(limit)}'
    )
    return d1_query(sql)


def probe_candidates(candidates: list[str]) -> dict[str, dict]:
    if not candidates:
        return {}
    req = urllib.request.Request(
        PROBE_URL,
        data=json.dumps({'candidates': candidates}).encode(),
        headers={'Content-Type': 'application/json', 'User-Agent': UA},
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = json.loads(resp.read().decode('utf-8', 'replace'))
    items = data if isinstance(data, list) else (data.get('results') or [])
    return {item.get('candidate'): item for item in items if item.get('candidate')}


def chunked(seq: list[str], size: int) -> list[list[str]]:
    return [seq[i:i + size] for i in range(0, len(seq), size)]


def row_candidate(row: dict) -> str:
    ip = str(row.get('ip') or '').strip()
    port = str(row.get('port') or '').strip()
    return f'{ip}:{port}'


def row_id(row: dict) -> str:
    return str(row.get('id') or '').strip()


def row_updated_at(row: dict) -> int:
    try:
        return int(row.get('updated_at') or 0)
    except Exception:
        return 0


def delete_ids(ids: list[str], pause: float = 0.0) -> int:
    deleted = 0
    for rid in ids:
        d1_exec(f'DELETE FROM records WHERE id = {q(rid)}')
        deleted += 1
        if pause > 0:
            time.sleep(pause)
    return deleted


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Full-fetch random-sample probe-prune cfip D1 records; delete invalid sampled rows.')
    p.add_argument('--fetch-limit', type=int, default=15000, help='Rows to fetch from D1 each run (default: 15000)')
    p.add_argument('--sample-size', type=int, default=1000, help='Random rows to probe from fetched set (default: 1000)')
    p.add_argument('--seed', type=int, default=None, help='Optional random seed for reproducibility')
    p.add_argument('--probe-batch', type=int, default=3, help='Probe batch size (default: 3)')
    p.add_argument('--delete-pause', type=float, default=0.0, help='Sleep seconds between deletes')
    p.add_argument('--dry-run', action='store_true', help='Do not delete, only report invalid rows')
    p.add_argument('--json-out', default='', help='Optional path to write JSON summary')
    return p.parse_args()


def main() -> int:
    args = parse_args()
    rows = fetch_rows(args.fetch_limit)
    eligible_rows = [r for r in rows if row_id(r) and row_candidate(r) and ':' in row_candidate(r)]
    sample_n = min(max(0, args.sample_size), len(eligible_rows))
    rng = random.Random(args.seed)
    sampled_rows = rng.sample(eligible_rows, sample_n) if sample_n < len(eligible_rows) else list(eligible_rows)
    candidates = [row_candidate(r) for r in sampled_rows]
    unique_candidates = list(dict.fromkeys(candidates))

    results: dict[str, dict] = {}
    probed = 0
    for batch in chunked(unique_candidates, max(1, args.probe_batch)):
        probed += len(batch)
        results.update(probe_candidates(batch))

    invalid_ids: list[str] = []
    invalid_rows: list[dict] = []
    valid_count = 0
    for row in sampled_rows:
        rid = row_id(row)
        cand = row_candidate(row)
        ok = bool(results.get(cand, {}).get('ok'))
        if ok:
            valid_count += 1
        else:
            invalid_ids.append(rid)
            invalid_rows.append({
                'id': rid,
                'candidate': cand,
                'updated_at': row_updated_at(row),
                'probe': results.get(cand, {}),
            })

    deleted = 0
    if invalid_ids and not args.dry_run:
        deleted = delete_ids(invalid_ids, pause=args.delete_pause)

    summary = {
        'success': True,
        'source': 'cloudflare-d1-direct',
        'fetch_limit': args.fetch_limit,
        'fetched_rows': len(rows),
        'eligible_rows': len(eligible_rows),
        'sample_size_requested': args.sample_size,
        'sampled_rows': len(sampled_rows),
        'seed': args.seed,
        'probe_batch': args.probe_batch,
        'probed_candidates': probed,
        'valid_rows': valid_count,
        'invalid_rows': len(invalid_ids),
        'deleted_rows': deleted,
        'dry_run': args.dry_run,
        'invalid_samples': invalid_rows[:50],
    }

    if args.json_out:
        path = Path(args.json_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
