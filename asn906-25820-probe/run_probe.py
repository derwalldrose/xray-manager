#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

PROBE_URL = 'https://ck.batch10p.workers.dev/probe'
USER_AGENT = 'Mozilla/5.0'


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


def is_ok(item: dict[str, Any]) -> bool:
    return bool(item.get('ok'))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='Probe ASN-filtered candidate list via batch4.')
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--metadata-csv', type=Path, required=True)
    p.add_argument('--outdir', type=Path, required=True)
    p.add_argument('--batch-size', type=int, default=2)
    p.add_argument('--workers', type=int, default=24)
    p.add_argument('--timeout', type=int, default=15)
    p.add_argument('--retries', type=int, default=2)
    args = p.parse_args(argv)

    args.outdir.mkdir(parents=True, exist_ok=True)
    candidates = [line.strip() for line in args.input.read_text(encoding='utf-8').splitlines() if line.strip()]
    meta_rows = list(csv.DictReader(args.metadata_csv.read_text(encoding='utf-8-sig').splitlines()))
    meta = {row['candidate']: row for row in meta_rows}

    batches = [candidates[i:i+args.batch_size] for i in range(0, len(candidates), args.batch_size)]
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(do_batch, batch, args.timeout, args.retries): batch for batch in batches}
        for idx, fut in enumerate(as_completed(futs), start=1):
            results.extend(fut.result())
            if idx % 20 == 0 or idx == len(batches):
                print(f'completed {idx}/{len(batches)} batches', flush=True)

    by_candidate = {}
    for item in results:
        cand = item.get('candidate')
        if cand and cand not in by_candidate:
            by_candidate[cand] = item
    for cand in candidates:
        by_candidate.setdefault(cand, {'candidate': cand, 'ok': False, 'batch_error': 'no result recorded', 'probe_results': []})
    final_results = [by_candidate[c] for c in candidates]

    out_json = args.outdir / 'probe-results.json'
    out_csv = args.outdir / 'probe-summary.csv'
    out_ok = args.outdir / 'probe-ok.txt'
    out_json.write_text(json.dumps(final_results, ensure_ascii=False, indent=2), encoding='utf-8')

    ok_candidates = []
    with out_csv.open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f)
        w.writerow(['candidate', 'asn', 'org', 'sources', 'ok', 'inferred_stack', 'supports_ipv4', 'supports_ipv6', 'dual_stack', 'first_exit_country', 'first_exit_asn', 'first_exit_org', 'batch_error'])
        for item in final_results:
            m = meta.get(item['candidate'], {})
            prs = item.get('probe_results') or []
            first = prs[0] if prs else {}
            if is_ok(item):
                ok_candidates.append(item['candidate'])
            w.writerow([
                item['candidate'],
                m.get('asn', ''),
                m.get('org', ''),
                m.get('sources', ''),
                item.get('ok'),
                item.get('inferred_stack', ''),
                item.get('supports_ipv4', ''),
                item.get('supports_ipv6', ''),
                item.get('dual_stack', ''),
                first.get('exit_country', ''),
                first.get('exit_asn', ''),
                first.get('exit_org', ''),
                item.get('batch_error', ''),
            ])
    out_ok.write_text('\n'.join(ok_candidates) + ('\n' if ok_candidates else ''), encoding='utf-8')

    summary = {
        'tested_candidates': len(candidates),
        'ok_total': sum(1 for x in final_results if x.get('ok')),
        'output_files': {
            'results_json': str(out_json),
            'summary_csv': str(out_csv),
            'ok_txt': str(out_ok),
        }
    }
    (args.outdir / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
