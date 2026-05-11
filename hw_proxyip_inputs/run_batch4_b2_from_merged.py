from pathlib import Path
import csv, json, time, urllib.request, threading
from concurrent.futures import ThreadPoolExecutor, as_completed

base = Path(__file__).resolve().parent
candidates = sorted({line.strip() for line in (base / 'hw-kt-merged-candidates.txt').read_text(encoding='utf-8').splitlines() if line.strip()})

url = 'https://ck.batch10p.workers.dev/probe'
headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
batch_size = 2
max_workers = 32
retries = 2
timeout = 15
batches = [candidates[i:i+batch_size] for i in range(0, len(candidates), batch_size)]
lock = threading.Lock()
done = {'n': 0}


def do_batch(batch):
    payload = json.dumps({'candidates': batch}).encode()
    last_err = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, data=payload, headers=headers, method='POST')
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode('utf-8', 'replace')
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


results = []
with ThreadPoolExecutor(max_workers=max_workers) as ex:
    future_map = {ex.submit(do_batch, batch): batch for batch in batches}
    for fut in as_completed(future_map):
        results.extend(fut.result())
        with lock:
            done['n'] += 1
            if done['n'] % 50 == 0 or done['n'] == len(batches):
                print(f"batch_size=2: completed {done['n']}/{len(batches)} batches", flush=True)

by_candidate = {}
for item in results:
    cand = item.get('candidate')
    if cand and cand not in by_candidate:
        by_candidate[cand] = item
for cand in candidates:
    by_candidate.setdefault(cand, {'candidate': cand, 'ok': False, 'batch_error': 'no result recorded', 'probe_results': []})
final_results = [by_candidate[c] for c in candidates]


def is_kr_result(item):
    probe_results = item.get('probe_results') or []
    countries = [pr.get('exit_country') for pr in probe_results if isinstance(pr, dict) and pr.get('exit_country')]
    return any(c in ('South Korea', 'Korea, Republic of', 'KR', '韩国') for c in countries)

out_json = base / 'hw-kt-batch4-b2-results.json'
out_csv = base / 'hw-kt-batch4-b2-summary.csv'
out_ok = base / 'hw-kt-batch4-b2-ok-kr.txt'
out_ips = base / 'hw-kt-batch4-b2-ok-kr-ips.txt'
out_meta = base / 'hw-kt-batch4-b2-summary.json'

out_json.write_text(json.dumps(final_results, ensure_ascii=False, indent=2), encoding='utf-8')
ok_kr = []
with out_csv.open('w', encoding='utf-8-sig', newline='') as f:
    w = csv.writer(f)
    w.writerow([
        'candidate', 'ok', 'is_kr_exit', 'inferred_stack', 'supports_ipv4', 'supports_ipv6',
        'dual_stack', 'has_status_200', 'first_exit_country', 'first_exit_city', 'first_exit_asn',
        'first_exit_org', 'batch_error', 'probe_errors'
    ])
    for item in final_results:
        probe_results = item.get('probe_results') or []
        first = probe_results[0] if probe_results else {}
        status200 = any(pr.get('status_code') == 200 for pr in probe_results if isinstance(pr, dict))
        kr = is_kr_result(item)
        if item.get('ok') and kr:
            ok_kr.append(item['candidate'])
        probe_errors = ' | '.join(sorted({str(pr.get('error')) for pr in probe_results if isinstance(pr, dict) and pr.get('error')}))
        w.writerow([
            item.get('candidate'), item.get('ok'), kr, item.get('inferred_stack'), item.get('supports_ipv4'),
            item.get('supports_ipv6'), item.get('dual_stack'), status200, first.get('exit_country'),
            first.get('exit_city'), first.get('exit_asn'), first.get('exit_org'), item.get('batch_error', ''),
            probe_errors,
        ])

out_ok.write_text('\n'.join(ok_kr) + ('\n' if ok_kr else ''), encoding='utf-8')
unique_ips = sorted({cand.split(':', 1)[0] for cand in ok_kr})
out_ips.write_text('\n'.join(unique_ips) + ('\n' if unique_ips else ''), encoding='utf-8')

summary = {
    'batch_size': batch_size,
    'tested_candidates': len(final_results),
    'ok_total': sum(1 for r in final_results if r.get('ok')),
    'ok_kr_total': len(ok_kr),
    'ok_unique_ips': len(unique_ips),
    'success_rate': round(sum(1 for r in final_results if r.get('ok')) / len(final_results), 6) if final_results else 0,
    'kr_success_rate': round(len(ok_kr) / len(final_results), 6) if final_results else 0,
    'output_files': {
        'results_json': str(out_json),
        'summary_csv': str(out_csv),
        'ok_kr_txt': str(out_ok),
        'ok_kr_ips': str(out_ips),
    },
    'ok_kr_examples': ok_kr[:20],
}
out_meta.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(summary, ensure_ascii=False, indent=2))
