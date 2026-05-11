from pathlib import Path
import csv, json, time, urllib.request, threading
from concurrent.futures import ThreadPoolExecutor, as_completed

base = Path('/mnt/code/hermes/workspace/hw_proxyip_inputs')
base.mkdir(exist_ok=True)

hw_candidates = set((base / 'hw-kr-merged-candidates.txt').read_text(encoding='utf-8').split())
kt_rows = list(csv.DictReader(Path('/mnt/code/hermes/workspace/Korea_Telecom.csv').read_text(encoding='utf-8-sig').splitlines()))
kt_candidates = {f"{r['IP地址'].strip()}:{r['端口'].strip()}" for r in kt_rows if r.get('IP地址') and r.get('端口')}
merged_candidates = sorted(hw_candidates | kt_candidates)

merged_txt = base / 'hw-kt-merged-candidates.txt'
merged_csv = base / 'hw-kt-merged-candidates.csv'
merged_txt.write_text('\n'.join(merged_candidates) + '\n', encoding='utf-8')
with merged_csv.open('w', encoding='utf-8-sig', newline='') as f:
    w = csv.writer(f)
    w.writerow(['candidate', 'in_hw_inputs', 'in_korea_telecom'])
    for cand in merged_candidates:
        w.writerow([cand, cand in hw_candidates, cand in kt_candidates])

url = 'https://ck.batch10p.workers.dev/probe'
headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
max_workers = 24
retries = 2
timeout = 15


def probe_candidates(candidates, batch_size):
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
                if done['n'] % 20 == 0 or done['n'] == len(batches):
                    print(f"batch_size={batch_size}: completed {done['n']}/{len(batches)} batches", flush=True)

    by_candidate = {}
    for item in results:
        cand = item.get('candidate')
        if cand and cand not in by_candidate:
            by_candidate[cand] = item
    for cand in candidates:
        by_candidate.setdefault(cand, {'candidate': cand, 'ok': False, 'batch_error': 'no result recorded', 'probe_results': []})
    final_results = [by_candidate[c] for c in candidates]
    return final_results


def is_kr_result(item):
    probe_results = item.get('probe_results') or []
    countries = [pr.get('exit_country') for pr in probe_results if isinstance(pr, dict) and pr.get('exit_country')]
    return any(c in ('South Korea', 'Korea, Republic of', 'KR', '韩国') for c in countries)


def flatten_outputs(results, batch_size):
    out_json = base / f'hw-kt-batch4-b{batch_size}-results.json'
    out_csv = base / f'hw-kt-batch4-b{batch_size}-summary.csv'
    out_ok = base / f'hw-kt-batch4-b{batch_size}-ok-kr.txt'
    out_ips = base / f'hw-kt-batch4-b{batch_size}-ok-kr-ips.txt'

    out_json.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
    ok_kr = []
    with out_csv.open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f)
        w.writerow([
            'candidate', 'ok', 'is_kr_exit', 'inferred_stack', 'supports_ipv4', 'supports_ipv6',
            'dual_stack', 'has_status_200', 'first_exit_country', 'first_exit_city', 'first_exit_asn',
            'first_exit_org', 'batch_error', 'probe_errors'
        ])
        for item in results:
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

    stats = {
        'batch_size': batch_size,
        'tested_candidates': len(results),
        'ok_total': sum(1 for r in results if r.get('ok')),
        'ok_kr_total': len(ok_kr),
        'ok_unique_ips': len(unique_ips),
        'success_rate': round(sum(1 for r in results if r.get('ok')) / len(results), 6) if results else 0,
        'kr_success_rate': round(len(ok_kr) / len(results), 6) if results else 0,
        'output_files': {
            'results_json': str(out_json),
            'summary_csv': str(out_csv),
            'ok_kr_txt': str(out_ok),
            'ok_kr_ips': str(out_ips),
        },
        'ok_kr_examples': ok_kr[:20],
    }
    return stats

summary = {
    'input_counts': {
        'hw_unique': len(hw_candidates),
        'korea_telecom_unique': len(kt_candidates),
        'overlap': len(hw_candidates & kt_candidates),
        'merged_unique': len(merged_candidates),
    },
    'runs': []
}
for batch_size in (10, 5):
    results = probe_candidates(merged_candidates, batch_size=batch_size)
    summary['runs'].append(flatten_outputs(results, batch_size=batch_size))

(base / 'hw-kt-batch4-compare-summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(summary, ensure_ascii=False, indent=2))
