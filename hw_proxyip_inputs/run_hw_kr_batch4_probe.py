from pathlib import Path
import csv, json, time, urllib.request, threading
from concurrent.futures import ThreadPoolExecutor, as_completed

base = Path('/mnt/code/hermes/workspace/hw_proxyip_inputs')
base.mkdir(exist_ok=True)

valid = []
for line in (base/'valid_results.tsv').read_text(encoding='utf-8-sig').splitlines():
    if not line.strip():
        continue
    first = line.split('\t', 1)[0].strip()
    if ':' in first:
        valid.append(first)

text = (base/'ip_out0315.csv').read_text(encoding='gb18030')
rows = list(csv.DictReader(text.splitlines()))
ipcsv_kr = []
for r in rows:
    ip = r.get('IP地址', '').strip()
    port = r.get('端口号', '').strip()
    country = r.get('国家', '').strip()
    if ip and port and country == '韩国':
        ipcsv_kr.append(f'{ip}:{port}')

krtxt = []
for line in (base/'kr.txt').read_text(encoding='utf-8-sig').splitlines():
    parts = [p.strip() for p in line.split(',')]
    if len(parts) >= 2 and parts[0] and parts[1]:
        krtxt.append(f'{parts[0]}:{parts[1]}')

valid_set = set(valid)
ipcsv_set = set(ipcsv_kr)
union_inputs = valid_set | ipcsv_set
krtxt_set = set(krtxt)
all_candidates = sorted(krtxt_set)

merged_csv = base/'hw-kr-merged-candidates.csv'
merged_txt = base/'hw-kr-merged-candidates.txt'
with merged_csv.open('w', encoding='utf-8-sig', newline='') as f:
    w = csv.writer(f)
    w.writerow(['candidate', 'in_valid_results', 'in_ip_out0315_kr', 'in_kr_txt', 'source_label'])
    for cand in sorted(krtxt_set | union_inputs):
        inv = cand in valid_set
        iip = cand in ipcsv_set
        ikr = cand in krtxt_set
        labels = []
        if inv:
            labels.append('valid_results')
        if iip:
            labels.append('ip_out0315_kr')
        if ikr and not (inv or iip):
            labels.append('kr_txt_only')
        elif ikr:
            labels.append('kr_txt')
        w.writerow([cand, inv, iip, ikr, '+'.join(labels)])
merged_txt.write_text('\n'.join(all_candidates) + '\n', encoding='utf-8')

url = 'https://ck.batch10p.workers.dev/probe'
headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
batch_size = 20
max_workers = 20
retries = 2
timeout = 20
batches = [all_candidates[i:i+batch_size] for i in range(0, len(all_candidates), batch_size)]
lock = threading.Lock()
progress = {'done': 0}

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
            time.sleep(1.5 * attempt)
    return [{'candidate': cand, 'ok': False, 'batch_error': last_err, 'probe_results': []} for cand in batch]

results = []
with ThreadPoolExecutor(max_workers=max_workers) as ex:
    future_map = {ex.submit(do_batch, batch): batch for batch in batches}
    for fut in as_completed(future_map):
        batch_results = fut.result()
        results.extend(batch_results)
        with lock:
            progress['done'] += 1
            if progress['done'] % 10 == 0 or progress['done'] == len(batches):
                print(f"completed {progress['done']}/{len(batches)} batches", flush=True)

by_candidate = {}
for item in results:
    cand = item.get('candidate')
    if cand and cand not in by_candidate:
        by_candidate[cand] = item
for cand in all_candidates:
    by_candidate.setdefault(cand, {'candidate': cand, 'ok': False, 'batch_error': 'no result recorded', 'probe_results': []})
final_results = [by_candidate[c] for c in all_candidates]

summary_csv = base/'hw-kr-batch4-summary.csv'
results_json = base/'hw-kr-batch4-results.json'
ok_kr_txt = base/'hw-kr-batch4-ok-kr.txt'

ok_kr = []
with summary_csv.open('w', encoding='utf-8-sig', newline='') as f:
    w = csv.writer(f)
    w.writerow([
        'candidate', 'ok', 'inferred_stack', 'supports_ipv4', 'supports_ipv6', 'dual_stack',
        'has_status_200', 'first_exit_country', 'first_exit_city', 'first_exit_asn', 'first_exit_org',
        'batch_error', 'probe_errors'
    ])
    for item in final_results:
        probe_results = item.get('probe_results') or []
        first = probe_results[0] if probe_results else {}
        status200 = any(pr.get('status_code') == 200 for pr in probe_results if isinstance(pr, dict))
        exit_countrys = [pr.get('exit_country') for pr in probe_results if isinstance(pr, dict) and pr.get('exit_country')]
        is_kr = any(c in ('South Korea', 'Korea, Republic of', 'KR', '韩国') for c in exit_countrys)
        if item.get('ok') and is_kr:
            ok_kr.append(item['candidate'])
        probe_errors = ' | '.join(sorted({str(pr.get('error')) for pr in probe_results if isinstance(pr, dict) and pr.get('error')}))
        w.writerow([
            item.get('candidate'), item.get('ok'), item.get('inferred_stack'), item.get('supports_ipv4'),
            item.get('supports_ipv6'), item.get('dual_stack'), status200,
            first.get('exit_country'), first.get('exit_city'), first.get('exit_asn'), first.get('exit_org'),
            item.get('batch_error', ''), probe_errors,
        ])

results_json.write_text(json.dumps(final_results, ensure_ascii=False, indent=2), encoding='utf-8')
ok_kr_txt.write_text('\n'.join(ok_kr) + ('\n' if ok_kr else ''), encoding='utf-8')

stats = {
    'valid_results_unique': len(valid_set),
    'ip_out0315_kr_unique': len(ipcsv_set),
    'union_inputs_unique': len(union_inputs),
    'kr_txt_unique': len(krtxt_set),
    'kr_txt_only_extra_vs_inputs': len(krtxt_set - union_inputs),
    'tested_candidates': len(all_candidates),
    'ok_total': sum(1 for x in final_results if x.get('ok')),
    'ok_kr_total': len(ok_kr),
    'output_files': {
        'merged_csv': str(merged_csv),
        'merged_txt': str(merged_txt),
        'results_json': str(results_json),
        'summary_csv': str(summary_csv),
        'ok_kr_txt': str(ok_kr_txt),
    },
    'kr_txt_only_examples': sorted(list(krtxt_set - union_inputs))[:20],
    'ok_kr_examples': ok_kr[:20],
}
print(json.dumps(stats, ensure_ascii=False, indent=2))
