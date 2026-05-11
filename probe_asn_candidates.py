import csv
import ipaddress
import json
import os
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

WORKDIR = '/mnt/code/hermes/workspace'
PORTS = (443, 8443)
BATCH_SIZE = 20
MAX_WORKERS = 8
RETRIES = 2
TIMEOUT = 45
URL = 'https://ck.batch10p.workers.dev/probe'
HEADERS = {
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0',
}

ASNS = [
    ('dmit906', '/mnt/code/hermes/workspace/dmit906-ip-ranges.txt'),
    ('25820', '/mnt/code/hermes/workspace/25820-ip-ranges.txt'),
]

SKIPPED = [
    ('4766', '/mnt/code/hermes/workspace/4766-ip-ranges.txt', 'skipped by default because full IPv4 expansion is extremely large (~138.8M ip:port entries for ports 443/8443)')
]

print_lock = Lock()
file_lock = Lock()
count_lock = Lock()


def log(msg):
    with print_lock:
        print(msg, flush=True)


def load_ipv4_prefixes(path):
    out = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            net = ipaddress.ip_network(line, strict=False)
            if net.version == 4:
                out.append(net)
    return out


def hosts_of(net):
    if net.prefixlen <= 30:
        return net.hosts()
    return iter(net)


def write_candidate_file(name, prefixes):
    out_path = os.path.join(WORKDIR, f'{name}-ipv4-443-8443.txt')
    count = 0
    with open(out_path, 'w', encoding='utf-8') as out:
        for net in prefixes:
            for ip in hosts_of(net):
                s = str(ip)
                for port in PORTS:
                    out.write(f'{s}:{port}\n')
                    count += 1
    return out_path, count


def iter_batches(prefixes):
    batch = []
    for net in prefixes:
        for ip in hosts_of(net):
            s = str(ip)
            for port in PORTS:
                batch.append(f'{s}:{port}')
                if len(batch) >= BATCH_SIZE:
                    yield batch
                    batch = []
    if batch:
        yield batch


def post_batch(batch):
    payload = json.dumps({'candidates': batch}).encode('utf-8')
    last_err = None
    for attempt in range(1, RETRIES + 1):
        try:
            req = urllib.request.Request(URL, data=payload, headers=HEADERS, method='POST')
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                data = json.loads(r.read().decode('utf-8', 'replace'))
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list):
                raise ValueError(f'unexpected response type: {type(data)}')
            return data, None
        except Exception as e:
            last_err = f'{type(e).__name__}: {e}'
            time.sleep(attempt)
    return None, last_err


def process_asn(name, cidr_path):
    prefixes = load_ipv4_prefixes(cidr_path)
    log(f'[{name}] loaded {len(prefixes)} IPv4 prefixes')

    candidate_path, candidate_count = write_candidate_file(name, prefixes)
    success_txt = os.path.join(WORKDIR, f'{name}-successful-ip-port.txt')
    success_csv = os.path.join(WORKDIR, f'{name}-successful-ip-port.csv')
    manifest_path = os.path.join(WORKDIR, f'{name}-probe-manifest.json')

    total_batches = (candidate_count + BATCH_SIZE - 1) // BATCH_SIZE
    log(f'[{name}] candidate file written: {candidate_path} ({candidate_count} entries, {total_batches} batches)')

    counters = {
        'submitted_batches': 0,
        'completed_batches': 0,
        'failed_batches': 0,
        'success_candidates': 0,
        'batch_errors': [],
    }

    with open(success_txt, 'w', encoding='utf-8') as txt_out, open(success_csv, 'w', encoding='utf-8', newline='') as csv_f:
        writer = csv.writer(csv_f)
        writer.writerow(['candidate', 'asn_label', 'ok', 'inferred_stack', 'supports_ipv4', 'supports_ipv6', 'dual_stack', 'status_codes', 'exit_ips', 'exit_countries', 'exit_asns'])

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            batch_iter = iter_batches(prefixes)
            inflight = {}
            batch_index = 0

            def submit_next():
                nonlocal batch_index
                try:
                    batch = next(batch_iter)
                except StopIteration:
                    return False
                batch_index += 1
                fut = ex.submit(post_batch, list(batch))
                inflight[fut] = (batch_index, list(batch))
                counters['submitted_batches'] = batch_index
                return True

            for _ in range(MAX_WORKERS):
                if not submit_next():
                    break

            while inflight:
                fut = next(as_completed(list(inflight)))
                idx, batch = inflight.pop(fut)
                data, err = fut.result()
                if err:
                    counters['failed_batches'] += 1
                    counters['batch_errors'].append({'batch': idx, 'error': err, 'count': len(batch)})
                else:
                    for item in data:
                        if item.get('ok') is True:
                            candidate = item.get('candidate', '')
                            prs = item.get('probe_results') or []
                            status_codes = ';'.join(str(p.get('status_code')) for p in prs if p.get('status_code') is not None)
                            exit_ips = ';'.join(sorted({p.get('exit_ip') for p in prs if p.get('exit_ip')}))
                            exit_countries = ';'.join(sorted({p.get('exit_country') for p in prs if p.get('exit_country')}))
                            exit_asns = ';'.join(sorted({str(p.get('exit_asn')) for p in prs if p.get('exit_asn') is not None}))
                            txt_out.write(candidate + '\n')
                            writer.writerow([
                                candidate,
                                name,
                                item.get('ok'),
                                item.get('inferred_stack', ''),
                                item.get('supports_ipv4'),
                                item.get('supports_ipv6'),
                                item.get('dual_stack'),
                                status_codes,
                                exit_ips,
                                exit_countries,
                                exit_asns,
                            ])
                            counters['success_candidates'] += 1
                counters['completed_batches'] += 1
                if counters['completed_batches'] % 100 == 0 or counters['completed_batches'] == total_batches:
                    log(f'[{name}] progress {counters["completed_batches"]}/{total_batches} batches, successes={counters["success_candidates"]}, failed_batches={counters["failed_batches"]}')
                submit_next()

    manifest = {
        'asn_label': name,
        'cidr_source': cidr_path,
        'candidate_file': candidate_path,
        'success_txt': success_txt,
        'success_csv': success_csv,
        'candidate_count': candidate_count,
        'batch_size': BATCH_SIZE,
        'total_batches': total_batches,
        'success_candidates': counters['success_candidates'],
        'failed_batches': counters['failed_batches'],
        'batch_errors': counters['batch_errors'],
    }
    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    log(f'[{name}] done, successes={counters["success_candidates"]}, manifest={manifest_path}')
    return manifest


def main():
    manifests = []
    for entry in SKIPPED:
        log(f'[skip] {entry[0]}: {entry[2]}')
    for name, path in ASNS:
        manifests.append(process_asn(name, path))
    summary_path = os.path.join(WORKDIR, 'asn-probe-summary.json')
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump({'processed': manifests, 'skipped': SKIPPED}, f, ensure_ascii=False, indent=2)
    log(f'[all done] summary={summary_path}')


if __name__ == '__main__':
    main()
