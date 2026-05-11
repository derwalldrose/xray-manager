import argparse
import csv
import ipaddress
import json
import os
import random
import re
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Sequence

WORKDIR = '/mnt/code/hermes/workspace'
DEFAULT_PORTS = (443, 8443)
DEFAULT_BATCH_SIZE = 20
DEFAULT_MAX_WORKERS = 8
DEFAULT_RETRIES = 2
DEFAULT_TIMEOUT = 45
DEFAULT_PROBE_URL = 'https://ck.batch10p.workers.dev/probe'
DEFAULT_MAX_RANDOM_4766 = 1_000_000
DEFAULT_HEADERS = {
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0',
}


def log(message: str) -> None:
    print(message, flush=True)


def build_default_asn_plan(max_random_4766: int = DEFAULT_MAX_RANDOM_4766):
    return [
        {
            'label': 'dmit906',
            'asn': 'AS906',
            'generation_mode': 'full',
            'ports': DEFAULT_PORTS,
        },
        {
            'label': '25820',
            'asn': 'AS25820',
            'generation_mode': 'full',
            'ports': DEFAULT_PORTS,
        },
        {
            'label': '4766',
            'asn': 'AS4766',
            'generation_mode': 'random',
            'max_candidates': max_random_4766,
            'ports': DEFAULT_PORTS,
        },
    ]


def normalize_label(label: str) -> str:
    return label.strip().lower().removeprefix('as')


def select_plan(plan, only_labels: Sequence[str] | None = None):
    if not only_labels:
        return list(plan)

    normalized_requested = [normalize_label(label) for label in only_labels]
    selected = [item for item in plan if normalize_label(item['label']) in normalized_requested or normalize_label(item['asn']) in normalized_requested]
    found = {normalize_label(item['label']) for item in selected} | {normalize_label(item['asn']) for item in selected}
    missing = [label for label in only_labels if normalize_label(label) not in found]
    if missing:
        raise ValueError(f"unknown ASN labels: {', '.join(missing)}")
    return selected


def fetch_ipinfo_asn_html(asn: str, timeout: int = 60) -> str:
    url = f'https://ipinfo.io/{asn}'
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode('utf-8', 'replace')


def extract_cidrs_from_ipinfo_html(html: str, asn: str) -> List[str]:
    pattern = re.compile(rf'/{re.escape(asn)}/([0-9A-Fa-f:.%]+/\d+)')
    cidrs = set()
    for raw in pattern.findall(html):
        cidr = raw.replace('%2F', '/')
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        cidrs.add(cidr)
    return sorted(
        cidrs,
        key=lambda cidr: (
            ipaddress.ip_network(cidr, strict=False).version,
            int(ipaddress.ip_network(cidr, strict=False).network_address),
            ipaddress.ip_network(cidr, strict=False).prefixlen,
        ),
    )


def download_asn_ranges(asn: str, output_path: str) -> List[str]:
    html = fetch_ipinfo_asn_html(asn)
    cidrs = extract_cidrs_from_ipinfo_html(html, asn)
    with open(output_path, 'w', encoding='utf-8') as f:
        for cidr in cidrs:
            f.write(cidr + '\n')
    return cidrs


def load_ipv4_prefixes(path: str) -> List[ipaddress.IPv4Network]:
    prefixes = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            net = ipaddress.ip_network(line, strict=False)
            if net.version == 4:
                prefixes.append(net)
    return prefixes


def hosts_of(net: ipaddress.IPv4Network):
    if net.prefixlen <= 30:
        return net.hosts()
    return iter(net)


def expand_candidates_full(prefixes: Sequence[ipaddress.IPv4Network], ports: Sequence[int] = DEFAULT_PORTS) -> Iterable[str]:
    for net in prefixes:
        for ip in hosts_of(net):
            host = str(ip)
            for port in ports:
                yield f'{host}:{port}'


def total_host_count(prefixes: Sequence[ipaddress.IPv4Network]) -> int:
    total = 0
    for net in prefixes:
        total += net.num_addresses - 2 if net.prefixlen <= 30 else net.num_addresses
    return total


def sample_random_candidates(
    prefixes: Sequence[ipaddress.IPv4Network],
    ports: Sequence[int] = DEFAULT_PORTS,
    max_candidates: int = DEFAULT_MAX_RANDOM_4766,
    seed: int | None = None,
) -> List[str]:
    if max_candidates <= 0:
        return []

    rng = random.Random(seed)
    port_list = list(ports)
    weighted = []
    total_hosts = 0
    for net in prefixes:
        host_count = net.num_addresses - 2 if net.prefixlen <= 30 else net.num_addresses
        if host_count <= 0:
            continue
        total_hosts += host_count
        weighted.append((net, host_count))

    if not weighted:
        return []

    capacity = total_hosts * len(port_list)
    target = min(max_candidates, capacity)
    seen = set()
    population = [net for net, _ in weighted]
    weights = [host_count for _, host_count in weighted]

    while len(seen) < target:
        net = rng.choices(population, weights=weights, k=1)[0]
        if net.prefixlen <= 30:
            offset = rng.randint(1, net.num_addresses - 2)
        else:
            offset = rng.randint(0, net.num_addresses - 1)
        ip = net.network_address + offset
        port = rng.choice(port_list)
        seen.add(f'{ip}:{port}')

    return list(seen)


def write_candidates_to_file(candidates: Iterable[str], output_path: str) -> int:
    count = 0
    with open(output_path, 'w', encoding='utf-8') as f:
        for candidate in candidates:
            f.write(candidate + '\n')
            count += 1
    return count


def batched(items: Sequence[str], size: int) -> Iterable[List[str]]:
    for start in range(0, len(items), size):
        yield list(items[start:start + size])


def post_batch(
    batch: Sequence[str],
    probe_url: str = DEFAULT_PROBE_URL,
    retries: int = DEFAULT_RETRIES,
    timeout: int = DEFAULT_TIMEOUT,
):
    payload = json.dumps({'candidates': list(batch)}).encode('utf-8')
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(probe_url, data=payload, headers=DEFAULT_HEADERS, method='POST')
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode('utf-8', 'replace'))
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list):
                raise ValueError(f'unexpected response type: {type(data)}')
            return data, None
        except Exception as exc:
            last_error = f'{type(exc).__name__}: {exc}'
            time.sleep(attempt)
    return None, last_error


def probe_candidates(
    candidates: Sequence[str],
    label: str,
    workdir: str = WORKDIR,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_workers: int = DEFAULT_MAX_WORKERS,
    probe_url: str = DEFAULT_PROBE_URL,
    retries: int = DEFAULT_RETRIES,
    timeout: int = DEFAULT_TIMEOUT,
):
    success_txt = os.path.join(workdir, f'{label}-successful-ip-port.txt')
    success_csv = os.path.join(workdir, f'{label}-successful-ip-port.csv')
    manifest_path = os.path.join(workdir, f'{label}-probe-manifest.json')

    total_batches = (len(candidates) + batch_size - 1) // batch_size if candidates else 0
    stats = {
        'candidate_count': len(candidates),
        'batch_size': batch_size,
        'total_batches': total_batches,
        'success_candidates': 0,
        'failed_batches': 0,
        'batch_errors': [],
    }

    with open(success_txt, 'w', encoding='utf-8') as txt_out, open(success_csv, 'w', encoding='utf-8', newline='') as csv_out:
        writer = csv.writer(csv_out)
        writer.writerow(['candidate', 'asn_label', 'ok', 'inferred_stack', 'supports_ipv4', 'supports_ipv6', 'dual_stack', 'status_codes', 'exit_ips', 'exit_countries', 'exit_asns'])

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            batches = list(batched(candidates, batch_size))
            future_map = {
                executor.submit(post_batch, batch, probe_url, retries, timeout): (idx, batch)
                for idx, batch in enumerate(batches, start=1)
            }

            for future in as_completed(future_map):
                batch_index, batch = future_map[future]
                data, error = future.result()
                if error:
                    stats['failed_batches'] += 1
                    stats['batch_errors'].append({'batch': batch_index, 'count': len(batch), 'error': error})
                else:
                    for item in data:
                        if item.get('ok') is not True:
                            continue
                        probe_results = item.get('probe_results') or []
                        candidate = item.get('candidate', '')
                        status_codes = ';'.join(str(p.get('status_code')) for p in probe_results if p.get('status_code') is not None)
                        exit_ips = ';'.join(sorted({p.get('exit_ip') for p in probe_results if p.get('exit_ip')}))
                        exit_countries = ';'.join(sorted({p.get('exit_country') for p in probe_results if p.get('exit_country')}))
                        exit_asns = ';'.join(sorted({str(p.get('exit_asn')) for p in probe_results if p.get('exit_asn') is not None}))
                        txt_out.write(candidate + '\n')
                        writer.writerow([
                            candidate,
                            label,
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
                        stats['success_candidates'] += 1
                if batch_index % 100 == 0 or batch_index == total_batches:
                    log(f'[{label}] progress {batch_index}/{total_batches} batches, successes={stats["success_candidates"]}, failed_batches={stats["failed_batches"]}')

    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    return {
        'success_txt': success_txt,
        'success_csv': success_csv,
        'manifest_path': manifest_path,
        **stats,
    }


def process_asn_item(
    item,
    workdir: str,
    seed: int | None,
    download_only: bool = False,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_workers: int = DEFAULT_MAX_WORKERS,
    probe_url: str = DEFAULT_PROBE_URL,
    retries: int = DEFAULT_RETRIES,
    timeout: int = DEFAULT_TIMEOUT,
):
    label = item['label']
    asn = item['asn']
    range_path = os.path.join(workdir, f'{label}-ip-ranges.txt')
    log(f'[{label}] downloading ranges from {asn}')
    cidrs = download_asn_ranges(asn, range_path)
    prefixes = load_ipv4_prefixes(range_path)
    log(f'[{label}] saved {len(cidrs)} ranges, IPv4 prefixes={len(prefixes)}')

    candidate_path = os.path.join(workdir, f'{label}-ipv4-443-8443.txt')
    if item['generation_mode'] == 'full':
        candidate_count = write_candidates_to_file(expand_candidates_full(prefixes, item['ports']), candidate_path)
        generation = {'mode': 'full', 'candidate_count': candidate_count}
    elif item['generation_mode'] == 'random':
        candidates = sample_random_candidates(prefixes, item['ports'], item['max_candidates'], seed=seed)
        candidate_count = write_candidates_to_file(candidates, candidate_path)
        generation = {'mode': 'random', 'candidate_count': candidate_count, 'max_candidates': item['max_candidates'], 'seed': seed}
    else:
        raise ValueError(f'unknown generation mode: {item["generation_mode"]}')

    result = {
        'label': label,
        'asn': asn,
        'range_path': range_path,
        'candidate_path': candidate_path,
        **generation,
    }

    if download_only:
        return result

    with open(candidate_path, 'r', encoding='utf-8') as f:
        candidates = [line.strip() for line in f if line.strip()]
    probe_summary = probe_candidates(
        candidates,
        label,
        workdir=workdir,
        batch_size=batch_size,
        max_workers=max_workers,
        probe_url=probe_url,
        retries=retries,
        timeout=timeout,
    )
    result.update(probe_summary)
    return result


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Download ASN ranges, generate IP:port candidates, and probe them.')
    parser.add_argument('--workdir', default=WORKDIR)
    parser.add_argument('--asn', action='append', help='Only run selected ASN labels, e.g. 4766, 25820, dmit906, AS906')
    parser.add_argument('--seed', type=int, default=4766)
    parser.add_argument('--max-random-4766', type=int, default=DEFAULT_MAX_RANDOM_4766)
    parser.add_argument('--batch-size', type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument('--max-workers', type=int, default=DEFAULT_MAX_WORKERS)
    parser.add_argument('--retries', type=int, default=DEFAULT_RETRIES)
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument('--probe-url', default=DEFAULT_PROBE_URL)
    parser.add_argument('--download-only', action='store_true')
    return parser.parse_args(argv)


def main():
    args = parse_args()
    os.makedirs(args.workdir, exist_ok=True)
    plan = select_plan(build_default_asn_plan(max_random_4766=args.max_random_4766), only_labels=args.asn)
    results = []
    for item in plan:
        results.append(
            process_asn_item(
                item,
                workdir=args.workdir,
                seed=args.seed,
                download_only=args.download_only,
                batch_size=args.batch_size,
                max_workers=args.max_workers,
                probe_url=args.probe_url,
                retries=args.retries,
                timeout=args.timeout,
            )
        )
    summary_path = os.path.join(args.workdir, 'complete-asn-probe-summary.json')
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    log(f'[all done] summary={summary_path}')


if __name__ == '__main__':
    main()
