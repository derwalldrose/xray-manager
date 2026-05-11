#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

USER_AGENT = "Mozilla/5.0"
TARGET_COUNT = 3
DEFAULT_PORT = "12345"
DEFAULT_HOSTNAME = "kr1.270376.xyz"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_pool(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def save_pool(path: Path, candidates: list[str]) -> None:
    uniq = list(dict.fromkeys(candidates))
    path.write_text("\n".join(uniq) + ("\n" if uniq else ""), encoding="utf-8")


def backup_with_timestamp(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_name(f"{path.stem}.bak-{time.strftime('%Y%m%d-%H%M%S')}{path.suffix}")
    backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return backup


def candidate_ip(candidate: str) -> str:
    return candidate.rsplit(":", 1)[0] if ":" in candidate else candidate


def candidate_port(candidate: str) -> str:
    return candidate.rsplit(":", 1)[1] if ":" in candidate else ""


class TelegramNotifier:
    def __init__(self, token: str | None, chat_id: str | None):
        self.token = token or ""
        self.chat_id = str(chat_id or "")

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def send(self, text: str) -> None:
        if not self.enabled:
            return
        data = urllib.parse.urlencode({
            "chat_id": self.chat_id,
            "text": text,
            "disable_web_page_preview": "true",
        }).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{self.token}/sendMessage",
            data=data,
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = resp.read().decode("utf-8", "replace")
            parsed = json.loads(body)
            if not parsed.get("ok", False):
                print(f"telegram notify failed: {parsed}", flush=True)
        except Exception as e:
            print(f"telegram notify exception: {e!r}", flush=True)


class CloudflareClient:
    def __init__(self, *, email: str, global_api_key: str):
        self.email = email
        self.global_api_key = global_api_key

    def _request(self, method: str, url: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {
            "User-Agent": USER_AGENT,
            "X-Auth-Email": self.email,
            "X-Auth-Key": self.global_api_key,
        }
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", "replace")
        parsed = json.loads(body)
        if not parsed.get("success", False):
            raise RuntimeError(f"Cloudflare API failed: {parsed}")
        return parsed

    def get_zone_id(self, zone_name: str) -> str:
        q = urllib.parse.quote(zone_name)
        data = self._request("GET", f"https://api.cloudflare.com/client/v4/zones?name={q}")
        results = data.get("result") or []
        if not results:
            raise RuntimeError(f"zone not found: {zone_name}")
        return results[0]["id"]

    def list_txt_records(self, zone_id: str, name: str) -> list[dict[str, Any]]:
        qname = urllib.parse.quote(name)
        data = self._request("GET", f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=TXT&name={qname}")
        return data.get("result") or []

    def list_a_records(self, zone_id: str, name: str) -> list[dict[str, Any]]:
        qname = urllib.parse.quote(name)
        data = self._request("GET", f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={qname}")
        return data.get("result") or []

    def upsert_single_txt_record(self, zone_id: str, name: str, content: str, ttl: int = 60) -> dict[str, Any]:
        existing = self.list_txt_records(zone_id, name)
        payload = {"type": "TXT", "name": name, "content": content, "ttl": ttl}
        if existing:
            primary = existing[0]
            data = self._request("PUT", f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{primary['id']}", payload)
            for extra in existing[1:]:
                self._request("DELETE", f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{extra['id']}")
            return data["result"]
        data = self._request("POST", f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", payload)
        return data["result"]

    def replace_a_records(self, zone_id: str, name: str, ips: list[str], ttl: int = 60) -> list[dict[str, Any]]:
        existing = self.list_a_records(zone_id, name)
        for rec in existing:
            self._request("DELETE", f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec['id']}")
        created = []
        for ip in ips:
            data = self._request("POST", f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", {
                "type": "A", "name": name, "content": ip, "ttl": ttl, "proxied": False
            })
            created.append(data["result"])
        return created


def probe_one(candidate: str, timeout: int = 15) -> dict[str, Any]:
    payload = json.dumps({"candidates": [candidate]}).encode()
    req = urllib.request.Request(
        "https://ck.batch10p.workers.dev/probe",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
        data = json.loads(body)
        if isinstance(data, dict):
            if "results" in data and isinstance(data["results"], list):
                data = data["results"]
            else:
                data = [data]
        if data:
            item = data[0]
            item.setdefault("candidate", candidate)
            return item
    except Exception as e:
        return {"candidate": candidate, "ok": False, "batch_error": repr(e), "probe_results": []}
    return {"candidate": candidate, "ok": False, "batch_error": "empty response", "probe_results": []}


def is_kr_success(item: dict[str, Any]) -> bool:
    if not item.get("ok"):
        return False
    for pr in item.get("probe_results") or []:
        country = pr.get("exit_country")
        if country in ("South Korea", "Korea, Republic of", "KR", "韩国"):
            return True
    return False


def extract_csv_candidates(csv_path: Path, *, asn: str, port: str) -> list[str]:
    if not csv_path.exists():
        return []
    rows = list(csv.DictReader(csv_path.read_text(encoding="utf-8-sig").splitlines()))
    out: list[str] = []
    for r in rows:
        ip = (r.get("IP地址") or "").strip()
        row_port = (r.get("端口号") or r.get("端口") or "").strip()
        row_asn = (r.get("ASN号码") or "").strip()
        if ip and row_port == port and row_asn == asn:
            out.append(f"{ip}:{row_port}")
    return list(dict.fromkeys(out))


def wait_for_scan_finish(timeout_secs: int = 14400) -> None:
    start = time.time()
    while True:
        proc = subprocess.run(["/root/scan-asn.sh", "status"], capture_output=True, text=True)
        out = proc.stdout.strip()
        print(out, flush=True)
        if not out.startswith("running "):
            return
        if time.time() - start > timeout_secs:
            raise TimeoutError(f"scan wait timeout after {timeout_secs}s")
        time.sleep(30)


def run_scan(asn: str, port: str, rate: str, csv_path: Path) -> None:
    subprocess.run([
        "/root/scan-asn.sh", "start",
        "--asn", asn,
        "--ports", port,
        "--rate", rate,
        "--iptest-speedtest", "0",
        "--workdir", "/root/masscan-asn-runner",
    ], check=True)
    wait_for_scan_finish()
    if not csv_path.exists():
        raise FileNotFoundError(f"missing expected iptest output: {csv_path}")


def merge_into_pool(pool_path: Path, additions: list[str]) -> dict[str, Any]:
    existing = load_pool(pool_path)
    backup = backup_with_timestamp(pool_path)
    merged = list(dict.fromkeys(existing + additions))
    save_pool(pool_path, merged)
    return {
        "backup": str(backup) if backup else None,
        "existing": len(existing),
        "new_unique": len(set(additions)),
        "merged": len(merged),
        "new_additions": len(set(additions) - set(existing)),
    }


def get_current_txt(cf: CloudflareClient, zone_id: str, name: str) -> list[str]:
    records = cf.list_txt_records(zone_id, name)
    if not records:
        return []
    content = records[0].get("content", "")
    return [part.strip() for part in content.split(",") if part.strip()]


def maintain(args: argparse.Namespace) -> dict[str, Any]:
    config = load_json(args.config)
    cf = CloudflareClient(email=config["email"], global_api_key=config["globalApiKey"])
    notifier = TelegramNotifier(args.tg_token, args.tg_chat_id)
    zone = args.zone or config["zone"]
    hostname = args.record_name
    zone_id = cf.get_zone_id(zone)

    pool_path = args.success_pool
    pool = load_pool(pool_path)
    current_txt = get_current_txt(cf, zone_id, hostname)
    checked_failed: list[str] = []
    kept: list[str] = []
    seen = set()

    for cand in current_txt:
        if cand in seen or candidate_port(cand) != args.port:
            continue
        seen.add(cand)
        item = probe_one(cand)
        if is_kr_success(item):
            kept.append(cand)
        else:
            checked_failed.append(cand)

    if len(kept) < args.target_count:
        for cand in pool:
            if cand in seen or cand in kept:
                continue
            if candidate_port(cand) != args.port:
                continue
            seen.add(cand)
            item = probe_one(cand)
            if is_kr_success(item):
                kept.append(cand)
            else:
                checked_failed.append(cand)
            if len(kept) >= args.target_count:
                break

    if checked_failed:
        backup = backup_with_timestamp(pool_path)
        pool = [c for c in pool if c not in set(checked_failed)]
        save_pool(pool_path, pool)
    else:
        backup = None

    if len(kept) < args.target_count:
        raise SystemExit(f"not enough working KR candidates for {hostname} port {args.port}: {len(kept)} < {args.target_count}")

    selected = kept[:args.target_count]
    txt_content = ",".join(selected)
    txt_result = None
    a_result = None
    if not args.dry_run:
        txt_result = cf.upsert_single_txt_record(zone_id, hostname, txt_content, ttl=60)
        ips = [candidate_ip(c) for c in selected]
        a_result = cf.replace_a_records(zone_id, hostname, ips, ttl=60)

    result = {
        "hostname": hostname,
        "port": args.port,
        "selected": selected,
        "ips": [candidate_ip(c) for c in selected],
        "checked_failed": checked_failed,
        "pool_size": len(load_pool(pool_path)),
        "backup": str(backup) if backup else None,
        "dry_run": args.dry_run,
        "txt_updated": bool(txt_result),
        "a_updated": bool(a_result),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
    notifier.send(
        f"kr1 maintain\n"
        f"host={hostname}\n"
        f"port={args.port}\n"
        f"selected={txt_content}\n"
        f"pool={result['pool_size']}"
    )
    return result


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--config", type=Path, default=Path("/root/hw_proxyip_inputs/cf-2025-270376.json"))
    p.add_argument("--success-pool", type=Path, default=Path("/root/hw_proxyip_inputs/state/success-pool.txt"))
    p.add_argument("--csv", type=Path, default=Path("/root/masscan-asn-runner/as4766-iptest.csv"))
    p.add_argument("--record-name", default=DEFAULT_HOSTNAME)
    p.add_argument("--zone", default="")
    p.add_argument("--port", default=DEFAULT_PORT)
    p.add_argument("--asn", default="4766")
    p.add_argument("--rate", default="30k")
    p.add_argument("--target-count", type=int, default=TARGET_COUNT)
    p.add_argument("--tg-token", default="")
    p.add_argument("--tg-chat-id", default="")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("mode", choices=["maintain", "run-once", "postprocess-only"])
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.mode == "run-once":
        run_scan(args.asn, args.port, args.rate, args.csv)
        additions = extract_csv_candidates(args.csv, asn=args.asn, port=args.port)
        if additions:
            print(json.dumps(merge_into_pool(args.success_pool, additions), ensure_ascii=False), flush=True)
        return 0
    if args.mode == "postprocess-only":
        additions = extract_csv_candidates(args.csv, asn=args.asn, port=args.port)
        print(json.dumps({"selected": len(additions), "candidates": additions}, ensure_ascii=False), flush=True)
        if additions:
            print(json.dumps(merge_into_pool(args.success_pool, additions), ensure_ascii=False), flush=True)
        return 0
    maintain(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
