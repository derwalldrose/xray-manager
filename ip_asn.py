"""Offline IPv4 -> ASN lookup from the public-domain iptoasn.com dataset.

The TSV (range_start, range_end, as_number, country, as_description) is kept
gzip-compressed on disk and loaded into compact arrays; a lookup is a single
bisect, so the panel no longer waits on whois for ASN/owner columns.
"""
import array
import bisect
import csv
import gzip
import ipaddress
import os
import threading
import time
import urllib.request

DEFAULT_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
# Same iptoasn data republished by ip-location-db on npm; served by jsDelivr,
# much faster from mainland China but without the country column.
FALLBACK_URL = "https://cdn.jsdelivr.net/npm/@ip-location-db/iptoasn-asn/iptoasn-asn-ipv4.csv"
MIN_ROWS = 100000          # sanity check for a downloaded file
REFRESH_SECONDS = 7 * 86400


class AsnDB:
    def __init__(self, path, urls=(DEFAULT_URL, FALLBACK_URL)):
        self.path = path
        self.urls = [u for u in ([urls] if isinstance(urls, str) else urls) if u]
        self.source = ""
        self._lock = threading.Lock()
        self._starts = array.array("I")
        self._ends = array.array("I")
        self._idx = array.array("I")
        self._info = []
        self.loaded_at = 0
        self.rows = 0
        self.error = ""
        self.updating = False

    # ---------- loading ----------
    @staticmethod
    def _parse(path):
        starts, ends, idx = array.array("I"), array.array("I"), array.array("I")
        info, info_index = [], {}
        with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as f:
            first = f.readline()
            f.seek(0)
            if "\t" in first:          # iptoasn TSV: start end asn country name
                rows = (line.rstrip("\r\n").split("\t") for line in f)
            else:                       # ip-location-db CSV: start,end,asn,name
                rows = ([r[0], r[1], r[2], "", r[3]] for r in csv.reader(f) if len(r) >= 4)
            for parts in rows:
                if len(parts) < 5:
                    continue
                asn = parts[2]
                if asn in ("0", ""):    # "Not routed"
                    continue
                try:
                    a = int(ipaddress.IPv4Address(parts[0]))
                    b = int(ipaddress.IPv4Address(parts[1]))
                except ValueError:
                    continue
                if starts and a < starts[-1]:
                    continue            # keep the arrays sorted for bisect
                key = (asn, parts[3], parts[4])
                i = info_index.get(key)
                if i is None:
                    i = info_index[key] = len(info)
                    info.append(key)
                starts.append(a)
                ends.append(b)
                idx.append(i)
        return starts, ends, idx, info

    def load(self):
        if not os.path.exists(self.path):
            return False
        try:
            starts, ends, idx, info = self._parse(self.path)
        except Exception as e:  # corrupt file: keep the previous tables
            self.error = f"load: {e}"
            return False
        if len(starts) < MIN_ROWS:
            self.error = f"load: only {len(starts)} rows"
            return False
        with self._lock:
            self._starts, self._ends, self._idx, self._info = starts, ends, idx, info
            self.rows = len(starts)
            self.loaded_at = int(time.time())
            self.error = ""
        return True

    # ---------- updating ----------
    def file_age(self):
        try:
            return time.time() - os.path.getmtime(self.path)
        except OSError:
            return None

    def _fetch(self, url, tmp, timeout, deadline):
        req = urllib.request.Request(url, headers={"User-Agent": "derwalld"})
        gz = url.endswith(".gz")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out = open(tmp, "wb") if gz else gzip.open(tmp, "wb", compresslevel=6)
            with out:
                while True:
                    if time.time() > deadline:
                        raise TimeoutError("download too slow")
                    chunk = r.read(1 << 16)
                    if not chunk:
                        break
                    out.write(chunk)

    def update(self, timeout=60, total=900):
        """Download (first working URL), validate, atomically replace, reload."""
        if self.updating:
            return False
        self.updating = True
        tmp = self.path + ".tmp"
        errors = []
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            for url in self.urls:
                try:
                    self._fetch(url, tmp, timeout, time.time() + total)
                    starts, _, _, _ = self._parse(tmp)
                    if len(starts) < MIN_ROWS:
                        raise ValueError(f"only {len(starts)} rows")
                    os.replace(tmp, self.path)
                    self.source = url
                    return self.load()
                except Exception as e:
                    errors.append(f"{url}: {e}")
            self.error = "update: " + " | ".join(errors)
            return False
        finally:
            self.updating = False
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass

    def start(self):
        """Load in the background and refresh weekly; never blocks the caller."""
        def run():
            self.load()
            while True:
                age = self.file_age()
                if age is None or age > REFRESH_SECONDS:
                    self.update()
                time.sleep(6 * 3600)
        threading.Thread(target=run, name="ip-asn", daemon=True).start()

    # ---------- lookup ----------
    def lookup(self, ip):
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        with self._lock:
            i = bisect.bisect_right(self._starts, n) - 1
            if i < 0 or n > self._ends[i]:
                return None
            asn, cc, name = self._info[self._idx[i]]
        return {"asn": asn, "country": cc, "as_name": name, "source": "iptoasn"}

    def status(self):
        return {"rows": self.rows, "loaded_at": self.loaded_at, "error": self.error,
                "updating": self.updating, "file_age": self.file_age(), "source": self.source}
