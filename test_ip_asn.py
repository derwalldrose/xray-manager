import gzip, os, tempfile, unittest
import ip_asn


def _write(path, lines):
    with gzip.open(path, "wt") as f:
        f.write("\n".join(lines) + "\n")


class AsnDBTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.old_min = ip_asn.MIN_ROWS
        ip_asn.MIN_ROWS = 1

    def tearDown(self):
        ip_asn.MIN_ROWS = self.old_min

    def test_tsv_with_country(self):
        p = os.path.join(self.dir, "a.tsv.gz")
        _write(p, ["1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET",
                   "1.0.1.0\t1.0.3.255\t0\tNone\tNot routed",
                   "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE"])
        db = ip_asn.AsnDB(p)
        self.assertTrue(db.load())
        self.assertEqual(db.lookup("8.8.8.8")["asn"], "15169")
        self.assertEqual(db.lookup("1.0.0.1")["country"], "US")
        self.assertIsNone(db.lookup("1.0.2.1"))       # not routed
        self.assertIsNone(db.lookup("9.9.9.9"))       # gap
        self.assertIsNone(db.lookup("2001:db8::1"))   # IPv6 -> fallback

    def test_csv_without_country(self):
        p = os.path.join(self.dir, "b.csv.gz")
        _write(p, ['1.0.0.0,1.0.0.255,13335,CLOUDFLARENET',
                   '8.8.8.0,8.8.8.255,15169,"GOOGLE, LLC"'])
        db = ip_asn.AsnDB(p)
        self.assertTrue(db.load())
        m = db.lookup("8.8.8.8")
        self.assertEqual((m["asn"], m["country"], m["as_name"]), ("15169", "", "GOOGLE, LLC"))

    def test_bad_file_keeps_previous(self):
        p = os.path.join(self.dir, "c.tsv.gz")
        _write(p, ["8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE"])
        db = ip_asn.AsnDB(p)
        self.assertTrue(db.load())
        with open(p, "wb") as f:
            f.write(b"not gzip")
        self.assertFalse(db.load())
        self.assertEqual(db.lookup("8.8.8.8")["asn"], "15169")

    def test_failed_download_retries_with_backoff_then_resets(self):
        p = os.path.join(self.dir, "d.tsv.gz")
        missing = "file://" + os.path.join(self.dir, "nope.tsv.gz")
        db = ip_asn.AsnDB(p, [missing])
        waits = [db._tick() for _ in range(6)]
        self.assertEqual(waits, [300, 600, 1200, 2400, 3600, 3600])
        self.assertIn("update:", db.error)
        src = os.path.join(self.dir, "src.tsv.gz")
        _write(src, ["8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE"])
        db.urls = ["file://" + src]
        self.assertEqual(db._tick(), ip_asn.CHECK_SECONDS)
        self.assertEqual((db.rows, db.error), (1, ""))
        self.assertEqual(db.lookup("8.8.8.8")["asn"], "15169")

    def test_replaced_file_is_reloaded_without_restart(self):
        p = os.path.join(self.dir, "e.tsv.gz")
        _write(p, ["8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE"])
        db = ip_asn.AsnDB(p, ["file:///nonexistent.tsv.gz"])
        self.assertTrue(db.load())
        self.assertEqual(db._tick(), ip_asn.CHECK_SECONDS)   # unchanged: no reload
        loaded = db.loaded_at
        tmp = p + ".new"
        _write(tmp, ["1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET",
                     "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE"])
        os.utime(tmp, (os.path.getmtime(p) + 5,) * 2)
        os.replace(tmp, p)
        db._tick()
        self.assertEqual(db.rows, 2)
        self.assertEqual(db.lookup("1.0.0.1")["asn"], "13335")
        self.assertGreaterEqual(db.loaded_at, loaded)

    def test_missing_file_at_start_is_loaded_when_it_appears(self):
        p = os.path.join(self.dir, "f.tsv.gz")
        db = ip_asn.AsnDB(p, ["file:///nonexistent.tsv.gz"])
        self.assertFalse(db.load())
        self.assertEqual(db._tick(), 300)                     # download failed
        _write(p, ["8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE"])   # fetched by hand
        self.assertEqual(db._tick(), ip_asn.CHECK_SECONDS)
        self.assertEqual(db.rows, 1)

    def test_corrupt_replacement_is_not_reparsed_every_tick(self):
        p = os.path.join(self.dir, "g.tsv.gz")
        _write(p, ["8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE"])
        db = ip_asn.AsnDB(p, ["file:///nonexistent.tsv.gz"])
        self.assertTrue(db.load())
        with open(p, "wb") as f:
            f.write(b"not gzip")
        os.utime(p, (os.path.getmtime(p) + 5,) * 2)
        calls = []
        orig = db._parse
        db._parse = lambda path: (calls.append(path), orig(path))[1]
        db._tick(); db._tick()
        self.assertEqual(len(calls), 1)
        self.assertEqual(db.lookup("8.8.8.8")["asn"], "15169")


if __name__ == "__main__":
    unittest.main()
