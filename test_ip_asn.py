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


if __name__ == "__main__":
    unittest.main()
