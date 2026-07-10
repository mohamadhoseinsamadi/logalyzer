import tempfile
import unittest
from logalyzer import parse_line, basic_report, hourly_distribution

class TestParser(unittest.TestCase):
    def test_valid_line(self):
        line = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /products/1877 HTTP/1.1" 200 5324 "-" "Mozilla/5.0"'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry['ip'], '203.0.113.42')
        self.assertEqual(entry['status'], 200)
        self.assertEqual(entry['path'], '/products/1877')
        self.assertEqual(entry['size'], 5324)

    def test_invalid_line(self):
        line = "garbage line"
        self.assertIsNone(parse_line(line))

    def test_line_without_size(self):
        line = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET / HTTP/1.1" 200 - "-" "curl/7.68.0"'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertIsNone(entry['size'])

class TestReport(unittest.TestCase):
    def setUp(self):
        # Create a temporary log file
        self.tmp = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.tmp.write('203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /a HTTP/1.1" 200 100 "-" "Mozilla"\n')
        self.tmp.write('203.0.113.43 - - [01/Jun/2026:09:14:23 +0000] "GET /b HTTP/1.1" 404 0 "-" "Mozilla"\n')
        self.tmp.write('203.0.113.42 - - [01/Jun/2026:09:15:00 +0000] "GET /a HTTP/1.1" 200 50 "-" "Mozilla"\n')
        self.tmp.write('invalid line\n')
        self.tmp.close()

    def tearDown(self):
        import os
        os.unlink(self.tmp.name)

    def test_total_requests(self):
        from logalyzer import read_logs_with_bad
        entries = (e for e in read_logs_with_bad(self.tmp.name) if e is not None)
        stats = basic_report(entries)
        self.assertEqual(stats['total_requests'], 3)

    def test_unique_ips(self):
        from logalyzer import read_logs_with_bad
        entries = (e for e in read_logs_with_bad(self.tmp.name) if e is not None)
        stats = basic_report(entries)
        self.assertEqual(stats['unique_ips'], 2)

    def test_error_rate(self):
        from logalyzer import read_logs_with_bad
        entries = (e for e in read_logs_with_bad(self.tmp.name) if e is not None)
        stats = basic_report(entries)
        self.assertAlmostEqual(stats['error_rate'], 33.33, places=2)

    def test_hourly_distribution(self):
        from logalyzer import read_logs_with_bad
        entries = (e for e in read_logs_with_bad(self.tmp.name) if e is not None)
        dist = hourly_distribution(entries)
        self.assertEqual(dist['2026-06-01 09:00'], 3)

if __name__ == '__main__':
    unittest.main()
