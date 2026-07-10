import tempfile
import os
import unittest
from logalyzer import parse_line, read_logs_with_bad


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
        os.unlink(self.tmp.name)

    def _get_stats(self):
        """Helper to run a single pass over the temp file and return basic stats."""
        total = 0
        ip_set = set()
        endpoints = {}
        errors = 0
        hourly = {}
        bad = 0
        for entry in read_logs_with_bad(self.tmp.name):
            if entry is None:
                bad += 1
                continue
            total += 1
            ip_set.add(entry['ip'])
            path = entry['path']
            endpoints[path] = endpoints.get(path, 0) + 1
            if 400 <= entry['status'] <= 599:
                errors += 1
            hour = entry['datetime'].strftime('%Y-%m-%d %H:00')
            hourly[hour] = hourly.get(hour, 0) + 1
        error_rate = (errors / total * 100) if total > 0 else 0.0
        return total, len(ip_set), error_rate, hourly

    def test_total_requests(self):
        total, _, _, _ = self._get_stats()
        self.assertEqual(total, 3)

    def test_unique_ips(self):
        _, unique_ips, _, _ = self._get_stats()
        self.assertEqual(unique_ips, 2)

    def test_error_rate(self):
        _, _, error_rate, _ = self._get_stats()
        self.assertAlmostEqual(error_rate, 33.33, places=2)

    def test_hourly_distribution(self):
        _, _, _, hourly = self._get_stats()
        self.assertEqual(hourly['2026-06-01 09:00'], 3)


if __name__ == '__main__':
    unittest.main()