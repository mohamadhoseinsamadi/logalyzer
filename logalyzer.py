#!/usr/bin/env python3
"""
Logalyzer – CLI tool for Apache combined log analysis.
"""

import argparse
import re
import sys
from collections import Counter
from datetime import datetime
from typing import Generator


# Regex for Combined Log Format.
LOG_PATTERN = re.compile(
    r'^(\S+) '  # IP
    r'(\S+) '  # ident
    r'(\S+) '  # user
    r'\[([^\]]+)\] '  # [datetime timezone]
    r'"(\S+) (\S+) (\S+)" '  # "METHOD /path PROTOCOL"
    r'(\d{3}) '  # status
    r'(\S+) '  # size
    r'"([^"]*)" '  # referer
    r'"([^"]*)"$'  # user-agent
)


def parse_line(line: str):
    """Parse a single log line. Returns dict with extracted fields or None if malformed."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    ip, ident, user, dt_str, method, path, protocol, status_str, size_str, referer, ua = match.groups()

    try:
        dt_part, tz_part = dt_str.rsplit(' ', 1)
        dt = datetime.strptime(dt_part, '%d/%b/%Y:%H:%M:%S')
    except (ValueError, AttributeError):
        return None

    try:
        status = int(status_str)
    except ValueError:
        return None

    size = None
    if size_str != '-':
        try:
            size = int(size_str)
        except ValueError:
            size = None

    return {
        'ip': ip,
        'datetime': dt,
        'timezone': tz_part,
        'method': method,
        'path': path,
        'protocol': protocol,
        'status': status,
        'size': size,
        'referer': referer,
        'user_agent': ua
    }


def read_logs(file_path: str) -> Generator[dict, None, None]:
    """Generator that yields parsed log entries line by line."""
    with open(file_path, 'rt', encoding='utf-8', errors='replace') as f:
        for line in f:
            entry = parse_line(line)
            if entry:
                yield entry


def basic_report(entries):
    total = 0
    ip_set = set()
    endpoint_counter = Counter()
    errors_4xx_5xx = 0

    for entry in entries:
        total += 1
        ip_set.add(entry['ip'])
        endpoint_counter[entry['path']] += 1
        if 400 <= entry['status'] <= 599:
            errors_4xx_5xx += 1

    error_rate = (errors_4xx_5xx / total * 100) if total > 0 else 0.0
    top10 = endpoint_counter.most_common(10)

    return {
        'total_requests': total,
        'unique_ips': len(ip_set),
        'top_endpoints': top10,
        'error_rate': round(error_rate, 2)
    }


def main():
    parser = argparse.ArgumentParser(description='Analyze Apache combined access logs.')
    parser.add_argument('file', help='Path to log file (plain or .gz)')
    args = parser.parse_args()

    entries = read_logs(args.file)
    report = basic_report(entries)

    print(f"Total requests: {report['total_requests']}")
    print(f"Unique IPs: {report['unique_ips']}")
    print(f"Error rate (4xx+5xx): {report['error_rate']}%")
    print("\nTop 10 endpoints:")
    for path, count in report['top_endpoints']:
        print(f"  {count:>6} {path}")


if __name__ == '__main__':
    main()