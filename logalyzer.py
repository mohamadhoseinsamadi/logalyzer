#!/usr/bin/env python3
"""
Logalyzer – CLI tool for Apache combined log analysis.
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, Generator, Optional


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


def parse_line(line: str) -> Optional[dict]:
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
        'ip': ip, 'datetime': dt, 'timezone': tz_part,
        'method': method, 'path': path, 'protocol': protocol,
        'status': status, 'size': size, 'referer': referer, 'user_agent': ua
    }


def print_hourly_histogram(hourly: Dict[str, int]):
    if not hourly:
        print("No data for hourly distribution.")
        return
    max_count = max(hourly.values())
    scale = 1
    if max_count > 60:
        scale = max_count // 60 + 1
    print("\nHourly request distribution:")
    print("Hour                Count  Histogram")
    print("-" * 60)
    for hour, count in hourly.items():
        bar = '#' * (count // scale)
        print(f"{hour}  {count:>6}  {bar}")


def main():
    parser = argparse.ArgumentParser(description='Analyze Apache combined access logs.')
    parser.add_argument('file', help='Path to log file (plain or .gz)')
    parser.add_argument('--start', help='Filter entries after this ISO datetime')
    parser.add_argument('--end', help='Filter entries before this ISO datetime')
    args = parser.parse_args()

    # Read generator that also yields None for bad lines
    def read_logs_with_bad(file_path: str):
        with open(file_path, 'rt', encoding='utf-8', errors='replace') as f:
            for line in f:
                entry = parse_line(line)
                yield entry  # may be None

    entries_stream = read_logs_with_bad(args.file)

    # Apply time filters if needed
    if args.start or args.end:
        try:
            start_dt = datetime.fromisoformat(args.start) if args.start else None
            end_dt = datetime.fromisoformat(args.end) if args.end else None
        except ValueError:
            print("Invalid start/end datetime format. Use ISO format, e.g., 2026-06-01T09:00:00")
            sys.exit(1)

        def time_filter(gen):
            for entry in gen:
                if entry is None:
                    yield None
                    continue
                if args.start and entry['datetime'] < start_dt:
                    continue
                if args.end and entry['datetime'] > end_dt:
                    continue
                yield entry
        entries_stream = time_filter(entries_stream)

    # Single pass: gather all statistics
    total = 0
    ip_set = set()
    endpoint_counter = Counter()
    errors_4xx_5xx = 0
    hourly = defaultdict(int)
    bad_lines = 0

    for entry in entries_stream:
        if entry is None:
            bad_lines += 1
            continue
        total += 1
        ip_set.add(entry['ip'])
        endpoint_counter[entry['path']] += 1
        if 400 <= entry['status'] <= 599:
            errors_4xx_5xx += 1
        hour_key = entry['datetime'].strftime('%Y-%m-%d %H:00')
        hourly[hour_key] += 1

    error_rate = (errors_4xx_5xx / total * 100) if total > 0 else 0.0
    top10 = endpoint_counter.most_common(10)

    print(f"Total requests: {total}")
    print(f"Bad lines skipped: {bad_lines}")
    print(f"Unique IPs: {len(ip_set)}")
    print(f"Error rate (4xx+5xx): {round(error_rate, 2)}%")
    print("\nTop 10 endpoints:")
    for path, count in top10:
        print(f"  {count:>6} {path}")

    print_hourly_histogram(dict(sorted(hourly.items())))


if __name__ == '__main__':
    main()