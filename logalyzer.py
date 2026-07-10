#!/usr/bin/env python3
"""
Logalyzer – CLI tool for Apache combined log analysis.

Usage:
    python logalyzer.py access.log
    python logalyzer.py access.log --json
    python logalyzer.py access.log --start "2026-06-01T09:00:00" --end "2026-06-01T10:00:00"
    python logalyzer.py access.log --suspicious --suspicious-threshold 10
    python logalyzer.py access.log --error-bursts --burst-threshold 10
    python logalyzer.py access.log.gz
"""

import argparse
import gzip
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, Generator, List, Optional, Tuple

# Combined Log Format regex
LOG_PATTERN = re.compile(
    r'^(\S+) '                         # IP
    r'(\S+) '                          # ident (usually -)
    r'(\S+) '                          # user (usually -)
    r'\[([^\]]+)\] '                   # [datetime timezone]
    r'"(\S+) (\S+) (\S+)" '            # "METHOD /path PROTOCOL"
    r'(\d{3}) '                        # status
    r'(\S+) '                          # size (or -)
    r'"([^"]*)" '                      # referer
    r'"([^"]*)"$'                      # user-agent
)


def parse_line(line: str) -> Optional[dict]:
    """Parse a single log line. Returns dict with extracted fields or None if malformed."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    ip, ident, user, dt_str, method, path, protocol, status_str, size_str, referer, ua = match.groups()

    # Parse datetime: format 01/Jun/2026:09:14:22 +0000
    try:
        dt_part, tz_part = dt_str.rsplit(' ', 1)
        dt = datetime.strptime(dt_part, '%d/%b/%Y:%H:%M:%S')
    except (ValueError, AttributeError):
        return None

    # Parse status code
    try:
        status = int(status_str)
    except ValueError:
        return None

    # Size can be '-' or integer
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


def read_logs_with_bad(file_path: str) -> Generator[Optional[dict], None, None]:
    """
    Generator that yields parsed log entries line by line.
    Yields None for malformed lines so they can be counted.
    Supports plain text and gzipped files.
    """
    open_func = gzip.open if file_path.endswith('.gz') else open
    with open_func(file_path, 'rt', encoding='utf-8', errors='replace') as f:
        for line in f:
            yield parse_line(line)          # may be None


def print_hourly_histogram(hourly: Dict[str, int]) -> None:
    """Print a simple ASCII histogram of hourly request counts."""
    if not hourly:
        print("No data for hourly distribution.")
        return

    max_count = max(hourly.values())
    scale = 1
    if max_count > 60:          # scale bar width to fit terminal
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
    parser.add_argument('--json', action='store_true', help='Output report in JSON format')
    parser.add_argument('--start', help='Filter entries after this ISO datetime (e.g., 2026-06-01T09:00:00)')
    parser.add_argument('--end', help='Filter entries before this ISO datetime')
    parser.add_argument('--suspicious', action='store_true', help='Detect suspicious activity (401 on /login)')
    parser.add_argument('--suspicious-threshold', type=int, default=50,
                        help='Min number of 401 attempts on /login to flag (default: 50)')
    parser.add_argument('--error-bursts', action='store_true', help='Detect time windows with high 5xx error rate')
    parser.add_argument('--burst-threshold', type=float, default=20.0,
                        help='Error rate percent threshold for bursts (default 20)')
    args = parser.parse_args()

    start_time = time.time()

    # Single-pass generator (yields None for bad lines)
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

    # Aggregation counters
    total = 0
    ip_set = set()
    endpoint_counter = Counter()
    errors_4xx_5xx = 0
    hourly = defaultdict(int)
    ip_401_login = Counter()
    minute_total = defaultdict(int)
    minute_5xx = defaultdict(int)
    bad_lines = 0

    # Main single-pass loop
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

        # Suspicious: match /login with or without trailing slash
        if args.suspicious and entry['path'].rstrip('/') == '/login' and entry['status'] == 401:
            ip_401_login[entry['ip']] += 1

        # Error burst data: per-minute counts
        minute = entry['datetime'].replace(second=0, microsecond=0)
        minute_total[minute] += 1
        if 500 <= entry['status'] <= 599:
            minute_5xx[minute] += 1

    # Compute basic statistics
    error_rate = (errors_4xx_5xx / total * 100) if total > 0 else 0.0
    top10 = endpoint_counter.most_common(10)

    # Suspicious IPs (configurable threshold)
    suspicious_ips = [(ip, cnt) for ip, cnt in ip_401_login.items() if cnt >= args.suspicious_threshold]

    # Error burst detection (5-minute sliding window)
    bursts = []
    if args.error_bursts and minute_total:
        all_minutes = sorted(minute_total.keys())
        start_t = all_minutes[0]
        end_t = all_minutes[-1] + timedelta(minutes=1)
        window = 5               # 5-minute window
        current = start_t
        while current + timedelta(minutes=window) <= end_t:
            window_end = current + timedelta(minutes=window)
            w_total = 0
            w_errors = 0
            for t in all_minutes:
                if current <= t < window_end:
                    w_total += minute_total[t]
                    w_errors += minute_5xx[t]
            if w_total > 0:
                rate = w_errors / w_total * 100
                if rate >= args.burst_threshold:
                    bursts.append({
                        'start': current.strftime('%Y-%m-%d %H:%M'),
                        'end': window_end.strftime('%Y-%m-%d %H:%M'),
                        'error_rate': round(rate, 2)
                    })
            current += timedelta(minutes=1)

    # Build report dictionary
    report = {
        'total_requests': total,
        'bad_lines': bad_lines,
        'unique_ips': len(ip_set),
        'top_endpoints': top10,
        'error_rate_percent': round(error_rate, 2),
        'hourly_distribution': dict(sorted(hourly.items()))
    }
    if args.suspicious:
        report['suspicious_ips'] = suspicious_ips
        report['suspicious_threshold'] = args.suspicious_threshold
    if args.error_bursts:
        report['error_bursts'] = bursts

    elapsed = time.time() - start_time
    report['execution_time_sec'] = round(elapsed, 2)

    # Output
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"Total requests: {total}")
        print(f"Bad lines skipped: {bad_lines}")
        print(f"Unique IPs: {len(ip_set)}")
        print(f"Error rate (4xx+5xx): {round(error_rate, 2)}%")
        print("\nTop 10 endpoints:")
        for path, count in top10:
            print(f"  {count:>6} {path}")

        if args.suspicious:
            print(f"\nSuspicious activity (>={args.suspicious_threshold} x 401 on /login):")
            if suspicious_ips:
                for ip, cnt in suspicious_ips:
                    print(f"  {ip}: {cnt} attempts")
            else:
                print("  None detected.")

        if args.error_bursts:
            print(f"\nError bursts (5xx rate >= {args.burst_threshold}% in 5-min windows):")
            if bursts:
                for b in bursts:
                    print(f"  {b['start']} – {b['end']}: {b['error_rate']}%")
            else:
                print("  No bursts detected.")

        print_hourly_histogram(report['hourly_distribution'])

        print(f"\nExecution time: {elapsed:.2f} seconds")


if __name__ == '__main__':
    main()
