#!/usr/bin/env python3
"""
Logalyzer – CLI tool for Apache combined log analysis.

Usage:
    python logalyzer.py access.log
    python logalyzer.py access.log --json
    python logalyzer.py access.log --start "2026-06-01T09:00:00" --end "2026-06-01T10:00:00"
    python logalyzer.py access.log --suspicious
    python logalyzer.py access.log.gz
"""

import argparse
import gzip
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, Generator, List, Optional, Tuple

# Regex for Combined Log Format.
# Groups: ip, ident, user, datetime, tz, method, path, protocol, status, size, referer, user_agent
LOG_PATTERN = re.compile(
    r'^(\S+) '  # IP
    r'(\S+) '  # ident (usually -)
    r'(\S+) '  # user (usually -)
    r'\[([^\]]+)\] '  # [datetime timezone]
    r'"(\S+) (\S+) (\S+)" '  # "METHOD /path PROTOCOL"
    r'(\d{3}) '  # status
    r'(\S+) '  # size (or -)
    r'"([^"]*)" '  # referer
    r'"([^"]*)"$'  # user-agent
)


def parse_line(line: str) -> Optional[dict]:
    """Parse a single log line. Returns dict with extracted fields or None if line is malformed."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    ip, ident, user, dt_str, method, path, protocol, status_str, size_str, referer, ua = match.groups()

    # Parse datetime: format 01/Jun/2026:09:14:22 +0000
    try:
        # Split datetime and timezone
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


def read_logs(file_path: str) -> Generator[dict, None, None]:
    """Generator that yields parsed log entries line by line.
    Supports plain text and gzipped files.
    """
    open_func = gzip.open if file_path.endswith('.gz') else open
    with open_func(file_path, 'rt', encoding='utf-8', errors='replace') as f:
        for line in f:
            entry = parse_line(line)
            if entry:
                yield entry
            # Bad lines are silently skipped; counted later if needed.


def basic_report(entries: Generator[dict, None, None]) -> dict:
    """Compute basic statistics: total requests, unique IPs, top 10 endpoints, error rate."""
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


def hourly_distribution(entries: Generator[dict, None, None]) -> Dict[str, int]:
    """Return a dict mapping hour (YYYY-MM-DD HH:00) to request count."""
    hourly = defaultdict(int)
    for entry in entries:
        # Round down to hour
        hour_key = entry['datetime'].strftime('%Y-%m-%d %H:00')
        hourly[hour_key] += 1
    return dict(sorted(hourly.items()))


def print_hourly_histogram(hourly: Dict[str, int]):
    """Print a simple ASCII histogram of hourly request counts."""
    if not hourly:
        print("No data for hourly distribution.")
        return

    max_count = max(hourly.values())
    scale = 1
    if max_count > 60:  # scale bar width to fit terminal
        scale = max_count // 60 + 1

    print("\nHourly request distribution:")
    print("Hour                Count  Histogram")
    print("-" * 60)
    for hour, count in hourly.items():
        bar = '#' * (count // scale)
        print(f"{hour}  {count:>6}  {bar}")


def detect_suspicious_activity(entries: Generator[dict, None, None],
                               path: str = '/login/',
                               status: int = 401,
                               threshold: int = 50) -> List[Tuple[str, int]]:
    """
    Detect IPs with unusually high numbers of certain status on a specific path.
    Returns list of (IP, count) above threshold.
    """
    ip_counter = Counter()
    for entry in entries:
        if entry['path'] == path and entry['status'] == status:
            ip_counter[entry['ip']] += 1
    return [(ip, cnt) for ip, cnt in ip_counter.items() if cnt >= threshold]


def detect_error_bursts(entries: Generator[dict, None, None],
                        window_minutes: int = 5,
                        error_rate_spike: float = 20.0) -> List[dict]:
    """
    Detect time windows where 5xx error rate exceeds a threshold.
    We aggregate requests in 5-minute windows and flag those with error rate > spike%.
    Returns list of dicts with window start and error rate.
    """
    # We need to process entries in chronological order (log files usually are).
    # First, collect per-minute counts of total and 5xx errors.
    minute_total = defaultdict(int)
    minute_5xx = defaultdict(int)
    for entry in entries:
        minute = entry['datetime'].replace(second=0, microsecond=0)
        minute_total[minute] += 1
        if 500 <= entry['status'] <= 599:
            minute_5xx[minute] += 1

    if not minute_total:
        return []

    # Slide a window of window_minutes over the time range.
    all_minutes = sorted(minute_total.keys())
    start_time = all_minutes[0]
    end_time = all_minutes[-1] + timedelta(minutes=1)

    bursts = []
    current = start_time
    while current + timedelta(minutes=window_minutes) <= end_time:
        window_end = current + timedelta(minutes=window_minutes)
        total = 0
        errors = 0
        for t in all_minutes:
            if current <= t < window_end:
                total += minute_total[t]
                errors += minute_5xx[t]
        if total > 0:
            rate = errors / total * 100
            if rate >= error_rate_spike:
                bursts.append({
                    'start': current.strftime('%Y-%m-%d %H:%M'),
                    'end': window_end.strftime('%Y-%m-%d %H:%M'),
                    'error_rate': round(rate, 2)
                })
        current += timedelta(minutes=1)  # step by 1 minute for finer detection
    return bursts


def main():
    parser = argparse.ArgumentParser(description='Analyze Apache combined access logs.')
    parser.add_argument('file', help='Path to log file (plain or .gz)')
    parser.add_argument('--json', action='store_true', help='Output report in JSON format')
    parser.add_argument('--start', help='Filter entries after this ISO datetime (e.g., 2026-06-01T09:00:00)')
    parser.add_argument('--end', help='Filter entries before this ISO datetime')
    parser.add_argument('--suspicious', action='store_true', help='Detect suspicious activity (401 on /login/)')
    parser.add_argument('--error-bursts', action='store_true', help='Detect time windows with high 5xx error rate')
    parser.add_argument('--burst-threshold', type=float, default=20.0,
                        help='Error rate percent threshold for bursts (default 20)')
    args = parser.parse_args()

    # Read generator (filtered if needed)
    entries_raw = read_logs(args.file)

    # Apply time filters
    if args.start:
        try:
            start_dt = datetime.fromisoformat(args.start)
            entries_raw = (e for e in entries_raw if e['datetime'] >= start_dt)
        except ValueError:
            print("Invalid start datetime format. Use ISO format, e.g., 2026-06-01T09:00:00")
            sys.exit(1)
    if args.end:
        try:
            end_dt = datetime.fromisoformat(args.end)
            entries_raw = (e for e in entries_raw if e['datetime'] <= end_dt)
        except ValueError:
            print("Invalid end datetime format.")
            sys.exit(1)

    # Since generators can be consumed only once, we need to duplicate for multiple reports.
    # We will collect entries into a list (memory) ONLY if multiple reports are requested.
    # For mandatory single pass, we can compute basic stats, hourly, suspicious, bursts by
    # processing entries in a single loop, but here for clarity we'll use separate passes
    # with a single read and caching if needed. For true line-by-line without storing all,
    # we would combine computations. The task says "process line by line without loading entire file"
    # so we should avoid a list. However, to provide multiple optional reports, we might
    # need multiple passes (reading file again). I'll implement a "collector" that aggregates
    # all required stats in one pass, then print them. Let's design a single-pass collector.

    # Collect all needed statistics in one pass.
    # We'll define a class or just a function that computes everything and returns results.
    # We'll use a single loop over the generator.

    # Prepare counters
    total = 0
    ip_set = set()
    endpoint_counter = Counter()
    errors_4xx_5xx = 0
    hourly = defaultdict(int)
    # Suspicious detection
    ip_401_login = Counter()
    # Error bursts: per minute counts
    minute_total = defaultdict(int)
    minute_5xx = defaultdict(int)
    # Bad lines counter (we'll count how many lines yielded None)
    bad_lines = 0

    # We'll need to iterate over the generator once and collect all
    # For bad lines counting, we need to read raw lines; better to modify read_logs to yield
    # bad lines count. But we can compute bad lines by difference if we know total lines.
    # Simpler: count total raw lines and successful parses. We'll open file separately to count
    # raw lines? That's another pass. Alternatively, we can handle inside read_logs.
    # I'll modify the approach: read_logs will be a generator that also yields None for bad lines,
    # then we count. But the generator needs to return None for bad lines, and we filter.
    # I'll redesign read_logs to yield a tuple (is_valid, entry) or just entry or None.
    # Since we already have parse_line returning None, read_logs can yield that None.
    # Let's update: read_logs yields parsed dict or None. We'll count None as bad.


    entries_stream = read_logs_with_bad(args.file)

    # Apply time filters to stream that may contain None (skip None for time check)
    if args.start or args.end:
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

    # Single pass
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
        # suspicious
        if args.suspicious and entry['path'] == '/login/' and entry['status'] == 401:
            ip_401_login[entry['ip']] += 1
        # burst preparation
        minute = entry['datetime'].replace(second=0, microsecond=0)
        minute_total[minute] += 1
        if 500 <= entry['status'] <= 599:
            minute_5xx[minute] += 1

    # Compute reports
    error_rate = (errors_4xx_5xx / total * 100) if total > 0 else 0.0
    top10 = endpoint_counter.most_common(10)

    # Compute suspicious list
    suspicious_ips = [(ip, cnt) for ip, cnt in ip_401_login.items() if cnt >= 50]  # threshold 50

    # Compute error bursts if requested
    bursts = []
    if args.error_bursts and minute_total:
        all_minutes = sorted(minute_total.keys())
        start_t = all_minutes[0]
        end_t = all_minutes[-1] + timedelta(minutes=1)
        window = 5  # minutes
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

    # Prepare output
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
    if args.error_bursts:
        report['error_bursts'] = bursts

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
            print("\nSuspicious activity (>=50 x 401 on /login/):")
            if suspicious_ips:
                for ip, cnt in suspicious_ips:
                    print(f"  {ip}: {cnt} attempts")
            else:
                print("  None detected.")
        if args.error_bursts:
            print("\nError bursts (5xx rate >= {}% in 5-min windows):".format(args.burst_threshold))
            if bursts:
                for b in bursts:
                    print(f"  {b['start']} – {b['end']}: {b['error_rate']}%")
            else:
                print("  No bursts detected.")
        print_hourly_histogram(report['hourly_distribution'])

def read_logs_with_bad(file_path: str):
    open_func = gzip.open if file_path.endswith('.gz') else open
    with open_func(file_path, 'rt', encoding='utf-8', errors='replace') as f:
        for line in f:
            entry = parse_line(line)
            yield entry  # may be None


if __name__ == '__main__':
    main()
