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
import math

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

# -------------------------------------------------------------------
# Web attack signature patterns (compiled regex)
# -------------------------------------------------------------------
ATTACK_PATTERNS = {
    'SQL Injection': re.compile(
        r"(\bUNION\b\s+\bSELECT\b)|"          # UNION SELECT
        r"(' OR\s+'1'='1)|"                   # ' OR '1'='1
        r"(';?\s*--)|"                         # '; --
        r"(\bSELECT\b.*\bFROM\b)",             # SELECT ... FROM
        re.IGNORECASE
    ),
    'XSS': re.compile(
        r"(<script[^>]*>)|"                   # <script>
        r"(javascript:)|"                      # javascript:
        r"(onerror\s*=)|"                      # onerror=
        r"(alert\s*\()",                       # alert(
        re.IGNORECASE
    ),
    'Path Traversal': re.compile(
        r"(\.\./|\.\.%2F|\.\.%5C|\.\.\\)|"    # ../, ..%2F, ..\
        r"(/etc/passwd|/etc/shadow)|"          # /etc/passwd
        r"(\\windows\\|\/windows\/)",          # \windows\ or /windows/
        re.IGNORECASE
    ),
    'Command Injection': re.compile(
        r"(\b(cmd|bash|sh|powershell)\b.*\|)|" # command pipe
        r"(;\s*(ls|cat|pwd|whoami|id)\b)|"     # ; ls
        r"(\|\|\s*(ls|cat|pwd|whoami|id)\b)|"  # || ls
        r"(`[^`]*`)",                           # backtick injection
        re.IGNORECASE
    ),
}

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
    parser.add_argument('--traffic-anomaly', action='store_true',
                        help='Detect hours with unusually high or low traffic')
    parser.add_argument('--anomaly-std', type=float, default=2.0,
                        help='Number of standard deviations for anomaly threshold (default: 2.0)')
    parser.add_argument('--brute-force', action='store_true',
                        help='Detect brute force attacks (high rate of 401 on /login in short time windows)')
    parser.add_argument('--brute-window', type=int, default=1,
                        help='Time window in minutes for brute force detection (default: 1)')
    parser.add_argument('--brute-threshold', type=int, default=10,
                        help='Min number of 401 attempts in the window to flag as brute force (default: 10)')
    parser.add_argument('--attack-scan', action='store_true',
                        help='Scan request paths for web attack patterns (SQLi, XSS, etc.)')
    parser.add_argument('--attack-threshold', type=int, default=1,
                        help='Min number of malicious requests from an IP to report (default: 1)')

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
    ip_401_minute = defaultdict(lambda: defaultdict(int))
    minute_total = defaultdict(int)
    minute_5xx = defaultdict(int)
    bad_lines = 0
    ip_attack_counts = defaultdict(lambda: defaultdict(int))  # IP -> {attack_type: count}

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

        # Web attack scan
        if args.attack_scan:
            path = entry['path']
            for attack_type, pattern in ATTACK_PATTERNS.items():
                if pattern.search(path):
                    ip_attack_counts[entry['ip']][attack_type] += 1

        if args.brute_force:
            minute_key = entry['datetime'].replace(second=0, microsecond=0)
            ip_401_minute[entry['ip']][minute_key] += 1

        # Error burst data: per-minute counts
        minute = entry['datetime'].replace(second=0, microsecond=0)
        minute_total[minute] += 1
        if 500 <= entry['status'] <= 599:
            minute_5xx[minute] += 1

    # --- Traffic anomaly detection ---
    traffic_anomalies = []
    if args.traffic_anomaly and hourly:
        counts = list(hourly.values())
        mean = sum(counts) / len(counts)
        variance = sum((x - mean) ** 2 for x in counts) / len(counts)
        std_dev = math.sqrt(variance)
        high_threshold = mean + args.anomaly_std * std_dev
        low_threshold = mean - args.anomaly_std * std_dev

        for hour, count in sorted(hourly.items()):
            if count > high_threshold:
                traffic_anomalies.append({'hour': hour, 'count': count, 'type': 'high'})
            elif count < low_threshold:
                traffic_anomalies.append({'hour': hour, 'count': count, 'type': 'low'})

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

    brute_force_ips = []
    if args.brute_force:
        window_delta = timedelta(minutes=args.brute_window)
        for ip, minute_counts in ip_401_minute.items():
            sorted_minutes = sorted(minute_counts.keys())
            # sliding window
            max_attempts = 0
            max_start = None
            for i, start in enumerate(sorted_minutes):
                end = start + window_delta
                attempts = 0
                for t in sorted_minutes[i:]:
                    if t < end:
                        attempts += minute_counts[t]
                    else:
                        break
                if attempts > max_attempts:
                    max_attempts = attempts
                    max_start = start
            if max_attempts >= args.brute_threshold:
                brute_force_ips.append({
                    'ip': ip,
                    'max_attempts': max_attempts,
                    'window_start': max_start.strftime('%Y-%m-%d %H:%M'),
                    'window_end': (max_start + window_delta).strftime('%Y-%m-%d %H:%M')
                })

    # Web attack detection
    web_attacks = []
    if args.attack_scan:
        for ip, type_counts in ip_attack_counts.items():
            total_attacks = sum(type_counts.values())
            if total_attacks >= args.attack_threshold:
                web_attacks.append({
                    'ip': ip,
                    'total': total_attacks,
                    'details': dict(type_counts)  # e.g., {'SQL Injection': 5, 'XSS': 2}
                })

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

    if args.traffic_anomaly:
        report['traffic_anomalies'] = traffic_anomalies
    if args.brute_force:
        report['brute_force_ips'] = brute_force_ips
    if args.attack_scan:
        report['web_attacks'] = web_attacks

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
        if args.brute_force:
            print(
                f"\nBrute force attacks (>= {args.brute_threshold} x 401 on /login in {args.brute_window}-min window):")
            if brute_force_ips:
                for bf in brute_force_ips:
                    print(
                        f"  {bf['ip']}: {bf['max_attempts']} attempts between {bf['window_start']} - {bf['window_end']}")
            else:
                print("  No brute force attacks detected.")
        if args.attack_scan:
            print(f"\nWeb attack patterns detected (threshold >= {args.attack_threshold}):")
            if web_attacks:
                for wa in web_attacks:
                    details = ', '.join(f"{k}: {v}" for k, v in wa['details'].items())
                    print(f"  {wa['ip']} → {details}")
            else:
                print("  No web attacks detected.")

        if args.error_bursts:
            print(f"\nError bursts (5xx rate >= {args.burst_threshold}% in 5-min windows):")
            if bursts:
                for b in bursts:
                    print(f"  {b['start']} – {b['end']}: {b['error_rate']}%")
            else:
                print("  No bursts detected.")

        if args.traffic_anomaly:
            print(f"\nTraffic anomalies (hours beyond {args.anomaly_std} std from mean):")
            if traffic_anomalies:
                for a in traffic_anomalies:
                    direction = "HIGH" if a['type'] == 'high' else "LOW"
                    print(f"  {a['hour']} : {a['count']:>6}  ({direction})")
            else:
                print("  No anomalies detected.")

        print_hourly_histogram(report['hourly_distribution'])

        print(f"\nExecution time: {elapsed:.2f} seconds")


if __name__ == '__main__':
    main()
