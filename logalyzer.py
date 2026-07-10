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

import os
import argparse
import gzip
import json
import re
import sys
import time
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, Generator, List, Optional, Tuple


# -------------------------------------------------------------------
# ANSI color support for terminal output
# -------------------------------------------------------------------
class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @staticmethod
    def colorize(text: str, color: str) -> str:
        """Apply color if output is a terminal, otherwise return plain text."""
        if sys.stdout.isatty():
            return f"{color}{text}{Colors.RESET}"
        return text


# -------------------------------------------------------------------
# Fancy progress bar
# -------------------------------------------------------------------
def print_progress(processed: int, total: int, start_time: float) -> None:
    """Display a colorful progress bar on stderr."""
    if total == 0:
        return
    percent = processed / total * 100
    bar_len = 40
    filled = int(bar_len * processed / total)
    bar = '█' * filled + '░' * (bar_len - filled)
    elapsed = time.time() - start_time
    line = (f"\r{Colors.BOLD}{Colors.CYAN}[Progress] {Colors.RESET}"
            f"{Colors.YELLOW}|{bar}|{Colors.RESET} "
            f"{Colors.GREEN}{percent:.1f}%{Colors.RESET} "
            f"({processed}/{total}) "
            f"{Colors.MAGENTA}Elapsed: {elapsed:.1f}s{Colors.RESET}")
    sys.stderr.write(line)
    sys.stderr.flush()


# -------------------------------------------------------------------
# Combined Log Format regex
# -------------------------------------------------------------------
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
        r"(\bUNION\b\s+\bSELECT\b)|"
        r"(' OR\s+'1'='1)|"
        r"(';?\s*--)|"
        r"(\bSELECT\b.*\bFROM\b)",
        re.IGNORECASE
    ),
    'XSS': re.compile(
        r"(<script[^>]*>)|"
        r"(javascript:)|"
        r"(onerror\s*=)|"
        r"(alert\s*\()",
        re.IGNORECASE
    ),
    'Path Traversal': re.compile(
        r"(\.\./|\.\.%2F|\.\.%5C|\.\.\\)|"
        r"(/etc/passwd|/etc/shadow)|"
        r"(\\windows\\|\/windows\/)",
        re.IGNORECASE
    ),
    'Command Injection': re.compile(
        r"(\b(cmd|bash|sh|powershell)\b.*\|)|"
        r"(;\s*(ls|cat|pwd|whoami|id)\b)|"
        r"(\|\|\s*(ls|cat|pwd|whoami|id)\b)|"
        r"(`[^`]*`)",
        re.IGNORECASE
    ),
}


def parse_line(line: str) -> Optional[dict]:
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


def read_logs_with_bad(file_path: str) -> Generator[Optional[dict], None, None]:
    open_func = gzip.open if file_path.endswith('.gz') else open
    with open_func(file_path, 'rt', encoding='utf-8', errors='replace') as f:
        for line in f:
            yield parse_line(line)


def print_hourly_histogram(hourly: Dict[str, int]) -> None:
    if not hourly:
        print("No data for hourly distribution.")
        return

    max_count = max(hourly.values())
    scale = 1
    if max_count > 60:
        scale = max_count // 60 + 1

    print(Colors.colorize("\nHourly request distribution:", Colors.CYAN + Colors.BOLD))
    print("Hour                Count  Histogram")
    print("-" * 60)
    for hour, count in hourly.items():
        bar = '#' * (count // scale)
        print(f"{hour}  {count:>6}  {bar}")


def main():
    parser = argparse.ArgumentParser(description='Analyze Apache combined access logs.')
    parser.add_argument('file', help='Path to log file (plain or .gz)')
    parser.add_argument('--json', action='store_true', help='Output report in JSON format')
    parser.add_argument('--start', help='Filter entries after this ISO datetime')
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
                        help='Detect brute force attacks')
    parser.add_argument('--brute-window', type=int, default=1,
                        help='Time window in minutes for brute force detection (default: 1)')
    parser.add_argument('--brute-threshold', type=int, default=10,
                        help='Min number of 401 attempts in the window to flag (default: 10)')
    parser.add_argument('--attack-scan', action='store_true',
                        help='Scan request paths for web attack patterns (SQLi, XSS, etc.)')
    parser.add_argument('--attack-threshold', type=int, default=1,
                        help='Min number of malicious requests from an IP to report (default: 1)')
    parser.add_argument('--detect-bots', action='store_true',
                        help='Detect automated traffic by User-Agent heuristics')
    parser.add_argument('--bot-threshold', type=float, default=15.0,
                        help='Percentage threshold to flag a User-Agent as bot (default: 30.0)')
    parser.add_argument('--no-progress', action='store_true',
                        help='Disable progress indicator during processing')

    args = parser.parse_args()
    start_time = time.time()

    # --- Progress indicator setup ---
    total_lines = None
    if not args.no_progress and not args.file.endswith('.gz'):
        try:
            with open(args.file, 'r', encoding='utf-8', errors='replace') as f:
                total_lines = sum(1 for _ in f)
        except (OSError, UnicodeDecodeError):
            total_lines = None

    entries_stream = read_logs_with_bad(args.file)

    # Apply time filters if needed
    if args.start or args.end:
        try:
            start_dt = datetime.fromisoformat(args.start) if args.start else None
            end_dt = datetime.fromisoformat(args.end) if args.end else None
        except ValueError:
            print("Invalid start/end datetime format.")
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
    ip_attack_counts = defaultdict(lambda: defaultdict(int))
    ua_counter = Counter()
    ua_ip_counter = defaultdict(lambda: Counter())
    processed_lines = 0

    # Main single-pass loop
    for entry in entries_stream:
        processed_lines += 1
        if not args.no_progress and total_lines and processed_lines % 10000 == 0:
            print_progress(processed_lines, total_lines, start_time)

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

        if args.suspicious and entry['path'].rstrip('/') == '/login' and entry['status'] == 401:
            ip_401_login[entry['ip']] += 1

        if args.detect_bots:
            ua = entry['user_agent']
            ua_counter[ua] += 1
            ua_ip_counter[ua][entry['ip']] += 1

        if args.attack_scan:
            path = entry['path']
            for attack_type, pattern in ATTACK_PATTERNS.items():
                if pattern.search(path):
                    ip_attack_counts[entry['ip']][attack_type] += 1

        if args.brute_force:
            minute_key = entry['datetime'].replace(second=0, microsecond=0)
            ip_401_minute[entry['ip']][minute_key] += 1

        minute = entry['datetime'].replace(second=0, microsecond=0)
        minute_total[minute] += 1
        if 500 <= entry['status'] <= 599:
            minute_5xx[minute] += 1

    if not args.no_progress and total_lines:
        print_progress(total_lines, total_lines, start_time)
        sys.stderr.write('\n')
        sys.stderr.flush()

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
    suspicious_ips = [(ip, cnt) for ip, cnt in ip_401_login.items() if cnt >= args.suspicious_threshold]

    # Error burst detection (5-minute sliding window)
    bursts = []
    if args.error_bursts and minute_total:
        all_minutes = sorted(minute_total.keys())
        start_t = all_minutes[0]
        end_t = all_minutes[-1] + timedelta(minutes=1)
        window = 5
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

    # Brute force detection
    brute_force_ips = []
    if args.brute_force:
        window_delta = timedelta(minutes=args.brute_window)
        for ip, minute_counts in ip_401_minute.items():
            sorted_minutes = sorted(minute_counts.keys())
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
                    'details': dict(type_counts)
                })

    # Bot detection
    bot_user_agents = []
    if args.detect_bots and total > 0:
        for ua, count in ua_counter.items():
            percentage = count / total * 100
            if percentage >= args.bot_threshold:
                top_ips = ua_ip_counter[ua].most_common(3)
                bot_user_agents.append({
                    'user_agent': ua,
                    'count': count,
                    'percentage': round(percentage, 2),
                    'top_ips': [{'ip': ip, 'count': cnt} for ip, cnt in top_ips]
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
    if args.traffic_anomaly:
        report['traffic_anomalies'] = traffic_anomalies
    if args.brute_force:
        report['brute_force_ips'] = brute_force_ips
    if args.attack_scan:
        report['web_attacks'] = web_attacks
    if args.detect_bots:
        report['bot_user_agents'] = bot_user_agents

    elapsed = time.time() - start_time
    report['execution_time_sec'] = round(elapsed, 2)

    # Output
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        # ---- Colored text output ----
        print(Colors.colorize(f"Total requests: {total}", Colors.CYAN + Colors.BOLD))
        print(Colors.colorize(f"Bad lines skipped: {bad_lines}", Colors.YELLOW))
        print(Colors.colorize(f"Unique IPs: {len(ip_set)}", Colors.CYAN))

        error_color = Colors.RED if error_rate > 5 else Colors.GREEN
        print(Colors.colorize(f"Error rate (4xx+5xx): {round(error_rate, 2)}%", error_color))

        print(Colors.colorize("\nTop 10 endpoints:", Colors.BOLD))
        for path, count in top10:
            print(f"  {count:>6} {path}")

        if args.suspicious:
            print(Colors.colorize(
                f"\nSuspicious activity (>={args.suspicious_threshold} x 401 on /login):",
                Colors.YELLOW + Colors.BOLD))
            if suspicious_ips:
                for ip, cnt in suspicious_ips:
                    print(Colors.colorize(f"  {ip}: {cnt} attempts", Colors.RED))
            else:
                print(Colors.colorize("  None detected.", Colors.GREEN))

        if args.brute_force:
            print(Colors.colorize(
                f"\nBrute force attacks (>= {args.brute_threshold} x 401 on /login in {args.brute_window}-min window):",
                Colors.RED + Colors.BOLD))
            if brute_force_ips:
                for bf in brute_force_ips:
                    print(Colors.colorize(
                        f"  {bf['ip']}: {bf['max_attempts']} attempts between {bf['window_start']} - {bf['window_end']}",
                        Colors.RED))
            else:
                print(Colors.colorize("  No brute force attacks detected.", Colors.GREEN))

        if args.attack_scan:
            print(Colors.colorize(
                f"\nWeb attack patterns detected (threshold >= {args.attack_threshold}):",
                Colors.RED + Colors.BOLD))
            if web_attacks:
                for wa in web_attacks:
                    details = ', '.join(f"{k}: {v}" for k, v in wa['details'].items())
                    print(Colors.colorize(f"  {wa['ip']} → {details}", Colors.RED))
            else:
                print(Colors.colorize("  No web attacks detected.", Colors.GREEN))

        if args.error_bursts:
            print(Colors.colorize(
                f"\nError bursts (5xx rate >= {args.burst_threshold}% in 5-min windows):",
                Colors.MAGENTA + Colors.BOLD))
            if bursts:
                for b in bursts:
                    line = f"  {b['start']} – {b['end']}: {b['error_rate']}%"
                    print(Colors.colorize(line, Colors.RED))
            else:
                print(Colors.colorize("  No bursts detected.", Colors.GREEN))

        if args.traffic_anomaly:
            print(Colors.colorize(
                f"\nTraffic anomalies (hours beyond {args.anomaly_std} std from mean):",
                Colors.YELLOW))
            if traffic_anomalies:
                for a in traffic_anomalies:
                    color = Colors.RED if a['type'] == 'high' else Colors.BLUE
                    direction = "HIGH" if a['type'] == 'high' else "LOW"
                    print(Colors.colorize(f"  {a['hour']} : {a['count']:>6}  ({direction})", color))
            else:
                print(Colors.colorize("  No anomalies detected.", Colors.GREEN))

        if args.detect_bots:
            print(Colors.colorize(
                f"\nBot detection (User-Agents >= {args.bot_threshold}% of traffic):",
                Colors.BLUE + Colors.BOLD))
            if bot_user_agents:
                for bot in bot_user_agents:
                    print(Colors.colorize(f"  {bot['user_agent']}: {bot['percentage']}% ({bot['count']} requests)", Colors.CYAN))
                    for ip_info in bot['top_ips']:
                        print(Colors.colorize(f"    Top IP: {ip_info['ip']} ({ip_info['count']} requests)", Colors.MAGENTA))
            else:
                print(Colors.colorize("  No bot-like User-Agents detected.", Colors.GREEN))

        print_hourly_histogram(report['hourly_distribution'])

        exec_color = Colors.YELLOW if elapsed > 5 else Colors.GREEN
        print(Colors.colorize(f"\nExecution time: {elapsed:.2f} seconds", exec_color))


if __name__ == '__main__':
    main()