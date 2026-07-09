#!/usr/bin/env python3
"""
Logalyzer – CLI tool for Apache combined log analysis.
"""

import argparse
import re
from datetime import datetime


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

    # Parse datetime
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


def main():
    parser = argparse.ArgumentParser(description='Analyze Apache combined access logs.')
    parser.add_argument('file', help='Path to log file (plain or .gz)')
    args = parser.parse_args()
    # For now just test parsing with a dummy line
    test_line = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /products/1877 HTTP/1.1" 200 5324 "-" "Mozilla/5.0"'
    result = parse_line(test_line)
    print(result)


if __name__ == '__main__':
    main()