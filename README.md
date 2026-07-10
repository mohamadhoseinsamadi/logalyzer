# Logalyzer

A command-line tool for analyzing Apache combined access logs. It parses logs line-by-line with minimal memory footprint and provides basic statistics, hourly distribution, and optional advanced features like suspicious activity detection, error burst detection, and JSON output.

## Requirements
- Python 3.7+ (uses standard libraries only; no external dependencies)

## How to run

```bash
python logalyzer.py access.log
```

For gzipped logs:
```bash
python logalyzer.py access.log.gz
```

## Options

| Option | Description |
|--------|-------------|
| `--json` | Output report in JSON format |
| `--start ISO_DATETIME` | Filter entries after this time (e.g., `2026-06-01T09:00:00`) |
| `--end ISO_DATETIME` | Filter entries before this time |
| `--suspicious` | Detect IPs with ≥50 `401` responses on `/login/` |
| `--error-bursts` | Find 5-minute windows where 5xx error rate exceeds threshold (default 20%) |
| `--burst-threshold PERCENT` | Set custom error burst threshold (default 20) |

Examples:
```bash
python logalyzer.py access.log --start "2026-06-01T09:00:00" --end "2026-06-01T10:00:00" --json
python logalyzer.py access.log --suspicious --error-bursts
```

## Running tests
```bash
python -m pytest test_logalyzer.py   # or python -m unittest test_logalyzer.py
```

## Key decisions

- **Single-pass processing**: The script reads the log once and computes all required statistics simultaneously. This avoids multiple file scans and keeps memory usage low because only counters and sets (unique IPs, endpoint counts) are stored, not the entire log lines. Bad lines are counted and ignored without crashing.
- **Regex for parsing**: The combined log format is parsed with a regular expression. The datetime is parsed manually using `strptime` after separating the timezone. This approach is robust against minor variations.
- **Hourly histogram**: An ASCII bar chart is printed directly to the terminal. The bar width is scaled to fit within 60 characters to avoid line wrapping.
- **Time filtering**: Optional start/end filters are applied before aggregation. If filtering is active, only entries within the range are processed.
- **Suspicious activity**: Counts `401` status on `/login/` per IP and reports those exceeding a threshold (default 50, but modifiable in code).
- **Error burst detection**: Aggregates per-minute total and 5xx counts, then slides a 5-minute window across the time range, flagging windows where the error rate exceeds the given threshold. This operates after the single pass, using the already collected minute-level data (which is small).
- **Gzip support**: Detects `.gz` extension and uses `gzip.open` transparently.

## Problem encountered and solution

**Problem:**  
When testing the `--suspicious` flag with the sample log file, the tool unexpectedly reported “None detected,” even though the log clearly contained repeated 401 responses on `/login` from the same IP. After investigation, I found that some requests used `/login` while the detection logic expected an exact match with `/login/` (with trailing slash). This mismatch caused the feature to silently fail.

**Solution:**  
Instead of hardcoding the path with a trailing slash or adding multiple conditionals, I normalized the path by removing any trailing slashes before comparison (`path.rstrip('/') == '/login'`). This single change made the detection robust against inconsistencies in log formatting, while keeping the code clean and readable. The fix was verified by running the tool with a low threshold, immediately revealing the suspicious IP with thousands of attempts.
