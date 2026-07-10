# Logalyzer

A command-line tool for analyzing Apache combined access logs. It parses logs line-by-line with minimal memory footprint and provides basic statistics, hourly distribution, and optional advanced features like suspicious activity detection, error burst detection, and JSON output.

## Requirements
- Python 3.7+ (uses standard libraries only; no external dependencies)



## Options

| Option | Description                                                                                                |
|--------|------------------------------------------------------------------------------------------------------------|
| `--json` | Output report in JSON format                                                                               |
| `--start ISO_DATETIME` | Filter entries after this time (e.g., `2026-06-01T09:00:00`)                                               |
| `--end ISO_DATETIME` | Filter entries before this time                                                                            |
| `--suspicious` | Detect IPs with excessive `401` responses on `/login` (default threshold 50, see `--suspicious-threshold`) |
| `--suspicious-threshold N` | Set minimum number of `401` attempts to flag (default: 50)                                                 |
| `--error-bursts` | Find 5-minute windows where 5xx error rate exceeds threshold (default 20%)                                 |
| `--burst-threshold PERCENT` | Set custom error burst threshold (default 20)                                                              |
| `--traffic-anomaly` | Detect hours with unusually high or low request counts                                                     |
| `--anomaly-std N` | Number of standard deviations for anomaly sensitivity (default: 2.0)                                       |
| `--brute-force` | Detect brute force attacks (high rate of 401 on /login)                                                    |
| `--brute-window N` | Time window in minutes for brute force detection (default: 1)                                              |
| `--brute-threshold N` | Min number of 401 attempts in the window to flag (default: 10)                                             |
| `--attack-scan` | Scan request paths for web attack patterns (SQLi, XSS, Path Traversal, CMDi)                               |
| `--attack-threshold N` | Min number of malicious requests from an IP to report (default: 1)                                         |
| `--detect-bots` | Detect automated traffic based on User-Agent percentage                                                    |
| `--bot-threshold PERCENT` | Min percentage of traffic to flag a User-Agent as bot (default: 15)                                        |
| `--no-progress` | Disable the progress bar during processing |

## How to run
Basic analysis

```bash
python logalyzer.py access.log
```

For gzipped logs:
```bash
python logalyzer.py access.log.gz
```

JSON output
```
python logalyzer.py access.log --json
```
Filter by time range (ISO format)
```
python logalyzer.py access.log --start "2026-06-01T04:00:00" --end "2026-06-01T05:00:00"
```
Detect suspicious IPs (default threshold: 50)
```
python logalyzer.py access.log --suspicious
```
Custom threshold for suspicious detection
```
python logalyzer.py access.log --suspicious --suspicious-threshold 10
```
Find error bursts (5xx rate ≥ 20% in 5‑minute windows)
```
python logalyzer.py access.log --error-bursts
```
Custom error burst threshold (e.g., 10%)
```
python logalyzer.py access.log --error-bursts --burst-threshold 10
```
Combine time filtering, suspicious detection, and JSON
```
python logalyzer.py access.log --start "2026-06-01T00:00:00" --end "2026-06-01T03:00:00" --suspicious --json
```
Detect traffic anomalies (hours with unusual request counts):
```
python logalyzer.py access.log --traffic-anomaly
```

Detect brute force attacks (10+ failed logins per minute):
```
python logalyzer.py access.log --brute-force --brute-threshold 5
```

web attack pattern detection
```
python logalyzer.py access.log --attack-scan --attack-threshold 2
```

bot detection via User-Agent heuristics
```
python logalyzer.py access.log --detect-bots --bot-threshold 20
```

Full security analysis (suspicious, brute force, error bursts, JSON):
```
python logalyzer.py access.log --suspicious --brute-force --attack-scan --detect-bots --error-bursts --traffic-anomaly --json
```

### Running tests
```bash
python -m pytest test_logalyzer.py   # or python -m unittest test_logalyzer.py
```

## Key decisions

- **Single-pass processing**: The script reads the log once and computes all required statistics simultaneously. This avoids multiple file scans and keeps memory usage low because only counters and sets (unique IPs, endpoint counts) are stored, not the entire log lines. Bad lines are counted and ignored without crashing.
- **Regex for parsing**: The combined log format is parsed with a regular expression. The datetime is parsed manually using `strptime` after separating the timezone. This approach is robust against minor variations.
- **Hourly histogram**: An ASCII bar chart is printed directly to the terminal. The bar width is scaled to fit within 60 characters to avoid line wrapping.
- **Time filtering**: Optional start/end filters are applied before aggregation. If filtering is active, only entries within the range are processed.
- **Suspicious activity**: Counts `401` responses on `/login` (with or without trailing slash) per IP and flags those exceeding a configurable threshold (default 50). The threshold can be changed via `--suspicious-threshold`.
- **Error burst detection**: Aggregates per-minute total and 5xx counts, then slides a 5-minute window across the time range, flagging windows where the error rate exceeds the given threshold. This operates after the single pass, using the already collected minute-level data (which is small).
- **Gzip support**: Detects `.gz` extension and uses `gzip.open` transparently.
- **Traffic anomaly detection**: Uses simple statistical methods (mean and standard deviation) to automatically flag hours with unusually high or low request counts. This helps identify outages or unexpected traffic spikes without manual inspection.
- **Brute force detection**: Monitors the rate of failed login attempts (401 on /login) per IP within configurable time windows. This goes beyond simple counting and detects actual attack patterns where many attempts are concentrated in a short period.
- **Colorized terminal output**: Uses ANSI escape codes to highlight important metrics (errors, attacks, anomalies) directly in the terminal, improving readability and quick diagnosis.
- **Real‑time progress bar**: Displays a visual progress bar with elapsed time during processing, giving users immediate feedback on large files without slowing down the analysis.

## Problem encountered and solution

**Problem:**  
When testing the `--suspicious` flag with the sample log file, the tool unexpectedly reported “None detected,” even though the log clearly contained repeated 401 responses on `/login` from the same IP. After investigation, I found that some requests used `/login` while the detection logic expected an exact match with `/login/` (with trailing slash). This mismatch caused the feature to silently fail.

**Solution:**  
Instead of hardcoding the path with a trailing slash or adding multiple conditionals, I normalized the path by removing any trailing slashes before comparison (`path.rstrip('/') == '/login'`). This single change made the detection robust against inconsistencies in log formatting, while keeping the code clean and readable. The fix was verified by running the tool with a low threshold, immediately revealing the suspicious IP with thousands of attempts.
