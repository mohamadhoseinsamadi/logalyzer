# Logalyzer

A command-line tool for analyzing Apache combined access logs.

## Usage
python logalyzer.py <logfile> [options]

Examples:
python logalyzer.py access.log
python logalyzer.py access.log --json
python logalyzer.py access.log --start "2026-06-01T09:00:00" --end "2026-06-01T10:00:00"
python logalyzer.py access.log --suspicious
python logalyzer.py access.log.gz

## Design Decisions
- **Single-pass processing:** All statistics are gathered in one loop to avoid reading the file multiple times, ensuring line-by-line processing and low memory usage.
- **Regex parsing:** A carefully crafted regular expression extracts all fields from the combined log format. Malformed lines are gracefully skipped and counted.
- **Optional features:** Suspicious IP detection and error burst detection are implemented as optional flags, keeping the default output focused.

## Problem Encountered
Initially, I implemented separate functions for each report (basic report, hourly distribution). However, each function consumed the generator independently, causing the file to be read multiple times. This violated the requirement of line-by-line processing and was inefficient for large files. The solution was to merge all metric collection into a single `for` loop, using a single pass over the file. This required careful state management but significantly improved performance and memory usage.
