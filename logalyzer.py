#!/usr/bin/env python3
"""
Logalyzer – CLI tool for Apache combined log analysis.
"""

import argparse


def main():
    parser = argparse.ArgumentParser(description='Analyze Apache combined access logs.')
    parser.add_argument('file', help='Path to log file (plain or .gz)')
    args = parser.parse_args()
    print(f"Analyzing {args.file}... (not implemented yet)")


if __name__ == '__main__':
    main()