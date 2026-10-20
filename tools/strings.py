#!/usr/bin/env python3
"""strings.py — Cross-platform strings extractor with regex filter."""
import sys, re, argparse

def extract_strings(filepath, min_len=4, pattern=None):
    with open(filepath, "rb") as f:
        data = f.read()
    regex = re.compile(rb"[A-Za-z0-9_!#$%&'()*+,\-./:;<=>?@[\]^_`{|}~ ]{" + str(min_len).encode() + rb",}")
    matcher = re.compile(pattern.encode()) if pattern else None
    for m in regex.finditer(data):
        val = m.group()
        if not matcher or matcher.search(val):
            try:
                print(val.decode("ascii", errors="ignore"))
            except Exception:
                pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract printable strings from file")
    parser.add_argument("file", help="Path to binary or data file")
    parser.add_argument("-n", "--min-len", type=int, default=4, help="Minimum string length")
    parser.add_argument("-p", "--pattern", help="Filter strings matching regex pattern (e.g. cspp|flag)")
    args = parser.parse_args()
    extract_strings(args.file, args.min_len, args.pattern)
