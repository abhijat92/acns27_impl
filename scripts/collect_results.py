#!/usr/bin/env python3
"""Convert benchmark terminal CSV lines into a normalized CSV file."""
import csv
import sys
from pathlib import Path

if len(sys.argv) != 3:
    raise SystemExit("usage: collect_results.py benchmark.log results.csv")

src, dst = map(Path, sys.argv[1:])
rows = []
header = None
for line in src.read_text().splitlines():
    if line.startswith("# Fields:"):
        header = line[len("# Fields:"):].strip().split(",")
    elif line and not line.startswith("#") and "," in line:
        rows.append(line.split(","))
if not header:
    raise SystemExit("benchmark header not found")
with dst.open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(header)
    w.writerows(rows)
print(f"wrote {len(rows)} rows to {dst}")
