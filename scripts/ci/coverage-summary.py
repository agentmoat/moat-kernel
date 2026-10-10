#!/usr/bin/env python3
"""Print line coverage per crate from an lcov file, as a Markdown table.

The weekly workflow (`.github/workflows/weekly.yml`) appends the table to the job
summary; the lcov file and the HTML report are the downloadable artifact.

    python3 scripts/ci/coverage-summary.py lcov.info
"""

import sys
from collections import defaultdict
from pathlib import PurePosixPath


def crate_of(source):
    parts = PurePosixPath(source.replace("\\", "/")).parts
    if "crates" in parts:
        index = parts.index("crates")
        if index + 1 < len(parts):
            return parts[index + 1]
    return "other"


def main(path):
    found = defaultdict(int)
    hit = defaultdict(int)
    crate = "other"
    with open(path, encoding="utf-8") as lcov:
        for line in lcov:
            line = line.strip()
            if line.startswith("SF:"):
                crate = crate_of(line[3:])
            elif line.startswith("LF:"):
                found[crate] += int(line[3:])
            elif line.startswith("LH:"):
                hit[crate] += int(line[3:])
    print("| Crate | Lines covered | Lines | Coverage |")
    print("|---|---:|---:|---:|")
    for name in sorted(found):
        total = found[name]
        share = 100 * hit[name] / total if total else 0
        print(f"| {name} | {hit[name]} | {total} | {share:.1f}% |")
    total = sum(found.values())
    share = 100 * sum(hit.values()) / total if total else 0
    print(f"| **all** | {sum(hit.values())} | {total} | **{share:.1f}%** |")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: coverage-summary.py <lcov.info>")
    main(sys.argv[1])
