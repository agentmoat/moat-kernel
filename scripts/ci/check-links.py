#!/usr/bin/env python3
"""Fail on a relative Markdown link whose file or heading anchor does not exist.

Offline on purpose: links with a scheme (https:, mailto:) are not fetched, so a
remote site being down never fails CI. Checks every tracked `*.md` file.

    python3 scripts/ci/check-links.py
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFERENCE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)")
HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
HTML_ANCHOR = re.compile(r"<a\s+(?:name|id)=\"([^\"]+)\"")
SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
FENCE = re.compile(r"^\s{0,3}(```|~~~)")
CODE_SPAN = re.compile(r"(`+).*?\1")


def prose_lines(text):
    """Yield (line number, line) for each line outside fenced code blocks."""
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        match = FENCE.match(line)
        if match:
            if fence is None:
                fence = match.group(1)
            elif match.group(1) == fence:
                fence = None
            continue
        if fence is None:
            yield number, line


def slug(heading):
    """GitHub's heading anchor: lowercase, punctuation dropped, spaces to hyphens."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = text.replace("`", "").strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


ANCHORS = {}


def anchors(path):
    """Every anchor a link into `path` may name."""
    if path not in ANCHORS:
        found, seen = set(), {}
        for _, line in prose_lines(path.read_text(encoding="utf-8")):
            found.update(HTML_ANCHOR.findall(line))
            match = HEADING.match(line)
            if match:
                base = slug(match.group(2))
                count = seen.get(base, 0)
                seen[base] = count + 1
                found.add(base if count == 0 else f"{base}-{count}")
        ANCHORS[path] = found
    return ANCHORS[path]


def broken(source, target):
    if SCHEME.match(target) or target.startswith("//"):
        return None
    file_part, _, anchor = target.partition("#")
    if file_part.startswith("/"):
        resolved = ROOT / file_part.lstrip("/")
    else:
        resolved = (source.parent / file_part) if file_part else source
    if not resolved.exists():
        return "no such file"
    if anchor and resolved.is_file() and resolved.suffix == ".md":
        if anchor.lower() not in anchors(resolved):
            return f"no heading #{anchor}"
    return None


def main():
    listed = subprocess.run(
        ["git", "ls-files", "*.md"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.split()
    failures = 0
    for name in listed:
        source = ROOT / name
        for number, line in prose_lines(source.read_text(encoding="utf-8")):
            line = CODE_SPAN.sub("", line)
            targets = INLINE.findall(line)
            reference = REFERENCE.match(line)
            if reference:
                targets.append(reference.group(1))
            for target in targets:
                reason = broken(source, target)
                if reason:
                    failures += 1
                    print(f"{name}:{number}: {target}: {reason}")
    if failures:
        print(f"{failures} broken relative link(s)", file=sys.stderr)
        return 1
    print(f"links ok in {len(listed)} Markdown files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
