#!/usr/bin/env python3
"""Seed the fuzz corpora from the repository's own test data.

decide_shell and literal_pattern start from every shell command in the
conformance fixtures; host_payload from the golden host payloads; policy_parse
from the default policy. Run from the repository root:

    python3 fuzz/seed_corpus.py
"""

import glob
import hashlib
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "fuzz", "corpus")


def write(target: str, data: bytes) -> None:
    directory = os.path.join(CORPUS, target)
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, hashlib.sha1(data).hexdigest()), "wb") as f:
        f.write(data)


commands = []
for path in glob.glob(os.path.join(ROOT, "tests", "conformance", "*.yaml")):
    with open(path, encoding="utf-8") as f:
        for match in re.finditer(r'shell: "((?:[^"\\]|\\.)*)"', f.read()):
            commands.append(match.group(1).encode().decode("unicode_escape").encode())
for command in commands:
    write("decide_shell", command)
    write("literal_pattern", command)
for path in glob.glob(os.path.join(ROOT, "tests", "fixtures", "hosts", "*", "*.json")):
    with open(path, "rb") as f:
        write("host_payload", f.read())
with open(os.path.join(ROOT, "crates", "moat-core", "policies", "default-v1.yaml"), "rb") as f:
    write("policy_parse", f.read())
print(f"seeded {len(commands)} commands")
