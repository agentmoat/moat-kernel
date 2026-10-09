#!/usr/bin/env python3
"""Run a command on a pseudo-terminal of its own, as a person's terminal runs an
agent: the terminal is the command's controlling terminal and its standard
input, output and error. Prints what the command writes there and exits with
its status.

Used by the differential suite (crates/openmoat-cli/tests/e2e/differential/
scripts.rs) for the scripts that need a terminal, such as one that types into it.
The terminal is this script's own, never the one running the tests.

  on_terminal.py <command> [args...]
"""
import os
import pty
import sys

pid, master = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])
while True:
    try:
        chunk = os.read(master, 4096)
    except OSError:  # EIO once the command and its children closed the terminal
        break
    if not chunk:
        break
    sys.stdout.buffer.write(chunk)
sys.stdout.flush()
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status) & 0xFF)
