#!/usr/bin/env python3
"""Audit a live scan's syscall trace. Does not require root on normal Linux."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
binary = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory() as temp:
    log = Path(temp) / 'trace'
    result = subprocess.run(['strace', '-f', '-qq', '-o', str(log), '-e', 'trace=%file,%network,%process,write,writev,pwrite64,ftruncate,fchmod,fchown', binary, '--format', 'json'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise SystemExit(f'strace scan failed: {result.stderr.decode()}')
    lines = log.read_text().splitlines()
    forbidden = re.compile(r'\b(socket|connect|sendto|sendmsg|bind|listen|accept|accept4|clone|clone3|fork|vfork|unlink|unlinkat|rename|renameat|renameat2|mkdir|mkdirat|rmdir|chmod|fchmod|fchmodat|chown|fchown|fchownat|truncate|ftruncate|pwrite64|link|linkat|symlink|symlinkat|mknod|mknodat|mount|umount2)\(')
    failures = []
    execs = 0
    for line in lines:
        if 'execve(' in line:
            execs += 1
        if forbidden.search(line):
            failures.append(line)
        if re.search(r'\bopen(at|at2)?\(', line) and re.search(r'O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND', line):
            failures.append(line)
        if re.search(r'\bwrite(v)?\(', line) and not re.search(r'\bwrite(v)?\([12],', line):
            failures.append(line)
    if execs != 1 or failures:
        raise SystemExit(f'Unexpected syscalls: execs={execs}; {failures}')
    print(f'PASS: {len(lines)} traced lines; one initial exec, no child processes, network calls, mutating file calls or writes except stdout/stderr.')
