#!/usr/bin/env python3
"""Compare two scanner binaries byte-for-byte; no system modifications."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

old, new = (str(Path(p).resolve()) for p in sys.argv[1:3])
fixtures = Path(__file__).parent / 'fixtures'
comparisons = 0

def compare(args):
    global comparisons
    results = [subprocess.run([binary, *args], capture_output=True, timeout=15) for binary in (old, new)]
    a, b = results
    if (a.returncode, a.stdout, a.stderr) != (b.returncode, b.stdout, b.stderr):
        raise AssertionError(f'behavior differs for {args!r}: exit {a.returncode}/{b.returncode}')
    comparisons += 1

for fixture in sorted(fixtures.glob('*.json')):
    spec = json.loads(fixture.read_text())
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for name, item in spec['files'].items():
            path = root / name.lstrip('/')
            path.parent.mkdir(parents=True, exist_ok=True)
            if item.get('directory'):
                path.mkdir(exist_ok=True)
            else:
                path.write_text(item.get('text', ''))
            path.chmod(int(item.get('mode', '644'), 8))
        for fmt in ('text', 'json', 'markdown'):
            for selection in ([], ['--category', 'kernel'], ['--check', 'SBS-ACC-001'],
                              ['--category', 'files', '--check', 'SBS-FILE-002']):
                for threshold in ([], ['--fail-on', 'problem'], ['--fail-on', 'deviation']):
                    compare(['--root', temporary, '--format', fmt, *selection, *threshold])
for args in (['--help'], ['--version'], ['--list-checks'], ['--bad'], ['--check', 'bad']):
    compare(args)
# Live whole reports may change between processes (sockets/mounts). Compare the
# default report without normalization; any transient mismatch is reported.
for fmt in ('text', 'json', 'markdown'):
    compare(['--format', fmt])
    compare(['--format', fmt, '--category', 'files', '--fail-on', 'problem'])
    compare(['--format', fmt, '--category', 'files', '--fail-on', 'deviation'])
print(f'PASS: {comparisons} byte-exact stdout/stderr/exit comparisons, nine fixture trees and live reports')
