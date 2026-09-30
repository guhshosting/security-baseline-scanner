#!/usr/bin/env python3
"""Distro fixtures, CLI/output validation, privacy and filesystem safety."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
binary = str(Path(sys.argv[1]).resolve())
fixtures = Path(sys.argv[2])
assertions = 0

def check(ok, why):
    global assertions
    assertions += 1
    if not ok:
        raise AssertionError(why)

def invoke(*args, code=0):
    result = subprocess.run([binary, *args], capture_output=True, timeout=15)
    check(result.returncode == code, (args, result.returncode, result.stderr))
    return result.stdout

def snapshot(root):
    out = {}
    for p in sorted(root.rglob('*')):
        st = p.lstat()
        digest = hashlib.sha256(p.read_bytes()).hexdigest() if stat.S_ISREG(st.st_mode) else None
        out[str(p.relative_to(root))] = (st.st_mode, st.st_uid, st.st_gid, st.st_mtime_ns, digest)
    return out

ids = (fixtures / 'check-ids.txt').read_text().splitlines()
check([r.split('\t')[0] for r in invoke('--list-checks').decode().splitlines()] == ids, 'stable IDs')
for fixture in sorted(fixtures.glob('*.json')):
    spec = json.loads(fixture.read_text())
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, entry in spec['files'].items():
            p = root / name.lstrip('/')
            p.parent.mkdir(parents=True, exist_ok=True)
            if entry.get('directory'):
                p.mkdir(exist_ok=True)
            else:
                p.write_text(entry.get('text', ''))
            p.chmod(int(entry.get('mode', '644'), 8))
        before = snapshot(root)
        raw = invoke('--root', tmp, '--format', 'json')
        check(raw == invoke('--root', tmp, '--format', 'json'), 'determinism')
        report = json.loads(raw)
        check(report['version'] == '1.0.0' and report['schema_version'] == 1, 'version')
        check(report['scope'] == 'offline-root', 'provenance')
        findings = {f['id']: f for f in report['findings']}
        check(list(findings) == ids, 'ordering')
        check(sum(report['summary'].values()) == len(findings), 'summary total')
        for key, value in report['summary'].items():
            check(value == sum(f['status'] == key for f in findings.values()), 'summary counts')
        for f in findings.values():
            check(set(f) == {'id', 'category', 'title', 'status', 'severity', 'evidence', 'explanation', 'recommendation', 'limitations'}, 'schema')
            check(isinstance(f['evidence'], list) and all(isinstance(e, str) for e in f['evidence']), 'evidence type')
            check(f['severity'] in {'none', 'low', 'medium', 'high'}, 'severity')
            check(all(isinstance(f[k], str) and f[k] for k in ['id', 'title', 'explanation', 'recommendation', 'limitations']), 'text')
        for key, status in spec['expected'].items():
            if key.startswith('SBS-FILE-') and status == 'PASS' and os.geteuid() != 0:
                status = 'DEVIATION'  # Offline inode ownership is the fixture creator.
            check(findings[key]['status'] == status, (fixture.name, key, findings[key]))
        for fmt in ['text', 'markdown']:
            output = invoke('--root', tmp, '--format', fmt)
            check(b'SBS-FW-001' in output and b'Limitations:' in output, 'human report')
            check(b'PRIVATE_HASH' not in output and b'PRIVATE_NAME' not in output and b'\x1b' not in output, 'privacy')
        check(b'PRIVATE_HASH' not in raw and b'PRIVATE_NAME' not in raw, 'JSON privacy')
        for threshold, statuses in [('problem', {'PROBLEM'}), ('deviation', {'PROBLEM', 'DEVIATION'})]:
            code = int(any(f['status'] in statuses for f in findings.values()))
            invoke('--root', tmp, '--fail-on', threshold, code=code)
        subset = json.loads(invoke('--root', tmp, '--format', 'json', '--category', 'kernel', '--check', 'SBS-KERN-001'))
        check(len(subset['findings']) == 1, 'intersection')
        check(snapshot(root) == before, 'scanner mutated fixture')
for args in [('--bad',), ('--format',), ('--format', 'xml'), ('--root', 'relative'), ('--check', 'typo'), ('--category', 'typo'), ('--fail-on', 'high'), ('--category', 'ssh', '--check', 'SBS-OS-001'), ('--list-checks', '--format', 'json')]:
    invoke(*args, code=2)
invoke('--root', '/this/path/does/not/exist', code=3)
check(b'1.0.0' in invoke('--version'), 'version command')
check(b'Usage:' in invoke('--help'), 'help command')
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    (root / 'etc').mkdir()
    sensitive = root / 'etc/shadow'
    def source_status():
        return json.loads(invoke('--root', tmp, '--check', 'SBS-ACC-002', '--format', 'json'))['findings'][0]['status']
    sensitive.symlink_to('/etc/shadow')
    check(source_status() == 'UNAVAILABLE', 'leaf symlink')
    sensitive.unlink()
    os.mkfifo(sensitive)
    check(source_status() == 'UNAVAILABLE', 'FIFO blocked')
    sensitive.unlink()
    sensitive.write_bytes(b'x' * (1024 * 1024 + 1))
    check(source_status() == 'UNKNOWN', 'size limit')
    sensitive.write_bytes(b'root:\x00:1:0:99999:7:::\n')
    check(source_status() == 'UNKNOWN', 'NUL rejection')
    sensitive.unlink()
    (root / 'etc').rmdir()
    (root / 'etc').symlink_to('/etc')
    check(source_status() == 'UNAVAILABLE', 'intermediate symlink')
    (root / 'etc').unlink()
    (root / 'etc').mkdir()
    (root / 'etc/os-release').write_bytes(b'ID="bad\x1b[31m"\n')
    check(b'\x1b' not in invoke('--root', tmp, '--format', 'json'), 'control bytes')
live = json.loads(invoke('--format', 'json'))
check(len(live['findings']) == 32, 'live scan')
if Path('/dev/full').exists():
    with open('/dev/full', 'wb') as out:
        p = subprocess.run([binary, '--format', 'json'], stdout=out, stderr=subprocess.PIPE, timeout=15)
    check(p.returncode == 3, 'output error')
print(f'{assertions} integration assertions; {len(list(fixtures.glob("*.json")))} distro/scenario fixtures')
