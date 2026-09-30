#!/usr/bin/env python3
"""Repack a manifest-verified source release with deterministic metadata.

Usage: python3 packaging/source-archive.py /absolute/output-directory
Run after regenerating SOURCE-MANIFEST.sha256 if source contents changed.
"""
import gzip
import hashlib
from pathlib import Path
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parent.parent
NAME = 'security-baseline-scanner-1.0.0'
EPOCH = 1789430400  # 2026-09-15 00:00:00 UTC
if EPOCH > time.time():
    raise SystemExit('Release epoch is in the future; refusing to create archive')
files = []
for line in (ROOT / 'SOURCE-MANIFEST.sha256').read_text().splitlines():
    expected, name = line.split('  ', 1)
    path = Path(name)
    if path.is_absolute() or '..' in path.parts or path.as_posix() != name:
        raise SystemExit('Invalid manifest path')
    source = ROOT / path
    if source.is_symlink() or not source.is_file():
        raise SystemExit('Manifest entry is not a regular source file: ' + name)
    if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
        raise SystemExit('Manifest mismatch: ' + name)
    files.append(path)
files.append(Path('SOURCE-MANIFEST.sha256'))
directories = {Path('.')}
for path in files:
    directories.update(path.parents)
output = Path(sys.argv[1]).resolve()
output.mkdir(parents=True, exist_ok=True)
with (output / (NAME + '.tar.gz')).open('wb') as raw:
    with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=EPOCH) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for path in sorted(directories | set(files), key=lambda p: p.as_posix()):
                member = tarfile.TarInfo(NAME if path == Path('.') else NAME + '/' + path.as_posix())
                member.uid = member.gid = 0
                member.uname = member.gname = 'root'
                member.mtime = EPOCH
                if path in directories:
                    member.type = tarfile.DIRTYPE
                    member.mode = 0o755
                    archive.addfile(member)
                else:
                    member.mode = 0o755 if str(path) in ('debian/rules', 'scripts/validate.sh') else 0o644
                    member.size = (ROOT / path).stat().st_size
                    with (ROOT / path).open('rb') as content:
                        archive.addfile(member, content)
