# Packaging and timestamp validation

This packaging-only revision follows the repaired v1.0.0 source archive with
SHA-256 `80ff8554a6a4bb86a0ba972cbdd320028a66643231f0afa5d039f8b819aa2f5c`.
Application source, headers, tests, fixtures and both minimal analyzer
reproducers are byte-identical to that archive. Version remains 1.0.0.

## Changes

- CMakeLists.txt: maintainer, homepage and RPM vendor metadata; explicit 0755
  installation directory permissions. Existing automatic DEB shlibdeps retained.
- debian/control, debian/changelog, debian/copyright: maintainer/homepage metadata.
- packaging/security-baseline-scanner.spec: Packager, URL and changelog identity.
- README.md and ANALYZER-REPAIR.md: current compiler-analysis limitation status,
  attributed user-reported Debian 13 results and corrected contact information.
- packaging/source-archive.py: deterministic, manifest-verified source archiver.
- PACKAGING-VALIDATION.md (this report) and regenerated SOURCE-MANIFEST.sha256.

## Timestamp strategy

Every tar member and the gzip header use 2026-09-15 00:00:00 UTC (1789430400).
The archiver rejects this epoch if it is later than its actual creation clock.
Entries are sorted, ownership is root:root, directories are 0755, ordinary
files 0644, and debian/rules and scripts/validate.sh are 0755. No variable
PAX time fields or gzip filename are emitted. The manifest excludes itself.
The manifest lists the source release; no build trees, generated binaries,
DEB or RPM payloads are included. There is exactly one archive root:
`security-baseline-scanner-1.0.0`. Historical validation text logs are retained.

To reproduce from an unchanged source extraction:

```
python3 packaging/source-archive.py /absolute/output-directory
```

## Validation performed in this environment

Ubuntu 24.04 container, GCC 13.3.0, CMake/CPack/CTest 4.4.3, amd64.
The exact final archive was freshly extracted and built with Release and
`-Wall -Wextra -Wpedantic -Werror`. CTest passed 3/3 (unit, integration,
FD lifecycle). Extraction, configure, build and CPack logs contained no
future-timestamp, clock-skew, invalid-escape or developer warnings.
The full source manifest verified. Repacking the unchanged extraction produced
an identical source archive hash. Source/header/test byte comparison passed.

CPack generated a DEB without installing it. Inspected control and data archives:
package security-baseline-scanner, version 1.0.0, architecture amd64,
maintainer GuhsHosting <guhshosting@users.noreply.github.com>, homepage
https://github.com/guhshosting/security-baseline-scanner. Dependencies were
automatically generated: libc6 (>= 2.34), libgcc-s1 (>= 3.0),
libstdc++6 (>= 13.1). These are build-environment-derived, not hardcoded.
All payload directories are 0755, executable 0755, docs/man page 0644,
root:root ownership, with no setuid/setgid bits. Control archive contains
only control and md5sums: zero maintainer scripts. Existing /usr/bin,
/usr/share/doc/security-baseline-scanner and /usr/share/man/man1 paths remain.
No active example.invalid metadata remains.

## Limitations and provenance

rpmbuild is unavailable: RPM generation/inspection was not performed.
Native debhelper packaging and installation/upgrades were not exercised;
DEB validation uses CPack and dpkg-deb inspection, without package installation.
No new Debian 13 physical-host validation is claimed. The user's successful
Debian 13/GCC 14.2 results apply to the prior repaired application source,
which is unchanged. This packaging pass does not rerun analyzers, sanitizers,
or tracing. Historical analyzer documentation/reproducers remain intact;
GCC 14 analyzer diagnostics remain documented compiler-analysis limitations.
