# security-baseline-scanner 1.0.0

Current analyzer refactor status: [ANALYZER-REPAIR.md](ANALYZER-REPAIR.md).
GCC 14 analyzer diagnostics are documented compiler-analysis limitations.
The user reports successful Debian 13 / GCC 14.2 Release, tests and sanitizer
validation; see the addendum and [PACKAGING-VALIDATION.md](PACKAGING-VALIDATION.md).

A Linux-only C++17 CLI for conservative local security-baseline observations.
MIT licensed. No telemetry, network access, subprocesses, package-manager calls,
service-manager calls, or remediation. Reports go to standard output.

## Build and run

Build dependencies: GCC with C++17 support, CMake >= 3.16, make (or Ninja).
Tests additionally require Python >= 3.8, with no third-party modules.
The installed program uses only libc/libstdc++ and Linux interfaces.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
./build/security-baseline-scanner
./build/security-baseline-scanner --format json
./build/security-baseline-scanner --format markdown
./build/security-baseline-scanner --list-checks
./build/security-baseline-scanner --category kernel --category files
./build/security-baseline-scanner --check SBS-ACC-001 --check SBS-SSH-001
./build/security-baseline-scanner --fail-on problem
```

Start as an ordinary user. Restricted evidence is explicitly UNAVAILABLE; root is
optional and should never be used to force a complete-looking report. Root can
read shadow records, but account names and hashes are never included in output.
The application does not elevate privileges and must not be installed setuid.

`--root /absolute/offline/root` reads a supplied filesystem tree, without chroot,
mounting anything, following source symlinks, or falling back to live host files.
Offline proc/sys evidence must be supplied and can be stale. The report is marked
`offline-root`. The kernel `/proc/self/fd` interface is required by the reader
only to reopen inspected file descriptors; it is never used as offline evidence.
Use a trusted local tree, not an attacker-controlled FUSE/NFS mount.

Repeated check/category selectors form unions within their kind and intersect
across kinds. Unknown IDs, unknown categories and empty intersections are errors.
The rule catalog lists all 32 stable IDs; the order is deterministic. Reports omit
wall-clock time, hostname, IP/MAC addresses, account names, password hashes,
mount paths and repository credentials. Review reports before sharing: kernel
release, distribution, permission modes and security settings remain visible.

## Scope and threat model

This is a bounded, local configuration review aid for Debian/Ubuntu and
Fedora/RHEL-style installations, including restricted namespaces. It is **not** a
CIS/STIG compliance certification, penetration test, malware detector, CVE
scanner, or guarantee that a host is secure. There is no numeric score.

It assumes a trustworthy kernel and ordinary, responsive local filesystems.
It cannot detect a compromised kernel fabricating evidence. Reads are not an
atomic snapshot: files and runtime settings can change during a scan. Containers
may expose host-wide kernel settings and only a subset of network/mount state.
Absence of a container marker does not prove bare metal or exclude virtualization.
No VM vendor or hardware attestation is attempted.

The program only opens evidence for reading/metadata, rejects symlinks at every
source path component, rejects devices/FIFOs/sockets before opening for content,
and bounds each content read to 1 MiB. It never executes configuration, invokes
a shell, writes files, changes permissions, installs packages, changes services,
or touches firewall rules. Read access may cause kernel-managed atime or audit
records; this is not a forensic zero-side-effect acquisition tool. Shell output
redirection and installation/build/test tools write their own artifacts at the
operator's request and are separate from scanner execution.

Security mechanisms and policy dependencies are deliberately not guessed:

- Update freshness, repository trust and firewall enforcement remain UNKNOWN.
- SSH static values do not prove effective running-daemon policy; Include/Match
  contexts and launch arguments require native evaluation.
- Sudo policy requires its native parser, including remote policy and aliases.
  NOPASSWD is not automatically called a vulnerability.
- Service state is not inferred from configuration or enablement symlinks.
- AppArmor enabled and SELinux enforcing do not prove service confinement.
- Lockdown does not prove Secure Boot, encryption or firmware trust.
- Listening sockets do not prove external reachability. Only TCP counts are
  reported; UDP and process attribution are outside this release's scope.

These limitations are deliberate coverage boundaries, not successful checks.
Detailed evidence paths and decision rules: [docs/CHECKS.md](docs/CHECKS.md).
Architecture and extension contract: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Findings and exit codes

| Status | Meaning |
|---|---|
| PASS | Only the specific supported predicate met its baseline |
| PROBLEM | Concrete problematic permission bits observed; exploitability not proven |
| DEVIATION | Role-dependent best-practice difference requiring review |
| INFO | Observation without a security judgment |
| UNAVAILABLE | Missing, denied, unsupported file type/symlink or I/O failure |
| NOT_APPLICABLE | A narrowly scoped check does not apply to observed evidence |
| UNKNOWN | Evidence cannot establish a conclusion, or parsing is ambiguous |

Severity (`none`, `low`, `medium`, `high`) is qualitative, not CVSS or a score.
All recommendations require human review; there is no repair mode.
JSON schema version 1 is documented in `docs/report.schema.json`. Text, JSON and
Markdown carry the same evidence, explanation, recommendation and limitations.
All control/non-ASCII bytes are escaped, and Markdown metacharacters are escaped.

| Exit | Meaning |
|---|---|
| 0 | Report produced; does not imply secure or complete |
| 1 | Explicit `--fail-on problem` or `--fail-on deviation` threshold met |
| 2 | Invalid CLI option or selection |
| 3 | Operational error, unreadable root or output failure |

`--fail-on deviation` includes PROBLEM. UNKNOWN and UNAVAILABLE never trigger
those thresholds. Monitor JSON status counts separately for coverage. Unix signal
termination retains standard signal semantics (for example SIGPIPE).

## Validation and packaging

```sh
./scripts/validate.sh  # cppcheck >= 2.13; strace requires permitted ptrace
# Debian binary package, no installation or maintainer scripts:
(cd build-release && cpack -G DEB)
dpkg-deb --info build-release/*.deb
dpkg-deb --contents build-release/*.deb
# Native Debian source packaging (requires debhelper >= 13):
dpkg-buildpackage -us -uc -b
# RPM native recipe; run from a source release with an RPM build tree:
rpmbuild -ba packaging/security-baseline-scanner.spec
```

For RPM, put `security-baseline-scanner-1.0.0.tar.gz` in the RPM SOURCES directory.
The spec uses standard CMake RPM macros from `cmake`; tests run during `%check`.
CPack also supports `cpack -G RPM` where rpmbuild is installed. No package installs
services, configuration, capabilities, setuid binaries or maintainer script hooks.
Native packaging tools can apply distribution build and hardening policies.
Package maintainer: GuhsHosting <guhshosting@users.noreply.github.com>.
Homepage: https://github.com/guhshosting/security-baseline-scanner

For your independent Debian 13 validation, unpack the source archive, run
`./scripts/validate.sh`, inspect its logs, then run the scanner unprivileged on the
physical machine. Optionally compare a privileged report with the restricted
one. Read `VALIDATION.md` for the actual environment and untested boundaries.
Do not publish solely on the basis of synthetic distro fixtures.
