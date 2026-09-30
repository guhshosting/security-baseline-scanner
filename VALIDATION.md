> Current 2026-09-29 analyzer refactor: see ANALYZER-REPAIR.md. The analyzer
> blocker remains OPEN. The report below describes the original 2026-09-16 archive.

# Validation report — security-baseline-scanner 1.0.0

Date: 2026-09-16. Source release for independent Debian 13 physical-machine
validation, not a claim of cross-distribution certification.

## Executed validation

| Gate | Actual result |
|---|---|
| GCC 13.3.0 Debug, C++17, -Wall -Wextra -Wpedantic -Werror | Passed |
| GCC 13.3.0 Release, same warning policy | Passed |
| Unit suite | 8,748 assertions passed, including 200 deterministic malformed-input samples across content evaluators |
| Black-box integration suite | 1,490 assertions passed across nine synthetic distro/scenario fixtures |
| ASan and UBSan Debug build | Both suites passed; leak detection disabled because LeakSanitizer is blocked by the environment |
| cppcheck 2.17.1 | Passed warning/style/performance/portability analysis with exhaustive branch analysis; no suppressions |
| Fresh source tree, separate Release build directory | Configure/build and both suites passed, using no prior objects |
| CPack Debian binary package | Built; control/dependency metadata and contents inspected; extracted without installation; extracted program produced valid JSON |
| Native Debian source packaging | `dpkg-source -b` successfully built native source archive and .dsc |
| Man page | Rendered by groff; no diagnostics; rendered content inspected |
| Report formats | JSON decoded and fields/types/status counts verified; text/Markdown checked for content and privacy; output failures and deterministic ordering tested |
| Safety review | Source, imported symbols, fixed paths, open flags, symlink/FIFO rejection and unchanged fixture bytes/modes/mtime inspected |
| Source artifact | Complete tree, path/type/mode and SHA-256 manifest inspection; no build binaries or downloaded dependencies included |

The two CTest suites aggregate the assertion counts above; these are not 10,238
independent test cases. Representative fixtures cover Debian 13, Ubuntu 24.04,
Fedora 42, RHEL 9, a container layout, a VM-like layout, deliberately unsafe modes,
missing data and malformed/conflicting evidence. Fixtures are synthetic and do
not mean these operating systems were booted or their vendor defaults certified.

The tests cover permission-denied and I/O outcomes through a memory source,
secure/deviating/problematic permissions, Debian shadow group readability,
empty-password ambiguity, duplicate accounts, SSH Include/Match and first-value
semantics, ambiguous OS/login settings, namespace limitations, malformed and
oversized data, NUL input, leaf/intermediate symlinks, FIFOs, selector errors,
exit thresholds, stdout failure, privacy, catalog stability and unchanged source
files. The live scan completed in the available restricted environment; some
proc/securityfs evidence was unavailable, correctly reported as such.

## Environment and blocked validation

Build environment: restricted Linux x86-64 container with Ubuntu 24.04 userspace,
GCC 13.3.0, CMake 4.4.3, Python 3.12.14 and cppcheck 2.17.1. CMake/cppcheck were
provided in a local development-tool directory; the application and its build
have no downloaded runtime dependencies or network activity.

- **ptrace/strace:** attempted once and failed with `PTRACE_TRACEME: Operation not
  permitted`. No successful dynamic syscall trace is claimed. The included
  `tests/safety_trace.py` uses a 30-second subprocess deadline.
- **LeakSanitizer:** failed to inspect `/proc/<pid>/task` in the container. ASan
  and UBSan were then run with `ASAN_OPTIONS=detect_leaks=0` and
  `UBSAN_OPTIONS=halt_on_error=1`. No leak-check pass is claimed.
- **RPM:** native spec and CPack configuration are included. A bounded CPack RPM
  attempt failed because `rpmbuild` is not installed. No RPM build/install or
  spec expansion success is claimed.
- **Native Debian binary recipe/lintian:** debhelper and lintian are unavailable.
  The CPack .deb and dpkg-source paths were exercised; `dpkg-buildpackage` with
  debhelper and lintian certification were not.
- **Physical hosts/full distros:** not available. No real Fedora/RHEL boot,
  systemd service interrogation, Secure Boot/firmware validation or physical
  Debian 13 run was performed. Permission denial was injected in unit tests;
  unprivileged-user privilege transitions are restricted in this container.
- **Network/firewall/SSH policy:** current security updates, effective firewall,
  sudo, SSH, repository and running/enabled service policy are intentionally
  outside static inference. UNKNOWN is an honest coverage limit, not a test pass.

Final compiler, static-analysis and test runs used bounded commands; CTest tests
have a 60-second timeout and CLI subprocess tests have 15-second timeouts. No
indefinite retries were used for blocked procfs, tracing or sanitizer capabilities.
`./scripts/validate.sh` is deliberately fail-fast if an installed tracing tool
cannot perform its check; inspect the log rather than interpret the exit as an
application defect. See `docs/SAFETY-REVIEW.md` for the dedicated review and fixes.

## Independent Debian 13 validation

1. Unpack the source archive and run `sha256sum -c SOURCE-MANIFEST.sha256` inside
   its root before creating build files.
2. With GCC, CMake, make, Python, cppcheck >= 2.13, groff and strace available, run
   `./scripts/validate.sh`. Inspect `validation-logs/` and resolve real failures.
3. Run ASan/UBSan on the physical host, including LeakSanitizer if supported:

   ```sh
   cmake -S . -B build-sanitize -DCMAKE_BUILD_TYPE=Debug \
     -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
     -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
   cmake --build build-sanitize -j2
   ctest --test-dir build-sanitize --timeout 60 --output-on-failure
   ```

4. Run ordinary-user scans first; compare restricted/privileged results only if
   desired. No remediation or administrative command is invoked by the scanner.
5. Build/inspect the Debian package with native debhelper and lintian. Test the
   RPM recipe on a Fedora/RHEL builder before distributing RPMs. Set a real
   public maintainer contact in packaging metadata before publication.

The development .deb was built for the available Ubuntu toolchain and is not
included as a recommended Debian 13 binary. The deliverable is the complete
source tree, with packaging recipes, tests, documentation and validation logs.
