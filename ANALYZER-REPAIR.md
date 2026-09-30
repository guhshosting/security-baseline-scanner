# Analyzer refactor report — 2026-09-29

**Status: targeted refactor and behavior validation complete; the analyzer
release blocker is NOT cleared.** GCC 14.2 is unavailable here. Available GCC
13.3 still rejects the source under `-O0 -fanalyzer -Werror`, including warnings
that it also emits for the included minimal valid-C++ reproducers. This archive
is a candidate for the requested GCC 14.2 retest, not an analyzer-clean release.
No warnings were suppressed, flags weakened, or analyzer-specific exclusions
introduced. No success is claimed for an analyzer binary or analyzer CTest.

## Diagnostic families and source-level investigation

| Family | Findings and classification | Change and remaining uncertainty |
|---|---|---|
| `name(Access)` literal-to-string returns | Literal strings have initialized contents and static lifetime. No source-level uninitialized read was found; probable GCC/libstdc++ modeling false positives. | Return `const char* noexcept` internally. All label bytes are identical. Three literal-concatenation callers now append the label to an owned evidence string. These warnings no longer appear in the local source.cpp analyzer run. |
| `operator+`, string moves, `to_string` in proc paths | Owned temporary strings and integer formatting were valid; no dangling lifetime was identified. Probable analyzer false positives. | Named strings plus `append` and bounded `to_chars` replace the chains and `to_string`. The copied suffix indexes are unchanged (10 for both aliases). No warning from these operator+/to_string instantiations remains in the local source.cpp diagnostics. |
| Default `Evidence` / returned `Evidence` | `access`, `mode`, `uid`, and `directory` already had default member initializers; `text` was default-constructed as an empty string. Every early return was deterministic. No genuine uninitialized field was found. | `text{}`, `result{}` and `leaf{}` make existing initialization explicit. Returned/default-constructed Evidence warnings still occur locally. A standalone function returning a default-constructed std::string triggers the same GCC 13 family. No meaningless buffer-zeroing or broader interface redesign was added. |
| `analyzer-fd-leak` at root acquisition | **No genuine original leak found.** The original destructor called close(root_fd_); copying was deleted and implicit moves were unavailable. A failed open returned -1 and the constructor threw without acquiring a descriptor. The original post-open live-string comparison did not perform an allocating operation. | Root ownership now uses the same small scoped FD owner as local traversal/read descriptors. Acquisition occurs after initialization of other members. A successful open is immediately adopted by a noexcept reset. GCC 13 still reports a leak at this open; a standalone valid scoped-owner reproducer also warns. FD lifecycle tests against both original and refactored code pass, as do candidate sanitizer tests. GCC 14 confirmation remains required. |

These conclusions identify the source operations involved, language-level
initialization/ownership guarantees and observed local compiler behavior. The
exact internal GCC defect has **not** been established by a compiler patch or
bug bisect. Calling these probable modeling false positives is not a claim that
an analyzer pass was obtained. GCC 13 reproductions are not substitutes for GCC
14.2 testing. Repeated harmless initialization variants did not resolve returned
string warnings, so they were not retained as speculative workarounds.

## Exact ownership after refactor

`FileSource::root_fd_` is `detail::Fd`, initialized to the invalid sentinel -1.
`live_` is initialized before any root descriptor is acquired. `open` uses the
same O_PATH/O_DIRECTORY/O_NOFOLLOW/O_CLOEXEC flags as before. Negative results
throw the same runtime_error with the same message. A successful descriptor is
adopted through `reset`, which is noexcept; nothing afterward can throw.
The defaulted FileSource destructor destroys root_fd_, whose destructor calls
close exactly once for a nonnegative descriptor. All local descriptors use the
same owner and close during normal return and exception unwinding. Copy and move
construction/assignment are explicitly deleted for both owner classes. Moving
is not required by any caller and was already unavailable for FileSource.
Destruction through Source's virtual destructor remains supported. No new
allocation or runtime dependency was introduced by the FD owner.

## Files changed relative to the delivered original

- `include/sbs/scanner.hpp`: Access label return type, explicit text initialization,
  scoped root owner, explicit deleted move operations.
- `include/sbs/fd.hpp`: existing project-local FD helper promoted to a shared
  internal header; no external dependency.
- `src/source.cpp`: named path construction, to_chars formatting, explicit
  aggregate initialization and scoped root acquisition.
- `src/rules.cpp`: three label assembly sites only; no rule decisions changed.
- `CMakeLists.txt`: add only the FD lifecycle test target and its timeout.
- `scripts/validate.sh`: include the new lifecycle test source in cppcheck.
- `tests/fd_lifecycle.cpp`: ownership regression and compile-time copy/move checks.
- `tests/compare_behavior.py`: bounded original/candidate CLI comparison utility.
- `tests/analyzer-repro/{string,fd}.cpp`: minimal compiler diagnostic reproducers;
  not application code and intentionally not normal CMake test targets.
- `ANALYZER-REPAIR.md`, README, VALIDATION, ARCHITECTURE and the source manifest:
  current status/provenance documentation.
- `validation-logs/analyzer-repair-2026-09-29/`: current-run logs. Prior logs remain
  explicitly historical and are not presented as validation of this refactor.

No stable rule ID, threshold, finding text, severity, report format or CLI exit
code was changed. Version remains 1.0.0. Path component rejection, no-follow
flags, pinned-descriptor reopening, size limits, offline behavior and privacy
remain unchanged. There are no package-manager/system-management calls or
network calls in the scanner or new tests.

## Executed results in this environment

Environment: Ubuntu 24.04 userspace, GCC/libstdc++ 13.3.0, CMake 4.4.3,
Python 3.12.14, cppcheck 2.17.1, restricted Linux x86-64 execution container.

| Requested validation | Actual result |
|---|---|
| Strict Release | PASS, -Wall -Wextra -Wpedantic -Werror |
| Full CTest | PASS, 3/3 (original two suites plus FD lifecycle) |
| Fresh -O0 -fanalyzer -Werror | FAIL on available GCC 13.3: remaining Evidence/string and FD-model warnings; no suppressed categories |
| GCC 14.2 analyzer | NOT RUN: compiler unavailable |
| Analyzer CTest | NOT RUN: analyzer build failed, no fallback binary used |
| Exhaustive cppcheck 2.17.1 | PASS, zero diagnostics after correcting a test-only unused-allocation observation by exercising virtual dispatch |
| ASan/UBSan | PASS, 3/3; ASAN_OPTIONS=detect_leaks=0, UBSAN_OPTIONS=halt_on_error=1 |
| FD lifecycle | PASS: 2,000 successful constructions/destructions, 2,000 failed opens, virtual-base destruction; no descriptor growth; copy/move disabled |
| Behavior equivalence | PASS: 338 byte-exact comparisons of stdout, stderr and exit code against a fresh build of the original archive |
| Exact replacement archive extraction | Release and full CTest results are checked after archive creation; see delivery result |

Behavior comparisons cover all nine supplied fixture trees, default reports,
text/JSON/Markdown, category/check/intersection selections, both failure
thresholds, help/version/catalog/invalid CLI cases, and available live reports.
Live comparisons are sequential snapshots and do not certify unchanging host
state. Offline fixture ownership and contents are identical for both binaries.
The old archive SHA-256 is:
`d5a56786227e3a8be10be10ad08fbc1597297d3cf339c5391a0111606e509d80`.

The lifecycle test avoids procfs enumeration: it uses bounded F_GETFD queries,
requires fewer than 64 inherited low descriptors and relies on Linux allocating
the lowest available descriptor for sequential open/dup operations. It compares
the set periodically and at completion; it does not claim arbitrary process-wide
leak detection under concurrent threads. CTest's deadline is 60 seconds.
Behavior subprocesses have 15-second deadlines. Builds/analysis use bounded
commands. Existing container LeakSanitizer/ptrace restrictions were not retried.

The Debian 13/GCC 14.2 live/strace/sanitizer/cppcheck successes supplied by the
user apply to the **prior archive**, not this candidate. No new Debian-host,
ptrace, LeakSanitizer or RPM validation is claimed here. Packaging metadata and
recipes were not changed by this repair task. The analyzer blocker must remain
open unless the GCC 14.2 retest succeeds or a further permissible repair is made.

## Reproduction

```sh
cmake -S . -B build-analyzer -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS='-O0 -Wall -Wextra -Wpedantic -Werror -fanalyzer'
cmake --build build-analyzer -j2
ctest --test-dir build-analyzer --timeout 60 --output-on-failure
```

Minimal diagnostic probes (not claimed to pass):

```sh
g++ -std=c++17 -O0 -Wall -Wextra -Wpedantic -Werror -fanalyzer \
  -c tests/analyzer-repro/string.cpp -o string-repro.o
g++ -std=c++17 -O0 -Wall -Wextra -Wpedantic -Werror -fanalyzer \
  -c tests/analyzer-repro/fd.cpp -o fd-repro.o
```

## Subsequent host validation (user-reported)

The user subsequently validated the repaired archive on Debian 13 with GCC
14.2: strict Release, CTest 3/3, cppcheck 2.17.1, ASan/UBSan 3/3, live scan,
JSON, Markdown, fail-on semantics, read-only strace and FD lifecycle passed.
The minimal string and scoped-RAII FD reproducers reproduce the GCC 14 analyzer
diagnostics. These are accepted compiler-analysis limitations, not a reason
for further application refactoring. This is user-provided host evidence, not
a Debian 13 test performed in the packaging environment. Historical results
above remain preserved. The packaging-only revision changes no application
source, headers, tests or reproducers.
