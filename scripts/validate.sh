#!/bin/sh
# Local reproducible validation; writes build directories and validation logs only.
set -eu
cd "$(dirname "$0")/.."
mkdir -p validation-logs
for kind in Debug Release; do
    lower=$(printf '%s' "$kind" | tr '[:upper:]' '[:lower:]')
    cmake -S . -B "build-$lower" -DCMAKE_BUILD_TYPE="$kind" > "validation-logs/configure-$lower.log" 2>&1
    cmake --build "build-$lower" -j2 > "validation-logs/build-$lower.log" 2>&1
    ctest --test-dir "build-$lower" --output-on-failure -V > "validation-logs/test-$lower.log" 2>&1
    printf '%s build and tests passed\n' "$kind"
done
if command -v cppcheck >/dev/null 2>&1; then
    cppcheck --enable=warning,style,performance,portability --check-level=exhaustive --error-exitcode=1 --std=c++17 -I include src tests/unit.cpp tests/fd_lifecycle.cpp > validation-logs/cppcheck.log 2>&1
    printf 'cppcheck passed\n'
else
    printf 'cppcheck unavailable; validation incomplete\n' >&2
    exit 1
fi
if command -v strace >/dev/null 2>&1; then
    python3 tests/safety_trace.py build-release/security-baseline-scanner > validation-logs/safety-trace.log 2>&1
    printf 'Read-only syscall trace passed\n'
else
    printf 'strace unavailable; syscall safety validation not run\n' >&2
fi
if command -v groff >/dev/null 2>&1; then
    groff -man -Tutf8 docs/security-baseline-scanner.1 > validation-logs/man-render.txt 2> validation-logs/man-render-errors.txt
fi
