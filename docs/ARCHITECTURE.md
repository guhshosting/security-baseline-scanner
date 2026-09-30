# Architecture

`include/sbs/scanner.hpp` defines the boundary between evidence collection,
rule evaluation and output. There are no third-party runtime dependencies.

1. `FileSource` implements the `Source` read/metadata interface. It pins the root
   with O_PATH, walks fixed absolute evidence paths with descriptor-relative
   openat and O_NOFOLLOW, validates types with fstat, and reopens the pinned
   regular-file descriptor through trusted kernel procfs. It never reopens a
   mutable evidence pathname. Read descriptors use O_RDONLY/O_NONBLOCK/CLOEXEC.
   Files larger than 1 MiB, embedded NULs, errors and denied access have explicit
   states. Input is never executed. Descriptor RAII covers all early returns.
2. `rules()` is the stable rule catalog. Each entry has a unique ID, category,
   title, evidence path and evaluator kind, with parameters for common checks.
   `evaluate` dispatches individual rules to conservative bounded parsers and
   predicates. It returns a structured `Finding`; it cannot write to `Source`.
   Reusable permissions and sysctl evaluators share documented semantics.
3. `scan` validates selectors before evaluating the catalog in fixed order.
   `render` converts findings to text, JSON or Markdown, with explicit escaping.
   JSON has schema version 1 and status counts, never a numerical risk score.
4. `main` parses options, controls stdout and maps errors to exit codes. No
   service manager, package manager, NSS lookup, DNS, shell or child process is
   used. Runtime contains no socket or write-to-files API.

Live `/proc/self/mountinfo` and `/proc/net/tcp{,6}` aliases are translated to
`/proc/<own-pid>/...` to avoid following procfs symlinks. This translation occurs
only for root `/`; offline roots retain their supplied paths. OS identity may
fall back to `/usr/lib/os-release`; that fallback is reported as evidence.
Other symlink evidence is UNAVAILABLE, including legitimate configuration links.
This favors safe predictable traversal over exhaustive coverage.

This is a namespace-scoped reader, not a filesystem sandbox against hostile
mounts, kernel forgery or concurrent mount replacement. Content byte limits do
not impose a hard deadline on a stalled remote filesystem. Use local trusted
filesystems. Metadata and contents may change across rules; reports are not an
atomic snapshot. A missing file does not prove the corresponding feature is
uninstalled or disabled.

## Adding a rule

Add a unique stable ID to the catalog and check-ID manifest. Add its evaluator,
evidence paths, syntax acceptance, error behavior, decision rationale and coverage
limits to CHECKS.md. Add safe, deviation/problem, absent, denied, malformed,
conflicting and role-specific cases. Never reinterpret an existing ID as a
materially different check. Source collection remains read-only; new external
commands or network dependencies would violate the design contract.

## Testing

Memory-source unit tests make permission-denied/I/O failures reproducible even
as root. JSON fixture trees cover Debian 13, Ubuntu, Fedora, RHEL, containers,
deliberate unsafe modes, missing evidence and conflicting/malformed input.
Black-box tests check deterministic ordering, summary counts, schema fields,
privacy, exit codes, filters, output errors, unchanged bytes/modes/mtime and
symlink/FIFO/size/NUL handling. Fixtures run as either root or ordinary users;
o chown, mount or privilege elevation is required. These are representative
synthetic layouts, not full booted distributions or compliance profiles.

## FD ownership clarification (2026-09-29)

The common scoped descriptor owner is now in `include/sbs/fd.hpp`. It owns both
the root descriptor and traversal/read descriptors. FileSource explicitly forbids
copying and moving; its defaulted destructor destroys the root owner. Root
acquisition occurs only after other member initialization. See ANALYZER-REPAIR.md
for analyzer limitations and the additional bounded lifecycle regression test.
