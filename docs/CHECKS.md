# Check catalog, version 1.0.0

IDs are stable; catalog order is deterministic. Every check includes evidence,
status, qualitative severity, explanation, recommendation and limitations.
No score is calculated. These are local predicates, not distribution compliance
profiles. Known Debian/Ubuntu and Fedora/RHEL differences are deliberately
accepted or left unknown.

Unless otherwise documented: missing, permission-denied, unsupported symlink or
file type and read errors yield UNAVAILABLE; malformed/NUL/over-limit data yield
UNKNOWN. No absent evidence yields PASS. Sensitive content is never printed.
Metadata uses the same pinned inode; separate checks are not an atomic snapshot.
Recommendations ask for human contextual review, never automatic remediation.

## SBS-OS-001: Operating system

Category: `system`. Evidence: `/etc/os-release`.

INFO for supported ID/version fields; duplicate or malformed selected fields yield UNKNOWN. Falls back to /usr/lib/os-release if the first path cannot be read. No lifecycle or patch judgment.

## SBS-OS-002: Kernel release

Category: `system`. Evidence: `/proc/sys/kernel/osrelease`.

INFO for a bounded kernel release string. No CVE inference: distributions backport patches.

## SBS-ENV-001: Execution environment

Category: `system`. Evidence: `/run/systemd/container`.

INFO for container marker presence or non-observation, using /run/systemd/container, /.dockerenv and /run/.containerenv. Missing markers never prove bare metal or rule out virtualization.

## SBS-UPD-001: Security update assessment

Category: `updates`. Evidence: paths/constraints described below.

Always UNKNOWN. No cached package data or installed version establishes current security updates without authoritative repository freshness. No cache refresh is attempted.

## SBS-ACC-001: Local privileged accounts

Category: `accounts`. Evidence: `/etc/passwd`.

Parse seven-field local records and numeric UID/GID, reject duplicates/malformed/NIS compatibility entries. PASS for one root-named UID-0 entry; DEVIATION (medium) for extra or renamed UID-0 entries; zero UID-0 entries UNKNOWN. Report counts only. NSS/LDAP and effective privileges outside local records are not assessed.

## SBS-ACC-002: Local empty password fields

Category: `accounts`. Evidence: `/etc/shadow`.

Parse nine-field records, unique names and numeric/empty/-1 aging fields. Empty password fields yield DEVIATION (medium); none yields PASS. Malformed data UNKNOWN. Never claim empty fields permit login; PAM, locks, expiry and shells matter. Hashes and account names are never output.

## SBS-AUTH-001: Password aging defaults

Category: `accounts`. Evidence: `/etc/login.defs`.

INFO for PASS_MAX_DAYS, PASS_MIN_DAYS and PASS_WARN_AGE, if present and numeric (or -1); duplicates or malformed selected values UNKNOWN. Only defaults for newly created accounts; no demand for mandatory rotation.

## SBS-SUDO-001: Sudo policy scope

Category: `sudo`. Evidence: `/etc/sudoers`.

Always UNKNOWN when present: effective authorization requires native sudo policy evaluation. Includes, aliases, ordering, command matching and remote policy are not resolved. No inference from NOPASSWD or apparent ALL grants.

## SBS-SSH-001: SSH static configuration scope

Category: `ssh`. Evidence: `/etc/ssh/sshd_config`.

Always UNKNOWN when present. Count static directives. Observe first values for PermitRootLogin, PasswordAuthentication and PermitEmptyPasswords only when there is no Include/Match or complex selected directive. No defaults inferred; supported-value parsing rejects ambiguity. First-value semantics are honored but do not establish the running daemon policy. No fragment is executed or included.

## SBS-FILE-001: Password database permissions

Category: `files`. Evidence: `/etc/passwd`.

Inspect inode mode and numeric owner only. World write yields PROBLEM (high); for shadow/gshadow, world read also yields PROBLEM (high). Otherwise non-root owner or group write yields DEVIATION (medium); otherwise PASS for these predicates only. Group read of shadow is permitted (Debian shadow group). Directories at expected file paths yield UNKNOWN. ACLs, parent access, groups, namespaces, LSMs and read-only mounts can limit effective access: this confirms mode bits, not exploitability.

## SBS-FILE-002: Shadow database permissions

Category: `files`. Evidence: `/etc/shadow`.

Inspect inode mode and numeric owner only. World write yields PROBLEM (high); for shadow/gshadow, world read also yields PROBLEM (high). Otherwise non-root owner or group write yields DEVIATION (medium); otherwise PASS for these predicates only. Group read of shadow is permitted (Debian shadow group). Directories at expected file paths yield UNKNOWN. ACLs, parent access, groups, namespaces, LSMs and read-only mounts can limit effective access: this confirms mode bits, not exploitability.

## SBS-FILE-003: Group database permissions

Category: `files`. Evidence: `/etc/group`.

Inspect inode mode and numeric owner only. World write yields PROBLEM (high); for shadow/gshadow, world read also yields PROBLEM (high). Otherwise non-root owner or group write yields DEVIATION (medium); otherwise PASS for these predicates only. Group read of shadow is permitted (Debian shadow group). Directories at expected file paths yield UNKNOWN. ACLs, parent access, groups, namespaces, LSMs and read-only mounts can limit effective access: this confirms mode bits, not exploitability.

## SBS-FILE-004: Group shadow permissions

Category: `files`. Evidence: `/etc/gshadow`.

Inspect inode mode and numeric owner only. World write yields PROBLEM (high); for shadow/gshadow, world read also yields PROBLEM (high). Otherwise non-root owner or group write yields DEVIATION (medium); otherwise PASS for these predicates only. Group read of shadow is permitted (Debian shadow group). Directories at expected file paths yield UNKNOWN. ACLs, parent access, groups, namespaces, LSMs and read-only mounts can limit effective access: this confirms mode bits, not exploitability.

## SBS-FILE-005: Sudo policy file permissions

Category: `files`. Evidence: `/etc/sudoers`.

Inspect inode mode and numeric owner only. World write yields PROBLEM (high); for shadow/gshadow, world read also yields PROBLEM (high). Otherwise non-root owner or group write yields DEVIATION (medium); otherwise PASS for these predicates only. Group read of shadow is permitted (Debian shadow group). Directories at expected file paths yield UNKNOWN. ACLs, parent access, groups, namespaces, LSMs and read-only mounts can limit effective access: this confirms mode bits, not exploitability.

## SBS-FILE-006: SSH configuration permissions

Category: `files`. Evidence: `/etc/ssh/sshd_config`.

Inspect inode mode and numeric owner only. World write yields PROBLEM (high); for shadow/gshadow, world read also yields PROBLEM (high). Otherwise non-root owner or group write yields DEVIATION (medium); otherwise PASS for these predicates only. Group read of shadow is permitted (Debian shadow group). Directories at expected file paths yield UNKNOWN. ACLs, parent access, groups, namespaces, LSMs and read-only mounts can limit effective access: this confirms mode bits, not exploitability.

## SBS-FILE-007: Temporary directory sticky bit

Category: `files`. Evidence: `/tmp`.

Directory metadata only. World-write without sticky bit yields PROBLEM (high); otherwise non-root ownership yields DEVIATION (medium); otherwise PASS. A file at /tmp yields UNKNOWN. A private non-world-writable directory need not have sticky bit.

## SBS-MNT-001: Mount restriction observations

Category: `mounts`. Evidence: `/proc/self/mountinfo`.

INFO counts total mounts and per-mount nodev/nosuid/noexec in the current namespace. No universal required flags; device/executable mounts can be intentional. Empty/malformed mountinfo UNKNOWN. Paths and devices omitted; superblock and nested-mount policies not combined.

## SBS-SVC-001: Service manager observations

Category: `services`. Evidence: `/proc/1/comm`.

Read PID-1 command name. systemd yields UNKNOWN because state is not queried. A different nonempty PID-1 name yields NOT_APPLICABLE only for a systemd PID-1 assessment, not all services. Empty/multiline data UNKNOWN. Enabled/running units are not inferred from file presence.

## SBS-FW-001: Firewall enforcement

Category: `network`. Evidence: paths/constraints described below.

Always UNKNOWN. Metadata observations at /etc/nftables.conf, /etc/ufw/ufw.conf, /etc/firewalld/firewalld.conf and /proc/net/ip{,6}_tables_names cannot establish active rules, namespace coverage or upstream filtering.

## SBS-NET-001: TCP listening socket observations

Category: `network`. Evidence: `/proc/net/tcp`.

Read /proc/net/tcp and /proc/net/tcp6; count syntactically supported state 0A records. INFO only when both inputs are available and parseable; partial/invalid data UNKNOWN (or UNAVAILABLE if primary input cannot be read). Does not prove reachability or a vulnerable service. No addresses, ports or owners are reported; no UDP/process attribution.

## SBS-KERN-001: Userspace address randomization

Category: `kernel`. Evidence: `/proc/sys/kernel/randomize_va_space`.

Parse one unsigned decimal runtime value. PASS at or above the listed minimum and within the listed supported maximum. Lower values DEVIATION (low), not a vulnerability; role/compatibility/diagnostics can justify them. Malformed, negative or out-of-range values UNKNOWN. No persistence or per-process assessment.

Baseline minimum: 2; supported range: 0–2. Scope: Full userspace ASLR.

## SBS-KERN-002: Kernel pointer disclosure restriction

Category: `kernel`. Evidence: `/proc/sys/kernel/kptr_restrict`.

Parse one unsigned decimal runtime value. PASS at or above the listed minimum and within the listed supported maximum. Lower values DEVIATION (low), not a vulnerability; role/compatibility/diagnostics can justify them. Malformed, negative or out-of-range values UNKNOWN. No persistence or per-process assessment.

Baseline minimum: 1; supported range: 0–2. Scope: Restricted kernel pointer presentation.

## SBS-KERN-003: Kernel log access restriction

Category: `kernel`. Evidence: `/proc/sys/kernel/dmesg_restrict`.

Parse one unsigned decimal runtime value. PASS at or above the listed minimum and within the listed supported maximum. Lower values DEVIATION (low), not a vulnerability; role/compatibility/diagnostics can justify them. Malformed, negative or out-of-range values UNKNOWN. No persistence or per-process assessment.

Baseline minimum: 1; supported range: 0–1. Scope: Restricted kernel log access.

## SBS-KERN-004: Protected symbolic links

Category: `kernel`. Evidence: `/proc/sys/fs/protected_symlinks`.

Parse one unsigned decimal runtime value. PASS at or above the listed minimum and within the listed supported maximum. Lower values DEVIATION (low), not a vulnerability; role/compatibility/diagnostics can justify them. Malformed, negative or out-of-range values UNKNOWN. No persistence or per-process assessment.

Baseline minimum: 1; supported range: 0–1. Scope: Sticky-directory symlink protections.

## SBS-KERN-005: Protected hard links

Category: `kernel`. Evidence: `/proc/sys/fs/protected_hardlinks`.

Parse one unsigned decimal runtime value. PASS at or above the listed minimum and within the listed supported maximum. Lower values DEVIATION (low), not a vulnerability; role/compatibility/diagnostics can justify them. Malformed, negative or out-of-range values UNKNOWN. No persistence or per-process assessment.

Baseline minimum: 1; supported range: 0–1. Scope: Hard-link ownership protections.

## SBS-KERN-006: Protected FIFO creation

Category: `kernel`. Evidence: `/proc/sys/fs/protected_fifos`.

Parse one unsigned decimal runtime value. PASS at or above the listed minimum and within the listed supported maximum. Lower values DEVIATION (low), not a vulnerability; role/compatibility/diagnostics can justify them. Malformed, negative or out-of-range values UNKNOWN. No persistence or per-process assessment.

Baseline minimum: 1; supported range: 0–2. Scope: Sticky-directory FIFO protections.

## SBS-KERN-007: Protected regular file creation

Category: `kernel`. Evidence: `/proc/sys/fs/protected_regular`.

Parse one unsigned decimal runtime value. PASS at or above the listed minimum and within the listed supported maximum. Lower values DEVIATION (low), not a vulnerability; role/compatibility/diagnostics can justify them. Malformed, negative or out-of-range values UNKNOWN. No persistence or per-process assessment.

Baseline minimum: 1; supported range: 0–2. Scope: Sticky-directory regular-file protections.

## SBS-BOOT-001: Kernel lockdown state

Category: `boot`. Evidence: `/sys/kernel/security/lockdown`.

INFO only for the three standard lockdown listings with exactly one active mode. Other contents UNKNOWN. Missing evidence is UNAVAILABLE, not proof that lockdown is disabled or Secure Boot is absent.

## SBS-MAC-001: SELinux runtime enforcement

Category: `mechanisms`. Evidence: `/sys/fs/selinux/enforce`.

INFO for runtime enforce=0 or 1; other values UNKNOWN. Permissive is not automatically a problem; enforcing does not prove all services are confined. Missing path does not prove no MAC protection.

## SBS-MAC-002: AppArmor runtime availability

Category: `mechanisms`. Evidence: `/sys/module/apparmor/parameters/enabled`.

INFO for Y/N module flag; other values UNKNOWN. Enabled does not prove profiles loaded, enforcing or covering the relevant services. No preference for AppArmor over SELinux.

## SBS-PKG-001: Package database observations

Category: `packages`. Evidence: paths/constraints described below.

INFO if any database path exists: /var/lib/dpkg/status, /usr/lib/sysimage/rpm, /var/lib/rpm. Otherwise UNKNOWN. No installed package list, integrity or patch status inference.

## SBS-REPO-001: Repository trust assessment

Category: `packages`. Evidence: paths/constraints described below.

Always UNKNOWN. Metadata for /etc/apt/sources.list, /etc/apt/sources.list.d and /etc/yum.repos.d only. Does not parse trust overrides, include graphs, keys or repository URLs; no credential exposure.

## Primary references

Semantics consulted during development; no reference is fetched at scanner runtime.

- [Linux kernel sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [Linux filesystem sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/fs.html)
- [OpenSSH sshd_config manual](https://man.openbsd.org/sshd_config)
- [Linux proc interfaces](https://man7.org/linux/man-pages/man5/proc.5.html)

Distribution-native tooling and documentation remain authoritative for effective
policy. This release intentionally does not embed a vulnerability database or
assume that defaults for a server, desktop, VM and container are interchangeable.
