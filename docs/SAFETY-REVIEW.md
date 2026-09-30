# Dedicated false-positive and safety review

Reviewed 2026-09-16 against the 1.0.0 source, separately from initial implementation.

## Conclusions and corrections

- **Missing or denied evidence:** content predicates never PASS on unavailable
  input. Missing securityfs/sysctl paths are UNAVAILABLE, not disabled mechanisms.
  Reproducible memory-source tests cover denied, I/O, type and size errors.
- **Distribution roles:** Debian group-readable shadow files pass mode checks.
  Group write/non-root ownership is a deviation needing review, not proven
  exploitation. Empty shadow fields and extra UID-0 accounts are deviations;
  PAM, NSS, account locks and legitimate administrative roles remain limitations.
- **SSH and sudo:** static files do not establish running effective policy.
  SSH first-value semantics are preserved; Include/Match suppress apparent
  effective-value reporting. No unsafe last-value-wins or fragment-only PASS.
  Sudo NOPASSWD is never automatically labeled a vulnerability.
- **Firewall, updates, repositories:** presence and cache information cannot
  establish enforcement, current patch status or trust. These remain UNKNOWN.
- **Containers and VMs:** no marker is not proof of bare metal. Sysctl reports
  explicitly limit themselves to visible runtime settings. Non-systemd PID 1
  yields NOT_APPLICABLE only for a systemd PID-1 assessment, not all services.
- **Mounts, listeners and MAC:** no required universal mount flags, no listener
  reachability claim, no AppArmor-enable/SELinux-enforce claim of full coverage.
  Missing IPv6 input makes TCP coverage UNKNOWN. Socket row parsing was tightened
  to validate addresses, slots and numeric UIDs before counting.
- **Malformed evidence:** duplicate local accounts, conflicting OS IDs/aging
  defaults and invalid sysctl values become UNKNOWN. Lockdown parsing was
  tightened to exact supported listings; ambiguous active modes become UNKNOWN.
  Empty/multiline PID-1 evidence is UNKNOWN.
- **Permission problems:** PROBLEM refers to definite inode mode bits (other
  write, shadow other-read, non-sticky world-writable /tmp), not proof of usable
  access through ACLs, parent traversal, read-only mounts or LSMs.
- **Read-only implementation:** no external command execution, socket calls,
  writes to source files, or mutable open flags. Source and imported symbols were
  inspected. Configuration is never executed. Source symlinks/FIFOs/devices are
  rejected before content reads. Pinned descriptors avoid pathname replacement
  between inspection and read. Buffers are bounded to 1 MiB per file.
- **Output:** raw accounts, hashes, network addresses, repository URLs and mount
  paths are omitted. Control bytes and Markdown metacharacters are escaped.
  Fixture bytes, modes, ownership and mtime remain unchanged across scans.
- **Packaging:** no service files, capabilities, setuid modes, automatic changes
  or maintainer scripts. RPM duplicate documentation declaration was removed;
  CPack Debian packages include copyright metadata and a syntactically complete,
  explicitly reserved maintainer contact for replacement before publication.

## Limits of the review

Static inspection and fixture immutability checks are not a dynamic syscall
proof. ptrace is denied in this environment, so the included bounded strace test
must be run on a supporting machine. The reader is not a forensic acquisition
engine or hostile-filesystem sandbox: normal reads can cause atime/audit updates,
concurrent evidence can change, and an unresponsive filesystem may block a read.
Kernel-controlled /proc visibility is restricted here; unsupported visibility is
not treated as an application defect. No scanner conclusions claim host-wide
completeness or a security score.
