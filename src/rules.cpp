#include "sbs/scanner.hpp"
#include <algorithm>
#include <charconv>
#include <set>
#include <sstream>
#include <stdexcept>

namespace sbs {
namespace {
std::string trim(const std::string& s) {
    const auto a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) { return {}; }
    return s.substr(a, s.find_last_not_of(" \t\r\n") - a + 1);
}
bool number(const std::string& s, unsigned& n) {
    if (s.empty()) { return false; }
    const auto parsed = std::from_chars(s.data(), s.data() + s.size(), n);
    return parsed.ec == std::errc{} && parsed.ptr == s.data() + s.size();
}
std::vector<std::string> split(const std::string& line, char delimiter) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (;;) {
        const auto pos = line.find(delimiter, start);
        out.push_back(line.substr(start, pos == std::string::npos ? pos : pos - start));
        if (pos == std::string::npos) { return out; }
        start = pos + 1;
    }
}
void unavailable(Finding& f, const Evidence& e) {
    f.status = e.access == Access::invalid || e.access == Access::too_large ? Status::unknown : Status::unavailable;
    f.explanation = "The requested evidence could not be assessed.";
    f.recommendation = "Review evidence availability and permissions; do not weaken protections to enable scanning.";
}
void malformed(Finding& f) {
    f.status = Status::unknown;
    f.severity = "none";
    f.explanation = "Evidence is empty, malformed, ambiguous, or outside the supported syntax.";
    f.recommendation = "Review the source with its native administrative tools.";
}
}
std::string name(Status value) {
    switch (value) {
    case Status::pass: return "PASS";
    case Status::problem: return "PROBLEM";
    case Status::deviation: return "DEVIATION";
    case Status::info: return "INFO";
    case Status::unavailable: return "UNAVAILABLE";
    case Status::not_applicable: return "NOT_APPLICABLE";
    case Status::unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}
const std::vector<Rule>& rules() {
    static const std::vector<Rule> value {
        {"SBS-OS-001", "system", "Operating system", "os", "/etc/os-release", "", 0, 0},
        {"SBS-OS-002", "system", "Kernel release", "kernel", "/proc/sys/kernel/osrelease", "", 0, 0},
        {"SBS-ENV-001", "system", "Execution environment", "environment", "/run/systemd/container", "", 0, 0},
        {"SBS-UPD-001", "updates", "Security update assessment", "updates", "", "", 0, 0},
        {"SBS-ACC-001", "accounts", "Local privileged accounts", "passwd", "/etc/passwd", "", 0, 0},
        {"SBS-ACC-002", "accounts", "Local empty password fields", "shadow", "/etc/shadow", "", 0, 0},
        {"SBS-AUTH-001", "accounts", "Password aging defaults", "login", "/etc/login.defs", "", 0, 0},
        {"SBS-SUDO-001", "sudo", "Sudo policy scope", "sudo", "/etc/sudoers", "", 0, 0},
        {"SBS-SSH-001", "ssh", "SSH static configuration scope", "ssh", "/etc/ssh/sshd_config", "", 0, 0},
        {"SBS-FILE-001", "files", "Password database permissions", "permissions", "/etc/passwd", "public", 0, 0},
        {"SBS-FILE-002", "files", "Shadow database permissions", "permissions", "/etc/shadow", "secret", 0, 0},
        {"SBS-FILE-003", "files", "Group database permissions", "permissions", "/etc/group", "public", 0, 0},
        {"SBS-FILE-004", "files", "Group shadow permissions", "permissions", "/etc/gshadow", "secret", 0, 0},
        {"SBS-FILE-005", "files", "Sudo policy file permissions", "permissions", "/etc/sudoers", "public", 0, 0},
        {"SBS-FILE-006", "files", "SSH configuration permissions", "permissions", "/etc/ssh/sshd_config", "public", 0, 0},
        {"SBS-FILE-007", "files", "Temporary directory sticky bit", "tmp", "/tmp", "", 0, 0},
        {"SBS-MNT-001", "mounts", "Mount restriction observations", "mounts", "/proc/self/mountinfo", "", 0, 0},
        {"SBS-SVC-001", "services", "Service manager observations", "services", "/proc/1/comm", "", 0, 0},
        {"SBS-FW-001", "network", "Firewall enforcement", "firewall", "", "", 0, 0},
        {"SBS-NET-001", "network", "TCP listening socket observations", "listeners", "/proc/net/tcp", "", 0, 0},
        {"SBS-KERN-001", "kernel", "Userspace address randomization", "sysctl", "/proc/sys/kernel/randomize_va_space", "Full userspace ASLR", 2, 2},
        {"SBS-KERN-002", "kernel", "Kernel pointer disclosure restriction", "sysctl", "/proc/sys/kernel/kptr_restrict", "Restricted kernel pointer presentation", 1, 2},
        {"SBS-KERN-003", "kernel", "Kernel log access restriction", "sysctl", "/proc/sys/kernel/dmesg_restrict", "Restricted kernel log access", 1, 1},
        {"SBS-KERN-004", "kernel", "Protected symbolic links", "sysctl", "/proc/sys/fs/protected_symlinks", "Sticky-directory symlink protections", 1, 1},
        {"SBS-KERN-005", "kernel", "Protected hard links", "sysctl", "/proc/sys/fs/protected_hardlinks", "Hard-link ownership protections", 1, 1},
        {"SBS-KERN-006", "kernel", "Protected FIFO creation", "sysctl", "/proc/sys/fs/protected_fifos", "Sticky-directory FIFO protections", 1, 2},
        {"SBS-KERN-007", "kernel", "Protected regular file creation", "sysctl", "/proc/sys/fs/protected_regular", "Sticky-directory regular-file protections", 1, 2},
        {"SBS-BOOT-001", "boot", "Kernel lockdown state", "lockdown", "/sys/kernel/security/lockdown", "", 0, 0},
        {"SBS-MAC-001", "mechanisms", "SELinux runtime enforcement", "selinux", "/sys/fs/selinux/enforce", "", 0, 0},
        {"SBS-MAC-002", "mechanisms", "AppArmor runtime availability", "apparmor", "/sys/module/apparmor/parameters/enabled", "", 0, 0},
        {"SBS-PKG-001", "packages", "Package database observations", "packages", "", "", 0, 0},
        {"SBS-REPO-001", "packages", "Repository trust assessment", "repositories", "", "", 0, 0}
    };
    return value;
}
Finding evaluate(const Rule& rule, const Source& source) {
    Finding f;
    f.id = rule.id; f.category = rule.category; f.title = rule.title;
    f.limitations = "Point-in-time evidence in the current filesystem and namespaces; not a host-wide assurance or vulnerability assessment.";
    f.recommendation = "Review in the context of this system's role and distribution policy.";
    const bool meta = rule.kind == "permissions" || rule.kind == "tmp";
    Evidence e;
    if (!rule.path.empty()) {
        e = meta ? source.metadata(rule.path) : source.read(rule.path);
        f.evidence.push_back(rule.path + ": " + name(e.access));
    }
    if (rule.kind == "os" && e.access != Access::ok) {
        e = source.read("/usr/lib/os-release");
        f.evidence.emplace_back("/usr/lib/os-release: ");
        f.evidence.back().append(name(e.access));
    }
    if (rule.kind == "environment") {
        const auto docker = source.metadata("/.dockerenv");
        const auto podman = source.metadata("/run/.containerenv");
        f.evidence.emplace_back("/.dockerenv: ");
        f.evidence.back().append(name(docker.access));
        f.evidence.emplace_back("/run/.containerenv: ");
        f.evidence.back().append(name(podman.access));
        f.status = Status::info;
        f.explanation = (e.access == Access::ok || docker.access == Access::ok || podman.access == Access::ok)
            ? "Container markers observed. Kernel and network findings may reflect shared or restricted namespaces."
            : "No supported container marker observed; this does not establish a physical host or exclude a VM/container.";
        return f;
    }
    if (rule.kind == "updates") {
        f.status = Status::unknown;
        f.explanation = "Installed versions and local cache age cannot establish current security-update availability without authoritative repository data.";
        f.recommendation = "Independently review current vendor advisories and package-manager update information. This scanner never refreshes caches.";
        return f;
    }
    if (rule.kind == "firewall") {
        for (const auto* path : {"/etc/nftables.conf", "/etc/ufw/ufw.conf", "/etc/firewalld/firewalld.conf", "/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"}) {
            const auto item = source.metadata(path);
            f.evidence.push_back(std::string(path) + ": " + name(item.access));
        }
        f.status = Status::unknown;
        f.explanation = "Configuration or legacy interface presence cannot establish loaded nftables/iptables rules or effective filtering.";
        f.recommendation = "Have an administrator review loaded IPv4/IPv6 rules and external filtering in the appropriate network namespace.";
        return f;
    }
    if (rule.kind == "packages" || rule.kind == "repositories") {
        const std::vector<std::string> paths = rule.kind == "packages"
            ? std::vector<std::string>{"/var/lib/dpkg/status", "/usr/lib/sysimage/rpm", "/var/lib/rpm"}
            : std::vector<std::string>{"/etc/apt/sources.list", "/etc/apt/sources.list.d", "/etc/yum.repos.d"};
        bool seen = false;
        for (const auto& path : paths) {
            const auto item = source.metadata(path);
            seen = seen || item.access == Access::ok;
            f.evidence.push_back(path + ": " + name(item.access));
        }
        f.status = rule.kind == "packages" && seen ? Status::info : Status::unknown;
        f.explanation = rule.kind == "packages" ? "Package database paths are observations only; installation integrity and patch status are not inferred."
            : "Repository fragments, keyrings, overrides and package-manager policy require native evaluation; directory presence does not establish trust.";
        return f;
    }
    if (e.access != Access::ok) { unavailable(f, e); return f; }
    if (rule.kind == "permissions" || rule.kind == "tmp") {
        std::ostringstream mode; mode << std::oct << e.mode;
        f.evidence.push_back("mode=0" + mode.str() + "; uid=" + std::to_string(e.uid));
        if ((rule.kind == "permissions" && e.directory) || (rule.kind == "tmp" && !e.directory)) {
            malformed(f); return f;
        }
        const bool bad = rule.kind == "tmp" ? ((e.mode & 0002U) != 0 && (e.mode & 01000U) == 0)
            : ((e.mode & 0002U) != 0 || (rule.parameter == "secret" && (e.mode & 0004U) != 0));
        if (bad) {
            f.status = Status::problem; f.severity = "high";
            f.explanation = rule.kind == "tmp" ? "A world-writable temporary directory lacks the sticky bit."
                : "Mode bits grant other-user write access to a security-sensitive file or other-user read access to a shadow database.";
            f.recommendation = "Review ownership, ACLs, mount restrictions and distribution policy; arrange a deliberate administrator-led correction if unintended.";
        } else if (e.uid != 0 || (rule.kind == "permissions" && (e.mode & 0020U) != 0)) {
            f.status = Status::deviation; f.severity = "medium";
            f.explanation = "Non-root ownership or group-write permission merits review; delegated administration and user namespaces can explain it.";
        } else {
            f.status = Status::pass;
            f.explanation = "The specific mode-bit checks found no deviation. Group-readable shadow files are allowed for distribution-managed shadow groups.";
        }
        f.limitations += " Only inode mode/owner are checked: ACLs, parent traversal, mount flags, group membership, namespaces and LSMs may change effective access. PROBLEM describes mode bits, not proven exploitability.";
    } else if (rule.kind == "sysctl") {
        unsigned value = 0;
        if (!number(trim(e.text), value) || value > static_cast<unsigned>(rule.maximum)) { malformed(f); return f; }
        f.evidence.push_back("observed=" + std::to_string(value));
        f.status = value >= static_cast<unsigned>(rule.minimum) ? Status::pass : Status::deviation;
        f.severity = f.status == Status::deviation ? "low" : "none";
        f.explanation = rule.parameter + (f.status == Status::pass ? " meet the documented baseline threshold." : " are below the documented baseline threshold; compatibility or diagnostic needs may justify this.");
        f.limitations += " Runtime value only; persistence and per-process exceptions are not evaluated. Containers may inherit host policy.";
    } else if (rule.kind == "passwd" || rule.kind == "shadow") {
        std::istringstream input(e.text); std::string line;
        unsigned rows = 0, zero = 0, nonroot = 0, empty = 0;
        std::set<std::string> names;
        while (std::getline(input, line)) {
            if (trim(line).empty()) { continue; }
            const auto fields = split(line, ':');
            const std::size_t expected = rule.kind == "passwd" ? 7 : 9;
            if (fields.size() != expected || fields[0].empty() || !names.insert(fields[0]).second ||
                fields[0].front() == '+' || fields[0].front() == '-') { malformed(f); return f; }
            if (rule.kind == "passwd") {
                unsigned uid = 0, gid = 0;
                if (!number(fields[2], uid) || !number(fields[3], gid)) { malformed(f); return f; }
                if (uid == 0) { ++zero; if (fields[0] != "root") { ++nonroot; } }
            } else {
                for (std::size_t i = 2; i < 8; ++i) {
                    unsigned value = 0;
                    if (!fields[i].empty() && fields[i] != "-1" && !number(fields[i], value)) { malformed(f); return f; }
                }
                if (fields[1].empty()) { ++empty; }
            }
            ++rows;
        }
        if (rows == 0) { malformed(f); return f; }
        f.evidence.push_back("local_records=" + std::to_string(rows));
        if (rule.kind == "passwd") {
            f.evidence.push_back("uid_zero_records=" + std::to_string(zero) + "; non_root_named=" + std::to_string(nonroot));
            f.status = zero == 0 ? Status::unknown : (zero > 1 || nonroot > 0 ? Status::deviation : Status::pass);
            f.explanation = "UID 0 confers local superuser identity. Additional or renamed UID-0 accounts warrant intentional-policy review.";
        } else {
            f.evidence.push_back("empty_password_fields=" + std::to_string(empty));
            f.status = empty > 0 ? Status::deviation : Status::pass;
            f.explanation = "Empty local shadow password fields warrant authentication-policy review; they do not prove passwordless login is possible.";
        }
        f.severity = f.status == Status::deviation ? "medium" : "none";
        f.limitations += " No account names, hashes or personal fields are output. NSS/LDAP, PAM, shells, expiry, account locks and service-specific authentication are not evaluated.";
    } else if (rule.kind == "ssh") {
        std::istringstream input(e.text); std::string line;
        std::map<std::string, std::string> observed;
        bool complex = false; unsigned directives = 0;
        while (std::getline(input, line)) {
            line = trim(line.substr(0, line.find('#')));
            if (line.empty()) { continue; }
            std::istringstream tokens(line); std::string key, value;
            tokens >> key >> value;
            std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c); });
            ++directives;
            if (key == "include" || key == "match") { complex = true; }
            if (value.empty()) { malformed(f); return f; }
            if (key == "permitrootlogin" || key == "passwordauthentication" || key == "permitemptypasswords") {
                std::string extra;
                if (tokens >> extra) { complex = true; }
                observed.emplace(key, value); // OpenSSH first-value semantics, never last-wins.
            }
        }
        for (const auto& item : observed) {
            const auto& v = item.second;
            if (v != "yes" && v != "no" && !(item.first == "permitrootlogin" &&
                (v == "prohibit-password" || v == "without-password" || v == "forced-commands-only"))) { malformed(f); return f; }
        }
        f.evidence.push_back("directives=" + std::to_string(directives) + "; include_or_match_or_complex=" + (complex ? "yes" : "no"));
        f.status = Status::unknown;
        f.explanation = "Static sshd_config cannot establish effective running-daemon policy. Includes, Match contexts, defaults, launch options and alternate config paths may apply.";
        if (!complex) {
            for (const auto& item : observed) { f.evidence.push_back("static_first_" + item.first + "=" + item.second); }
        }
        f.recommendation = "Have an administrator validate effective OpenSSH configuration for relevant connection contexts and confirm the running daemon uses it.";
    } else if (rule.kind == "sudo") {
        f.status = Status::unknown;
        f.explanation = "Sudoers presence is not an effective authorization assessment. Includes, aliases, negation, ordering, LDAP/SSSD and command matching need native evaluation.";
        f.recommendation = "Review effective sudo privileges and intended delegation with the system administrator; NOPASSWD alone is not treated as a vulnerability.";
    } else if (rule.kind == "login") {
        std::istringstream input(e.text); std::string line;
        std::set<std::string> seen;
        while (std::getline(input, line)) {
            line = trim(line.substr(0, line.find('#')));
            std::istringstream tokens(line); std::string key, value, extra;
            tokens >> key;
            if (key != "PASS_MAX_DAYS" && key != "PASS_MIN_DAYS" && key != "PASS_WARN_AGE") { continue; }
            tokens >> value;
            unsigned parsed = 0;
            if ((!number(value, parsed) && value != "-1") || !seen.insert(key).second || (tokens >> extra)) { malformed(f); return f; }
            f.evidence.push_back(key + "=" + value);
        }
        f.status = Status::info;
        f.explanation = "These are account-creation defaults, not current account or PAM policy. Mandatory periodic password rotation is not scored.";
    } else if (rule.kind == "os") {
        std::istringstream input(e.text); std::string line; std::set<std::string> seen;
        while (std::getline(input, line)) {
            const auto pos = line.find('='); if (pos == std::string::npos) { continue; }
            const auto key = line.substr(0, pos);
            if (key != "ID" && key != "VERSION_ID" && key != "ID_LIKE") { continue; }
            auto value = line.substr(pos + 1);
            if (!seen.insert(key).second || value.empty()) { malformed(f); return f; }
            if (value.front() == '"' || value.front() == '\'') {
                if (value.size() < 2 || value.back() != value.front()) { malformed(f); return f; }
                value = value.substr(1, value.size() - 2);
            }
            if (value.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._ -") != std::string::npos) { malformed(f); return f; }
            f.evidence.push_back(key + "=" + value);
        }
        if (seen.count("ID") == 0) { malformed(f); return f; }
        f.status = Status::info;
        f.explanation = "Distribution identity only; version numbers do not establish support lifecycle or patch status.";
    } else if (rule.kind == "kernel") {
        const auto value = trim(e.text);
        if (value.empty() || value.size() > 256 || value.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-") != std::string::npos) { malformed(f); return f; }
        f.evidence.push_back("release=" + value); f.status = Status::info;
        f.explanation = "Running kernel release; vendor backports prevent reliable vulnerability inference from version alone.";
    } else if (rule.kind == "mounts") {
        std::istringstream input(e.text); std::string line; unsigned total = 0, nodev = 0, nosuid = 0, noexec = 0;
        while (std::getline(input, line)) {
            std::istringstream tokens(line); std::vector<std::string> fields; std::string word;
            while (tokens >> word) { fields.push_back(word); }
            const auto sep = std::find(fields.begin(), fields.end(), "-");
            unsigned id = 0, parent = 0;
            if (fields.size() < 10 || sep < fields.begin() + 6 || sep == fields.end() ||
                std::distance(sep, fields.end()) != 4 || !number(fields[0], id) || !number(fields[1], parent)) { malformed(f); return f; }
            const auto opts = split(fields[5], ',');
            nodev += std::find(opts.begin(), opts.end(), "nodev") != opts.end() ? 1U : 0U;
            nosuid += std::find(opts.begin(), opts.end(), "nosuid") != opts.end() ? 1U : 0U;
            noexec += std::find(opts.begin(), opts.end(), "noexec") != opts.end() ? 1U : 0U;
            ++total;
        }
        if (total == 0) { malformed(f); return f; }
        f.evidence.push_back("mounts=" + std::to_string(total) + "; nodev=" + std::to_string(nodev) + "; nosuid=" + std::to_string(nosuid) + "; noexec=" + std::to_string(noexec));
        f.status = Status::info;
        f.explanation = "Counts of mount restrictions in this mount namespace. Missing flags are not automatically a weakness; executable and device filesystems have legitimate roles.";
        f.limitations += " Mount paths and sources are omitted for privacy. Superblock flags and nested-mount effective policy are not combined.";
    } else if (rule.kind == "listeners") {
        unsigned total = 0; bool complete = true;
        for (const auto* path : {"/proc/net/tcp", "/proc/net/tcp6"}) {
            const auto data = std::string(path) == rule.path ? e : source.read(path);
            f.evidence.push_back(std::string(path) + ": " + name(data.access));
            if (data.access != Access::ok) { complete = false; continue; }
            std::istringstream input(data.text); std::string line;
            if (!std::getline(input, line) || line.find("local_address") == std::string::npos) { complete = false; continue; }
            while (std::getline(input, line)) {
                if (trim(line).empty()) { continue; }
                std::istringstream row(line); std::vector<std::string> fields; std::string field;
                while (row >> field) { fields.push_back(field); }
                if (fields.size() < 10 || fields[3].size() != 2 || fields[3].find_first_not_of("0123456789ABCDEFabcdef") != std::string::npos) { complete = false; continue; }
                const std::size_t address_length = std::string(path) == "/proc/net/tcp" ? 8 : 32;
                const auto address_ok = [address_length](const std::string& address) {
                    return address.size() == address_length + 5 && address[address_length] == ':' &&
                        address.substr(0, address_length).find_first_not_of("0123456789ABCDEFabcdef") == std::string::npos &&
                        address.substr(address_length + 1).find_first_not_of("0123456789ABCDEFabcdef") == std::string::npos;
                };
                unsigned slot = 0, uid = 0;
                if (fields[0].empty() || fields[0].back() != ':' ||
                    !number(fields[0].substr(0, fields[0].size() - 1), slot) || !number(fields[7], uid) ||
                    !address_ok(fields[1]) || !address_ok(fields[2])) { complete = false; continue; }
                if (fields[3] == "0A" || fields[3] == "0a") { ++total; }
            }
        }
        f.status = complete ? Status::info : Status::unknown;
        f.evidence.push_back("observed_tcp_listeners=" + std::to_string(total));
        f.explanation = "TCP LISTEN entries observed; a listener does not establish external reachability or a vulnerable service.";
        f.limitations += " Current network namespace only; no addresses, ports or process identities output. UDP, Unix sockets and transient sockets are not assessed; missing IPv6 data makes coverage unknown.";
    } else if (rule.kind == "services") {
        const auto comm = trim(e.text);
        if (comm.empty() || comm.find_first_of("\r\n") != std::string::npos) { malformed(f); return f; }
        f.evidence.push_back(comm == "systemd" ? "pid1_is_systemd=yes" : "pid1_is_systemd=no");
        f.status = comm == "systemd" ? Status::unknown : Status::not_applicable;
        f.explanation = comm == "systemd" ? "systemd observed as PID 1; unit files alone cannot establish running/enabled service state. No service-manager commands are executed."
            : "A systemd PID-1 service assessment is not applicable to the observed environment; other supervisors and services are not assessed.";
    } else if (rule.kind == "selinux") {
        const auto value = trim(e.text);
        if (value != "0" && value != "1") { malformed(f); return f; }
        f.evidence.push_back("enforce=" + value); f.status = Status::info;
        f.explanation = value == "1" ? "SELinux reports enforcing mode; this does not prove every process is confined."
            : "SELinux reports permissive mode; development, troubleshooting or alternate mechanisms may explain it.";
    } else if (rule.kind == "apparmor") {
        const auto value = trim(e.text);
        if (value != "Y" && value != "N") { malformed(f); return f; }
        f.evidence.push_back("enabled=" + value); f.status = Status::info;
        f.explanation = "AppArmor module enablement does not establish loaded profiles, enforcement mode or coverage of individual services.";
    } else if (rule.kind == "lockdown") {
        const auto value = trim(e.text);
        if (value != "[none] integrity confidentiality" && value != "none [integrity] confidentiality" &&
            value != "none integrity [confidentiality]") { malformed(f); return f; }
        const bool none = value.find("[none]") != std::string::npos;
        const bool integrity = value.find("[integrity]") != std::string::npos;
        const bool confidentiality = value.find("[confidentiality]") != std::string::npos;
        if (static_cast<int>(none) + static_cast<int>(integrity) + static_cast<int>(confidentiality) != 1) { malformed(f); return f; }
        f.evidence.push_back(std::string("lockdown=") + (none ? "none" : (integrity ? "integrity" : "confidentiality")));
        f.status = Status::info;
        f.explanation = "Kernel lockdown mode only. It does not establish UEFI Secure Boot, measured boot, firmware trust or disk encryption.";
    } else { malformed(f); }
    return f;
}
std::vector<Finding> scan(const Source& source, const std::vector<std::string>& categories, const std::vector<std::string>& checks) {
    const auto bad_id = std::find_if(checks.begin(), checks.end(), [](const std::string& id) {
        return std::none_of(rules().begin(), rules().end(), [&](const Rule& r) { return r.id == id; });
    });
    if (bad_id != checks.end()) { throw std::invalid_argument("unknown check: " + *bad_id); }
    const auto bad_category = std::find_if(categories.begin(), categories.end(), [](const std::string& category) {
        return std::none_of(rules().begin(), rules().end(), [&](const Rule& r) { return r.category == category; });
    });
    if (bad_category != categories.end()) { throw std::invalid_argument("unknown category: " + *bad_category); }
    std::vector<Finding> out;
    for (const auto& r : rules()) {
        if ((!categories.empty() && std::find(categories.begin(), categories.end(), r.category) == categories.end()) ||
            (!checks.empty() && std::find(checks.begin(), checks.end(), r.id) == checks.end())) { continue; }
        out.push_back(evaluate(r, source));
    }
    if (out.empty()) { throw std::invalid_argument("selection contains no checks"); }
    return out;
}
}
