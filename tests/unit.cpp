#include "sbs/scanner.hpp"
#include <algorithm>
#include <iostream>
#include <set>
#include <cstdint>
#include <stdexcept>
namespace {
unsigned assertions = 0;
void expect(bool value, const std::string& why) {
    ++assertions; if (!value) { throw std::runtime_error(why); }
}
class Memory final : public sbs::Source {
public:
    std::map<std::string, sbs::Evidence> entries;
    sbs::Evidence read(const std::string& p) const override {
        const auto i = entries.find(p); return i == entries.end() ? sbs::Evidence{} : i->second;
    }
    sbs::Evidence metadata(const std::string& p) const override { return read(p); }
};
sbs::Evidence good(const std::string& text, unsigned mode = 0644, unsigned uid = 0, bool dir = false) {
    return {sbs::Access::ok, text, mode, uid, dir};
}
sbs::Finding run(const std::string& id, const Memory& m) { return sbs::scan(m, {}, {id}).at(0); }
void status(const std::string& id, const Memory& m, sbs::Status wanted) {
    expect(run(id, m).status == wanted, id + " got " + sbs::name(run(id, m).status));
}
}
int main() {
    try {
        using sbs::Status;
        Memory m;
        std::set<std::string> ids;
        for (const auto& r : sbs::rules()) {
            expect(ids.insert(r.id).second, "duplicate ID");
            const auto f = sbs::evaluate(r, m);
            expect(f.status != Status::pass && f.status != Status::problem && f.status != Status::deviation, "missing data pass/fail");
            expect(!f.explanation.empty() && !f.recommendation.empty() && !f.limitations.empty(), "missing text");
            if (!r.path.empty() && r.kind != "environment" && r.kind != "os") {
                for (const auto a : {sbs::Access::denied, sbs::Access::io_error, sbs::Access::unsupported, sbs::Access::invalid, sbs::Access::too_large}) {
                    m.entries[r.path] = {a, "", 0, 0, false};
                    const auto e = run(r.id, m);
                    expect(e.status == Status::unavailable || e.status == Status::unknown, "unavailable evidence");
                }
                m.entries.clear();
            }
            if (r.kind == "sysctl") {
                for (int n = 0; n <= r.maximum; ++n) {
                    m.entries[r.path] = good(std::to_string(n) + "\n");
                    status(r.id, m, n >= r.minimum ? Status::pass : Status::deviation);
                }
                for (const auto* t : {"", "-1", "3", "1garbage", "1\n0", "99999999999999999"}) {
                    m.entries[r.path] = good(t); status(r.id, m, Status::unknown);
                }
                m.entries.clear();
            }
        }
        expect(ids.size() == 32, "catalog size");
        m.entries["/etc/shadow"] = good("root:!:1:0:99999:7:::\nservice::1:0:99999:7:::\n", 0640);
        status("SBS-FILE-002", m, Status::pass);
        status("SBS-ACC-002", m, Status::deviation);
        m.entries["/etc/shadow"].mode = 0644; status("SBS-FILE-002", m, Status::problem);
        m.entries["/etc/shadow"] = good("root:$6$PRIVATE:1:0:99999:7:::\n", 0600);
        status("SBS-ACC-002", m, Status::pass);
        expect(sbs::render({run("SBS-ACC-002", m)}, "json", true).find("PRIVATE") == std::string::npos, "hash leaked");
        for (const auto* t : {"", "bad", "root:!:1:0:99999:7:::\nroot:!:1:0:99999:7:::\n", "root:!:junk:0:99999:7:::\n"}) {
            m.entries["/etc/shadow"] = good(t); status("SBS-ACC-002", m, Status::unknown);
        }
        m.entries["/etc/passwd"] = good("root:x:0:0:PRIVATE:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/sh\n");
        status("SBS-ACC-001", m, Status::pass);
        m.entries["/etc/passwd"].text += "extra:x:0:0::/:/bin/sh\n"; status("SBS-ACC-001", m, Status::deviation);
        for (const auto* t : {"user:x:1000:1000::/:/bin/sh", "bad", "root:x:-1:0::/:/bin/sh", "+::::::", "root:x:0:0::/:/bin/sh\nroot:x:0:0::/:/bin/sh"}) {
            m.entries["/etc/passwd"] = good(t); status("SBS-ACC-001", m, Status::unknown);
        }
        m.entries["/etc/passwd"] = good("", 0664); status("SBS-FILE-001", m, Status::deviation);
        m.entries["/etc/passwd"].mode = 0666; status("SBS-FILE-001", m, Status::problem);
        m.entries["/etc/passwd"] = good("", 0644, 1000); status("SBS-FILE-001", m, Status::deviation);
        m.entries["/tmp"] = good("", 01777, 0, true); status("SBS-FILE-007", m, Status::pass);
        m.entries["/tmp"].mode = 0777; status("SBS-FILE-007", m, Status::problem);
        m.entries["/tmp"].mode = 0755; status("SBS-FILE-007", m, Status::pass);
        m.entries["/tmp"].directory = false; status("SBS-FILE-007", m, Status::unknown);
        for (const auto* t : {"PermitRootLogin no\nPermitRootLogin yes\n", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no", "Match User root\nPasswordAuthentication yes", "PermitRootLogin invalid", "PermitRootLogin", "# comments only", ""}) {
            m.entries["/etc/ssh/sshd_config"] = good(t); status("SBS-SSH-001", m, Status::unknown);
        }
        m.entries["/etc/ssh/sshd_config"] = good("PermitRootLogin no\nPermitRootLogin yes\n");
        const auto ssh = run("SBS-SSH-001", m);
        expect(std::find(ssh.evidence.begin(), ssh.evidence.end(), "static_first_permitrootlogin=no") != ssh.evidence.end(), "SSH first wins");
        m.entries["/etc/sudoers"] = good("ALL ALL=(ALL) NOPASSWD: ALL"); status("SBS-SUDO-001", m, Status::unknown);
        m.entries["/etc/login.defs"] = good("PASS_MAX_DAYS 99999\n"); status("SBS-AUTH-001", m, Status::info);
        m.entries["/etc/login.defs"].text += "PASS_MAX_DAYS 30\n"; status("SBS-AUTH-001", m, Status::unknown);
        m.entries["/etc/nftables.conf"] = good("flush ruleset\n"); status("SBS-FW-001", m, Status::unknown);
        for (const auto* t : {"0", "1"}) { m.entries["/sys/fs/selinux/enforce"] = good(t); status("SBS-MAC-001", m, Status::info); }
        m.entries["/sys/fs/selinux/enforce"] = good("x"); status("SBS-MAC-001", m, Status::unknown);
        m.entries["/sys/module/apparmor/parameters/enabled"] = good("Y\n"); status("SBS-MAC-002", m, Status::info);
        m.entries["/sys/kernel/security/lockdown"] = good("none [integrity] confidentiality\n"); status("SBS-BOOT-001", m, Status::info);
        m.entries["/sys/kernel/security/lockdown"].text = "[none] [integrity]"; status("SBS-BOOT-001", m, Status::unknown);
        m.entries["/proc/1/comm"] = good("systemd\n"); status("SBS-SVC-001", m, Status::unknown);
        m.entries["/proc/1/comm"] = good("tini\n"); status("SBS-SVC-001", m, Status::not_applicable);
        m.entries["/proc/self/mountinfo"] = good("36 25 0:32 / / rw,nosuid,nodev - tmpfs tmpfs rw\n"); status("SBS-MNT-001", m, Status::info);
        m.entries["/proc/self/mountinfo"].text = "bad"; status("SBS-MNT-001", m, Status::unknown);
        m.entries["/etc/os-release"] = good("ID=debian\nVERSION_ID=13\n"); status("SBS-OS-001", m, Status::info);
        m.entries["/etc/os-release"].text = "ID=debian\nID=fedora"; status("SBS-OS-001", m, Status::unknown);
        m.entries["/etc/os-release"].text = "ID=\"unterminated"; status("SBS-OS-001", m, Status::unknown);
        m.entries["/etc/os-release"] = {sbs::Access::unsupported, "", 0, 0, false};
        m.entries["/usr/lib/os-release"] = good("ID=fedora"); status("SBS-OS-001", m, Status::info);
        for (int i = 0; i < 3; ++i) {
            bool threw = false;
            try { static_cast<void>(sbs::scan(m, i == 0 ? std::vector<std::string>{"bad"} : (i == 2 ? std::vector<std::string>{"ssh"} : std::vector<std::string>{}), i == 1 ? std::vector<std::string>{"bad"} : (i == 2 ? std::vector<std::string>{"SBS-OS-001"} : std::vector<std::string>{}))); }
            catch (const std::invalid_argument&) { threw = true; }
            expect(threw, "bad selection");
        }
        expect(sbs::safe_text("\x1b[31m\n") == "\\x1b[31m\\x0a", "terminal escape");
        // Real reader API rejects traversal before accessing content.
        sbs::FileSource local("/");
        for (const auto* path : {"", "relative", "/", "/../etc/passwd", "/etc/../passwd", "/etc//passwd", "/etc/./passwd", "/etc/passwd/"}) {
            expect(local.read(path).access == sbs::Access::invalid, "unsafe path accepted");
        }
        // Deterministic malformed-input corpus exercises every content evaluator.
        std::uint32_t seed = 0x5ba5eU;
        for (unsigned iteration = 0; iteration < 200; ++iteration) {
            std::string data;
            for (unsigned j = 0; j < iteration % 128; ++j) {
                seed = seed * 1664525U + 1013904223U;
                data.push_back(static_cast<char>(32U + seed % 95U));
                if (j % 13 == 0) { data.push_back('\n'); }
            }
            for (const auto& rule : sbs::rules()) {
                if (rule.path.empty() || rule.kind == "permissions" || rule.kind == "tmp") { continue; }
                Memory input;
                input.entries[rule.path] = good(data);
                const auto finding = sbs::evaluate(rule, input);
                expect(!finding.explanation.empty() && !finding.limitations.empty(), "malformed corpus missing explanation");
                expect(finding.status != Status::problem, "arbitrary content labeled confirmed problem");
            }
        }

        std::cout << assertions << " unit assertions passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
    return 0;
}
