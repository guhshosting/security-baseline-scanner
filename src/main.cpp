#include "sbs/scanner.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
const char* help = R"(Usage: security-baseline-scanner [OPTIONS]
Read-only Linux baseline observations. No network or system-management commands.

  --format text|json|markdown   Report format (default text)
  --category NAME              Select category (repeatable)
  --check ID                   Select stable rule ID (repeatable)
  --root DIRECTORY             Inspect an offline root (absolute path)
  --list-checks                List stable IDs, categories and titles
  --fail-on problem|deviation  Exit 1 when selected findings meet this threshold
  --help                       Show this help
  --version                    Show version

Selections intersect when both category and check options are supplied.
Exit codes: 0 report produced, 1 requested threshold met, 2 usage error,
3 operational/output error. UNKNOWN/UNAVAILABLE never imply a secure system.
Reports go to stdout. Shell redirection is controlled by the caller.
)";
}
int main(int argc, char** argv) {
    try {
        std::string format = "text", root = "/", fail;
        std::vector<std::string> categories, checks;
        bool list = false;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--help") { std::cout << help; return std::cout ? 0 : 3; }
            if (arg == "--version") { std::cout << "security-baseline-scanner " << sbs::version << '\n'; return std::cout ? 0 : 3; }
            if (arg == "--list-checks") { list = true; continue; }
            if (arg != "--format" && arg != "--root" && arg != "--category" && arg != "--check" && arg != "--fail-on") {
                throw std::invalid_argument("unknown option");
            }
            if (++i == argc || std::string(argv[i]).empty()) { throw std::invalid_argument("option requires a nonempty value"); }
            const std::string value = argv[i];
            if (arg == "--format") { format = value; }
            else if (arg == "--root") { root = value; }
            else if (arg == "--category") { categories.push_back(value); }
            else if (arg == "--check") { checks.push_back(value); }
            else { fail = value; }
        }
        if (format != "text" && format != "json" && format != "markdown") { throw std::invalid_argument("unsupported format"); }
        if (!fail.empty() && fail != "problem" && fail != "deviation") { throw std::invalid_argument("unsupported failure threshold"); }
        if (root.front() != '/') { throw std::invalid_argument("--root must be absolute"); }
        if (list) {
            if (!categories.empty() || !checks.empty() || !fail.empty() || format != "text" || root != "/") { throw std::invalid_argument("--list-checks cannot be combined with scan options"); }
            for (const auto& r : sbs::rules()) { std::cout << r.id << '\t' << r.category << '\t' << r.title << '\n'; }
            return std::cout ? 0 : 3;
        }
        sbs::FileSource source(root);
        const auto findings = sbs::scan(source, categories, checks);
        std::cout << sbs::render(findings, format, root != "/");
        std::cout.flush();
        if (!std::cout) { return 3; }
        const bool failed = std::any_of(findings.begin(), findings.end(), [&](const sbs::Finding& finding) {
            return !fail.empty() && (finding.status == sbs::Status::problem ||
                (fail == "deviation" && finding.status == sbs::Status::deviation));
        });
        return failed ? 1 : 0;
    } catch (const std::invalid_argument& e) {
        std::cerr << "security-baseline-scanner: " << sbs::safe_text(e.what()) << '\n'; return 2;
    } catch (const std::exception& e) {
        std::cerr << "security-baseline-scanner: " << sbs::safe_text(e.what()) << '\n'; return 3;
    }
}
