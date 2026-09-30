#include "sbs/scanner.hpp"
#include <iomanip>
#include <sstream>

namespace sbs {
std::string safe_text(const std::string& value) {
    std::ostringstream out;
    for (const unsigned char c : value) {
        if (c >= 32 && c <= 126) { out << static_cast<char>(c); }
        else { out << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(c); }
    }
    return out.str();
}
namespace {
std::string quote(const std::string& value) {
    std::ostringstream out; out << '"';
    for (const unsigned char c : value) {
        if (c == '"' || c == '\\') { out << '\\' << static_cast<char>(c); }
        else if (c < 32 || c >= 127) { out << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(c); }
        else { out << static_cast<char>(c); }
    }
    out << '"'; return out.str();
}
std::string markdown(const std::string& value) {
    std::string out;
    for (const char c : safe_text(value)) {
        if (std::string("\\`*_{}[]<>()#+-.!|").find(c) != std::string::npos) { out += '\\'; }
        out += c;
    }
    return out;
}
}
std::string render(const std::vector<Finding>& findings, const std::string& format, bool fixture) {
    const std::vector<Status> statuses {Status::pass, Status::problem, Status::deviation, Status::info, Status::unavailable, Status::not_applicable, Status::unknown};
    std::map<std::string, unsigned> counts;
    for (const auto status : statuses) { counts[name(status)] = 0; }
    for (const auto& f : findings) { ++counts[name(f.status)]; }
    std::ostringstream out;
    if (format == "json") {
        out << "{\"schema_version\":1,\"scanner\":\"security-baseline-scanner\",\"version\":" << quote(version)
            << ",\"scope\":" << quote(fixture ? "offline-root" : "current-namespaces") << ",\"summary\":{";
        bool first = true;
        for (const auto status : statuses) {
            if (!first) { out << ','; } first = false;
            out << quote(name(status)) << ':' << counts[name(status)];
        }
        out << "},\"findings\":[";
        first = true;
        for (const auto& f : findings) {
            if (!first) { out << ','; } first = false;
            out << "{\"id\":" << quote(f.id) << ",\"category\":" << quote(f.category) << ",\"title\":" << quote(f.title)
                << ",\"status\":" << quote(name(f.status)) << ",\"severity\":" << quote(f.severity) << ",\"evidence\":[";
            bool first_evidence = true;
            for (const auto& e : f.evidence) { if (!first_evidence) { out << ','; } first_evidence = false; out << quote(e); }
            out << "],\"explanation\":" << quote(f.explanation) << ",\"recommendation\":" << quote(f.recommendation)
                << ",\"limitations\":" << quote(f.limitations) << '}';
        }
        out << "]}\n";
    } else {
        const bool md = format == "markdown";
        const auto escape = [md](const std::string& value) { return md ? markdown(value) : safe_text(value); };
        out << (md ? "# " : "") << "security-baseline-scanner " << version << '\n';
        out << "\nScope: " << (fixture ? "offline root; supplied runtime files may be stale" : "current namespaces; point-in-time observations") << "\n";
        out << "No security score. PASS applies only to the named check, not overall security.\n\n";
        for (const auto status : statuses) { out << name(status) << ": " << counts[name(status)] << "  "; }
        out << "\n";
        for (const auto& f : findings) {
            out << '\n' << (md ? "## " : "") << f.id << " [" << name(f.status) << "/" << f.severity << "] " << escape(f.title) << "\n\n";
            out << "Category: " << f.category << "\n";
            for (const auto& evidence : f.evidence) { out << (md ? "\n- Evidence: " : "  Evidence: ") << escape(evidence) << '\n'; }
            out << "\nExplanation: " << escape(f.explanation) << "\n\nRecommendation: " << escape(f.recommendation)
                << "\n\nLimitations: " << escape(f.limitations) << '\n';
        }
    }
    return out.str();
}
}
