#pragma once
#include "sbs/fd.hpp"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace sbs {
inline constexpr const char* version = "1.0.0";
enum class Access { ok, missing, denied, unsupported, invalid, too_large, io_error };
const char* name(Access value) noexcept;
struct Evidence {
    Access access = Access::missing;
    std::string text{};
    std::uint32_t mode = 0;
    std::uint32_t uid = 0;
    bool directory = false;
};
class Source {
public:
    virtual ~Source() = default;
    virtual Evidence read(const std::string& path) const = 0;
    virtual Evidence metadata(const std::string& path) const = 0;
};
// Fixed-root, descriptor-relative reader; rejects symlinks and special files.
class FileSource final : public Source {
public:
    explicit FileSource(const std::string& root);
    ~FileSource() override;
    FileSource(const FileSource&) = delete;
    FileSource& operator=(const FileSource&) = delete;
    FileSource(FileSource&&) = delete;
    FileSource& operator=(FileSource&&) = delete;
    Evidence read(const std::string& path) const override;
    Evidence metadata(const std::string& path) const override;
private:
    detail::Fd root_fd_;
    bool live_;
    Evidence get(const std::string& path, bool contents) const;
};
enum class Status { pass, problem, deviation, info, unavailable, not_applicable, unknown };
std::string name(Status value);
struct Finding {
    std::string id, category, title;
    Status status = Status::unknown;
    std::string severity = "none";
    std::vector<std::string> evidence;
    std::string explanation, recommendation, limitations;
};
struct Rule {
    std::string id, category, title, kind, path, parameter;
    int minimum = 0, maximum = 0;
};
const std::vector<Rule>& rules();
Finding evaluate(const Rule& rule, const Source& source);
std::vector<Finding> scan(const Source& source, const std::vector<std::string>& categories,
                          const std::vector<std::string>& checks);
std::string render(const std::vector<Finding>& findings, const std::string& format, bool fixture);
std::string safe_text(const std::string& value);
}
