#include "sbs/scanner.hpp"
#include <cerrno>
#include <charconv>
#include <limits>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace sbs {
namespace {
using detail::Fd;
void append_decimal(std::string& output, int value) {
    // Enough room for every decimal int, including its sign. Only the bytes
    // written by to_chars are consumed; no uninitialized buffer bytes are read.
    char digits[std::numeric_limits<int>::digits10 + 3];
    const auto converted = std::to_chars(digits, digits + sizeof(digits), value);
    if (converted.ec != std::errc{}) { throw std::runtime_error("integer formatting failed"); }
    output.append(digits, static_cast<std::size_t>(converted.ptr - digits));
}
Access error_access(int error) {
    if (error == ENOENT) { return Access::missing; }
    if (error == EACCES || error == EPERM) { return Access::denied; }
    if (error == ELOOP || error == ENOTDIR) { return Access::unsupported; }
    return Access::io_error;
}
}
const char* name(Access value) noexcept {
    switch (value) {
    case Access::ok: return "ok";
    case Access::missing: return "missing";
    case Access::denied: return "permission-denied";
    case Access::unsupported: return "unsupported-file-type-or-symlink";
    case Access::invalid: return "invalid-data";
    case Access::too_large: return "size-limit-exceeded";
    case Access::io_error: return "io-error";
    }
    return "invalid-data";
}
FileSource::FileSource(const std::string& root)
    : live_(root == "/") {
    // Acquire only after all other members have been initialized. On success,
    // ownership transfers directly to this non-copyable, non-movable object.
    const int opened = ::open(root.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (opened < 0) { throw std::runtime_error("cannot open scan root"); }
    root_fd_.reset(opened);
}
FileSource::~FileSource() = default;
Evidence FileSource::read(const std::string& path) const {
    if (live_ && path.rfind("/proc/self/", 0) == 0) {
        std::string resolved("/proc/");
        append_decimal(resolved, ::getpid());
        resolved.append(path, 10, std::string::npos);
        return get(resolved, true);
    }
    if (live_ && path.rfind("/proc/net/", 0) == 0) {
        std::string resolved("/proc/");
        append_decimal(resolved, ::getpid());
        resolved.append("/net/");
        resolved.append(path, 10, std::string::npos);
        return get(resolved, true);
    }
    return get(path, true);
}
Evidence FileSource::metadata(const std::string& path) const { return get(path, false); }
Evidence FileSource::get(const std::string& path, bool contents) const {
    Evidence result{};
    if (path.empty() || path.front() != '/' || path.back() == '/') {
        result.access = Access::invalid; return result;
    }
    Fd directory(::fcntl(root_fd_.get(), F_DUPFD_CLOEXEC, 0));
    if (directory.get() < 0) { result.access = error_access(errno); return result; }
    std::size_t start = 1;
    std::string leaf{};
    while (start < path.size()) {
        const auto end = path.find('/', start);
        const auto component = path.substr(start, end == std::string::npos ? end : end - start);
        if (component.empty() || component == "." || component == ".." || component.find('\0') != std::string::npos) {
            result.access = Access::invalid; return result;
        }
        if (end == std::string::npos) { leaf = component; break; }
        const int next = ::openat(directory.get(), component.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) { result.access = error_access(errno); return result; }
        directory.reset(next);
        start = end + 1;
    }
    // O_PATH permits type inspection without opening a device or blocking on a FIFO.
    Fd handle(::openat(directory.get(), leaf.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    if (handle.get() < 0) { result.access = error_access(errno); return result; }
    struct stat st {};
    if (::fstat(handle.get(), &st) != 0) { result.access = error_access(errno); return result; }
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) { result.access = Access::unsupported; return result; }
    result.mode = static_cast<std::uint32_t>(st.st_mode & 07777);
    result.uid = st.st_uid;
    result.directory = S_ISDIR(st.st_mode);
    result.access = Access::ok;
    if (!contents) { return result; }
    if (!S_ISREG(st.st_mode)) { result.access = Access::unsupported; return result; }
    // Reopen the inspected inode through our own fd, never a mutable pathname.
    // /proc/self/fd is a trusted kernel interface, not a path beneath --root.
    std::string fd_path("/proc/self/fd/");
    append_decimal(fd_path, handle.get());
    Fd input(::open(fd_path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY));
    if (input.get() < 0) { result.access = error_access(errno); return result; }
    constexpr std::size_t limit = 1024 * 1024;
    char buffer[8192];
    for (;;) {
        const ssize_t count = ::read(input.get(), buffer, sizeof(buffer));
        if (count < 0) {
            if (errno == EINTR) { continue; }
            result.access = error_access(errno); result.text.clear(); return result;
        }
        if (count == 0) { break; }
        if (result.text.size() + static_cast<std::size_t>(count) > limit) {
            result.access = Access::too_large; result.text.clear(); return result;
        }
        result.text.append(buffer, static_cast<std::size_t>(count));
    }
    if (result.text.find('\0') != std::string::npos) { result.access = Access::invalid; result.text.clear(); }
    return result;
}
}
