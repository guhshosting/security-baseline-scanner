#include "sbs/scanner.hpp"
#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <unistd.h>
#include <vector>

static_assert(!std::is_copy_constructible<sbs::FileSource>::value, "unique ownership");
static_assert(!std::is_copy_assignable<sbs::FileSource>::value, "unique ownership");
static_assert(!std::is_move_constructible<sbs::FileSource>::value, "stable owner");
static_assert(!std::is_move_assignable<sbs::FileSource>::value, "stable owner");

// Avoid procfs entirely. Linux open/dup allocate the lowest available number.
// A baseline of fewer than 64 open low FDs ensures every descriptor allocated
// during these sequential operations is within this bounded inspection window.
static std::vector<int> descriptors() {
    std::vector<int> result;
    for (int fd = 0; fd < 4096; ++fd) {
        if (::fcntl(fd, F_GETFD) >= 0) { result.push_back(fd); }
        else if (errno != EBADF) { throw std::runtime_error("descriptor inspection failed"); }
    }
    return result;
}
int main() {
    try {
        const auto before = descriptors();
        if (before.size() >= 64) { throw std::runtime_error("test requires fewer than 64 inherited low descriptors"); }
        for (unsigned i = 0; i < 2000; ++i) {
            {
                sbs::FileSource source("/");
                static_cast<void>(source.metadata("/etc/passwd"));
                static_cast<void>(source.read("/etc/passwd"));
                static_cast<void>(source.read("/../rejected"));
                static_cast<void>(source.read("/etc/security-baseline-scanner-nonexistent-fixture"));
            }
            if (i % 100 == 0 && descriptors() != before) { throw std::runtime_error("descriptor growth after destruction"); }
            // /dev/null exists but cannot be opened as O_DIRECTORY. Constructor
            // must throw without acquiring any descriptor to be cleaned up.
            bool failed = false;
            try { sbs::FileSource invalid("/dev/null"); }
            catch (const std::runtime_error&) { failed = true; }
            if (!failed || (i % 100 == 0 && descriptors() != before)) { throw std::runtime_error("failed-open ownership regression"); }
        }
        // Virtual base destruction must also close the sole root owner.
        {
            const std::unique_ptr<sbs::Source> source = std::make_unique<sbs::FileSource>("/");
            static_cast<void>(source->metadata("/etc/passwd"));
        }
        if (descriptors() != before) { throw std::runtime_error("virtual destruction leaked"); }
        std::cout << "FD lifecycle: 2000 successful and 2000 failed constructions; no growth; copy/move disabled\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
    return 0;
}
