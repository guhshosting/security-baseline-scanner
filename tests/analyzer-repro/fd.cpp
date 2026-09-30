#include <fcntl.h>
#include <unistd.h>
// Valid scoped ownership with no copying. This is a compiler diagnostic
// reproducer, intentionally not a CMake test target.
class Owner {
public:
    explicit Owner(const char* path) : fd_(::open(path, O_RDONLY)) {}
    ~Owner() { if (fd_ >= 0) { ::close(fd_); } }
    Owner(const Owner&) = delete;
    Owner& operator=(const Owner&) = delete;
private:
    int fd_;
};
void scoped_owner() { Owner owner("/"); }
