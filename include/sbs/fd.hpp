#pragma once
#include <unistd.h>

namespace sbs::detail {
// Sole owner of one Linux descriptor. Never retries close (the number may have
// been released even when close reports an error). No copying or moving.
class Fd {
public:
    explicit Fd(int value = -1) noexcept : value_(value) {}
    ~Fd() { if (value_ >= 0) { ::close(value_); } }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&&) = delete;
    Fd& operator=(Fd&&) = delete;
    int get() const noexcept { return value_; }
    void reset(int value) noexcept {
        if (value_ >= 0) { ::close(value_); }
        value_ = value;
    }
private:
    int value_;
};
}
