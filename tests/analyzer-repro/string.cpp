#include <string>
// Valid C++17: the returned empty string is fully initialized. This standalone
// reproducer is intentionally not a CMake test target. See ANALYZER-REPAIR.md.
std::string initialized_string() {
    std::string value;
    return value;
}
