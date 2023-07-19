#include "common_func.h"
#include "common/util/string_util.h"

uint64_t ntohll(uint64_t val) {
#if __BIG_ENDIAN__
    return val;
#else
    return (uint64_t(ntohl(uint32_t(val))) << 32) | ntohl((uint32_t(val >> 32)));
#endif
}

uint64_t htonll(uint64_t val) {
#if __BIG_ENDIAN__
    return val;
#else
    return (uint64_t(htonl(uint32_t(val))) << 32) | htonl((uint32_t(val >> 32)));
#endif
}

std::string ParseProcessName(const char* argv) {
    std::vector<std::string> vec;
    StringUtil::Split(argv, DIRSPLIT, vec);
#ifdef WIN32
    auto s = *vec.rbegin();
    vec.clear();
    StringUtil::Split(s, ".", vec);
    return *vec.begin();
#else
    return *vec.rbegin();
#endif
}