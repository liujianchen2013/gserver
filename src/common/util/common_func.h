#pragma once
#include "common/type_define.h"

uint64_t ntohll(uint64_t val);
uint64_t htonll(uint64_t val);

std::string ParseProcessName(const char* argv);

template<typename T>
T SafeStringToNumber(const std::string &s) {
    std::istringstream ss(s);
    T num;
    ss >> num;
    return num;
}