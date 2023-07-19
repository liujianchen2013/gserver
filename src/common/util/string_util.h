#pragma once
#include "common/type_define.h"
#include "common/util/common_func.h"

#ifdef WIN32
static const std::string DIRSPLIT = "\\";
#else
static const std::string DIRSPLIT = "/";
#endif

class StringUtil {
public:
    static void Split(const std::string& str, const std::string& delimiters, std::vector<std::string>& tokens);
    static void Split(const char* str, const std::string& delimiters, std::vector<std::string>& tokens);
    static std::vector<std::string> Split(const std::string& str, const std::string& delimiters);
    static std::vector<std::string> Split(const char* str, const std::string& delimiters);
    static std::string FloatToString(float num, size_t precision = 2);

    template <typename T>
    static std::vector<T> SplitToVector(const std::string& str, const std::string& delimiters);
    template <typename T>
    static std::vector<T> SplitToVector(const char* str, const std::string& delimiter);

    template <typename T>
    static std::set<T> SplitToSet(const std::string& str, const std::string& delimiters);
    template <typename T>
    static std::set<T> SplitToSet(const char* str, const std::string& delimiter);

    template <typename T>
    static std::string Join(const T& v, const std::string& delimiter);
};

template <typename T>
std::vector<T> StringUtil::SplitToVector(const std::string& str, const std::string& delimiters) {
    std::vector<T> ret;
    auto tokens = Split(str, delimiters);
    for (const auto& token : tokens) {
        ret.emplace_back(SafeStringToNumber<T>(token));
    }
    return ret;
}
template <typename T>
std::vector<T> StringUtil::SplitToVector(const char* str, const std::string& delimiter) {
    return SplitToVector<T>(std::string(str ? str : ""), delimiter);
}

template <typename T>
std::set<T> StringUtil::SplitToSet(const std::string& str, const std::string& delimiters) {
    std::set<T> ret;
    auto tokens = Split(str, delimiters);
    for (const auto& token : tokens) {
        ret.emplace(SafeStringToNumber<T>(token));
    }
    return ret;
}
template <typename T>
std::set<T> StringUtil::SplitToSet(const char* str, const std::string& delimiter) {
    return SplitToSet<T>(std::string(str ? str : ""), delimiter);
}

template <typename T>
std::string StringUtil::Join(const T& v, const std::string& delimiter) {
    std::ostringstream oss;
    bool first = true;
    for (const auto& item : v) {
        if (first) {
            first = false;
            oss << std::to_string(item);
        } else {
            oss << delimiter << std::to_string(item);
        }
    }
    return oss.str();
}