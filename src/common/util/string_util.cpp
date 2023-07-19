#include "string_util.h"

void StringUtil::Split(const std::string& str, const std::string& delimiters, std::vector<std::string>& tokens) {
    // Skip delimiters at beginning.
    std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);
    // Find first "non-delimiter".
    std::string::size_type pos = str.find_first_of(delimiters, lastPos);
    while (std::string::npos != pos || std::string::npos != lastPos) {
        // Found a token, add it to the vector.
        tokens.push_back(str.substr(lastPos, pos - lastPos));
        // Skip delimiters.  Note the "not_of"
        lastPos = str.find_first_not_of(delimiters, pos);
        // Find next "non-delimiter"
        pos = str.find_first_of(delimiters, lastPos);
    }
}

void StringUtil::Split(const char* str, const std::string& delimiters, std::vector<std::string>& tokens) {
    if (str) {
        Split(std::string(str), delimiters, tokens);
    }
}

std::vector<std::string> StringUtil::Split(const std::string& str, const std::string& delimiters) {
    std::vector<std::string> vec;
    Split(str, delimiters, vec);
    return vec;
}

std::vector<std::string> StringUtil::Split(const char* str, const std::string& delimiters) {
    return Split(std::string(str), delimiters);
}

std::string StringUtil::FloatToString(float num, size_t precision/*  = 2 */) {
    std::stringstream ss;
    ss.precision(precision);
    ss.setf(std::ios::fixed);
    ss << num;
    return ss.str();
}