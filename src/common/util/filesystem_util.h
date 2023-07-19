#pragma once
#include "common/util/common_func.h"

class FileSystemUtil {
public:
    static bool IsDirExist(const std::string& path);
    static int32_t MkDir(const std::string& path);
};