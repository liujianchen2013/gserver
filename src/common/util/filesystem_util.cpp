#include "filesystem_util.h"

#include <dirent.h>
#include <sys/stat.h>

bool FileSystemUtil::IsDirExist(const std::string& path) {
#ifdef WIN32
    return _access(path.c_str(), 0) != -1;
#else
    DIR* dir = opendir(path.c_str());
    bool exist = nullptr != dir;
    if (dir) {
        closedir(dir);
    }
    return exist;
#endif
}

int32_t FileSystemUtil::MkDir(const std::string& path) {
#ifdef WIN32
    auto ret = CreateDirectory(dir.c_str(), nullptr);
    return ret ? 0 : -1;
#else
    return mkdir(path.c_str(), S_IRWXU);
#endif
}