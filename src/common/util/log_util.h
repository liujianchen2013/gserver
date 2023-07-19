#pragma once

#include <glog/logging.h>

struct LogConfig {
    std::string log_dir_;
    int32_t log_level_ = 0;
    uint32_t log_buf_sec_ = 0;  // log在缓存中几秒后才会写入硬盘
    std::string log_name_;
    int32_t debug_log_level_ = 0;  // 只控制debug日志，如果要极致性能考虑使用DLOG
};

class LogUtil {
public:
    static void ResetLogConfig(const LogConfig& log_config);

private:
    static bool log_init_;
};

#define LOGSPLIT '|'
#define LOGDEBUG VLOG(1) << __FUNCTION__ << LOGSPLIT
#define LOGINFO LOG(INFO) << __FUNCTION__ << LOGSPLIT
#define LOGWARN LOG(WARNING) << __FUNCTION__ << LOGSPLIT
#define LOGERROR LOG(ERROR) << __FUNCTION__ << LOGSPLIT

// **无论DEBUG还是RELEASE都会core dump**
#define LOGASSERT(condition) LOG_ASSERT(condition) << " "

#ifdef NDEBUG
// -DCMAKE_BUILD_TYPE=Release
#define ASSERTEX(condition) LOG_IF(WARNING, !condition) << __FUNCTION__ << LOGSPLIT
#else
// -DCMAKE_BUILD_TYPE=Debug
#define ASSERTEX(condition) LOGASSERT(condition)
#endif