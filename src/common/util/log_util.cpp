#include "log_util.h"

#include <glog/log_severity.h>

#include "common/util/filesystem_util.h"
#include "common/util/string_util.h"
#include "common/util/time_util.h"

bool LogUtil::log_init_;

void LogUtil::ResetLogConfig(const LogConfig& log_config) {
    if (log_init_) {
        google::ShutdownGoogleLogging();
    }
    log_init_ = true;
    google::InitGoogleLogging(log_config.log_name_.c_str());

    // 创建目录(glog不会自己创建目录)
    std::vector<std::string> dir_vec{
        log_config.log_dir_,
        log_config.log_name_,
        TimeUtil::TimestampToString(TimeUtil::Timestamp(), "%Y-%m-%d")};

    std::string cur_dir;
    for (auto& item : dir_vec) {
        cur_dir += item;
        cur_dir += DIRSPLIT;

        if (!FileSystemUtil::IsDirExist(cur_dir)) {
            if (FileSystemUtil::MkDir(cur_dir) != 0) {
                printf("failed to mkdir cur_dir:%s\n", cur_dir.c_str());
                return;
            }
        }
    }

    // logfiles are written into this directory
    FLAGS_log_dir = cur_dir;
    // Sets whether to avoid logging to the disk if the disk is full.
    FLAGS_stop_logging_if_full_disk = true;
    // Set whether log messages go to stderr in addition to logfiles.
    FLAGS_alsologtostderr = true;
    // Log messages at a level >= this flag are automatically sent to stderr in addition to log files.
    FLAGS_stderrthreshold = log_config.log_level_;
    // Set color messages logged to stderr (if supported by terminal).
    FLAGS_colorlogtostderr = true;
    // Log messages at a level <= this flag are buffered.
    FLAGS_logbuflevel = google::GLOG_WARNING;
    // Sets the maximum number of seconds which logs may be buffered for.
    FLAGS_logbufsecs = log_config.log_buf_sec_;
    // Log suppression level: messages logged at a lower level than this are suppressed.
    FLAGS_minloglevel = log_config.log_level_;
    // 自定义分级
    FLAGS_v = log_config.debug_log_level_;
}
