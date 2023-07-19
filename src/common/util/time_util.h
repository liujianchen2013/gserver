#pragma once
#include <chrono>
#include <common/type_define.h>

class TimeUtil {
public:
    static const int64_t ONE_MIN_SEC = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::minutes(1)).count();
    static const int64_t ONE_HOUR_SEC = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::hours(1)).count();
    static const int64_t ONE_DAY_HOURS = 24;
    static const int64_t ONE_DAY_SEC = (ONE_DAY_HOURS * ONE_HOUR_SEC);
    static const int32_t ONE_WEEK_DAY = 7;

public:
    static void SetTimeZone(int32_t time_zone);
    static void SetOffsetSec(time_t offset_sec);
    static void CalcTm(time_t ts, std::tm* tm);
    static void GmtTime(time_t ts, std::tm* tm);

    // 获取当前时间戳(含偏移)
    template<typename T = std::chrono::seconds>
    static time_t Timestamp() {
        auto now = std::chrono::system_clock::now() + std::chrono::seconds(offset_sec_);
        return std::chrono::duration_cast<T>(now.time_since_epoch()).count();
    }

    // 时间戳转字符串
    static std::string TimestampToString(time_t timestamp, const std::string& format = "%Y-%m-%d %H:%M:%S %Z");

private:
    static time_t offset_sec_;  // 时间偏移，测试调时间用
    static int32_t time_zone_;  // 自己定义时区，防止被系统时区影响
    static char time_zone_name_[7];
};
