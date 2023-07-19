#include "time_util.h"

time_t TimeUtil::offset_sec_ = 0;
int32_t TimeUtil::time_zone_ = 0;  // default UTC+00
char TimeUtil::time_zone_name_[7] = "UTC+00";

void TimeUtil::SetTimeZone(int32_t time_zone) {
    time_zone_ = time_zone;
    sprintf(time_zone_name_, "UTC%c%02d", time_zone_ < 0 ? '-' : '+', time_zone_);
}

void TimeUtil::SetOffsetSec(time_t offset_sec) {
    offset_sec_ = offset_sec;
}

void TimeUtil::GmtTime(time_t ts, std::tm* tm) {
#ifdef WIN32
    gmtime_s(tm, &ts);
#else
    gmtime_r(&ts, tm);
#endif
}

void TimeUtil::CalcTm(time_t ts, std::tm* tm) {
    time_t seconds_east_of_utc = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::hours(time_zone_)).count();
    GmtTime(ts + seconds_east_of_utc, tm);
#ifdef __USE_BSD
    tm->tm_gmtoff = seconds_east_of_utc; /* Seconds east of UTC.  */
    tm->tm_zone = time_zone_name_;       /* Timezone abbreviation.  */
#else
    tm->__tm_gmtoff = seconds_east_of_utc; /* Seconds east of UTC.  */
    tm->__tm_zone = time_zone_name_;       /* Timezone abbreviation.  */
#endif
}

// eg: 2023-02-01 08:46:18 UTC+00
std::string TimeUtil::TimestampToString(time_t timestamp, const std::string& format /*  = "%Y-%m-%d %H:%M:%S %Z" */) {
    std::tm tm;
    CalcTm(timestamp, &tm);
    char fmt[128] = {0};
    std::strftime(fmt, sizeof(fmt), format.c_str(), &tm);
    return fmt;
}