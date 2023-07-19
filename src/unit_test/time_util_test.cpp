#include "common/util/time_util.h"

#include "unit_test_define.h"

class TimeUtilTest : public ::testing::Test {
protected:
    void SetUp() override {
        TimeUtil::SetTimeZone(0);
    }
};

TEST_F(TimeUtilTest, TimeStamp) {
    auto time1 = TimeUtil::Timestamp();
    // std::cout << time1 << std::endl;
    // std::cout << TimeUtil::TimestampToString(time1) << std::endl;

    TimeUtil::SetOffsetSec(60);
    auto time2 = TimeUtil::Timestamp();
    EXPECT_GE(time2 - time1, 60);
    // std::cout << time2 << std::endl;
    // std::cout << TimeUtil::TimestampToString(time2) << std::endl;
}