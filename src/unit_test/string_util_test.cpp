#include "common/util/string_util.h"

#include "unit_test_define.h"

class StringUtilTest : public ::testing::Test {
protected:
    void SetUp() override {
    }

protected:
    std::string test_str_1 = "1:2:";
};

TEST_F(StringUtilTest, FloatToString) {
    {
        auto float_str = StringUtil::FloatToString(0.56f);
        EXPECT_STREQ(float_str.c_str(), "0.56");
    }

    {
        auto float_str = StringUtil::FloatToString(0.565f); // 0.5649999976F
        EXPECT_STREQ(float_str.c_str(), "0.56");
    }

    {
        auto float_str = StringUtil::FloatToString(0.566f); // 0.5659999847F
        EXPECT_STREQ(float_str.c_str(), "0.57");
    }

    {
        auto float_str = StringUtil::FloatToString(0.564f, 3);
        EXPECT_STREQ(float_str.c_str(), "0.564");
    }
}

TEST_F(StringUtilTest, SplitToVector) {
    {
        auto vec = StringUtil::SplitToVector<int32_t>("1:2", ":");
        EXPECT_TRUE(vec.size() == 2 && vec[0] == 1 && vec[1] == 2);
    }

    {
        auto vec = StringUtil::SplitToVector<uint16_t>("1:2:", ":");
        EXPECT_TRUE(vec.size() == 2 && vec[0] == 1 && vec[1] == 2);
    }

    {
        auto vec = StringUtil::SplitToVector<int8_t>(":1:2", ":");
        EXPECT_TRUE(vec.size() == 2 && vec[0] == '1' && vec[1] == '2');
    }
}

TEST_F(StringUtilTest, SplitToSet) {
    {
        auto vec = StringUtil::SplitToSet<int32_t>("1:2", ":");
        EXPECT_TRUE(vec.size() == 2);
    }

    {
        auto vec = StringUtil::SplitToSet<uint16_t>("1:2:", ":");
        EXPECT_TRUE(vec.size() == 2);
    }

    {
        auto vec = StringUtil::SplitToSet<int8_t>(":1:2", ":");
        EXPECT_TRUE(vec.size() == 2);
    }
}

TEST_F(StringUtilTest, Join) {
    {
        std::vector<uint32_t> vec{1, 2, 3};
        auto join_str = StringUtil::Join(vec, ":");
        EXPECT_STREQ(join_str.c_str(), "1:2:3");
    }

    {
        std::set<int16_t> vec{1, 2, 3};
        auto join_str = StringUtil::Join(vec, ":");
        EXPECT_STREQ(join_str.c_str(), "1:2:3");
    }

    {
        std::list<int8_t> vec{1, 2, 3};
        auto join_str = StringUtil::Join(vec, ":");
        EXPECT_STREQ(join_str.c_str(), "1:2:3");
    }
}