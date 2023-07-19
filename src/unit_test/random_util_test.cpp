#include "common/util/random_util.h"

#include "unit_test_define.h"

class RandomUtilTest : public ::testing::Test {
protected:
    void SetUp() override {
        RandomUtil::InitSeed();
    }
};

TEST_F(RandomUtilTest, Rand) {
    uint32_t rand_u32 = RandomUtil::Rand(1U, 10U);
    EXPECT_TRUE(rand_u32 >= 1U && rand_u32 <= 10U);
    std::cout << rand_u32 << std::endl;
    int32_t rand_i32 = RandomUtil::Rand(-2, -1);
    EXPECT_TRUE(rand_i32 >= -2 && rand_i32 <= -1);
    std::cout << rand_i32 << std::endl;
    
    RandomUtil::Rand(1);
    RandomUtil::Rand(1.0f);
    RandomUtil::Rand(1.0);
    RandomUtil::Rand(20U);

    float rand_float = RandomUtil::Rand(1.2f, 2.2f);
    EXPECT_TRUE(rand_float > 1.2f && rand_float <= 2.2f);
    std::cout << rand_float << std::endl;
    double rand_double = RandomUtil::Rand(2.2, 1.2);
    EXPECT_TRUE(rand_double > 1.2f && rand_double <= 2.2f);
    std::cout << rand_double << std::endl;

    {
        std::vector<int32_t> vec{10, 10, 50, 20, 10};
        RandomUtil::WeightGetter<decltype(vec)> getter = [](const typename decltype(vec)::value_type& item) { return item; };
        auto const* right_item = RandomUtil::RandByWeight(vec, getter);
        ASSERT_TRUE(right_item);
        std::cout << *right_item << std::endl;
    }
    {
        std::map<uint32_t, uint32_t> map{{1, 50}, {2, 50}};
        RandomUtil::WeightGetter<decltype(map)> getter = [](const typename decltype(map)::value_type& item) { return item.second; };
        auto const* right_item = RandomUtil::RandByWeight(map, getter);
        std::cout << right_item->first << std::endl;
    }
    {
        std::list<int32_t> list{10, 10, 50, 20, 10};
        RandomUtil::WeightGetter<decltype(list)> getter = [](const typename decltype(list)::value_type& item) { return item; };
        auto const* right_item = RandomUtil::RandByWeight(list, getter);
        ASSERT_TRUE(right_item);
        std::cout << *right_item << std::endl;
    }

    {
        struct Item {
            Item(int32_t id, uint32_t weight):id(id), weight(weight){}
            int32_t id;
            uint32_t weight;
        };
        using ItemPtr = std::shared_ptr<Item>;
        std::vector<ItemPtr> vec{ 
            std::make_shared<Item>(1, 10), 
            std::make_shared<Item>(2, 20),
            std::make_shared<Item>(3, 30),
            std::make_shared<Item>(4, 40),
        };
        RandomUtil::WeightGetter<decltype(vec)> getter = [](const typename decltype(vec)::value_type& item) { return item->weight; };
        auto const* right_item = RandomUtil::RandByWeight(vec, getter);
        ASSERT_TRUE(right_item);
        std::cout << (*right_item)->id << std::endl;
    }
}