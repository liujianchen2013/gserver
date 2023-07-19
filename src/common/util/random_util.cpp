#include "random_util.h"

int32_t RandomUtil::seed_;
std::mt19937 RandomUtil::engine_;

void RandomUtil::InitSeed(int32_t seed /* = 0 */) {
    seed_ = seed != 0 ? seed : std::random_device()();
    engine_ = std::mt19937(seed_);
}
