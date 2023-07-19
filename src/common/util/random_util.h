#pragma once

#include <random>
#include <functional>

#include "common/type_define.h"

class RandomUtil {
public:
    static void InitSeed(int32_t seed = 0);

    // 整数区间:[min, max] 浮点数区间:[min, max)
    template <typename T>
    static T Rand(T min, T max);
    template <typename T>
    static T Rand(T max);

    // 通过权重随机
    template <typename T>
    using WeightGetter = std::function<uint32_t(const typename T::value_type&)>;
    template <typename T>
    static const typename T::value_type* RandByWeight(const T& vec, WeightGetter<T>);

private:
    static int32_t seed_;
    static std::mt19937 engine_;
};

template <typename T>
T RandomUtil::Rand(T min, T max) {
    static_assert(std::is_integral<T>::value, "Rand() only supports arithmetic types.");
    if (min > max) {
        std::swap(min, max);
    }
    return std::uniform_int_distribution<T>(min, max)(engine_);
}

template <typename T>
T RandomUtil::Rand(T max) {
    return Rand<T>(0, max);
}

template <>
float RandomUtil::Rand(float min, float max) {
    if (min > max) {
        std::swap(min, max);
    }
    return std::uniform_real_distribution<float>(min, max)(engine_);
}

template <>
double RandomUtil::Rand(double min, double max) {
    if (min > max) {
        std::swap(min, max);
    }
    return std::uniform_real_distribution<double>(min, max)(engine_);
}

template <typename T>
const typename T::value_type* RandomUtil::RandByWeight(const T& vec, WeightGetter<T> weight_getter) {
    if (vec.empty()) {
        return nullptr;
    }

    uint32_t total_weight = 0U;
    for (auto iter = vec.begin(); iter != vec.end(); ++iter) {
        total_weight += weight_getter(*iter);
    }

    if (total_weight <= 0U) {
        return nullptr;
    }

    auto rand_weight = Rand(1U, total_weight);
    uint32_t right_weight = 0U;
    for (auto iter = vec.begin(); iter != vec.end(); ++iter) {
        right_weight += weight_getter(*iter);
        if (right_weight >= rand_weight) {
            return &(*iter);
        }
    }
    return nullptr;
}