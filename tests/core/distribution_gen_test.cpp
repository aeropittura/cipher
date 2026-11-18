//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#include <cmath>
#include <cstdint>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#include "cipher/ring/backend.h"
#include "cipher/math/distributions.h"
#include "cipher/math/number_theory.h"
#include "core/test_defs.h"
#include "cipher/util/debug.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/utilities.h"

using namespace cipher;

//////////////////////////////////////////////////////////////////
// Testing Methods of BigInteger DiscreteUniformGenerator
//////////////////////////////////////////////////////////////////

// helper functions defined later
template <typename V>
void test_discrete_uniform_generator(typename V::Integer& modulus, std::string test_name);

template <typename V>
void test_parallel_discrete_uniform_generator(typename V::Integer& modulus, std::string test_name);

template <typename V>
void discrete_uniform_generator_long(const std::string& msg) {
    // TEST CASE TO GENERATE A UNIFORM BIG BINARY INTEGER WITH SMALL MODULUS
    {
        typename V::Integer modulus("10403");
        auto dug = DiscreteUniformGeneratorImpl<V>();
        dug.set_modulus(modulus);
        typename V::Integer uni_rand_num = dug.generate_integer();

        EXPECT_LT(uni_rand_num, modulus) << msg << " Failure testing with_in_small_modulus_integer_small_modulus";
    }

    // TEST CASE TO GENERATE A UNIFORM BIG BINARY INTEGER WITH LARGE MODULUS
    {
        typename V::Integer modulus("10402635286389262637365363");
        auto dug = DiscreteUniformGeneratorImpl<V>();
        dug.set_modulus(modulus);
        typename V::Integer uni_rand_num = dug.generate_integer();

        EXPECT_LT(uni_rand_num, modulus) << msg << " Failure testing with_in_large_modulus_integer_large_modulus";
    }

    // TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH SMALL MODULUS
    {
        typename V::Integer modulus("10403");
        auto dug = DiscreteUniformGeneratorImpl<V>();

        uint32_t size = 10;
        V uni_rand_vector = dug.generate_vector(size, modulus);
        // test length
        EXPECT_EQ(uni_rand_vector.get_length(), size)
                << msg << " Failure testing vector_uniform_vector_small_modulus wrong length";
        // test content
        for (size_t i = 0; i < size; i++) {
            EXPECT_LT(uni_rand_vector.at(i), modulus) << msg
                                                      << " Failure testing vector_uniform_vector_small_modulus value "
                                                         "greater than modulus at index "
                                                      << i;
        }
    }

    // TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH LARGE MODULUS

    {
        typename V::Integer modulus("10402635286389262637365363");
        auto dug = DiscreteUniformGeneratorImpl<V>();

        uint32_t size = 100;
        V uni_rand_vector = dug.generate_vector(size, modulus);
        // test length
        EXPECT_EQ(uni_rand_vector.get_length(), size) << "Failure testing vector_uniform_vector_large_modulus";
        // test content
        for (size_t i = 0; i < size; i++) {
            EXPECT_LT(uni_rand_vector.at(i), modulus) << msg
                                                      << " Failure testing vector_uniform_vector_large_modulus value "
                                                         "greater than modulus at index "
                                                      << i;
        }
    }

    {
        // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS SMALL MODULUS
        typename V::Integer small_modulus("7919");
        test_discrete_uniform_generator<V>(small_modulus, msg + " small_modulus");
    }
    {
        // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS LARGE MODULUS
        typename V::Integer large_modulus("100019");
        test_discrete_uniform_generator<V>(large_modulus, msg + " large_modulus");
    }

    {
        // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS HUGE MODULUS
        typename V::Integer huge_modulus("10402635286389262637365363");
        test_discrete_uniform_generator<V>(huge_modulus, msg + " huge_modulus");
    }

    // TEST CASE TO RECREATE OVERFLOW ISSUE CAUSED WHEN CALCULATING MEAN OF BBI's
    {
        int caught_error = 0;
        try {
            typename V::Integer modulus("10402635286389262637365363");  // 10402635286389262637365363
            auto dug = DiscreteUniformGeneratorImpl<V>();

            uint32_t each_iteration_size = 1000, no_of_iterations = 100;
            typename V::Integer sum, mean, N(each_iteration_size);

            V uni_rand_vector = dug.generate_vector(each_iteration_size * no_of_iterations, modulus);

            for (uint32_t i = 0; i < no_of_iterations; i++) {
                sum = mean = typename V::Integer(0);
                for (size_t j = i * each_iteration_size; j < (i + 1) * each_iteration_size; j++) {
                    sum += uni_rand_vector.at(j);
                }
                mean = sum.divided_by(N);
            }
        } catch (...) {
            caught_error = 1;
        }
        EXPECT_EQ(caught_error, 0) << msg << " Failure recreate_overflow_issue threw an error";
    }
}

TEST(UTDistrGen, DiscreteUniformGenerator_LONG) {
    RUN_BIG_BACKENDS(discrete_uniform_generator_long, "DiscreteUniformGenerator_LONG")
}

//
// helper function to test first and second central moment of discrete uniform
// generator single thread case
template <typename V>
void test_discrete_uniform_generator(typename V::Integer& modulus, std::string test_name) {
    // TEST CASE ON FIRST CENTRAL MOMENT

    double modulus_in_double = modulus.convert_to_double();
    double expected_mean_in_double = modulus_in_double / 2.0;

    auto distr_uni_gen = DiscreteUniformGeneratorImpl<V>();
    distr_uni_gen.set_modulus(modulus);

    uint32_t size = 50000;
    V rand_big_vector = distr_uni_gen.generate_vector(size);

    double sum = 0;
    typename V::Integer length(std::to_string(rand_big_vector.get_length()));

    for (uint32_t index = 0; index < size; index++) {
        sum += (rand_big_vector.at(index)).convert_to_double();
    }

    double computed_mean_in_double = sum / size;
    double diff_in_means = std::abs(computed_mean_in_double - expected_mean_in_double);

    // within 1% of expected mean
    EXPECT_LT(diff_in_means, 0.01 * modulus_in_double)
            << "Failure testing first_moment_test_convertToDouble " << test_name;

    // TEST CASE ON SECOND CENTRAL MOMENT
    double expected_variance_in_double = ((modulus_in_double - 1.0) * (modulus_in_double - 1.0)) / 12.0;
    double expected_std_dev_in_double = std::sqrt(expected_variance_in_double);

    sum = 0;
    double temp;
    for (uint32_t index = 0; index < size; index++) {
        temp = (rand_big_vector.at(index)).convert_to_double() - expected_mean_in_double;
        temp *= temp;
        sum += temp;
    }

    double computed_variance = (sum / size);
    double computed_std_dev = std::sqrt(computed_variance);
    double diff_in_std_dev = std::abs(computed_std_dev - expected_std_dev_in_double);

    EXPECT_LT(diff_in_std_dev, 0.01 * expected_std_dev_in_double)
            << "Failure testing second_moment_test_convertToDouble " << test_name;
}

#ifdef CIPHER_PARALLEL
template <typename V>
void ParallelDiscreteUniformGenerator_LONG(const std::string& msg) {
    // BUILD SEVERAL VECTORS OF BBI IN CIPHER_PARALLEL, CONCATENATE THEM TO ONE LARGE
    // VECTOR AND TEST THE RESULT OF THE FIRST AND SECOND CENTRAL MOMENTS

    typename V::Integer small_modulus("7919");  // test small modulus
    test_parallel_discrete_uniform_generator<V>(small_modulus, msg + " small_modulus");

    typename V::Integer large_modulus("100019");  // test large modulus
    test_parallel_discrete_uniform_generator<V>(large_modulus, msg + " large_modulus");

    typename V::Integer huge_modulus("10402635286389262637365363");
    test_parallel_discrete_uniform_generator<V>(huge_modulus, msg + " huge_modulus");
}

TEST(UTDistrGen, ParallelDiscreteUniformGenerator_LONG) {
    RUN_BIG_BACKENDS(ParallelDiscreteUniformGenerator_LONG, "ParallelDiscreteUniformGenerator_LONG")
}

//
// helper function to test first and second central moment of discrete uniform
// generator multi thread case
template <typename V>
void test_parallel_discrete_uniform_generator(typename V::Integer& modulus, std::string test_name) {
    double modulus_in_double = modulus.convert_to_double();
    // we expect the mean to be modulus/2 (the mid range of the min-max data);
    double expected_mean_in_double = modulus_in_double / 2.0;
    uint32_t size = 50000;
    // uint32_t size = omp_get_max_threads() * 4;

    CIPHER_DEBUG_FLAG(false);
    std::vector<typename V::Integer> rand_big_vector;
    #pragma omp parallel  // this is executed in parallel
    {
        // private copies of our vector
        std::vector<typename V::Integer> randBigVectorPvt;
        auto distr_uni_gen = DiscreteUniformGeneratorImpl<V>();

        distr_uni_gen.set_modulus(modulus);
        // build the vectors in parallel
    #pragma omp for nowait schedule(static)
        for (uint32_t i = 0; i < size; i++) {
            // build private copies in parallel
            randBigVectorPvt.push_back(distr_uni_gen.generate_integer());
        }

    #pragma omp for schedule(static) ordered
        // now stitch them back together sequentially to preserve order of i
        for (int i = 0; i < omp_get_num_threads(); i++) {
    #pragma omp ordered
            {
                CIPHER_DEBUG("thread #" << omp_get_thread_num() << " moving " << (int)randBigVectorPvt.size()
                                        << " to starting point " << (int)rand_big_vector.size());
                rand_big_vector.insert(rand_big_vector.end(), randBigVectorPvt.begin(), randBigVectorPvt.end());
                CIPHER_DEBUG("thread #" << omp_get_thread_num() << " moved");
            }
        }
    }

    // now compute the sum over the entire vector
    double sum = 0;
    typename V::Integer length(std::to_string(rand_big_vector.size()));

    for (uint32_t index = 0; index < size; index++) {
        sum += (rand_big_vector[index]).convert_to_double();
    }
    // divide by the size (i.e. take mean)
    double computed_mean_in_double = sum / size;
    // compute the difference between the expected and actual
    double diff_in_means = std::abs(computed_mean_in_double - expected_mean_in_double);

    // within 1% of expected mean
    EXPECT_LT(diff_in_means, 0.01 * modulus_in_double)
            << "Failure testing parallel_first_central_moment_test " << test_name;

    // TEST CASE ON SECOND CENTRAL MOMENT SMALL MODULUS
    double expected_variance_in_double =
            ((modulus_in_double - 1.0) * (modulus_in_double - 1.0)) / 12.0;  // var = ((b-a)^2) /12
    double expected_std_dev_in_double = std::sqrt(expected_variance_in_double);

    sum = 0;
    double temp;
    for (uint32_t index = 0; index < size; index++) {
        temp = (rand_big_vector[index]).convert_to_double() - expected_mean_in_double;
        temp *= temp;
        sum += temp;
    }

    double computed_variance = (sum / size);
    double computed_std_dev = std::sqrt(computed_variance);

    double diff_in_std_dev = std::abs(computed_std_dev - expected_std_dev_in_double);

    // within 1% of expected std dev
    EXPECT_LT(diff_in_std_dev, 0.1 * expected_std_dev_in_double)
            << "Failure testing second_central_moment_test " << test_name;
}
#endif

// TEST(UTDistrGen, DiscreteUniformGeneratorSeed ) {
//   typename V::Integer modulus("7919"); // test small modulus
//   double sum1=0;
//   uint32_t size = 10;
//   {
//     DiscreteUniformGenerator distr_uni_gen =
//     cipher::DiscreteUniformGenerator(modulus, 12345);

//     V randBigVector1 = distr_uni_gen.generate_vector(size);

//     for(uint32_t index=0; index<size; index++) {
//       sum1 += (randBigVector1.at(index)).convert_to_double();
//     }
//   }
//   DiscreteUniformGenerator distr_uni_gen =
//   cipher::DiscreteUniformGenerator(modulus, 12345); V randBigVector2 =
//   distr_uni_gen.generate_vector(size); double sum2=0;

//   for(uint32_t index=0; index<size; index++) {
//     sum2 += (randBigVector2.at(index)).convert_to_double();
//   }

//   EXPECT_EQ(sum1, sum2) << "Failure, summs are different";

// }

////////////////////////////////////////////////
// Testing Methods of BigInteger BinaryUniformGenerator
////////////////////////////////////////////////

template <typename V>
void binary_uniform_generator_test(const std::string& msg) {
    // fail if less than 0
    {
        auto binary_uni_gen = BinaryUniformGeneratorImpl<V>();
        auto bin_uni_rand_num = binary_uni_gen.generate_integer();
        EXPECT_GE(bin_uni_rand_num.convert_to_int(), 0ULL) << msg << " Failure less than 0";
    }

    // fail if gt 1
    {
        auto binary_uni_gen = BinaryUniformGeneratorImpl<V>();
        auto bin_uni_rand_num = binary_uni_gen.generate_integer();
        EXPECT_LE(bin_uni_rand_num.convert_to_int(), 1ULL) << msg << " Failure greater than 1";
    }

    // mean test
    {
        auto binary_uni_gen = BinaryUniformGeneratorImpl<V>();

        uint32_t length = 100000;
        auto modulus = typename V::Integer("1041");
        auto rand_big_vector = binary_uni_gen.generate_vector(length, modulus);

        uint32_t sum = 0;

        for (uint32_t index = 0; index < rand_big_vector.get_length(); index++) {
            sum += rand_big_vector.at(index).convert_to_int();
        }

        float computed_mean = static_cast<float>(sum) / static_cast<float>(length);
        float expected_mean = 0.5;
        float dif = std::abs(computed_mean - expected_mean);

        EXPECT_LT(dif, 0.01) << msg << " Failure Mean is incorrect";
        // a large sample. Max of them should be less than q
    }
}

TEST(UTDistrGen, BinaryUniformGenerator) {
    RUN_ALL_BACKENDS(binary_uniform_generator_test, "BinaryUniformGeneratorTest")
}

// mean test
template <typename V>
void ternary_uniform_generator_test(const std::string& msg) {
    auto ternary_uni_gen = TernaryUniformGeneratorImpl<V>();

    uint32_t length = 100000;
    auto modulus = typename V::Integer("1041");
    V rand_big_vector = ternary_uni_gen.generate_vector(length, modulus);

    int32_t sum = 0;

    for (uint32_t index = 0; index < rand_big_vector.get_length(); index++) {
        if (rand_big_vector[index] == modulus - typename V::Integer(1))
            sum -= 1;
        else
            sum += rand_big_vector[index].convert_to_int();
    }

    float computed_mean = static_cast<double>(sum) / static_cast<double>(length);

    float expected_mean = 0;
    float dif = std::abs(computed_mean - expected_mean);

    EXPECT_LT(dif, 0.01) << msg << " Ternary Uniform Distribution Failure Mean is incorrect";
    // a large sample. Max of them should be less than q
}

TEST(UTDistrGen, TernaryUniformGenerator) {
    RUN_ALL_BACKENDS(ternary_uniform_generator_test, "TernaryUniformGeneratorTest")
}

template <typename V>
void ternary_uniform_generator_integer_test(const std::string& msg) {
    auto ternary_uni_gen = TernaryUniformGeneratorImpl<V>();
    auto modulus = typename V::Integer("1041");
    const auto minus_one = modulus - typename V::Integer(1);

    int32_t sum = 0;
    uint32_t counts[3]{};
    const uint32_t length = 100000;
    for (uint32_t i = 0; i < length; ++i) {
        auto x = ternary_uni_gen.generate_integer(modulus);
        if (x == minus_one) {
            --sum;
            ++counts[0];
        } else {
            ASSERT_LE(x, typename V::Integer(1)) << msg << " value outside {-1, 0, 1}";
            sum += x.convert_to_int();
            ++counts[1 + x.convert_to_int()];
        }
    }
    EXPECT_LT(std::abs(static_cast<double>(sum) / length), 0.01) << msg << " mean is incorrect";
    for (auto c : counts)
        EXPECT_GT(c, length / 4) << msg << " a value of {-1, 0, 1} is under-represented";
}

TEST(UTDistrGen, TernaryUniformGeneratorInteger) {
    RUN_ALL_BACKENDS(ternary_uniform_generator_integer_test, "TernaryUniformGeneratorIntegerTest")
}

// the smallest Hamming weights sit at the boundary of the balance check on the +1 count
template <typename V>
void ternary_uniform_generator_sparse_test(const std::string& msg) {
    auto ternary_uni_gen = TernaryUniformGeneratorImpl<V>();
    auto modulus = typename V::Integer("1041");
    const auto minus_one = modulus - typename V::Integer(1);
    const uint32_t size = 16;
    for (uint32_t h = 1; h <= 5; ++h) {
        V v = ternary_uni_gen.generate_vector(size, modulus, h);
        uint32_t weight = 0;
        for (uint32_t i = 0; i < size; ++i) {
            if (v[i] != typename V::Integer(0)) {
                EXPECT_TRUE(v[i] == typename V::Integer(1) || v[i] == minus_one) << msg << " h = " << h;
                ++weight;
            }
        }
        EXPECT_EQ(h, weight) << msg << " GenerateVector Hamming weight";

        auto iv = ternary_uni_gen.generate_int_vector(size, h);
        weight = 0;
        for (auto x : iv) {
            EXPECT_LE(std::abs(x), 1) << msg << " h = " << h;
            weight += (x != 0);
        }
        EXPECT_EQ(h, weight) << msg << " GenerateIntVector Hamming weight";
    }
}

TEST(UTDistrGen, TernaryUniformGeneratorSparse) {
    RUN_ALL_BACKENDS(ternary_uniform_generator_sparse_test, "TernaryUniformGeneratorSparseTest")
}

////////////////////////////////////////////////
// Testing Methods of BigInteger DiscreteGaussianGenerator
////////////////////////////////////////////////

template <typename V>
void discrete_gaussian_generator_test(const std::string& msg) {
    // mean test

    {
        int stdev = 5;
        uint32_t size = 100000;
        typename V::Integer modulus("10403");
        auto dgg = DiscreteGaussianGeneratorImpl<V>(stdev);
        auto dgg_char_vector = dgg.generate_int_vector(size);

        double mean = 0;
        for (uint32_t i = 0; i < size; i++) {
            mean += static_cast<double>(dgg_char_vector[i]);
        }
        mean /= size;

        EXPECT_LE(mean, 0.1) << msg << " Failure generate_char_vector_mean_test mean > 0.1";
        EXPECT_GE(mean, -0.1) << msg << " Failure generate_char_vector_mean_test mean < -0.1";
    }

    // generate_vector_mean_test
    {
        int stdev = 5;
        uint32_t size = 100000;
        typename V::Integer modulus("10403");
        typename V::Integer modulus_by_two(modulus.divided_by(2));
        const auto dgg = DiscreteGaussianGeneratorImpl<V>(stdev);
        V dgg_big_vector = dgg.generate_vector(size, modulus);

        uint32_t count_of_zero = 0;
        double mean = 0, current = 0;

        for (uint32_t i = 0; i < size; i++) {
            current = std::stod(dgg_big_vector.at(i).to_string());
            if (current == 0)
                count_of_zero++;
            mean += current;
        }

        mean /= (size - count_of_zero);

        double modulus_by_two_in_double = std::stod(modulus_by_two.to_string());

        double diff = std::abs(modulus_by_two_in_double - mean);
        EXPECT_LT(diff, 104) << msg << " Failure generate_vector_mean_test";
    }
}

TEST(UTDistrGen, DiscreteGaussianGenerator) {
    RUN_ALL_BACKENDS(discrete_gaussian_generator_test, "DiscreteGaussianGeneratorTest")
}

#ifdef CIPHER_PARALLEL
template <typename V>
void ParallelDiscreteGaussianGenerator_VERY_LONG(const std::string& msg) {
    // mean test
    CIPHER_DEBUG_FLAG(false);

    {
        int stdev = 5;
        uint32_t size = 10000;
        typename V::Integer modulus("10403");

        std::vector<int32_t> dgg_char_vector;

    #pragma omp parallel  // this is executed in parallel
        {
            // private copies of our vector
            std::vector<int32_t> dggCharVectorPvt;
            auto dgg = DiscreteGaussianGeneratorImpl<V>(stdev);

            // build the vectors in parallel
    #pragma omp for nowait schedule(static)
            for (uint32_t i = 0; i < size; i++) {
                // build private copies in parallel
                dggCharVectorPvt.push_back(dgg.generate_int());
            }

    #pragma omp for schedule(static) ordered
            // now stitch them back together sequentially to preserve order of i
            for (int i = 0; i < omp_get_num_threads(); i++) {
    #pragma omp ordered
                {
                    CIPHER_DEBUG("thread #" << omp_get_thread_num() << " " << "moving " << (int)dggCharVectorPvt.size()
                                            << " to starting point" << (int)dgg_char_vector.size());
                    dgg_char_vector.insert(dgg_char_vector.end(), dggCharVectorPvt.begin(), dggCharVectorPvt.end());
                }
            }
        }

        double mean = 0;
        for (uint32_t i = 0; i < size; i++) {
            mean += static_cast<double>(dgg_char_vector[i]);
        }
        mean /= size;

        EXPECT_LE(mean, 0.1) << msg << " Failure parallel generate_char_vector_mean_test mean > 0.1";
        EXPECT_GE(mean, -0.1) << msg << " Failure parallel generate_char_vector_mean_test mean < -0.1";
    }

    // generate_vector_mean_test
    {
        int stdev = 5;
        uint32_t size = 100000;
        typename V::Integer modulus("10403");
        typename V::Integer modulus_by_two(modulus.divided_by(2));

        std::vector<typename V::Integer> dgg_big_vector;
    #pragma omp parallel  // this is executed in parallel
        {
            // private copies of our vector
            std::vector<typename V::Integer> dggBigVectorPvt;
            auto dgg = DiscreteGaussianGeneratorImpl<V>(stdev);

            // build the vectors in parallel
    #pragma omp for nowait schedule(static)
            for (uint32_t i = 0; i < size; i++) {
                // build private copies in parallel
                dggBigVectorPvt.push_back(dgg.generate_integer(modulus));
            }

    #pragma omp for schedule(static) ordered
            // now stitch them back together sequentially to preserve order of i
            for (int i = 0; i < omp_get_num_threads(); i++) {
    #pragma omp ordered
                {
                    CIPHER_DEBUG("thread #" << omp_get_thread_num() << " " << "moving " << (int)dggBigVectorPvt.size()
                                            << " to starting point" << (int)dgg_big_vector.size());
                    dgg_big_vector.insert(dgg_big_vector.end(), dggBigVectorPvt.begin(), dggBigVectorPvt.end());
                }
            }
        }

        uint32_t count_of_zero = 0;
        double mean = 0, current = 0;

        for (uint32_t i = 0; i < size; i++) {
            current = std::stod(dgg_big_vector[i].to_string());
            if (current == 0)
                count_of_zero++;
            mean += current;
        }

        mean /= (size - count_of_zero);

        double modulus_by_two_in_double = std::stod(modulus_by_two.to_string());

        double diff = std::abs(modulus_by_two_in_double - mean);
        EXPECT_LT(diff, 104) << msg << " Failure generate_vector_mean_test";
    }
}

TEST(UTDistrGen, ParallelDiscreteGaussianGenerator_VERY_LONG) {
    RUN_ALL_BACKENDS(ParallelDiscreteGaussianGenerator_VERY_LONG, "ParallelDiscreteGaussianGenerator_VERY_LONG")
}
#endif  // CIPHER_PARALLEL

// Mean test for Karney sampling
template <typename V>
void karney_mean(const std::string& msg) {
    int stdev = 10;
    uint32_t size = 10000;
    double mean = 0;
    double center = 10;
    auto dgg = DiscreteGaussianGeneratorImpl<V>(stdev);
    for (unsigned int i = 0; i < size; i++) {
        mean += dgg.generate_integer_karney(center, stdev);
    }
    mean /= size;
    double difference = std::abs(mean - center);
    difference /= center;
    EXPECT_LE(difference, 0.1) << msg << " Failure to create mean with difference  < 10%";
}

TEST(UTDistrGen, Karney_Mean) {
    RUN_ALL_BACKENDS(karney_mean, "Karney_Mean")
}

// Variance test for Karney sampling
template <typename V>
void karney_variance(const std::string& msg) {
    int stdev = 10;
    uint32_t size = 10000;
    double mean = 0;
    double variance = 0;
    auto dgg = DiscreteGaussianGeneratorImpl<V>(stdev);
    int numbers[10000];

    for (unsigned int i = 0; i < size; i++) {
        numbers[i] = dgg.generate_integer_karney(0, stdev);
        mean += numbers[i];
    }
    mean /= size;
    for (unsigned int i = 0; i < size; i++) {
        variance += (numbers[i] - mean) * (numbers[i] - mean);
    }
    variance /= (size - 1);
    double difference = std::abs(variance - stdev * stdev) / (stdev * stdev);
    EXPECT_LE(difference, 0.1) << msg << " Failure to create variance with difference  < 10%";
}

TEST(UTDistrGen, Karney_Variance) {
    RUN_ALL_BACKENDS(karney_variance, "Karney_Variance")
}

#ifdef CIPHER_PARALLEL
void ThreadSafetyTestHelper() {
    PRNG& engine = PseudoRandomNumberGenerator::get_prng();
    engine();
}

template <typename V>
void ThreadSafetyInGetPRNG(const std::string& msg) {
    std::thread t1(ThreadSafetyTestHelper);
    t1.join();

    ThreadSafetyTestHelper();
}

TEST(UTDistrGen, ThreadSafetyInGetPRNG) {
    RUN_ALL_BACKENDS(ThreadSafetyInGetPRNG, "Thread safety in getPRNG")
}
#endif
