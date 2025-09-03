
#ifndef BITCOIN_TEST_FUZZ_PROTO_FUZZ_PROTO_H
#define BITCOIN_TEST_FUZZ_PROTO_FUZZ_PROTO_H

#include <cstdint>
#include <functional>
#include <span>
#include <string_view>

#include <libfuzzer/libfuzzer_macro.h>
// remove macro definition of libprotobuf-mutator, as we will use our one
#undef DEFINE_PROTO_FUZZER
#undef DEFINE_TEXT_PROTO_FUZZER
#undef DEFINE_BINARY_PROTO_FUZZER
#undef DEFINE_CUSTOM_PROTO_MUTATOR_IMPL
#undef DEFINE_CUSTOM_PROTO_CROSSOVER_IMPL
#undef DEFINE_TEST_ONE_PROTO_INPUT_IMPL
#undef DEFINE_POST_PROCESS_PROTO_MUTATION_IMPL
#undef DEFINE_PROTO_FUZZER_IMPL

using TypeProtoTestOneInput = std::function<void(const uint8_t*, size_t)>;
using TypeProtoCustomProtoMutator = std::function<size_t(uint8_t*, size_t, size_t, unsigned int)>;
using TypeProtoCustomProtoCrossover = std::function<size_t(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t, unsigned int)>;

struct FuzzProtoTargetOptions {
    std::function<void()> init{[] {}};
    bool hidden{false};
};


void FuzzProtoFrameworkRegisterTarget(std::string_view name,
    TypeProtoTestOneInput testOneInput,
    TypeProtoCustomProtoMutator mutator,
    TypeProtoCustomProtoCrossover crossOver,
    FuzzProtoTargetOptions opts);

#define FUZZ_PROTO_TEST_ONE_PROTO_INPUT_IMPL(use_binary, name, Proto)         \
  static int name##_proto_Test_One_Input(const uint8_t* data, size_t size) {  \
    using protobuf_mutator::libfuzzer::LoadProtoInput;                        \
    Proto input;                                                              \
    if (LoadProtoInput(use_binary, data, size, &input))                       \
      name##_fuzz_proto_target(input);                                        \
    return 0;                                                                 \
  }

#define FUZZ_PROTO_CUSTOM_PROTO_MUTATOR_IMPL(use_binary, name, Proto)          \
  static size_t name##_Custom_Mutator(                                         \
      uint8_t* data, size_t size, size_t max_size, unsigned int seed) {        \
    using protobuf_mutator::libfuzzer::CustomProtoMutator;                     \
    Proto input;                                                               \
    return CustomProtoMutator(use_binary, data, size, max_size, seed, &input); \
  }

#define FUZZ_PROTO_CUSTOM_PROTO_CROSSOVER_IMPL(use_binary, name, Proto)       \
  static size_t name##_Custom_CrossOver(                                      \
      const uint8_t* data1, size_t size1, const uint8_t* data2, size_t size2, \
      uint8_t* out, size_t max_out_size, unsigned int seed) {                 \
    using protobuf_mutator::libfuzzer::CustomProtoCrossOver;                  \
    Proto input1;                                                             \
    Proto input2;                                                             \
    return CustomProtoCrossOver(use_binary, data1, size1, data2, size2, out,  \
                                max_out_size, seed, &input1, &input2);        \
  }

#define DETAIL_FUZZ_PROTO(use_binary, name, Proto, ...)                               \
    static void name##_fuzz_proto_target(proto);                                      \
    FUZZ_PROTO_TEST_ONE_PROTO_INPUT_IMPL(use_binary, name, Proto)                     \
    FUZZ_PROTO_CUSTOM_PROTO_MUTATOR_IMPL(use_binary, name, Proto)                     \
    FUZZ_PROTO_CUSTOM_PROTO_CROSSOVER_IMPL(use_binary, name, Proto)                   \
    struct name##_proto_Before_Main {                                                 \
        name##_proto_Before_Main()                                                    \
        {                                                                             \
            FuzzProtoFrameworkRegisterTarget(#name,                                   \
                name##_proto_Test_One_Input,                                          \
                name##_Custom_Mutator,                                                \
                name##_Custom_CrossOver,                                              \
                {__VA_ARGS__});                                                       \
        }                                                                             \
    } const static g_##name##_proto_before_main;                                      \
    static void name##_proto_fuzz_target(Proto& target)

#define FUZZ_PROTO_TARGET(...) DETAIL_FUZZ_PROTO(true, __VA_ARGS__)
#define FUZZ_PROTO_TEXT_TARGET(...) DETAIL_FUZZ_PROTO(false, __VA_ARGS__)


#endif // BITCOIN_TEST_FUZZ_PROTO_FUZZ_PROTO_H
