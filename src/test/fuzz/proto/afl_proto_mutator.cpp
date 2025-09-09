#include <test/fuzz/proto/fuzz_proto.h>

#include <netaddress.h>
#include <netbase.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/coverage.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <vector>

struct FuzzTarget {
    const TypeProtoTestOneInput testOneInput;
    const TypeProtoCustomProtoMutator mutator;
    const TypeProtoCustomProtoCrossover crossOver;
    const FuzzProtoTargetOptions opts;
};

static auto& FuzzTargets()
{
    static std::map<std::string_view, FuzzTarget> g_fuzz_targets;
    return g_fuzz_targets;
}

void FuzzProtoFrameworkRegisterTarget(std::string_view name,
    TypeProtoTestOneInput testOneInput,
    TypeProtoCustomProtoMutator mutator,
    TypeProtoCustomProtoCrossover crossOver,
    FuzzProtoTargetOptions opts) {
    const auto [it, ins]{FuzzTargets().try_emplace(name,
        FuzzTarget{std::move(testOneInput),
                   std::move(mutator),
                   std::move(crossOver),
                   std::move(opts)})};
    Assert(ins);
}

static std::vector<const char*> g_args;

// static void SetArgs(int argc, char** argv) {
//     for (int i = 1; i < argc; ++i) {
//         // Only take into account arguments that start with `--`. The others are for the fuzz engine:
//         // `fuzz -runs=1 fuzz_corpora/address_deserialize_v2 --checkaddrman=5`
//         if (strlen(argv[i]) > 2 && argv[i][0] == '-' && argv[i][1] == '-') {
//             g_args.push_back(argv[i]);
//         }
//     }
// }

const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS = []() {
    return g_args;
};

const std::function<void(const std::string&)> G_TEST_LOG_FUN{};

static std::string_view g_fuzz_target;
static FuzzTarget* g_fuzz_target_info = nullptr;

const std::function<std::string()> G_TEST_GET_FULL_NAME{[]{
    return std::string{g_fuzz_target};
}};


namespace {

static void initialize()
{

    // By default, make the RNG deterministic with a fixed seed. This will affect all
    // randomness during the fuzz test, except:
    // - GetStrongRandBytes(), which is used for the creation of private key material.
    // - Randomness obtained before this call in g_rng_temp_path_init
    SeedRandomStateForTest(SeedRand::ZEROS);

    // Set time to the genesis block timestamp for deterministic initialization.
    SetMockTime(1231006505);

    // Terminate immediately if a fuzzing harness ever tries to create a socket.
    // Individual tests can override this by pointing CreateSock to a mocked alternative.
    CreateSock = [](int, int, int) -> std::unique_ptr<Sock> { std::terminate(); };

    // Terminate immediately if a fuzzing harness ever tries to perform a DNS lookup.
    g_dns_lookup = [](const std::string& name, bool allow_lookup) {
        if (allow_lookup) {
            std::terminate();
        }
        return WrappedGetAddrInfo(name, false);
    };

    bool should_exit{false};
    if (std::getenv("PRINT_ALL_FUZZ_TARGETS_AND_ABORT")) {
        for (const auto& [name, t] : FuzzTargets()) {
            if (t.opts.hidden) continue;
            std::cout << name << std::endl;
        }
        should_exit = true;
    }
    if (const char* out_path = std::getenv("WRITE_ALL_FUZZ_TARGETS_AND_ABORT")) {
        std::cout << "Writing all fuzz target names to '" << out_path << "'." << std::endl;
        std::ofstream out_stream{out_path, std::ios::binary};
        for (const auto& [name, t] : FuzzTargets()) {
            if (t.opts.hidden) continue;
            out_stream << name << std::endl;
        }
        should_exit = true;
    }
    if (should_exit) {
        std::exit(EXIT_SUCCESS);
    }
    if (const auto* env_fuzz{std::getenv("FUZZ")}) {
        // To allow for easier fuzz executable binary modification,
        static std::string g_copy{env_fuzz}; // create copy to avoid compiler optimizations, and
        g_fuzz_target = g_copy.c_str();      // strip string after the first null-char.
    } else {
        std::cerr << "Must select fuzz target with the FUZZ env var." << std::endl;
        std::cerr << "Hint: Set the PRINT_ALL_FUZZ_TARGETS_AND_ABORT=1 env var to see all compiled targets." << std::endl;
        std::exit(EXIT_FAILURE);
    }
    const auto it = FuzzTargets().find(g_fuzz_target);
    if (it == FuzzTargets().end()) {
        std::cerr << "No fuzz target compiled for " << g_fuzz_target << "." << std::endl;
        std::exit(EXIT_FAILURE);
    }
    if constexpr (!G_FUZZING_BUILD && !G_ABORT_ON_FAILED_ASSUME) {
        std::cerr << "Must compile with -DBUILD_FOR_FUZZING=ON or in Debug mode to execute a fuzz target." << std::endl;
        std::exit(EXIT_FAILURE);
    }
    if (!EnableFuzzDeterminism()) {
        if (std::getenv("FUZZ_NONDETERMINISM")) {
            std::cerr << "Warning: FUZZ_NONDETERMINISM env var set, results may be inconsistent with fuzz build" << std::endl;
        } else {
            g_enable_dynamic_fuzz_determinism = true;
            assert(EnableFuzzDeterminism());
        }
    }
    Assert(!g_fuzz_target_info);
    g_fuzz_target_info = &it->second;
    //it->second.opts.init();

    ResetCoverageCounters();
}

// This function is used by libFuzzer
size_t LLVMFuzzerCustomMutator(
    uint8_t* data, size_t size, size_t max_size, unsigned int seed) {

    Assert(g_fuzz_target_info != nullptr);
    return g_fuzz_target_info->mutator(data, size, max_size, seed);
}

// This function is used by libFuzzer
size_t LLVMFuzzerCustomCrossOver(
    const uint8_t* data1, size_t size1, const uint8_t* data2, size_t size2,
    uint8_t* out, size_t max_out_size, unsigned int seed) {

    Assert(g_fuzz_target_info != nullptr);
    return g_fuzz_target_info->crossOver(data1, size1, data2, size2, out, max_out_size, seed);
}

}

extern "C" {

struct my_mutator {
  std::vector<uint8_t> buf;
  unsigned int seed;
};

void *afl_custom_init(void *afl_state, unsigned int seed) {
    auto state = std::make_unique<my_mutator>();
    state->seed = seed;
    if (g_fuzz_target_info == nullptr) {
        initialize();
    }
    return state.release();
}

size_t afl_custom_fuzz(my_mutator *state, uint8_t *buf, size_t buf_size, uint8_t **out_buf, uint8_t *add_buf, size_t add_buf_size, size_t max_size) {
  size_t targetSize = std::max(max_size, buf_size);
  if (state->buf.size() < targetSize) {
      state->buf.resize(targetSize);
  }

  state->seed += 1;
  *out_buf = state->buf.data();

  if (add_buf != nullptr && add_buf_size > 0 && ((state->seed & 1) == 0)) {
      return LLVMFuzzerCustomCrossOver(buf, buf_size, add_buf, add_buf_size, *out_buf, max_size, state->seed);
  } else {
      if (buf != nullptr && buf_size > 0) {
        std::memcpy(*out_buf, buf, buf_size);
      }
      return LLVMFuzzerCustomMutator(*out_buf, buf_size, max_size, state->seed);
  }
}

size_t afl_custom_post_process(my_mutator *state, uint8_t *buf, size_t buf_size, uint8_t **out_buf) {
    *out_buf = buf;
    return buf_size;
}

void afl_custom_deinit(my_mutator *state) {
    auto state_owner = std::unique_ptr<my_mutator>(state);
    state_owner.reset();
}

}
