
#include <test/fuzz/proto/fuzz_proto.h>

#include <netaddress.h>
#include <netbase.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/coverage.h>

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#if defined(PROVIDE_FUZZ_MAIN_FUNCTION) && defined(__AFL_FUZZ_INIT)
__AFL_FUZZ_INIT();
#endif

const std::function<void(const std::string&)> G_TEST_LOG_FUN{};

static std::vector<const char*> g_args;

static void SetArgs(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        // Only take into account arguments that start with `--`. The others are for the fuzz engine:
        // `fuzz -runs=1 fuzz_corpora/address_deserialize_v2 --checkaddrman=5`
        if (strlen(argv[i]) > 2 && argv[i][0] == '-' && argv[i][1] == '-') {
            g_args.push_back(argv[i]);
        }
    }
}

const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS = []() {
    return g_args;
};

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

static std::string_view g_fuzz_target;
static FuzzTarget* g_fuzz_target_info = nullptr;

const std::function<std::string()> G_TEST_GET_FULL_NAME{[]{
    return std::string{g_fuzz_target};
}};

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
    it->second.opts.init();

    ResetCoverageCounters();
}

#if defined(PROVIDE_FUZZ_MAIN_FUNCTION)
static bool read_stdin(std::vector<uint8_t>& data)
{
    std::istream::char_type buffer[1024];
    std::streamsize length;
    while ((std::cin.read(buffer, 1024), length = std::cin.gcount()) > 0) {
        data.insert(data.end(), buffer, buffer + length);
    }
    return length == 0;
}
#endif

#if defined(PROVIDE_FUZZ_MAIN_FUNCTION) && !(defined(__AFL_LOOP) && !defined(FUZZING_WITHOUT_PERSISTENT))
static bool read_file(fs::path p, std::vector<uint8_t>& data)
{
    uint8_t buffer[1024];
    FILE* f = fsbridge::fopen(p, "rb");
    if (f == nullptr) return false;
    do {
        const size_t length = fread(buffer, sizeof(uint8_t), sizeof(buffer), f);
        if (ferror(f)) return false;
        data.insert(data.end(), buffer, buffer + length);
    } while (!feof(f));
    fclose(f);
    return true;
}
#endif

#if defined(PROVIDE_FUZZ_MAIN_FUNCTION) && !defined(__AFL_LOOP)
static fs::path g_input_path;
void signal_handler(int signal)
{
    if (signal == SIGABRT) {
        std::cerr << "Error processing input " << g_input_path << std::endl;
    } else {
        std::cerr << "Unexpected signal " << signal << " received\n";
    }
    std::_Exit(EXIT_FAILURE);
}
#endif

extern std::atomic<bool> g_used_system_time;

struct CheckGlobals {
    CheckGlobals()
    {
        g_used_g_prng = false;
        g_seeded_g_prng_zero = false;
        g_used_system_time = false;
        SetMockTime(0s);
    }
    ~CheckGlobals()
    {
        if (g_used_g_prng && !g_seeded_g_prng_zero) {
            std::cerr << "\n\n"
                         "The current fuzz target used the global random state.\n\n"

                         "This is acceptable, but requires the fuzz target to call \n"
                         "SeedRandomStateForTest(SeedRand::ZEROS) in the first line \n"
                         "of the FUZZ_TARGET function.\n\n"

                         "An alternative solution would be to avoid any use of globals.\n\n"

                         "Without a solution, fuzz instability and non-determinism can lead \n"
                         "to non-reproducible bugs or inefficient fuzzing.\n\n"
                      << std::endl;
            std::abort(); // Abort, because AFL may try to recover from a std::exit
        }

        if (g_used_system_time) {
            std::cerr << "\n\n"
                         "The current fuzz target accessed system time.\n\n"

                         "This is acceptable, but requires the fuzz target to call \n"
                         "SetMockTime() at the beginning of processing the fuzz input.\n\n"

                         "Without setting mock time, time-dependent behavior can lead \n"
                         "to non-reproducible bugs or inefficient fuzzing.\n\n"
                      << std::endl;
            std::abort();
        }
    }
};

static void test_one_input(const uint8_t* data, size_t size)
{
    CheckGlobals check{};
    Assert(g_fuzz_target_info)->testOneInput(data, size);
}

// This function is used by libFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    test_one_input(data, size);
    return 0;
}

// This function is used by libFuzzer
extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    SetArgs(*argc, *argv);
    initialize();
    return 0;
}

// This function is used by libFuzzer
extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* data, size_t size, size_t max_size, unsigned int seed) {

    Assert(g_fuzz_target_info != nullptr);
    return g_fuzz_target_info->mutator(data, size, max_size, seed);
}

// This function is used by libFuzzer
extern "C" size_t LLVMFuzzerCustomCrossOver(
    const uint8_t* data1, size_t size1, const uint8_t* data2, size_t size2,
    uint8_t* out, size_t max_out_size, unsigned int seed) {

    Assert(g_fuzz_target_info != nullptr);
    return g_fuzz_target_info->crossOver(data1, size1, data2, size2, out, max_out_size, seed);
}

#if defined(PROVIDE_FUZZ_MAIN_FUNCTION)
int main(int argc, char** argv)
{
    initialize();
    Assert(g_fuzz_target_info != nullptr);
#ifdef __AFL_LOOP
#ifdef FUZZING_WITHOUT_PERSISTENT
    __AFL_INIT();
    if (__afl_sharedmem_fuzzing) {
        const uint8_t* buffer = __AFL_FUZZ_TESTCASE_BUF;
        size_t buffer_len = __AFL_FUZZ_TESTCASE_LEN;
        test_one_input(buffer, buffer_len);
    } else if (argc <= 1) {
        std::vector<uint8_t> buffer;
        Assert(read_stdin(buffer));
        test_one_input(buffer.data(), buffer.size());
    } else if (argc == 2) {
        std::vector<uint8_t> buffer;
        fs::path input_path(argv[1]);
        Assert(read_file(input_path, buffer));
        test_one_input(buffer.data(), buffer.size());
    } else {
        return 1;
    }
    return 0;
#else
    // Enable AFL persistent mode. Requires compilation using afl-clang-fast++.
    // See fuzzing.md for details.
    const uint8_t* buffer = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        size_t buffer_len = __AFL_FUZZ_TESTCASE_LEN;
        test_one_input(buffer, buffer_len);
    }
#endif
#else
    std::vector<uint8_t> buffer;
    if (argc <= 1) {
        if (!read_stdin(buffer)) {
            return 0;
        }
        test_one_input(buffer.data(), buffer.size());
        return 0;
    }
    std::signal(SIGABRT, signal_handler);
    const auto start_time_us{Now<SteadyMicroseconds>()};
    int tested = 0;
    for (int i = 1; i < argc; ++i) {
        fs::path input_path(*(argv + i));
        if (fs::is_directory(input_path)) {
            std::vector<fs::path> files;
            for (fs::directory_iterator it(input_path); it != fs::directory_iterator(); ++it) {
                if (!fs::is_regular_file(it->path())) continue;
                files.emplace_back(it->path());
            }
            std::ranges::shuffle(files, std::mt19937{std::random_device{}()});
            for (const auto& input_path : files) {
                g_input_path = input_path;
                Assert(read_file(input_path, buffer));
                test_one_input(buffer.data(), buffer.size());
                ++tested;
                buffer.clear();
            }
        } else {
            g_input_path = input_path;
            Assert(read_file(input_path, buffer));
            test_one_input(buffer.data(), buffer.size());
            ++tested;
            buffer.clear();
        }
    }
    const auto end_time_us{Now<SteadyMicroseconds>()};
    const auto duration = count_microseconds(end_time_us - start_time_us);
    uint64_t execPerS = 0;
    if (duration > 0) {
        execPerS = (((uint64_t) tested) * 1000000ull) / duration;
    }
    std::cout << g_fuzz_target << ": succeeded against " << tested << " files in " << (duration / 1000000ull) << "s (" << execPerS << " exec/s)." << std::endl;
#endif
    return 0;
}
#endif
