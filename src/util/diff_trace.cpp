
#include "util/diff_trace.h"
#include <memory>

// Global serialization stream implementation
std::unique_ptr<AutoFile> g_datatrace_stream;

bool OpenDataTraceStream() noexcept
{
#if defined(ENABLE_DIFF_TRACING)
    try {
        // Close any existing stream first
        CloseDataTraceStream();

        // Get filename from environment variable
        const char* env_filename = std::getenv("FUZZ_DATA_TRACE_FILE");
        if (!env_filename) {
            return false;
        }

        // Open file for writing in binary mode
        std::FILE* file = std::fopen(env_filename, "wb");
        if (!file) {
            return false;
        }

        // Create AutoFile without XOR obfuscation
        g_datatrace_stream = std::make_unique<AutoFile>(file);

        return !g_datatrace_stream->IsNull();
    } catch (const std::exception&) {
        return false;
    }
#else
    return true;
#endif
}

void CloseDataTraceStream() noexcept
{
#if defined(ENABLE_DIFF_TRACING)
    if (g_datatrace_stream) {
        try {
            // Commit any pending writes before closing
            g_datatrace_stream->Commit();
        } catch (const std::exception&) {
            // Ignore errors during commit
        }
        g_datatrace_stream.reset();
    }
#endif
}
