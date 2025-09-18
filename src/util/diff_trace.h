#ifndef BITCOIN_UTIL_DIFF_TRACE_H
#define BITCOIN_UTIL_DIFF_TRACE_H

#include "streams.h"

#include <memory>

class AutoFile;

// Global data trace stream for writing objects to file
extern std::unique_ptr<AutoFile> g_datatrace_stream;

/**
 * Opens a file for writing serializable objects and creates a global stream.
 * The file path is read from the FUZZ_DATA_TRACE_FILE environment variable.
 * The stream can be used by any code that includes this header to write
 * Bitcoin Core serializable objects.
 *
 * @return true if file was opened successfully, false otherwise
 */
bool OpenDataTraceStream() noexcept;

/**
 * Closes the global serialization stream and flushes any pending writes.
 */
void CloseDataTraceStream() noexcept;

/**
 * Writes a serializable object to the global stream.
 * The stream must be opened first using OpenDataTraceStream().
 *
 * @param obj The object to serialize and write to the stream
 * @return true if write was successful, false otherwise
 */
template <typename T>
bool WriteToDataStream(const T& obj) noexcept
{
#if defined(ENABLE_DIFF_TRACING)
    if (!g_datatrace_stream || g_datatrace_stream->IsNull()) {
        return false;
    }

    try {
        *g_datatrace_stream << obj;
        return true;
    } catch (const std::exception&) {
        return false;
    }
#else
    return true;
#endif
}
template <typename T, typename... Args>
bool WriteToDataStream(const T& obj, Args... args) noexcept
{
  return WriteToDataStream(obj) && WriteToDataStream(std::forward<Args>(args)...);
}

/**
 * Convenience macro for writing objects to the global data trace stream.
 * Usage: SERIALIZE_TO_DATATRACE(my_transaction);
 */
#if defined(ENABLE_DIFF_TRACING)
#define SERIALIZE_TO_DATATRACE(...) WriteToDataStream(__VA_ARGS__)
#else
#define SERIALIZE_TO_DATATRACE(...)
#endif


#endif // BITCOIN_UTIL_DIFF_TRACE_H
