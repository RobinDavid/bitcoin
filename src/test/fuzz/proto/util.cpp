#include <array>

#include <test/fuzz/proto/util.h>

uint256 ConsumeUInt256(const proto_fuzz_util::uint256& val) {

    std::array<unsigned char, 32> value{};

    const std::string& buf = val.value();
    if (buf.size() > 0) {
        memcpy(value.data(), buf.data(), std::min(buf.size(), value.size()));
    }

    return uint256(value);
}

int64_t ConsumeTime(int64_t value, const std::optional<int64_t>& min, const std::optional<int64_t>& max) noexcept {
    // Avoid t=0 (1970-01-01T00:00:00Z) since SetMockTime(0) disables mocktime.
    static const int64_t time_min{ParseISO8601DateTime("2000-01-01T00:00:01Z").value()};
    static const int64_t time_max{ParseISO8601DateTime("2100-12-31T23:59:59Z").value()};
    return ConsumeIntegralInRange<int64_t>(value, min.value_or(time_min), max.value_or(time_max));
}

