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
