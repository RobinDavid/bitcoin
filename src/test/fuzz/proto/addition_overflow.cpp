// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/proto/fuzz_proto.h>
#include <test/fuzz/proto/addition_overflow.pb.h>
#include <util/overflow.h>

#include <cstdint>
#include <string>
#include <vector>

namespace {
template <typename T>
void TestAdditionOverflow(const T i, const T j)
{
    const bool is_addition_overflow_custom = AdditionOverflow(i, j);
    const auto maybe_add{CheckedAdd(i, j)};
    const auto sat_add{SaturatingAdd(i, j)};
    assert(is_addition_overflow_custom == !maybe_add.has_value());
    assert(is_addition_overflow_custom == AdditionOverflow(j, i));
    assert(maybe_add == CheckedAdd(j, i));
    assert(sat_add == SaturatingAdd(j, i));
#ifndef _MSC_VER
    T result_builtin;
    const bool is_addition_overflow_builtin = __builtin_add_overflow(i, j, &result_builtin);
    assert(is_addition_overflow_custom == is_addition_overflow_builtin);
    if (!is_addition_overflow_custom) {
        assert(i + j == result_builtin);
    }
#endif
    if (is_addition_overflow_custom) {
        assert(sat_add == std::numeric_limits<T>::min() || sat_add == std::numeric_limits<T>::max());
    } else {
        const auto add{i + j};
        assert(add == maybe_add.value());
        assert(add == sat_add);
    }
}
} // namespace

FUZZ_PROTO_TARGET(addition_overflow, const addition_overflow_fuzz::Target& el) {
    TestAdditionOverflow<int64_t>(el.s64_1(), el.s64_2());
    TestAdditionOverflow<uint64_t>(el.u64_1(), el.u64_2());
    TestAdditionOverflow<int32_t>(el.s32_1(), el.s32_2());
    TestAdditionOverflow<uint32_t>(el.u32_1(), el.u32_2());
    TestAdditionOverflow<int16_t>(el.s16_1(), el.s16_2());
    TestAdditionOverflow<uint16_t>(el.u16_1(), el.u16_2());
    TestAdditionOverflow<char>(el.c8_1(), el.c8_2());
    TestAdditionOverflow<signed char>(el.s8_1(), el.s8_2());
    TestAdditionOverflow<unsigned char>(el.u8_1(), el.u8_2());
}
