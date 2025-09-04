#ifndef BITCOIN_TEST_FUZZ_PROTO_UTIL_H
#define BITCOIN_TEST_FUZZ_PROTO_UTIL_H

#include <test/fuzz/proto/util.pb.h>
#include <uint256.h>

uint256 ConsumeUInt256(const proto_fuzz_util::uint256& val);

#endif // BITCOIN_TEST_FUZZ_PROTO_UTIL_H
