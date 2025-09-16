// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_PROTO_UTIL_MEMPOOL_H
#define BITCOIN_TEST_FUZZ_PROTO_UTIL_MEMPOOL_H

#include <kernel/mempool_entry.h>
#include <validation.h>
#include <test/fuzz/proto/util/mempool.pb.h>


class CTransaction;
class CTxMemPool;

class DummyChainState final : public Chainstate
{
public:
    void SetMempool(CTxMemPool* mempool)
    {
        m_mempool = mempool;
    }
};

[[nodiscard]] CTxMemPoolEntry ConsumeTxMemPoolEntry(const proto_fuzz_util_mempool::ConsumeTxMemPoolEntry& el, const CTransaction& tx, uint32_t max_height=std::numeric_limits<uint32_t>::max()) noexcept;

#endif // BITCOIN_TEST_FUZZ_PROTO_UTIL_MEMPOOL_H
