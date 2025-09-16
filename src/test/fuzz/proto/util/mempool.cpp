// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <kernel/mempool_entry.h>
#include <primitives/transaction.h>
#include <test/fuzz/proto/util/mempool.h>
#include <test/fuzz/proto/util.h>

#include <cassert>
#include <cstdint>
#include <limits>

CTxMemPoolEntry ConsumeTxMemPoolEntry(const proto_fuzz_util_mempool::ConsumeTxMemPoolEntry& el, const CTransaction& tx, uint32_t max_height) noexcept
{
    // Avoid:
    // policy/feerate.cpp:28:34: runtime error: signed integer overflow: 34873208148477500 * 1000 cannot be represented in type 'long'
    //
    // Reproduce using CFeeRate(348732081484775, 10).GetFeePerK()
    const CAmount fee{ConsumeMoney(el.fees(), /*max=*/std::numeric_limits<CAmount>::max() / CAmount{100'000})};
    assert(MoneyRange(fee));
    const int64_t time = el.time();
    const uint64_t entry_sequence = el.entry_sequence();
    const auto entry_height = ConsumeIntegralInRange<uint32_t>(el.entry_height(), 0, max_height);
    const bool spends_coinbase = el.spends_coinbase();
    const unsigned int sig_op_cost = ConsumeIntegralInRange<unsigned int>(el.sig_op_cost(), 0, MAX_BLOCK_SIGOPS_COST);
    return CTxMemPoolEntry{MakeTransactionRef(tx), fee, time, entry_height, entry_sequence, spends_coinbase, sig_op_cost, {}};
}
