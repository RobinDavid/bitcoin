// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <test/fuzz/proto/coins_view.pb.h>
#include <test/fuzz/proto/fuzz_proto.h>
#include <test/fuzz/proto/util.h>
#include <test/util/setup_common.h>
#include <util/hasher.h>

#include <cassert>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
const Coin EMPTY_COIN{};

bool operator==(const Coin& a, const Coin& b)
{
    if (a.IsSpent() && b.IsSpent()) return true;
    return a.fCoinBase == b.fCoinBase && a.nHeight == b.nHeight && a.out == b.out;
}
} // namespace

void initialize_coins_view()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
}

FUZZ_PROTO_TARGET(coins_view, const coins_view_fuzz::Target& el, .init = initialize_coins_view) {

    CCoinsView backend_coins_view;
    CCoinsViewCache coins_view_cache{&backend_coins_view, /*deterministic=*/true};
    COutPoint random_out_point;
    Coin random_coin;
    CMutableTransaction random_mutable_transaction;

    for (int i = 0; i < std::min(el.actions_size(), 10'000); i++) {
        const auto& currentAction = el.actions(i);
        switch (currentAction.action_type_case()) {
            default:
            case coins_view_fuzz::Target_Action::kAddCoin: {
                if (random_coin.IsSpent()) {
                    break;
                }
                Coin coin = random_coin;
                bool expected_code_path = false;
                const bool possible_overwrite = currentAction.addcoin();
                try {
                    coins_view_cache.AddCoin(random_out_point, std::move(coin), possible_overwrite);
                    expected_code_path = true;
                } catch (const std::logic_error& e) {
                    if (e.what() == std::string{"Attempted to overwrite an unspent coin (when possible_overwrite is false)"}) {
                        assert(!possible_overwrite);
                        expected_code_path = true;
                    }
                }
                assert(expected_code_path);
                break;
            }
            case coins_view_fuzz::Target_Action::kFlush: {
                (void)coins_view_cache.Flush();
                break;
            }
            case coins_view_fuzz::Target_Action::kSync: {
                (void)coins_view_cache.Sync();
                break;
            }
            case coins_view_fuzz::Target_Action::kSetBestBlock: {
                coins_view_cache.SetBestBlock(ConsumeUInt256(currentAction.setbestblock()));
                break;
            }
            case coins_view_fuzz::Target_Action::kSpendCoin: {
                Coin move_to;
                (void)coins_view_cache.SpendCoin(random_out_point, currentAction.spendcoin() ? &move_to : nullptr);
                break;
            }
            case coins_view_fuzz::Target_Action::kUncache: {
                coins_view_cache.Uncache(random_out_point);
                break;
            }
            case coins_view_fuzz::Target_Action::kSetBackend: {
                if (currentAction.setbackend()) {
                    backend_coins_view = CCoinsView{};
                }
                coins_view_cache.SetBackend(backend_coins_view);
                break;
            }
            case coins_view_fuzz::Target_Action::kSetRandomOutPoint: {
                random_out_point = ConsumeCOutPoint(currentAction.setrandomoutpoint());
                break;
            }
            case coins_view_fuzz::Target_Action::kSetRandomCoin: {
                random_coin = ConsumeCoin(currentAction.setrandomcoin());;
                break;
            }
            case coins_view_fuzz::Target_Action::kSetRandomTransaction: {
                random_mutable_transaction = ConsumeMutableTransaction(currentAction.setrandomtransaction());
                break;
            }
            case coins_view_fuzz::Target_Action::kBatchWrite: {
                const auto& batchWriteData = currentAction.batchwrite();
                CoinsCachePair sentinel{};
                sentinel.second.SelfRef(sentinel);
                size_t usage{0};
                CCoinsMapMemoryResource resource;
                CCoinsMap coins_map{0, SaltedOutpointHasher{/*deterministic=*/true}, CCoinsMap::key_equal{}, &resource};
                for (int j = 0; j < std::min(batchWriteData.elements_size(), 10'000); j++) {
                    const auto& currentElement = batchWriteData.elements(j);
                    CCoinsCacheEntry coins_cache_entry;
                    const auto dirty = currentElement.dirty();
                    const auto fresh = currentElement.fresh();
                    if (!currentElement.has_randomcoin()) {
                        coins_cache_entry.coin = random_coin;
                    } else {
                        coins_cache_entry.coin = ConsumeCoin(currentElement.randomcoin());
                    }
                    auto it{coins_map.emplace(random_out_point, std::move(coins_cache_entry)).first};
                    if (dirty) CCoinsCacheEntry::SetDirty(*it, sentinel);
                    if (fresh) CCoinsCacheEntry::SetFresh(*it, sentinel);
                    usage += it->second.coin.DynamicMemoryUsage();
                }
                bool expected_code_path = false;
                try {
                    auto cursor{CoinsViewCacheCursor(usage, sentinel, coins_map, /*will_erase=*/true)};
                    coins_view_cache.BatchWrite(cursor, batchWriteData.has_hash() ? ConsumeUInt256(batchWriteData.hash()) : coins_view_cache.GetBestBlock());
                    expected_code_path = true;
                } catch (const std::logic_error& e) {
                    if (e.what() == std::string{"FRESH flag misapplied to coin that exists in parent cache"}) {
                        expected_code_path = true;
                    }
                }
                assert(expected_code_path);
                break;
            }
        }
    }

    {
        const Coin& coin_using_access_coin = coins_view_cache.AccessCoin(random_out_point);
        const bool exists_using_access_coin = !(coin_using_access_coin == EMPTY_COIN);
        const bool exists_using_have_coin = coins_view_cache.HaveCoin(random_out_point);
        const bool exists_using_have_coin_in_cache = coins_view_cache.HaveCoinInCache(random_out_point);
        if (auto coin{coins_view_cache.GetCoin(random_out_point)}) {
            assert(*coin == coin_using_access_coin);
            assert(exists_using_access_coin && exists_using_have_coin_in_cache && exists_using_have_coin);
        } else {
            assert(!exists_using_access_coin && !exists_using_have_coin_in_cache && !exists_using_have_coin);
        }
        // If HaveCoin on the backend is true, it must also be on the cache if the coin wasn't spent.
        const bool exists_using_have_coin_in_backend = backend_coins_view.HaveCoin(random_out_point);
        if (!coin_using_access_coin.IsSpent() && exists_using_have_coin_in_backend) {
            assert(exists_using_have_coin);
        }
        if (auto coin{backend_coins_view.GetCoin(random_out_point)}) {
            assert(exists_using_have_coin_in_backend);
            // Note we can't assert that `coin_using_get_coin == *coin` because the coin in
            // the cache may have been modified but not yet flushed.
        } else {
            assert(!exists_using_have_coin_in_backend);
        }
    }

    {
        bool expected_code_path = false;
        try {
            (void)coins_view_cache.Cursor();
        } catch (const std::logic_error&) {
            expected_code_path = true;
        }
        assert(expected_code_path);
        (void)coins_view_cache.DynamicMemoryUsage();
        (void)coins_view_cache.EstimateSize();
        (void)coins_view_cache.GetBestBlock();
        (void)coins_view_cache.GetCacheSize();
        (void)coins_view_cache.GetHeadBlocks();
        (void)coins_view_cache.HaveInputs(CTransaction{random_mutable_transaction});
    }

    {
        std::unique_ptr<CCoinsViewCursor> coins_view_cursor = backend_coins_view.Cursor();
        assert(!coins_view_cursor);
        (void)backend_coins_view.EstimateSize();
        (void)backend_coins_view.GetBestBlock();
        (void)backend_coins_view.GetHeadBlocks();
    }

    switch (el.final_action_type_case()) {
        default:
            break;
        case coins_view_fuzz::Target::kFinalAddCoin: {
            const CTransaction transaction{random_mutable_transaction};
            bool is_spent = false;
            for (const CTxOut& tx_out : transaction.vout) {
                if (Coin{tx_out, 0, transaction.IsCoinBase()}.IsSpent()) {
                    is_spent = true;
                }
            }
            if (is_spent) {
                // Avoid:
                // coins.cpp:69: void CCoinsViewCache::AddCoin(const COutPoint &, Coin &&, bool): Assertion `!coin.IsSpent()' failed.
                break;
            }
            bool expected_code_path = false;
            const int height{int(el.finaladdcoin().height() >> 1)};
            const bool possible_overwrite = el.finaladdcoin().possible_overwrite();
            try {
                AddCoins(coins_view_cache, transaction, height, possible_overwrite);
                expected_code_path = true;
            } catch (const std::logic_error& e) {
                if (e.what() == std::string{"Attempted to overwrite an unspent coin (when possible_overwrite is false)"}) {
                    assert(!possible_overwrite);
                    expected_code_path = true;
                }
            }
            assert(expected_code_path);
            break;
        }
        case coins_view_fuzz::Target::kAreInputsStandard: {
            (void)AreInputsStandard(CTransaction{random_mutable_transaction}, coins_view_cache);
            break;
        }
        case coins_view_fuzz::Target::kCheckTxInputs: {
            TxValidationState state;
            CAmount tx_fee_out;
            const CTransaction transaction{random_mutable_transaction};
            if (ContainsSpentInput(transaction, coins_view_cache)) {
                // Avoid:
                // consensus/tx_verify.cpp:171: bool Consensus::CheckTxInputs(const CTransaction &, TxValidationState &, const CCoinsViewCache &, int, CAmount &): Assertion `!coin.IsSpent()' failed.
                break;
            }
            TxValidationState dummy;
            if (!CheckTransaction(transaction, dummy)) {
                // It is not allowed to call CheckTxInputs if CheckTransaction failed
                break;
            }
            if (Consensus::CheckTxInputs(transaction, state, coins_view_cache,
                                         ConsumeIntegralInRange<int>(el.checktxinputs(), 0, std::numeric_limits<int>::max()), tx_fee_out)) {
                assert(MoneyRange(tx_fee_out));
            }
            break;
        }
        case coins_view_fuzz::Target::kGetP2SHSigOpCount: {
            const CTransaction transaction{random_mutable_transaction};
            if (ContainsSpentInput(transaction, coins_view_cache)) {
                // Avoid:
                // consensus/tx_verify.cpp:130: unsigned int GetP2SHSigOpCount(const CTransaction &, const CCoinsViewCache &): Assertion `!coin.IsSpent()' failed.
                break;
            }
            (void)GetP2SHSigOpCount(transaction, coins_view_cache);
            break;
        }
        case coins_view_fuzz::Target::kGetTransactionSigOpCost: {
            const CTransaction transaction{random_mutable_transaction};
            if (ContainsSpentInput(transaction, coins_view_cache)) {
                // Avoid:
                // consensus/tx_verify.cpp:130: unsigned int GetP2SHSigOpCount(const CTransaction &, const CCoinsViewCache &): Assertion `!coin.IsSpent()' failed.
                break;
            }
            const auto flags{el.gettransactionsigopcost()};
            if (!transaction.vin.empty() && (flags & SCRIPT_VERIFY_WITNESS) != 0 && (flags & SCRIPT_VERIFY_P2SH) == 0) {
                // Avoid:
                // script/interpreter.cpp:1705: size_t CountWitnessSigOps(const CScript &, const CScript &, const CScriptWitness *, unsigned int): Assertion `(flags & SCRIPT_VERIFY_P2SH) != 0' failed.
                break;
            }
            (void)GetTransactionSigOpCost(transaction, coins_view_cache, flags);
            break;
        }
        case coins_view_fuzz::Target::kIsWitnessStandard: {
            (void)IsWitnessStandard(CTransaction{random_mutable_transaction}, coins_view_cache);
            break;
        }
    }
}
