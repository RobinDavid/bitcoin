// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <node/context.h>
#include <node/mempool_args.h>
#include <node/miner.h>
#include <policy/truc_policy.h>
#include <test/fuzz/proto/tx_pool.pb.h>
#include <test/fuzz/proto/fuzz_proto.h>
#include <test/fuzz/proto/util.h>
#include <test/fuzz/proto/util/mempool.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <util/check.h>
#include <util/rbf.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

using node::BlockAssembler;
using node::NodeContext;
using util::ToString;

namespace {

const TestingSetup* g_setup;
std::vector<COutPoint> g_outpoints_coinbase_init_mature;
std::vector<COutPoint> g_outpoints_coinbase_init_immature;

struct MockedTxPool : public CTxMemPool {
    void RollingFeeUpdate() EXCLUSIVE_LOCKS_REQUIRED(!cs)
    {
        LOCK(cs);
        lastRollingFeeUpdate = GetTime();
        blockSinceLastRollingFeeBump = true;
    }
};

void initialize_tx_pool()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();

    BlockAssembler::Options options;
    options.coinbase_output_script = P2WSH_OP_TRUE;

    for (int i = 0; i < 2 * COINBASE_MATURITY; ++i) {
        COutPoint prevout{MineBlock(g_setup->m_node, options)};
        // Remember the txids to avoid expensive disk access later on
        auto& outpoints = i < COINBASE_MATURITY ?
                              g_outpoints_coinbase_init_mature :
                              g_outpoints_coinbase_init_immature;
        outpoints.push_back(prevout);
    }
    g_setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

struct TransactionsDelta final : public CValidationInterface {
    std::set<CTransactionRef>& m_removed;
    std::set<CTransactionRef>& m_added;

    explicit TransactionsDelta(std::set<CTransactionRef>& r, std::set<CTransactionRef>& a)
        : m_removed{r}, m_added{a} {}

    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t /* mempool_sequence */) override
    {
        Assert(m_added.insert(tx.info.m_tx).second);
    }

    void TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t /* mempool_sequence */) override
    {
        Assert(m_removed.insert(tx).second);
    }
};

void SetMempoolConstraints(ArgsManager& args, const tx_pool_fuzz::MempoolConstraints& el)
{
    args.ForceSetArg("-limitancestorcount",
                     ToString(ConsumeIntegralInRange<unsigned>(el.limitancestorcount(), 0, 50)));
    args.ForceSetArg("-limitancestorsize",
                     ToString(ConsumeIntegralInRange<unsigned>(el.limitancestorsize(), 0, 202)));
    args.ForceSetArg("-limitdescendantcount",
                     ToString(ConsumeIntegralInRange<unsigned>(el.limitdescendantcount(), 0, 50)));
    args.ForceSetArg("-limitdescendantsize",
                     ToString(ConsumeIntegralInRange<unsigned>(el.limitdescendantsize(), 0, 202)));
    args.ForceSetArg("-maxmempool",
                     ToString(ConsumeIntegralInRange<unsigned>(el.maxmempool(), 0, 200)));
    args.ForceSetArg("-mempoolexpiry",
                     ToString(ConsumeIntegralInRange<unsigned>(el.mempoolexpiry(), 0, 999)));
}

void Finish(const tx_pool_fuzz::FinishMempool& el, MockedTxPool& tx_pool, Chainstate& chainstate)
{
    WITH_LOCK(::cs_main, tx_pool.check(chainstate.CoinsTip(), chainstate.m_chain.Height() + 1));
    {
        BlockAssembler::Options options;
        options.nBlockMaxWeight = ConsumeIntegralInRange(el.nblockmaxweight(), 0U, MAX_BLOCK_WEIGHT);
        options.blockMinFeeRate = CFeeRate{ConsumeMoney(el.blockminfeerate(), /*max=*/COIN)};
        auto assembler = BlockAssembler{chainstate, &tx_pool, options};
        auto block_template = assembler.CreateNewBlock();
        Assert(block_template->block.vtx.size() >= 1);
    }
    const auto info_all = tx_pool.infoAll();
    if (!info_all.empty()) {
        const auto& tx_to_remove = *PickValue(el.toremoveindex(), info_all).tx;
        WITH_LOCK(tx_pool.cs, tx_pool.removeRecursive(tx_to_remove, MemPoolRemovalReason::BLOCK /* dummy */));
        assert(tx_pool.size() < info_all.size());
        WITH_LOCK(::cs_main, tx_pool.check(chainstate.CoinsTip(), chainstate.m_chain.Height() + 1));
    }
    g_setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

void MockTime(int64_t v, const Chainstate& chainstate)
{
    const auto time = ConsumeTime(v,
                                  chainstate.m_chain.Tip()->GetMedianTimePast() + 1,
                                  std::numeric_limits<decltype(chainstate.m_chain.Tip()->nTime)>::max());
    SetMockTime(time);
}

std::unique_ptr<CTxMemPool> MakeMempool(bool mempool_require_standard, const NodeContext& node)
{
    // Take the default options for tests...
    CTxMemPool::Options mempool_opts{MemPoolOptionsForTest(node)};

    // ...override specific options for this specific fuzz suite
    mempool_opts.check_ratio = 1;
    mempool_opts.require_standard = mempool_require_standard;

    // ...and construct a CTxMemPool from it
    bilingual_str error;
    auto mempool{std::make_unique<CTxMemPool>(std::move(mempool_opts), error)};
    // ... ignore the error since it might be beneficial to fuzz even when the
    // mempool size is unreasonably small
    Assert(error.empty() || error.original.starts_with("-maxmempool must be at least "));
    return mempool;
}

void CheckATMPInvariants(const MempoolAcceptResult& res, bool txid_in_mempool, bool wtxid_in_mempool)
{

    switch (res.m_result_type) {
    case MempoolAcceptResult::ResultType::VALID:
    {
        Assert(txid_in_mempool);
        Assert(wtxid_in_mempool);
        Assert(res.m_state.IsValid());
        Assert(!res.m_state.IsInvalid());
        Assert(res.m_vsize);
        Assert(res.m_base_fees);
        Assert(res.m_effective_feerate);
        Assert(res.m_wtxids_fee_calculations);
        Assert(!res.m_other_wtxid);
        break;
    }
    case MempoolAcceptResult::ResultType::INVALID:
    {
        // It may be already in the mempool since in ATMP cases we don't set MEMPOOL_ENTRY or DIFFERENT_WITNESS
        Assert(!res.m_state.IsValid());
        Assert(res.m_state.IsInvalid());

        const bool is_reconsiderable{res.m_state.GetResult() == TxValidationResult::TX_RECONSIDERABLE};
        Assert(!res.m_vsize);
        Assert(!res.m_base_fees);
        // Fee information is provided if the failure is TX_RECONSIDERABLE.
        // In other cases, validation may be unable or unwilling to calculate the fees.
        Assert(res.m_effective_feerate.has_value() == is_reconsiderable);
        Assert(res.m_wtxids_fee_calculations.has_value() == is_reconsiderable);
        Assert(!res.m_other_wtxid);
        break;
    }
    case MempoolAcceptResult::ResultType::MEMPOOL_ENTRY:
    {
        // ATMP never sets this; only set in package settings
        Assert(false);
        break;
    }
    case MempoolAcceptResult::ResultType::DIFFERENT_WITNESS:
    {
        // ATMP never sets this; only set in package settings
        Assert(false);
        break;
    }
    }
}

FUZZ_PROTO_TARGET(tx_pool_standard, const tx_pool_fuzz::Target_tx_pool_standard& el, .init = initialize_tx_pool) {

    SeedRandomStateForTest(SeedRand::ZEROS);
    const auto& node = g_setup->m_node;
    auto& chainstate{static_cast<DummyChainState&>(node.chainman->ActiveChainstate())};

    MockTime(el.time(), chainstate);

    // All RBF-spendable outpoints
    std::set<COutPoint> outpoints_rbf;
    // All outpoints counting toward the total supply (subset of outpoints_rbf)
    std::set<COutPoint> outpoints_supply;
    for (const auto& outpoint : g_outpoints_coinbase_init_mature) {
        Assert(outpoints_supply.insert(outpoint).second);
    }
    outpoints_rbf = outpoints_supply;

    // The sum of the values of all spendable outpoints
    constexpr CAmount SUPPLY_TOTAL{COINBASE_MATURITY * 50 * COIN};

    SetMempoolConstraints(*node.args, el.memconstraints());
    auto tx_pool_{MakeMempool(el.mempool_require_standard(), node)};
    MockedTxPool& tx_pool = *static_cast<MockedTxPool*>(tx_pool_.get());

    chainstate.SetMempool(&tx_pool);

    // Helper to query an amount
    const CCoinsViewMemPool amount_view{WITH_LOCK(::cs_main, return &chainstate.CoinsTip()), tx_pool};
    const auto GetAmount = [&](const COutPoint& outpoint) {
        auto coin{amount_view.GetCoin(outpoint).value()};
        return coin.out.nValue;
    };

    for (unsigned i = 0; i < std::min<unsigned>(el.elements_size(), 300); i++) {
        const auto& currentElement = el.elements(i);
        {
            // Total supply is the mempool fee + all outpoints
            CAmount supply_now{WITH_LOCK(tx_pool.cs, return tx_pool.GetTotalFee())};
            for (const auto& op : outpoints_supply) {
                supply_now += GetAmount(op);
            }
            Assert(supply_now == SUPPLY_TOTAL);
        }
        Assert(!outpoints_supply.empty());

        // Create transaction to add to the mempool
        const CTransactionRef tx = [&] {
            CMutableTransaction tx_mut;
            tx_mut.version = currentElement.versiontruc() ? TRUC_VERSION : CTransaction::CURRENT_VERSION;
            tx_mut.nLockTime = currentElement.has_nlocktime() ? currentElement.nlocktime() : 0;
            const auto outpoints_rbf_size = outpoints_rbf.size();
            // const auto num_in = ConsumeIntegralInRange<int>(1, outpoints_rbf.size());
            const auto num_out = ConsumeIntegralInRange<int>(currentElement.num_out(), 1, outpoints_rbf_size * 2);

            CAmount amount_in{0};
            for (int j = 0; j < std::min<int>(currentElement.txinputs_size(), outpoints_rbf_size); ++j) {
                const auto& currentInput = currentElement.txinputs(j);
                // Pop random outpoint
                auto pop = outpoints_rbf.begin();
                std::advance(pop, ConsumeIntegralInRange<size_t>(currentInput.index(), 0, outpoints_rbf.size() - 1));
                const auto outpoint = *pop;
                outpoints_rbf.erase(pop);
                amount_in += GetAmount(outpoint);

                // Create input
                const auto sequence = ConsumeSequence(currentInput.sequence());
                const auto script_sig = CScript{};
                const auto script_wit_stack = std::vector<std::vector<uint8_t>>{WITNESS_STACK_ELEM_OP_TRUE};
                CTxIn in;
                in.prevout = outpoint;
                in.nSequence = sequence;
                in.scriptSig = script_sig;
                in.scriptWitness.stack = script_wit_stack;

                tx_mut.vin.push_back(in);
            }
            const auto amount_fee = ConsumeIntegralInRange<CAmount>(currentElement.amount_fee(), -1000, amount_in);
            const auto amount_out = (amount_in - amount_fee) / num_out;
            for (int j = 0; j < num_out; ++j) {
                tx_mut.vout.emplace_back(amount_out, P2WSH_OP_TRUE);
            }
            auto tx = MakeTransactionRef(tx_mut);
            // Restore previously removed outpoints
            for (const auto& in : tx->vin) {
                Assert(outpoints_rbf.insert(in.prevout).second);
            }
            return tx;
        }();

        if (currentElement.has_time()) {
            MockTime(currentElement.time(), chainstate);
        }
        if (currentElement.rollingfeeupdate()) {
            tx_pool.RollingFeeUpdate();
        }
        if (currentElement.has_priotx()) {
            const auto& txid = currentElement.priotx().has_priotxindex() ?
                                   PickValue(currentElement.priotx().priotxindex(), outpoints_rbf).hash :
                                   tx->GetHash();
            const auto delta = ConsumeIntegralInRange<CAmount>(currentElement.priotx().delta(), -50 * COIN, +50 * COIN);
            tx_pool.PrioritiseTransaction(txid.ToUint256(), delta);
        }

        // Remember all removed and added transactions
        std::set<CTransactionRef> removed;
        std::set<CTransactionRef> added;
        auto txr = std::make_shared<TransactionsDelta>(removed, added);
        node.validation_signals->RegisterSharedValidationInterface(txr);
        const bool bypass_limits = currentElement.bypass_limits();

        // Make sure ProcessNewPackage on one transaction works.
        // The result is not guaranteed to be the same as what is returned by ATMP.
        const auto result_package = WITH_LOCK(::cs_main,
                                    return ProcessNewPackage(chainstate, tx_pool, {tx}, true, /*client_maxfeerate=*/{}));
        // If something went wrong due to a package-specific policy, it might not return a
        // validation result for the transaction.
        if (result_package.m_state.GetResult() != PackageValidationResult::PCKG_POLICY) {
            auto it = result_package.m_tx_results.find(tx->GetWitnessHash());
            Assert(it != result_package.m_tx_results.end());
            Assert(it->second.m_result_type == MempoolAcceptResult::ResultType::VALID ||
                   it->second.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        }

        const auto res = WITH_LOCK(::cs_main, return AcceptToMemoryPool(chainstate, tx, GetTime(), bypass_limits, /*test_accept=*/false));
        const bool accepted = res.m_result_type == MempoolAcceptResult::ResultType::VALID;
        node.validation_signals->SyncWithValidationInterfaceQueue();
        node.validation_signals->UnregisterSharedValidationInterface(txr);

        bool txid_in_mempool = tx_pool.exists(GenTxid::Txid(tx->GetHash()));
        bool wtxid_in_mempool = tx_pool.exists(GenTxid::Wtxid(tx->GetWitnessHash()));
        CheckATMPInvariants(res, txid_in_mempool, wtxid_in_mempool);

        Assert(accepted != added.empty());
        if (accepted) {
            Assert(added.size() == 1); // For now, no package acceptance
            Assert(tx == *added.begin());
            CheckMempoolTRUCInvariants(tx_pool);
        } else {
            // Do not consider rejected transaction removed
            removed.erase(tx);
        }

        // Helper to insert spent and created outpoints of a tx into collections
        using Sets = std::vector<std::reference_wrapper<std::set<COutPoint>>>;
        const auto insert_tx = [](Sets created_by_tx, Sets consumed_by_tx, const auto& tx) {
            for (size_t i{0}; i < tx.vout.size(); ++i) {
                for (auto& set : created_by_tx) {
                    Assert(set.get().emplace(tx.GetHash(), i).second);
                }
            }
            for (const auto& in : tx.vin) {
                for (auto& set : consumed_by_tx) {
                    Assert(set.get().insert(in.prevout).second);
                }
            }
        };
        // Add created outpoints, remove spent outpoints
        {
            // Outpoints that no longer exist at all
            std::set<COutPoint> consumed_erased;
            // Outpoints that no longer count toward the total supply
            std::set<COutPoint> consumed_supply;
            for (const auto& removed_tx : removed) {
                insert_tx(/*created_by_tx=*/{consumed_erased}, /*consumed_by_tx=*/{outpoints_supply}, /*tx=*/*removed_tx);
            }
            for (const auto& added_tx : added) {
                insert_tx(/*created_by_tx=*/{outpoints_supply, outpoints_rbf}, /*consumed_by_tx=*/{consumed_supply}, /*tx=*/*added_tx);
            }
            for (const auto& p : consumed_erased) {
                Assert(outpoints_supply.erase(p) == 1);
                Assert(outpoints_rbf.erase(p) == 1);
            }
            for (const auto& p : consumed_supply) {
                Assert(outpoints_supply.erase(p) == 1);
            }
        }
    }
    Finish(el.finish(), tx_pool, chainstate);
}

FUZZ_PROTO_TARGET(tx_pool, const tx_pool_fuzz::Target_tx_pool& el, .init = initialize_tx_pool) {

    SeedRandomStateForTest(SeedRand::ZEROS);
    const auto& node = g_setup->m_node;
    auto& chainstate{static_cast<DummyChainState&>(node.chainman->ActiveChainstate())};

    MockTime(el.time(), chainstate);

    std::vector<Txid> txids;
    txids.reserve(g_outpoints_coinbase_init_mature.size());
    for (const auto& outpoint : g_outpoints_coinbase_init_mature) {
        txids.push_back(outpoint.hash);
    }
    for (int i{0}; i <= 3; ++i) {
        // Add some immature and non-existent outpoints
        txids.push_back(g_outpoints_coinbase_init_immature.at(i).hash);
        if (el.non_existent_outpoints_size() > i) {
            txids.push_back(Txid::FromUint256(ConsumeUInt256(el.non_existent_outpoints(i))));
        } else {
            txids.push_back(Txid::FromUint256(uint256(i)));
        }
    }

    SetMempoolConstraints(*node.args, el.memconstraints());
    auto tx_pool_{MakeMempool(el.mempool_require_standard(), node)};
    MockedTxPool& tx_pool = *static_cast<MockedTxPool*>(tx_pool_.get());

    chainstate.SetMempool(&tx_pool);

    for (unsigned i = 0; i < std::min<unsigned>(el.elements_size(), 300); i++) {
        const auto& currentElement = el.elements(i);

        const auto mut_tx = ConsumeComplexeTransaction(currentElement.tx(), txids);

        if (currentElement.has_time()) {
            MockTime(currentElement.time(), chainstate);
        }
        if (currentElement.rollingfeeupdate()) {
            tx_pool.RollingFeeUpdate();
        }
        if (currentElement.has_priotx()) {
            const auto txid = currentElement.priotx().has_priotxindex() ?
                                   PickValue(currentElement.priotx().priotxindex(), txids) :
                                   mut_tx.GetHash();
            const auto delta = ConsumeIntegralInRange<CAmount>(currentElement.priotx().delta(), -50 * COIN, +50 * COIN);
            tx_pool.PrioritiseTransaction(txid.ToUint256(), delta);
        }

        const auto tx = MakeTransactionRef(mut_tx);
        const bool bypass_limits = currentElement.bypass_limits();
        const auto res = WITH_LOCK(::cs_main, return AcceptToMemoryPool(chainstate, tx, GetTime(), bypass_limits, /*test_accept=*/false));
        const bool accepted = res.m_result_type == MempoolAcceptResult::ResultType::VALID;
        if (accepted) {
            txids.push_back(tx->GetHash());
            CheckMempoolTRUCInvariants(tx_pool);
        }
    }
    Finish(el.finish(), tx_pool, chainstate);
}
} // namespace
