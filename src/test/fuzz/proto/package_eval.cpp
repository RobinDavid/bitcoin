// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <node/context.h>
#include <node/mempool_args.h>
#include <node/miner.h>
#include <policy/truc_policy.h>
#include <test/fuzz/proto/package_eval.pb.h>
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

namespace {

const TestingSetup* g_setup;
std::vector<COutPoint> g_outpoints_coinbase_init_mature;

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
    options.coinbase_output_script = P2WSH_EMPTY;

    for (int i = 0; i < 2 * COINBASE_MATURITY; ++i) {
        COutPoint prevout{MineBlock(g_setup->m_node, options)};
        if (i < COINBASE_MATURITY) {
            // Remember the txids to avoid expensive disk access later on
            g_outpoints_coinbase_init_mature.push_back(prevout);
        }
    }
    g_setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

struct OutpointsUpdater final : public CValidationInterface {
    std::set<COutPoint>& m_mempool_outpoints;

    explicit OutpointsUpdater(std::set<COutPoint>& r)
        : m_mempool_outpoints{r} {}

    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t /* mempool_sequence */) override
    {
        // for coins spent we always want to be able to rbf so they're not removed

        // outputs from this tx can now be spent
        for (uint32_t index{0}; index < tx.info.m_tx->vout.size(); ++index) {
            m_mempool_outpoints.insert(COutPoint{tx.info.m_tx->GetHash(), index});
        }
    }

    void TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t /* mempool_sequence */) override
    {
        // outpoints spent by this tx are now available
        for (const auto& input : tx->vin) {
            // Could already exist if this was a replacement
            m_mempool_outpoints.insert(input.prevout);
        }
        // outpoints created by this tx no longer exist
        for (uint32_t index{0}; index < tx->vout.size(); ++index) {
            m_mempool_outpoints.erase(COutPoint{tx->GetHash(), index});
        }
    }
};

struct TransactionsDelta final : public CValidationInterface {
    std::set<CTransactionRef>& m_added;

    explicit TransactionsDelta(std::set<CTransactionRef>& a)
        : m_added{a} {}

    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t /* mempool_sequence */) override
    {
        // Transactions may be entered and booted any number of times
        m_added.insert(tx.info.m_tx);
    }

    void TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t /* mempool_sequence */) override
    {
        // Transactions may be entered and booted any number of times
         m_added.erase(tx);
    }
};

void MockTime(int64_t v, const Chainstate& chainstate)
{
    const auto time = ConsumeTime(v,
                                  chainstate.m_chain.Tip()->GetMedianTimePast() + 1,
                                  std::numeric_limits<decltype(chainstate.m_chain.Tip()->nTime)>::max());
    SetMockTime(time);
}

std::unique_ptr<CTxMemPool> MakeMempool(const package_eval_fuzz::MakeMempoolOpts& opts, const NodeContext& node)
{
    // Take the default options for tests...
    CTxMemPool::Options mempool_opts{MemPoolOptionsForTest(node)};


    // ...override specific options for this specific fuzz suite
    mempool_opts.limits.ancestor_count = ConsumeIntegralInRange<unsigned>(opts.ancestor_count(), 0, 50);
    mempool_opts.limits.ancestor_size_vbytes = ConsumeIntegralInRange<unsigned>(opts.ancestor_size_vbytes(), 0, 202) * 1'000;
    mempool_opts.limits.descendant_count = ConsumeIntegralInRange<unsigned>(opts.descendant_count(), 0, 50);
    mempool_opts.limits.descendant_size_vbytes = ConsumeIntegralInRange<unsigned>(opts.descendant_size_vbytes(), 0, 202) * 1'000;
    mempool_opts.max_size_bytes = ConsumeIntegralInRange<unsigned>(opts.max_size_bytes(), 0, 200) * 1'000'000;
    mempool_opts.expiry = std::chrono::hours{ConsumeIntegralInRange<unsigned>(opts.expiry(), 0, 999)};
    // Only interested in 2 cases: sigop cost 0 or when single legacy sigop cost is >> 1KvB
    nBytesPerSigOp = ConsumeIntegralInRange<unsigned>(opts.nbytespersigop(), 0, 1) * 10'000;

    mempool_opts.check_ratio = 1;
    mempool_opts.require_standard = opts.require_standard();

    bilingual_str error;
    // ...and construct a CTxMemPool from it
    auto mempool{std::make_unique<CTxMemPool>(std::move(mempool_opts), error)};
    // ... ignore the error since it might be beneficial to fuzz even when the
    // mempool size is unreasonably small
    Assert(error.empty() || error.original.starts_with("-maxmempool must be at least "));
    return mempool;
}

std::unique_ptr<CTxMemPool> MakeEphemeralMempool(const NodeContext& node)
{
    // Take the default options for tests...
    CTxMemPool::Options mempool_opts{MemPoolOptionsForTest(node)};

    mempool_opts.check_ratio = 1;

    // Require standardness rules otherwise ephemeral dust is no-op
    mempool_opts.require_standard = true;

    // And set minrelay to 0 to allow ephemeral parent tx even with non-TRUC
    mempool_opts.min_relay_feerate = CFeeRate(0);

    bilingual_str error;
    // ...and construct a CTxMemPool from it
    auto mempool{std::make_unique<CTxMemPool>(std::move(mempool_opts), error)};
    Assert(error.empty());
    return mempool;
}

// Scan mempool for a tx that has spent dust and return a
// prevout of the child that isn't the dusty parent itself.
// This is used to double-spend the child out of the mempool,
// leaving the parent childless.
// This assumes CheckMempoolEphemeralInvariants has passed for tx_pool.
std::optional<COutPoint> GetChildEvictingPrevout(const CTxMemPool& tx_pool)
{
    LOCK(tx_pool.cs);
    for (const auto& tx_info : tx_pool.infoAll()) {
        const auto& entry = *Assert(tx_pool.GetEntry(tx_info.tx->GetHash()));
        std::vector<uint32_t> dust_indexes{GetDust(*tx_info.tx, tx_pool.m_opts.dust_relay_feerate)};
        if (!dust_indexes.empty()) {
            const auto& children = entry.GetMemPoolChildrenConst();
            if (!children.empty()) {
                Assert(children.size() == 1);
                // Find an input that doesn't spend from parent's txid
                const auto& only_child = children.begin()->get().GetTx();
                for (const auto& tx_input : only_child.vin) {
                    if (tx_input.prevout.hash != tx_info.tx->GetHash()) {
                        return tx_input.prevout;
                    }
                }
            }
        }
    }

    return std::nullopt;
}

FUZZ_PROTO_TARGET(ephemeral_package_eval, const package_eval_fuzz::Target_ephemeral_package_eval& el, .init = initialize_tx_pool) {

    SeedRandomStateForTest(SeedRand::ZEROS);
    const auto& node = g_setup->m_node;
    auto& chainstate{static_cast<DummyChainState&>(node.chainman->ActiveChainstate())};

    MockTime(el.time(), chainstate);

    // All RBF-spendable outpoints outside of the unsubmitted package
    std::set<COutPoint> mempool_outpoints;
    std::unordered_map<COutPoint, CAmount, SaltedOutpointHasher> outpoints_value;
    for (const auto& outpoint : g_outpoints_coinbase_init_mature) {
        Assert(mempool_outpoints.insert(outpoint).second);
        outpoints_value[outpoint] = 50 * COIN;
    }

    auto outpoints_updater = std::make_shared<OutpointsUpdater>(mempool_outpoints);
    node.validation_signals->RegisterSharedValidationInterface(outpoints_updater);

    auto tx_pool_{MakeEphemeralMempool(node)};
    MockedTxPool& tx_pool = *static_cast<MockedTxPool*>(tx_pool_.get());

    chainstate.SetMempool(&tx_pool);

    for (unsigned i = 0; i < std::min<unsigned>(el.elements_size(), 300); i++) {
        const auto& currentElement = el.elements(i);

        Assert(!mempool_outpoints.empty());

        std::vector<CTransactionRef> txs;

        // Find something we may want to double-spend with two input single tx
        std::optional<COutPoint> outpoint_to_rbf{currentElement.outpointfromprev() ? GetChildEvictingPrevout(tx_pool) : std::nullopt};

        // Make small packages
        const unsigned num_txs = 1 + (outpoint_to_rbf ? 0 : std::min(currentElement.nextoutpoint_size(), 3));

        std::set<COutPoint> package_outpoints;
        while (txs.size() < num_txs) {
            const auto& txData = ((txs.size() == 0) ? currentElement.firstoutpoint() : currentElement.nextoutpoint(txs.size() - 1));
            // Create transaction to add to the mempool
            txs.emplace_back([&] {
                CMutableTransaction tx_mut;
                tx_mut.version = CTransaction::CURRENT_VERSION;
                tx_mut.nLockTime = 0;
                // Last transaction in a package needs to be a child of parents to get further in validation
                // so the last transaction to be generated(in a >1 package) must spend all package-made outputs
                // Note that this test currently only spends package outputs in last transaction.
                bool last_tx = num_txs > 1 && txs.size() == num_txs - 1;
                const auto num_in = outpoint_to_rbf ? 2 :
                    last_tx ? ConsumeIntegralInRange<int>(txData.num_inputs(), package_outpoints.size()/2 + 1, package_outpoints.size()) :
                    ConsumeIntegralInRange<int>(txData.num_inputs(), 1, 4);
                const auto num_out = outpoint_to_rbf ? 1 : ConsumeIntegralInRange<int>(txData.num_outputs(), 1, 4);

                auto& outpoints = last_tx ? package_outpoints : mempool_outpoints;

                //Assert((int)outpoints.size() >= num_in && num_in > 0);

                CAmount amount_in{0};
                for (int j = 0; j < num_in; ++j) {
                    // Pop random outpoint. We erase them to avoid double-spending
                    // while in this loop, but later add them back (unless last_tx).
                    auto pop = outpoints.begin();
                    std::advance(pop, ((txData.inputoffsets_size() <= j) ? 0 :
                          ConsumeIntegralInRange<size_t>(txData.inputoffsets(j), 0, outpoints.size() - 1)));
                    auto outpoint = *pop;

                    if (j == 0 && outpoint_to_rbf) {
                        outpoint = *outpoint_to_rbf;
                        outpoints.erase(outpoint);
                    } else {
                        outpoints.erase(pop);
                    }
                    // no need to update or erase from outpoints_value
                    amount_in += outpoints_value.at(outpoint);

                    // Create input
                    CTxIn in;
                    in.prevout = outpoint;
                    in.scriptWitness.stack = P2WSH_EMPTY_TRUE_STACK;

                    tx_mut.vin.push_back(in);
                }

                const auto amount_fee = ConsumeIntegralInRange<CAmount>(txData.amount_fee(), 0, amount_in);
                const auto amount_out = (amount_in - amount_fee) / num_out;
                for (int j = 0; j < num_out; ++j) {
                    tx_mut.vout.emplace_back(amount_out, P2WSH_EMPTY);
                }

                // Note output amounts can naturally drop to dust on their own.
                if (!outpoint_to_rbf && txData.has_dust_index()) {
                    uint32_t dust_index = ConsumeIntegralInRange<uint32_t>(txData.dust_index(), 0, num_out);
                    tx_mut.vout.insert(tx_mut.vout.begin() + dust_index, CTxOut(0, P2WSH_EMPTY));
                }

                auto tx = MakeTransactionRef(tx_mut);
                // Restore previously removed outpoints, except in-package outpoints (to allow RBF)
                if (!last_tx) {
                    for (const auto& in : tx->vin) {
                        Assert(outpoints.insert(in.prevout).second);
                    }
                    // Cache the in-package outpoints being made
                    for (size_t j = 0; j < tx->vout.size(); ++j) {
                        package_outpoints.emplace(tx->GetHash(), j);
                    }
                }
                // We need newly-created values for the duration of this run
                for (size_t j = 0; j < tx->vout.size(); ++j) {
                    outpoints_value[COutPoint(tx->GetHash(), j)] = tx->vout[j].nValue;
                }
                return tx;
            }());
        }

        if (currentElement.has_prioritytx()) {
            const auto& txid = currentElement.prioritytx().has_txindex() ?
                                   PickValue(currentElement.prioritytx().txindex(), mempool_outpoints).hash :
                                   txs.back()->GetHash();
            const auto delta = ConsumeIntegralInRange<CAmount>(currentElement.prioritytx().delta(), -50 * COIN, +50 * COIN);
            // We only prioritise out of mempool transactions since PrioritiseTransaction doesn't
            // filter for ephemeral dust
            if (tx_pool.exists(GenTxid::Txid(txid))) {
                const auto tx_info{tx_pool.info(GenTxid::Txid(txid))};
                if (GetDust(*tx_info.tx, tx_pool.m_opts.dust_relay_feerate).empty()) {
                    tx_pool.PrioritiseTransaction(txid.ToUint256(), delta);
                }
            }
        }

        auto single_submit = txs.size() == 1;

        const auto result_package = WITH_LOCK(::cs_main,
                                    return ProcessNewPackage(chainstate, tx_pool, txs, /*test_accept=*/single_submit, /*client_maxfeerate=*/{}));

        const auto res = WITH_LOCK(::cs_main, return AcceptToMemoryPool(chainstate, txs.back(), GetTime(),
                                   /*bypass_limits=*/currentElement.bypass_limits(), /*test_accept=*/!single_submit));

        if (!single_submit && result_package.m_state.GetResult() != PackageValidationResult::PCKG_POLICY) {
            // We don't know anything about the validity since transactions were randomly generated, so
            // just use result_package.m_state here. This makes the expect_valid check meaningless, but
            // we can still verify that the contents of m_tx_results are consistent with m_state.
            const bool expect_valid{result_package.m_state.IsValid()};
            Assert(!CheckPackageMempoolAcceptResult(txs, result_package, expect_valid, &tx_pool));
        }

        node.validation_signals->SyncWithValidationInterfaceQueue();

        CheckMempoolEphemeralInvariants(tx_pool);
    }

    node.validation_signals->UnregisterSharedValidationInterface(outpoints_updater);

    WITH_LOCK(::cs_main, tx_pool.check(chainstate.CoinsTip(), chainstate.m_chain.Height() + 1));
}


FUZZ_PROTO_TARGET(tx_package_eval, const package_eval_fuzz::Target_tx_package_eval& el, .init = initialize_tx_pool) {
    SeedRandomStateForTest(SeedRand::ZEROS);
    const auto& node = g_setup->m_node;
    auto& chainstate{static_cast<DummyChainState&>(node.chainman->ActiveChainstate())};

    MockTime(el.time(), chainstate);

    // All RBF-spendable outpoints outside of the unsubmitted package
    std::set<COutPoint> mempool_outpoints;
    std::unordered_map<COutPoint, CAmount, SaltedOutpointHasher> outpoints_value;
    for (const auto& outpoint : g_outpoints_coinbase_init_mature) {
        Assert(mempool_outpoints.insert(outpoint).second);
        outpoints_value[outpoint] = 50 * COIN;
    }

    auto outpoints_updater = std::make_shared<OutpointsUpdater>(mempool_outpoints);
    node.validation_signals->RegisterSharedValidationInterface(outpoints_updater);

    auto tx_pool_{MakeMempool(el.memopts(), node)};
    MockedTxPool& tx_pool = *static_cast<MockedTxPool*>(tx_pool_.get());

    chainstate.SetMempool(&tx_pool);

    for (unsigned i = 0; i < std::min<unsigned>(el.elements_size(), 300); i++) {
        const auto& currentElement = el.elements(i);
        Assert(!mempool_outpoints.empty());

        std::vector<CTransactionRef> txs;

        // Make packages of 1-to-26 transactions
        const unsigned num_txs = 1 + std::min(currentElement.nextoutpoint_size(), 25);
        std::set<COutPoint> package_outpoints;
        while (txs.size() < num_txs) {
            const auto& txData = ((txs.size() == 0) ? currentElement.firstoutpoint() : currentElement.nextoutpoint(txs.size() - 1));
            // Create transaction to add to the mempool
            txs.emplace_back([&] {
                CMutableTransaction tx_mut;
                tx_mut.version = txData.trucversion() ? TRUC_VERSION : CTransaction::CURRENT_VERSION;
                tx_mut.nLockTime = txData.has_nlocktime() ? txData.nlocktime() : 0;
                // Last transaction in a package needs to be a child of parents to get further in validation
                // so the last transaction to be generated(in a >1 package) must spend all package-made outputs
                // Note that this test currently only spends package outputs in last transaction.
                bool last_tx = num_txs > 1 && txs.size() == num_txs - 1;
                const int num_in = last_tx ? package_outpoints.size() : ConsumeIntegralInRange<int>(txData.num_inputs(), 1, mempool_outpoints.size());
                int num_out = ConsumeIntegralInRange<int>(txData.num_outputs(), 1, mempool_outpoints.size() * 2);

                auto& outpoints = last_tx ? package_outpoints : mempool_outpoints;

                Assert(!outpoints.empty());

                CAmount amount_in{0};
                for (int j = 0; j < num_in; ++j) {
                    package_eval_fuzz::Target_tx_package_eval_Element_TransactionData_InputData inputData;
                    if (txData.inputdatas_size() <= j) {
                        inputData.set_offset(0);
                        inputData.mutable_sequence()->set_limited(j);
                        inputData.set_script_wit_stack(j & 1);
                    } else {
                        inputData = txData.inputdatas(j);
                    }
                    // Pop random outpoint. We erase them to avoid double-spending
                    // while in this loop, but later add them back (unless last_tx).
                    auto pop = outpoints.begin();
                    std::advance(pop, ConsumeIntegralInRange<size_t>(inputData.offset(), 0, outpoints.size() - 1));
                    const auto outpoint = *pop;
                    outpoints.erase(pop);
                    // no need to update or erase from outpoints_value
                    amount_in += outpoints_value.at(outpoint);

                    // Create input
                    const auto sequence = ConsumeSequence(inputData.sequence());
                    const auto script_sig = CScript{};
                    const auto script_wit_stack = inputData.script_wit_stack() ? P2WSH_EMPTY_TRUE_STACK : P2WSH_EMPTY_TWO_STACK;

                    CTxIn in;
                    in.prevout = outpoint;
                    in.nSequence = sequence;
                    in.scriptSig = script_sig;
                    in.scriptWitness.stack = script_wit_stack;

                    tx_mut.vin.push_back(in);
                }

                // Duplicate an input
                bool dup_input = txData.dup_input();
                if (dup_input) {
                    tx_mut.vin.push_back(tx_mut.vin.back());
                }

                // Refer to a non-existent input
                if (txData.invalid_input()) {
                    tx_mut.vin.emplace_back();
                }

                // Make a p2pk output to make sigops adjusted vsize to violate TRUC rules, potentially, which is never spent
                if (last_tx && amount_in > 1000 && txData.invalid_p2pk_output()) {
                    tx_mut.vout.emplace_back(1000, CScript() << std::vector<unsigned char>(33, 0x02) << OP_CHECKSIG);
                    // Don't add any other outputs.
                    num_out = 1;
                    amount_in -= 1000;
                }

                const auto amount_fee = ConsumeIntegralInRange<CAmount>(txData.amount_fee(), 0, amount_in);
                const auto amount_out = (amount_in - amount_fee) / num_out;
                for (int j = 0; j < num_out; ++j) {
                    tx_mut.vout.emplace_back(amount_out, P2WSH_EMPTY);
                }
                auto tx = MakeTransactionRef(tx_mut);
                // Restore previously removed outpoints, except in-package outpoints
                if (!last_tx) {
                    for (const auto& in : tx->vin) {
                        // It's a fake input, or a new input, or a duplicate
                        Assert(in == CTxIn() || outpoints.insert(in.prevout).second || dup_input);
                    }
                    // Cache the in-package outpoints being made
                    for (size_t j = 0; j < tx->vout.size(); ++j) {
                        package_outpoints.emplace(tx->GetHash(), j);
                    }
                }
                // We need newly-created values for the duration of this run
                for (size_t j = 0; j < tx->vout.size(); ++j) {
                    outpoints_value[COutPoint(tx->GetHash(), j)] = tx->vout[j].nValue;
                }
                return tx;
            }());
        }

        if (currentElement.has_time()) {
            MockTime(currentElement.time(), chainstate);
        }
        if (currentElement.rollingfeeupdate()) {
            tx_pool.RollingFeeUpdate();
        }
        if (currentElement.has_prioritytx()) {
            const auto& txid = currentElement.prioritytx().has_txindex() ?
                                   PickValue(currentElement.prioritytx().txindex(), mempool_outpoints).hash :
                                   txs.back()->GetHash();
            const auto delta = ConsumeIntegralInRange<CAmount>(currentElement.prioritytx().delta(), -50 * COIN, +50 * COIN);
            tx_pool.PrioritiseTransaction(txid.ToUint256(), delta);
        }

        // Remember all added transactions
        std::set<CTransactionRef> added;
        auto txr = std::make_shared<TransactionsDelta>(added);
        node.validation_signals->RegisterSharedValidationInterface(txr);

        // When there are multiple transactions in the package, we call ProcessNewPackage(txs, test_accept=false)
        // and AcceptToMemoryPool(txs.back(), test_accept=true). When there is only 1 transaction, we might flip it
        // (the package is a test accept and ATMP is a submission).
        auto single_submit = txs.size() == 1 && currentElement.single_submit();

        // Exercise client_maxfeerate logic
        std::optional<CFeeRate> client_maxfeerate{};
        if (currentElement.has_client_maxfeerate()) {
            client_maxfeerate = CFeeRate(ConsumeIntegralInRange<CAmount>(currentElement.client_maxfeerate(), -1, 50 * COIN), 100);
        }

        const auto result_package = WITH_LOCK(::cs_main,
                                    return ProcessNewPackage(chainstate, tx_pool, txs, /*test_accept=*/single_submit, client_maxfeerate));

        // Always set bypass_limits to false because it is not supported in ProcessNewPackage and
        // can be a source of divergence.
        const auto res = WITH_LOCK(::cs_main, return AcceptToMemoryPool(chainstate, txs.back(), GetTime(),
                                   /*bypass_limits=*/false, /*test_accept=*/!single_submit));
        const bool passed = res.m_result_type == MempoolAcceptResult::ResultType::VALID;

        node.validation_signals->SyncWithValidationInterfaceQueue();
        node.validation_signals->UnregisterSharedValidationInterface(txr);

        // There is only 1 transaction in the package. We did a test-package-accept and a ATMP
        if (single_submit) {
            Assert(passed != added.empty());
            Assert(passed == res.m_state.IsValid());
            if (passed) {
                Assert(added.size() == 1);
                Assert(txs.back() == *added.begin());
            }
        } else if (result_package.m_state.GetResult() != PackageValidationResult::PCKG_POLICY) {
            // We don't know anything about the validity since transactions were randomly generated, so
            // just use result_package.m_state here. This makes the expect_valid check meaningless, but
            // we can still verify that the contents of m_tx_results are consistent with m_state.
            const bool expect_valid{result_package.m_state.IsValid()};
            Assert(!CheckPackageMempoolAcceptResult(txs, result_package, expect_valid, &tx_pool));
        } else {
            // This is empty if it fails early checks, or "full" if transactions are looked at deeper
            Assert(result_package.m_tx_results.size() == txs.size() || result_package.m_tx_results.empty());
        }

        CheckMempoolTRUCInvariants(tx_pool);

        // Dust checks only make sense when dust is enforced
        if (tx_pool.m_opts.require_standard) {
            CheckMempoolEphemeralInvariants(tx_pool);
        }
    }

    node.validation_signals->UnregisterSharedValidationInterface(outpoints_updater);

    WITH_LOCK(::cs_main, tx_pool.check(chainstate.CoinsTip(), chainstate.m_chain.Height() + 1));
}
} // namespace
