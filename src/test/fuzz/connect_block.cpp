// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
//#include <chainparams.h>
#include <consensus/merkle.h>
//#include <consensus/validation.h>
//#include <core_io.h>
//#include <core_memusage.h>
//#include <primitives/block.h>
#include <kernel/disconnected_transactions.h>
#include <node/kernel_notifications.h>
#include <pow.h>
//#include <pubkey.h>
//#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
//#include <util/chaintype.h>
#include <validation.h>

#include <cassert>
#include <string>

namespace {

TestingSetup* g_setup{nullptr};
static std::vector<std::shared_ptr<CBlock>> listBlocks;
static std::set<uint256> existingBlockHash;
// all UTXO (excluding OP_RETURN) (including not mature CoinBase and already
//                                 spend one)
static std::vector<CTxIn> allUTXO;

static const CScript P2SH_OP_TRUE = CScript() << OP_HASH160 << ToByteVector(ScriptHash(CScript() << OP_TRUE)) << OP_EQUAL;
static const CScript P2SH_OP_TRUE_UNLOCK = CScript() << MakeUCharSpan(CScript() << OP_TRUE);
static CScript TAPROOT_OP_TRUE;
static std::vector<std::vector<uint8_t>> TAPROOT_OP_TRUE_WITNESS;

static void init_taproot_script() {
    uint256 merkleTreeHash = ComputeTapleafHash(0xc0, MakeUCharSpan(CScript() << OP_TRUE));
    uint256 internalKey {std::vector<uint8_t>(32, 1)};
    auto res = XOnlyPubKey(internalKey).CreateTapTweak(&merkleTreeHash);
    Assert(res.has_value());
    auto control = ToByteVector(internalKey);
    control.insert(control.begin(), 0xc0 | (res->second?1:0));

    TAPROOT_OP_TRUE = CScript() << OP_1 << ToByteVector(res->first);
    TAPROOT_OP_TRUE_WITNESS.clear();
    TAPROOT_OP_TRUE_WITNESS.emplace_back(ToByteVector(CScript() << OP_TRUE));
    TAPROOT_OP_TRUE_WITNESS.emplace_back(std::move(control));
}

#if 0
#define DEBUGOUTPUT(x) (x);
#else
#define DEBUGOUTPUT(x)
#endif

[[maybe_unused]] static void printBlock(const CBlock& block) {
    DEBUGOUTPUT(std::cout << block.ToString() << std::endl);
}

static CTxIn getResolvUTXO(const CTransaction& tx, unsigned voutIndex) {
    Assert(voutIndex < tx.vout.size());
    const CTxOut& output = tx.vout[voutIndex];

    CTxIn res {COutPoint(tx.GetHash(), voutIndex)};
    if (output.scriptPubKey.size() >= 1 && output.scriptPubKey[0] == OP_RETURN)
        return res;

    if (output.scriptPubKey == P2WSH_OP_TRUE) {
        res.scriptSig = CScript();
        res.scriptWitness.stack.push_back(WITNESS_STACK_ELEM_OP_TRUE);
    } else if (output.scriptPubKey == P2SH_OP_TRUE) {
        res.scriptSig = P2SH_OP_TRUE_UNLOCK;
    } else if (output.scriptPubKey == CScript()) {
        res.scriptSig = CScript() << OP_TRUE;
    } else if (output.scriptPubKey == TAPROOT_OP_TRUE) {
        res.scriptSig = CScript();
        res.scriptWitness.stack = TAPROOT_OP_TRUE_WITNESS;
    }

    return res;
}

static void loadCurrentChain() {
    listBlocks.clear();
    existingBlockHash.clear();

    {
        LOCK(::cs_main);
        auto& CState = Assert(g_setup->m_node.chainman)->ActiveChainstate();
        Assert(CState.GetMempool());
        Assert(CState.HasCoinsViews());

        auto currentBlock = CState.m_chain.Tip();

        while (currentBlock != nullptr) {
            Assert(currentBlock->nHeight >= 0);
            if (listBlocks.size() <= (size_t) currentBlock->nHeight) {
                listBlocks.resize(currentBlock->nHeight + 1);
            }
            listBlocks[currentBlock->nHeight] = std::make_shared<CBlock>();
            Assert(CState.m_blockman.ReadBlock(*listBlocks[currentBlock->nHeight], *currentBlock));
            existingBlockHash.insert(listBlocks[currentBlock->nHeight]->GetHash());
            if constexpr (0) {
                printBlock(*listBlocks[currentBlock->nHeight]);
            }
            currentBlock = currentBlock->pprev;
        }
        if constexpr (0) {
            DEBUGOUTPUT(std::cout << "CoinsDB output : " << CState.CoinsDB().StoragePath() << std::endl);
        }
    }
    allUTXO.clear();

    for (const auto& b : listBlocks) {
        for (const auto& tx: b->vtx) {
            for (unsigned voutIndex = 0; voutIndex < tx->vout.size(); voutIndex++) {
                auto& vout = tx->vout[voutIndex];
                if (vout.scriptPubKey.size() >= 1 && vout.scriptPubKey[0] == OP_RETURN) continue;
                allUTXO.emplace_back(getResolvUTXO(*tx, voutIndex));
            }
        }
    }
}

static void initialize_connect_block() {
    fsbridge::setEnableMemFS(true);

    // Create btc structure
    static auto testing_setup = MakeNoLogFileContext<TestingSetup>(
    //static auto testing_setup = std::make_shared<TestingSetup>(
            /*chain_type=*/ChainType::REGTEST, TestOpts{
                .extra_args = {
                    "-minrelaytxfee=0",
                    "-acceptnonstdtxn",
                    // "-debuglogfile=/tmp/debug.log",
                },
            });
    g_setup = testing_setup.get();
    //g_setup->m_node.notifications->m_shutdown_on_fatal_error = false;
    init_taproot_script();

    node::BlockAssembler::Options options;
    options.coinbase_output_script = P2WSH_OP_TRUE;

    // Generate the first 200 block (100 last are not mature, so not spendable)
    for (int i = 0; i < 2 * COINBASE_MATURITY; ++i) {
        MineBlock(g_setup->m_node, options);
    }
    loadCurrentChain();

    // Prepare transaction for the 201 blocks. This blocks will includes
    // transaction from the first block coinbase tx.
    Assert(Assert(Assert(g_setup->m_node.chainman)->ActiveChainstate().GetMempool())->size() == 0);
    for (unsigned i = 1; i < 11; i++) {
        CMutableTransaction ctx;
        ctx.version = CTransaction::CURRENT_VERSION;
        ctx.vin.resize(1);
        ctx.vin[0] = allUTXO[i];
        ctx.vout.resize(4);
        // P2WSH
        ctx.vout[0].nValue = CAmount(15 * COIN);
        ctx.vout[0].scriptPubKey = P2WSH_OP_TRUE;
        // P2SH
        ctx.vout[1].nValue = CAmount(15 * COIN);
        ctx.vout[1].scriptPubKey = P2SH_OP_TRUE;
        // TAPSCRIPT
        ctx.vout[2].nValue = CAmount(10 * COIN);
        ctx.vout[2].scriptPubKey = TAPROOT_OP_TRUE;
        // NoScript
        ctx.vout[3].nValue = CAmount(10 * COIN);
        ctx.vout[3].scriptPubKey = CScript();

        //DEBUGOUTPUT(std::cout << MakeTransactionRef(ctx)->ToString() << std::endl);

        LOCK(::cs_main);
        // Add transaction in the mempool
        const MempoolAcceptResult ctx_result = g_setup->m_node.chainman->ProcessTransaction(MakeTransactionRef(ctx));
        if (ctx_result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
            DEBUGOUTPUT(std::cout << "Transaction rejected : " << ctx_result.m_state.GetRejectReason() << std::endl);
        }
        Assert(ctx_result.m_result_type == MempoolAcceptResult::ResultType::VALID);

        Assert(g_setup->m_node.chainman->ActiveChainstate().GetMempool()->size() == i);
        // Force the mempool to select this transaction (even if fees == 0)
        g_setup->m_node.chainman->ActiveChainstate().GetMempool()->PrioritiseTransaction(ctx.GetHash(), COIN);
    }

    MineBlock(g_setup->m_node, options);
    Assert(g_setup->m_node.chainman->ActiveChainstate().GetMempool()->size() == 0);

    loadCurrentChain();
    //printBlock(*listBlocks.back());

    if constexpr(0) {
        // Debug only, try to create the block 202 with tx that use the UTXO of
        // block 201
        for (unsigned i = 1; i < 11; i++) {
            CMutableTransaction ctx;
            ctx.version = CTransaction::CURRENT_VERSION;
            ctx.vin.resize(1);
            ctx.vin[0] = allUTXO[allUTXO.size() - i];
            ctx.vout.resize(1);
            // P2WSH
            ctx.vout[0].nValue = CAmount(10 * COIN);
            ctx.vout[0].scriptPubKey = P2WSH_OP_TRUE;

            // DEBUGOUTPUT(std::cout << MakeTransactionRef(ctx)->ToString() << std::endl);

            LOCK(::cs_main);
            const MempoolAcceptResult ctx_result = g_setup->m_node.chainman->ProcessTransaction(MakeTransactionRef(ctx));
            if (ctx_result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
                DEBUGOUTPUT(std::cout << "Transaction2 rejected : " << ctx_result.m_state.GetRejectReason() << std::endl);

            }
            Assert(ctx_result.m_result_type == MempoolAcceptResult::ResultType::VALID);
            Assert(g_setup->m_node.chainman->ActiveChainstate().GetMempool()->size() == i);
            g_setup->m_node.chainman->ActiveChainstate().GetMempool()->PrioritiseTransaction(ctx.GetHash(), COIN);
        }

        MineBlock(g_setup->m_node, options);
        loadCurrentChain();
        printBlock(*listBlocks.back());
    }

    g_setup->m_node.chainman->ActiveChainstate().ForceFlushStateToDisk();
    //Assert(fsbridge::createSnapshotMemFS());

    /*
    Initialiser chain avec:
    * des blocks "mature" (qui peuvent être dépensé)
    * s'assurer que la "active"

    * Ajouter des transactions:
        * SEGWIT / TAPROOT
        * qui requiert une clée privée

    [* Hardcoded les clés publics pour dépenser les coins]

    */
}

CTransactionRef ConsumeTransaction(FuzzedDataProvider& fuzzed_data_provider,
                                   std::vector<CTxIn>& additionnalUTXO, bool coinbase=false) {

    CMutableTransaction tx;
    if (coinbase) {
        tx.vin.resize(1);
        tx.vin[0].prevout.SetNull();
        tx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL; // Make sure timelock is enforced.
        auto scriptSig = ConsumeRandomLengthByteVector<unsigned char>(fuzzed_data_provider, 100);
        tx.vin[0].scriptSig = CScript(scriptSig.begin(), scriptSig.end());
    } else {
        int numInput = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 10);
        tx.vin.resize(numInput);
        for (int i = 0; i < numInput; i++) {
            uint32_t targetUTXO = fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(0, allUTXO.size() + additionnalUTXO.size() - 1);
            if (targetUTXO < allUTXO.size()) {
                tx.vin[i] = allUTXO[targetUTXO];
            } else {
                Assert(targetUTXO - allUTXO.size() < additionnalUTXO.size());
                tx.vin[i] = additionnalUTXO[targetUTXO - allUTXO.size()];
            }
            if (fuzzed_data_provider.ConsumeBool()) {
                tx.vin[i].nSequence = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
            }
            if (fuzzed_data_provider.ConsumeBool()) {
                tx.vin[i].prevout.n = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
            }
            if (fuzzed_data_provider.ConsumeBool()) {
                tx.vin[i].prevout.hash = Txid::FromUint256(ConsumeUInt256(fuzzed_data_provider));
            }
            if (fuzzed_data_provider.ConsumeBool()) {
                auto scriptSig = ConsumeRandomLengthByteVector<unsigned char>(fuzzed_data_provider, 100);
                tx.vin[i].scriptSig = CScript(scriptSig.begin(), scriptSig.end());;
            }
            if (fuzzed_data_provider.ConsumeBool()) {
                tx.vin[i].scriptWitness.stack.clear();
                for (int j = 0; j < fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 10); j++) {
                    tx.vin[i].scriptWitness.stack.push_back(ConsumeRandomLengthByteVector<unsigned char>(fuzzed_data_provider, 100));
                }
            }
        }
    }

    int numOutput = fuzzed_data_provider.ConsumeIntegralInRange<int>(1, 10);
    tx.vout.resize(numOutput);
    for (int i = 0; i < numOutput; i++) {
        tx.vout[i].nValue = fuzzed_data_provider.ConsumeIntegral<int64_t>();

        switch(fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 4)) {
            case 0:
                // P2WSH
                tx.vout[i].scriptPubKey = P2WSH_OP_TRUE;
                break;
            case 1:
                // P2SH
                tx.vout[i].scriptPubKey = P2SH_OP_TRUE;
                break;
            case 2:
                // TAPSCRIPT
                tx.vout[i].scriptPubKey = TAPROOT_OP_TRUE;
                break;
            case 3:
                // NoScript
                tx.vout[i].scriptPubKey = CScript();
                break;
            default: {
                auto scriptPubKey = ConsumeRandomLengthByteVector<unsigned char>(fuzzed_data_provider, 100);
                tx.vout[i].scriptPubKey = CScript(scriptPubKey.begin(), scriptPubKey.end());;
                break;
            }
        }
    }

    auto res = MakeTransactionRef(tx);

    // do it now, when the hash of the transaction will not change anymore
    for (int i = 0; i < numOutput; i++) {
        additionnalUTXO.emplace_back(getResolvUTXO(*res, i));
    }

    return res;
}

CBlock ConsumeBlock(FuzzedDataProvider& fuzzed_data_provider, const CBlock& prevBlock,
                    std::vector<CTxIn>& additionnalUTXO, bool forceValidBlock=false) {
    CBlock block;

    block.nVersion = fuzzed_data_provider.ConsumeIntegral<int32_t>();
    if (!forceValidBlock) {
        block.hashPrevBlock = ConsumeUInt256(fuzzed_data_provider);
        block.hashMerkleRoot = ConsumeUInt256(fuzzed_data_provider);
    }
    block.nTime = ConsumeTime(fuzzed_data_provider);
    block.nBits = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    block.nNonce = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    if (fuzzed_data_provider.ConsumeBool()) {
        block.nVersion = listBlocks.back()->nVersion;
    }
    if (fuzzed_data_provider.ConsumeBool()) {
        block.nBits = listBlocks.back()->nBits;
    }
    if (fuzzed_data_provider.ConsumeBool() || forceValidBlock) {
        block.hashPrevBlock = prevBlock.GetHash();
    }
    bool adjustNonce = fuzzed_data_provider.ConsumeBool() | forceValidBlock;
    bool adjustMerkle = fuzzed_data_provider.ConsumeBool() | forceValidBlock;

    block.vtx.push_back(ConsumeTransaction(fuzzed_data_provider, additionnalUTXO, true));

    int numTx = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 5);
    for (int i = 0; i < numTx; i++) {
        block.vtx.push_back(ConsumeTransaction(fuzzed_data_provider, additionnalUTXO));
    }

    if (adjustMerkle) {
        block.hashMerkleRoot = BlockMerkleRoot(block);
    }
    if (adjustNonce || existingBlockHash.contains(block.GetHash())) {
        const auto& consensus = g_setup->m_node.chainman->GetConsensus();
        block.nNonce = 0;
        // do not check against current nBits (as it may be a huge value)
        while (!CheckProofOfWork(block.GetHash(), listBlocks.back()->nBits, consensus) || existingBlockHash.contains(block.GetHash())) {
            ++block.nNonce;
            if (block.nNonce == 0) break;
        }
    }

    return block;
}

static unsigned NumLoop = 0;
static constexpr unsigned ResetEnvCount = 50000;

void reinitEnv() {
    g_setup->m_node.chainman.reset();
    Assert(fsbridge::clearMemFS());
    g_setup->m_make_chainman();
    //g_setup->m_node.notifications->m_shutdown_on_fatal_error = false;
    g_setup->LoadVerifyActivateChainstate();
    for (const auto&b : listBlocks) {
        if (b == listBlocks.front()) continue;
        ProcessBlock(g_setup->m_node, b);
    }
}

class Cleanup {

    uint256 tipHash;
public:
    Cleanup() {
        SeedRandomStateForTest(SeedRand::ZEROS);
        SetMockTime(listBlocks.back()->GetBlockTime() + 2);
        tipHash = listBlocks.back()->GetHash();

        if (NumLoop % ResetEnvCount == 0) {
            DEBUGOUTPUT(std::cout << "Reset by count" << std::endl);
            reinitEnv();
        } else if (g_setup->m_node.chainman->ActiveTip()->GetBlockHash() != tipHash) {
            DEBUGOUTPUT(std::cout << "Reset by wrong tip" << std::endl);
            reinitEnv();
        }
        NumLoop++;
        Assert(g_setup->m_node.chainman->ActiveTip()->GetBlockHash() == tipHash);
    }

    ~Cleanup() {
        // cleanup mempool
        CTxMemPool* mempool = g_setup->m_node.chainman->ActiveChainstate().GetMempool();
        Assert(mempool);
        while (mempool->size() > 0) {
            const CTxMemPoolEntry& entry = *(mempool->mapTx.begin());
            mempool->removeRecursive(entry.GetTx(), MemPoolRemovalReason::EXPIRY);
        }
        Assert(!g_setup->m_interrupt);

        Chainstate& active_chainstate = g_setup->m_node.chainman->ActiveChainstate();
        while (active_chainstate.m_chain.Tip()->nHeight >= (int) listBlocks.size()) {
            DisconnectedBlockTransactions disconnectpool{MAX_DISCONNECTED_TX_POOL_BYTES};
            ConnectTrace connectTrace;
            BlockValidationState state;
            bool disconnectSuccess = active_chainstate.DisconnectTip(state, &disconnectpool);
            active_chainstate.MaybeUpdateMempoolForReorg(disconnectpool, false);
            if (!disconnectSuccess) break;
        }
    }
};

static CBlockIndex* writeBlock(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
    ChainstateManager& csm = *g_setup->m_node.chainman;
    CBlockIndex* blockIndex = csm.m_blockman.LookupBlockIndex(block.GetHash());
    // if the hash already exists, this means that we got the same block before.
    // Don't at it a second time.
    if (blockIndex == nullptr) {
        CBlockIndex* bestBlock = nullptr;
        blockIndex = csm.m_blockman.AddToBlockIndex(block, bestBlock);
        Assert(bestBlock == blockIndex);

        FlatFilePos pos = csm.m_blockman.WriteBlock(block, blockIndex->nHeight);
        Assert(!pos.IsNull());
        csm.ReceivedBlockTransactions(block, blockIndex, pos);
        csm.ActiveChainstate().ForceFlushStateToDisk();
    }
    return blockIndex;
}

} // anonymous namespace

FUZZ_TARGET(connect_block, .init = initialize_connect_block)
{
    LOCK(::cs_main);
    Cleanup cleanEnvAtExit {};

    // Initialize data provider
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    Chainstate& active_chainstate = g_setup->m_node.chainman->ActiveChainstate();
    CBlockIndex* active_tip = active_chainstate.m_chain.Tip();
    CCoinsViewCache& active_coins = active_chainstate.CoinsTip();
    // CBlockHeader tip_header = active_tip->GetBlockHeader();
    DEBUGOUTPUT(std::cout << "Current Height: " << active_tip->nHeight << std::endl);

    // Read new block
    std::vector<CTxIn> additionnalUTXO;
    CBlock block = ConsumeBlock(fuzzed_data_provider, *listBlocks.back(), additionnalUTXO);
    CBlockHeader curr_header = block.GetBlockHeader();

    BlockValidationState state;
    const auto& consensus = g_setup->m_node.chainman->GetConsensus();
    if (!CheckBlock(block, state, consensus)) {
        DEBUGOUTPUT(std::cout << "Block invalid: " << state.GetRejectReason() << std::endl);
        return;
    }

    // Compute new CBlockIndex object
    uint256 currentHash = curr_header.GetHash();
    CBlockIndex new_index(curr_header);
    new_index.pprev = active_tip;
    new_index.nHeight = active_tip->nHeight + 1;
    new_index.phashBlock = &currentHash;

    bool success = active_chainstate.ConnectBlock(block,
                                                  state,
                                                  &new_index,
                                                  active_coins,
                                                  /* justCheck*/ false);

    if (success) {
        DEBUGOUTPUT(std::cout << "Block connected successfully: " << curr_header.GetHash().ToString() << std::endl);
        DEBUGOUTPUT(std::cout << "State: " << state.ToString() << std::endl);
        // printf(" %s\n", curr_header.GetHash().ToString());

        Assert(active_chainstate.DisconnectBlock(block, &new_index, active_coins) == DISCONNECT_OK);
    }
    else {
        DEBUGOUTPUT(std::cout << "Block connection failed: " << state.GetRejectReason() << std::endl);
        // printf("Block connection failed: %s\n", state.GetRejectReason());
        // If the connection failed, we can still try to disconnect the block
        // to ensure that the disconnect logic is robust.

        return;
    }
}

FUZZ_TARGET(connect_tip, .init = initialize_connect_block)
{
    LOCK(::cs_main);
    Cleanup cleanEnvAtExit {};

    // Initialize data provider
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    // Read new block
    std::vector<CTxIn> additionnalUTXO;
    CBlock block = ConsumeBlock(fuzzed_data_provider, *listBlocks.back(), additionnalUTXO);

    Chainstate& active_chainstate = g_setup->m_node.chainman->ActiveChainstate();
    DEBUGOUTPUT(std::cout << "Current Height: " << active_chainstate.m_chain.Tip()->nHeight << std::endl);

    BlockValidationState state;
    const auto& consensus = g_setup->m_node.chainman->GetConsensus();
    if (!CheckBlock(block, state, consensus)) {
        // do not test invalid block, as they will never be written on disk.
        // If an invalid block is written, it may raise an error when trying to
        // read it
        DEBUGOUTPUT(std::cout << "Block invalid: " << state.GetRejectReason() << std::endl);
        return;
    }

    DEBUGOUTPUT(std::cout << "Block generated : " << std::endl);
    DEBUGOUTPUT(std::cout << block.ToString() << std::endl);

    CBlockIndex* blockIndex = writeBlock(block);
    // if no pprev, we may trigger an assert in ChainstateManager::CheckBlockIndex()
    if (blockIndex->pprev != active_chainstate.m_chain.Tip()) {
        return;
    }

    DisconnectedBlockTransactions disconnectpool{MAX_DISCONNECTED_TX_POOL_BYTES};
    ConnectTrace connectTrace;

    {
        LOCK(active_chainstate.MempoolMutex());
        bool success = active_chainstate.ConnectTip(state, blockIndex, nullptr, connectTrace, disconnectpool);
        if (success) {
            DEBUGOUTPUT(std::cout << "Tip connected successfully: " << block.GetHash().ToString() << std::endl);
            DEBUGOUTPUT(std::cout << "State: " << state.ToString() << std::endl);

            disconnectpool.clear();

            if (active_chainstate.DisconnectTip(state, &disconnectpool)) {
                DEBUGOUTPUT(std::cout << "Tip disconnected successfully" << std::endl);
                DEBUGOUTPUT(std::cout << "State: " << state.ToString() << std::endl);
            } else {
                DEBUGOUTPUT(std::cout << "Block disconnection failed: " << state.GetRejectReason() << std::endl);
                Assert(false);
            }
            active_chainstate.MaybeUpdateMempoolForReorg(disconnectpool, false);
        } else {
            DEBUGOUTPUT(std::cout << "Block connection failed: " << state.GetRejectReason() << std::endl);
            // printf("Block connection failed: %s\n", state.GetRejectReason());
            // If the connection failed, we can still try to disconnect the block
            // to ensure that the disconnect logic is robust.

            return;
        }
    }
}

FUZZ_TARGET(activate_best_chain_step, .init = initialize_connect_block) {

    LOCK(::cs_main);
    Cleanup cleanEnvAtExit {};

    // Initialize data provider
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    Chainstate& active_chainstate = g_setup->m_node.chainman->ActiveChainstate();
    DEBUGOUTPUT(std::cout << "Begin with height: " << active_chainstate.m_chain.Tip()->nHeight << std::endl);

    // Step 1 : create few block and add them to the chain
    std::vector<CTxIn> additionnalUTXO;
    std::shared_ptr<const CBlock> prevBlock = listBlocks.back();
    CBlockIndex* originTip = active_chainstate.m_chain.Tip();
    CBlockIndex* prevIndex = originTip;
    const auto& consensus = g_setup->m_node.chainman->GetConsensus();

    for (int i = 0; i < 3; i++) {
        CBlock block = ConsumeBlock(fuzzed_data_provider, *prevBlock, additionnalUTXO, true);
        BlockValidationState state;
        if (!CheckBlock(block, state, consensus)) {
            // do not test invalid block, as they will never be written on disk.
            // If an invalid block is written, it may raise an error when trying to
            // read it
            DEBUGOUTPUT(std::cout << "Block invalid: " << state.GetRejectReason() << std::endl);
            return;
        }
        CBlockIndex* blockIndex = writeBlock(block);
        // if no pprev, we may trigger an assert in ChainstateManager::CheckBlockIndex()
        if (blockIndex->pprev != prevIndex) {
            DEBUGOUTPUT(std::cout << "Block invalid (pprev)" << std::endl);
            return;
        }

        DEBUGOUTPUT(std::cout << "Step1 NewBlock: "<< block.GetHash() << std::endl);
        prevBlock = std::make_shared<CBlock>(block);
        prevIndex = blockIndex;

        if (fuzzed_data_provider.ConsumeBool()) {
            break;
        }
    }

    // Step2: switch to this branch
    do {
        LOCK(active_chainstate.MempoolMutex());
        DisconnectedBlockTransactions disconnectpool{MAX_DISCONNECTED_TX_POOL_BYTES};
        ConnectTrace connectTrace;
        BlockValidationState state;

        bool foundInvalid = false;

        if (!active_chainstate.ActivateBestChainStep(state, prevIndex, prevBlock, foundInvalid, connectTrace)) {
            DEBUGOUTPUT(std::cout << "Step2 Fail" << std::endl);
            return;
        }
        if (foundInvalid) {
            DEBUGOUTPUT(std::cout << "Step2 Invalid" << std::endl);
            return;
        }
        DEBUGOUTPUT(std::cout << "Step2 Success : " << active_chainstate.m_chain.Tip()->nHeight << std::endl);
    } while (active_chainstate.m_chain.Tip()->nHeight < prevIndex->nHeight);

    // Step 3 : create a fork from the same origin than step1 and add them to the chain
    additionnalUTXO.clear();
    prevBlock = listBlocks.back();
    prevIndex = originTip;

    for (int i = 0; i < 5; i++) {
        CBlock block = ConsumeBlock(fuzzed_data_provider, *prevBlock, additionnalUTXO, true);
        BlockValidationState state;
        if (!CheckBlock(block, state, consensus)) {
            // do not test invalid block, as they will never be written on disk.
            // If an invalid block is written, it may raise an error when trying to
            // read it
            DEBUGOUTPUT(std::cout << "Block invalid: " << state.GetRejectReason() << std::endl);
            return;
        }
        CBlockIndex* blockIndex = writeBlock(block);
        // if no pprev, we may trigger an assert in ChainstateManager::CheckBlockIndex()
        if (blockIndex->pprev != prevIndex) {
            DEBUGOUTPUT(std::cout << "Block invalid (pprev)" << std::endl);
            return;
        }

        DEBUGOUTPUT(std::cout << "Step3 NewBlock: "<< block.GetHash() << std::endl);
        prevBlock = std::make_shared<CBlock>(block);
        prevIndex = blockIndex;

        if (fuzzed_data_provider.ConsumeBool()) {
            break;
        }
    }

    // Step4: rollback the previous branch and switch to this new one
    do {
        LOCK(active_chainstate.MempoolMutex());
        DisconnectedBlockTransactions disconnectpool{MAX_DISCONNECTED_TX_POOL_BYTES};
        ConnectTrace connectTrace;
        BlockValidationState state;

        bool foundInvalid = false;

        if (!active_chainstate.ActivateBestChainStep(state, prevIndex, prevBlock, foundInvalid, connectTrace)) {
            DEBUGOUTPUT(std::cout << "Step4 Fail" << std::endl);
            return;
        }
        if (foundInvalid) {
            DEBUGOUTPUT(std::cout << "Step4 Invalid" << std::endl);
            return;
        }
        DEBUGOUTPUT(std::cout << "Step4 Success : " << active_chainstate.m_chain.Tip()->nHeight << std::endl);
    } while (active_chainstate.m_chain.Tip()->nHeight < prevIndex->nHeight);
}
