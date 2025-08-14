// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
//#include <chainparams.h>
//#include <consensus/merkle.h>
//#include <consensus/validation.h>
//#include <core_io.h>
//#include <core_memusage.h>
//#include <primitives/block.h>
//#include <pubkey.h>
//#include <streams.h>
#include <test/fuzz/fuzz.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
//#include <util/chaintype.h>
#include <validation.h>

#include <cassert>
#include <string>

//static const std::vector<std::shared_ptr<CBlock>>* g_chain;
TestingSetup* g_setup{nullptr};
static std::vector<CBlock> listBlocks;
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

void printBlock(const CBlock& block) {
    std::cout << block.ToString() << std::endl;
}

void loadCurrentChain() {
    listBlocks.clear();

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
            Assert(CState.m_blockman.ReadBlock(listBlocks[currentBlock->nHeight], *currentBlock));
            if constexpr (0) {
                printBlock(listBlocks[currentBlock->nHeight]);
            }
            currentBlock = currentBlock->pprev;
        }
        if constexpr (0) {
            std::cout << "CoinsDB output : " << CState.CoinsDB().StoragePath() << std::endl;
        }
    }
    allUTXO.clear();

    for (const auto& b : listBlocks) {
        for (const auto& tx: b.vtx) {
            for (unsigned voutIndex = 0; voutIndex < tx->vout.size(); voutIndex++) {
                auto& vout = tx->vout[voutIndex];
                if (vout.scriptPubKey.size() >= 1 && vout.scriptPubKey[0] == OP_RETURN) continue;
                auto& target = allUTXO.emplace_back(COutPoint(tx->GetHash(), voutIndex));
                if (vout.scriptPubKey == P2WSH_OP_TRUE) {
                    target.scriptSig = CScript();
                    target.scriptWitness.stack.push_back(WITNESS_STACK_ELEM_OP_TRUE);
                } else if (vout.scriptPubKey == P2SH_OP_TRUE) {
                    target.scriptSig = P2SH_OP_TRUE_UNLOCK;
                } else if (vout.scriptPubKey == CScript()) {
                    target.scriptSig = CScript() << OP_TRUE;
                } else if (vout.scriptPubKey == TAPROOT_OP_TRUE) {
                    target.scriptSig = CScript();
                    target.scriptWitness.stack = TAPROOT_OP_TRUE_WITNESS;
                }
            }
        }
    }
}

static void initialize_connect_block() {

    static auto testing_setup = MakeNoLogFileContext<TestingSetup>(
            /*chain_type=*/ChainType::REGTEST, {
                .extra_args = {
                    "-minrelaytxfee=0",
                    "-acceptnonstdtxn",
                },
            });
    g_setup = testing_setup.get();
    init_taproot_script();

    node::BlockAssembler::Options options;
    options.coinbase_output_script = P2WSH_OP_TRUE;

    for (int i = 0; i < 2 * COINBASE_MATURITY; ++i) {
        MineBlock(g_setup->m_node, options);
    }
    loadCurrentChain();

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

        //std::cout << MakeTransactionRef(ctx)->ToString() << std::endl;

        LOCK(::cs_main);
        const MempoolAcceptResult ctx_result = g_setup->m_node.chainman->ProcessTransaction(MakeTransactionRef(ctx));
        if (ctx_result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
            std::cout << "Transaction rejected : " << ctx_result.m_state.GetRejectReason() << std::endl;
        }
        Assert(ctx_result.m_result_type == MempoolAcceptResult::ResultType::VALID);

        Assert(g_setup->m_node.chainman->ActiveChainstate().GetMempool()->size() == i);
        g_setup->m_node.chainman->ActiveChainstate().GetMempool()->PrioritiseTransaction(ctx.GetHash(), COIN);
    }

    MineBlock(g_setup->m_node, options);
    Assert(g_setup->m_node.chainman->ActiveChainstate().GetMempool()->size() == 0);

    loadCurrentChain();
    //printBlock(listBlocks.back());

    if constexpr(0) {
        // Test usage last transaction
        for (unsigned i = 1; i < 11; i++) {
            CMutableTransaction ctx;
            ctx.version = CTransaction::CURRENT_VERSION;
            ctx.vin.resize(1);
            ctx.vin[0] = allUTXO[allUTXO.size() - i];
            ctx.vout.resize(1);
            // P2WSH
            ctx.vout[0].nValue = CAmount(10 * COIN);
            ctx.vout[0].scriptPubKey = P2WSH_OP_TRUE;

            // std::cout << MakeTransactionRef(ctx)->ToString() << std::endl;

            LOCK(::cs_main);
            const MempoolAcceptResult ctx_result = g_setup->m_node.chainman->ProcessTransaction(MakeTransactionRef(ctx));
            if (ctx_result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
                std::cout << "Transaction2 rejected : " << ctx_result.m_state.GetRejectReason() << std::endl;

            }
            Assert(ctx_result.m_result_type == MempoolAcceptResult::ResultType::VALID);
            Assert(g_setup->m_node.chainman->ActiveChainstate().GetMempool()->size() == i);
            g_setup->m_node.chainman->ActiveChainstate().GetMempool()->PrioritiseTransaction(ctx.GetHash(), COIN);
        }

        MineBlock(g_setup->m_node, options);
        loadCurrentChain();
        printBlock(listBlocks.back());
    }

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


FUZZ_TARGET(connect_block, .init = initialize_connect_block)
{

    /*
        block = fuzzed_data_provider.Consume<CBlock>();

        res = ConnectBlock(block);

        if (success) {
            DisconnectBlock(block);
        }

    */

}

