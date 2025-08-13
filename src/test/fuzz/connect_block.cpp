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
                }
            }
        }
    }
}

void initialize_connect_block() {
    //const auto params{CreateChainParams(ArgsManager{}, ChainType::REGTEST)};
    //static const auto chain{CreateBlockChain(2 * COINBASE_MATURITY, *params)};
    //g_chain = &chain;

    static auto testing_setup = MakeNoLogFileContext<TestingSetup>(
            /*chain_type=*/ChainType::REGTEST, {});
    g_setup = testing_setup.get();

    node::BlockAssembler::Options options;
    options.coinbase_output_script = P2WSH_OP_TRUE;

    for (int i = 0; i < 2 * COINBASE_MATURITY; ++i) {
        MineBlock(g_setup->m_node, options);
    }
    loadCurrentChain();
    printBlock(listBlocks[1]);

    for (unsigned i = 1; i < 11; i++) {
        CMutableTransaction ctx;
        ctx.version = CTransaction::CURRENT_VERSION;
        ctx.vin.resize(1);
        ctx.vin[0] = allUTXO[i];
        ctx.vout.resize(2);
        // P2WSH
        ctx.vout[0].nValue = CAmount(24.5 * COIN);
        ctx.vout[0].scriptPubKey = P2WSH_OP_TRUE;
        // P2SH
        ctx.vout[1].nValue = CAmount(24.5 * COIN);
        ctx.vout[1].scriptPubKey = P2SH_OP_TRUE;
        std::cout << MakeTransactionRef(ctx)->ToString() << std::endl;

        LOCK(::cs_main);
        const MempoolAcceptResult ctx_result = g_setup->m_node.chainman->ProcessTransaction(MakeTransactionRef(ctx));
        if (ctx_result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
            std::cout << "Transaction rejected : " << ctx_result.m_state.GetRejectReason() << std::endl;

        }
        Assert(ctx_result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }

    MineBlock(g_setup->m_node, options);
    loadCurrentChain();
    //printBlock(listBlocks.back());

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

