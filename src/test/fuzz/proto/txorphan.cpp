// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/validation.h>
#include <net_processing.h>
#include <node/eviction.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <test/fuzz/proto/txorphan.pb.h>
#include <test/fuzz/proto/fuzz_proto.h>
#include <test/fuzz/proto/util.h>
#include <test/util/setup_common.h>
#include <txorphanage.h>
#include <uint256.h>
#include <util/check.h>
#include <util/time.h>

#include <cstdint>
#include <memory>
#include <set>
#include <utility>
#include <vector>

void initialize_orphanage()
{
    static const auto testing_setup = MakeNoLogFileContext();
}

FUZZ_PROTO_TARGET(txorphan, const txorphan_fuzz::Target& el, .init = initialize_orphanage) {

    FastRandomContext orphanage_rng{/*fDeterministic=*/true};
    SetMockTime(ConsumeTime(el.time()));

    TxOrphanage orphanage;
    std::vector<COutPoint> outpoints; // Duplicates are tolerated
    outpoints.reserve(200'000);

    // initial outpoints used to construct transactions later
    for (uint8_t i = 0; i < 4; i++) {
        outpoints.emplace_back(Txid::FromUint256(uint256{i}), 0);
    }

    CTransactionRef ptx_potential_parent = nullptr;

    std::vector<CTransactionRef> tx_history;

    for (int i = 0; i < std::min<int>(el.elements_size(), 10 * DEFAULT_MAX_ORPHAN_TRANSACTIONS) && outpoints.size() < 200'000; i++) {
        const auto& currentElement = el.elements(i);
        // construct transaction
        const CTransactionRef tx = [&] {
            CMutableTransaction tx_mut;
            const auto num_in = std::min<size_t>(1 + currentElement.nextelements_size(), outpoints.size());
            const auto num_out = ConsumeIntegralInRange<uint32_t>(currentElement.num_out(), 1, 256);
            // pick outpoints from outpoints as input. We allow input duplicates on purpose, given we are not
            // running any transaction validation logic before adding transactions to the orphanage
            tx_mut.vin.reserve(num_in);
            for (uint32_t j = 0; j < num_in; j++) {
                const auto& currentInput = (j == 0) ? currentElement.firstelement() : currentElement.nextelements(j-1);
                auto& prevout = PickValue(currentInput.prevout(), outpoints);
                // try making transactions unique by setting a random nSequence, but allow duplicate transactions if they happen
                tx_mut.vin.emplace_back(prevout, CScript{}, ConsumeIntegralInRange<uint32_t>(currentInput.sequencein(), 0, CTxIn::SEQUENCE_FINAL));
            }
            // output amount will not affect txorphanage
            tx_mut.vout.reserve(num_out);
            for (uint32_t j = 0; j < num_out; j++) {
                tx_mut.vout.emplace_back(CAmount{0}, CScript{});
            }
            auto new_tx = MakeTransactionRef(tx_mut);
            // add newly constructed outpoints to the coin pool
            for (uint32_t j = 0; j < num_out; j++) {
                outpoints.emplace_back(new_tx->GetHash(), j);
            }
            return new_tx;
        }();

        tx_history.push_back(tx);

        const auto wtxid{tx->GetWitnessHash()};

        // Trigger orphanage functions that are called using parents. ptx_potential_parent is a tx we constructed in a
        // previous loop and potentially the parent of this tx.
        if (ptx_potential_parent) {
            // Set up future GetTxToReconsider call.
            orphanage.AddChildrenToWorkSet(*ptx_potential_parent, orphanage_rng);

            // Check that all txns returned from GetChildrenFrom* are indeed a direct child of this tx.
            NodeId peer_id = currentElement.node_id();
            for (const auto& child : orphanage.GetChildrenFromSamePeer(ptx_potential_parent, peer_id)) {
                assert(std::any_of(child->vin.cbegin(), child->vin.cend(), [&](const auto& input) {
                    return input.prevout.hash == ptx_potential_parent->GetHash();
                }));
            }
        }

        // trigger orphanage functions
        for (int j = 0; j < std::min<int>(currentElement.loopelements_size(), 10 * DEFAULT_MAX_ORPHAN_TRANSACTIONS); j++) {
            const auto& currentLoopElement = currentElement.loopelements(j);

            NodeId peer_id = currentLoopElement.node_id();
            const auto total_bytes_start{orphanage.TotalOrphanUsage()};
            const auto total_peer_bytes_start{orphanage.UsageByPeer(peer_id)};
            const auto tx_weight{GetTransactionWeight(*tx)};

            switch (currentLoopElement.action_type_case()) {
                default:
                case txorphan_fuzz::Target_Element_ElementLoop::kGetTxToReconsider: {
                    CTransactionRef ref = orphanage.GetTxToReconsider(peer_id);
                    if (ref) {
                        Assert(orphanage.HaveTx(ref->GetWitnessHash()));
                    }
                    break;
                }
                case txorphan_fuzz::Target_Element_ElementLoop::kAddTx: {
                    bool have_tx = orphanage.HaveTx(tx->GetWitnessHash());
                    // AddTx should return false if tx is too big or already have it
                    // tx weight is unknown, we only check when tx is already in orphanage
                    {
                        bool add_tx = orphanage.AddTx(tx, peer_id);
                        // have_tx == true -> add_tx == false
                        Assert(!have_tx || !add_tx);

                        if (add_tx) {
                            Assert(orphanage.UsageByPeer(peer_id) == tx_weight + total_peer_bytes_start);
                            Assert(orphanage.TotalOrphanUsage() == tx_weight + total_bytes_start);
                            Assert(tx_weight <= MAX_STANDARD_TX_WEIGHT);
                        } else {
                            // Peer may have been added as an announcer.
                            if (orphanage.UsageByPeer(peer_id) == tx_weight + total_peer_bytes_start) {
                                Assert(orphanage.HaveTxFromPeer(wtxid, peer_id));
                            } else {
                                // Otherwise, there must not be any change to the peer byte count.
                                Assert(orphanage.UsageByPeer(peer_id) == total_peer_bytes_start);
                            }

                            // Regardless, total bytes should not have changed.
                            Assert(orphanage.TotalOrphanUsage() == total_bytes_start);
                        }
                    }
                    have_tx = orphanage.HaveTx(tx->GetWitnessHash());
                    {
                        bool add_tx = orphanage.AddTx(tx, peer_id);
                        // if have_tx is still false, it must be too big
                        Assert(!have_tx == (tx_weight > MAX_STANDARD_TX_WEIGHT));
                        Assert(!have_tx || !add_tx);
                    }
                    break;
                }
                case txorphan_fuzz::Target_Element_ElementLoop::kAddAnnouncer: {
                    bool have_tx = orphanage.HaveTx(tx->GetWitnessHash());
                    bool have_tx_and_peer = orphanage.HaveTxFromPeer(tx->GetWitnessHash(), peer_id);
                    // AddAnnouncer should return false if tx doesn't exist or we already HaveTxFromPeer.
                    {
                        bool added_announcer = orphanage.AddAnnouncer(tx->GetWitnessHash(), peer_id);
                        // have_tx == false -> added_announcer == false
                        Assert(have_tx || !added_announcer);
                        // have_tx_and_peer == true -> added_announcer == false
                        Assert(!have_tx_and_peer || !added_announcer);

                        // Total bytes should not have changed. If peer was added as announcer, byte
                        // accounting must have been updated.
                        Assert(orphanage.TotalOrphanUsage() == total_bytes_start);
                        if (added_announcer) {
                            Assert(orphanage.UsageByPeer(peer_id) == tx_weight + total_peer_bytes_start);
                        } else {
                            Assert(orphanage.UsageByPeer(peer_id) == total_peer_bytes_start);
                        }
                    }
                    break;
                }
                case txorphan_fuzz::Target_Element_ElementLoop::kEraseTx: {
                    bool have_tx = orphanage.HaveTx(tx->GetWitnessHash());
                    bool have_tx_and_peer{orphanage.HaveTxFromPeer(wtxid, peer_id)};
                    // EraseTx should return 0 if m_orphans doesn't have the tx
                    {
                        auto bytes_from_peer_before{orphanage.UsageByPeer(peer_id)};
                        Assert(have_tx == orphanage.EraseTx(tx->GetWitnessHash()));
                        if (have_tx) {
                            Assert(orphanage.TotalOrphanUsage() == total_bytes_start - tx_weight);
                            if (have_tx_and_peer) {
                                Assert(orphanage.UsageByPeer(peer_id) == bytes_from_peer_before - tx_weight);
                            } else {
                                Assert(orphanage.UsageByPeer(peer_id) == bytes_from_peer_before);
                            }
                        } else {
                            Assert(orphanage.TotalOrphanUsage() == total_bytes_start);
                        }
                    }
                    have_tx = orphanage.HaveTx(tx->GetWitnessHash());
                    have_tx_and_peer = orphanage.HaveTxFromPeer(wtxid, peer_id);
                    // have_tx should be false and EraseTx should fail
                    {
                        Assert(!have_tx && !have_tx_and_peer && !orphanage.EraseTx(wtxid));
                    }
                    break;
                }
                case txorphan_fuzz::Target_Element_ElementLoop::kEraseForPeer: {
                    orphanage.EraseForPeer(peer_id);
                    Assert(!orphanage.HaveTxFromPeer(tx->GetWitnessHash(), peer_id));
                    Assert(orphanage.UsageByPeer(peer_id) == 0);
                    break;
                }
                case txorphan_fuzz::Target_Element_ElementLoop::kEraseForBlock: {
                    // Make a block out of txs and then EraseForBlock
                    CBlock block;
                    for (int k{0}; k < std::min(currentLoopElement.eraseforblock().indextoremove_size(), 1000); ++k) {
                        auto& tx_to_remove = PickValue(currentLoopElement.eraseforblock().indextoremove(k), tx_history);
                        block.vtx.push_back(tx_to_remove);
                    }
                    orphanage.EraseForBlock(block);
                    for (const auto& tx_removed : block.vtx) {
                        Assert(!orphanage.HaveTx(tx_removed->GetWitnessHash()));
                        Assert(!orphanage.HaveTxFromPeer(tx_removed->GetWitnessHash(), peer_id));
                    }
                    break;
                }
                case txorphan_fuzz::Target_Element_ElementLoop::kLimitOrphans: {
                    // test mocktime and expiry
                    SetMockTime(ConsumeTime(currentLoopElement.limitorphans().time()));
                    unsigned int limit = currentLoopElement.limitorphans().limit();
                    orphanage.LimitOrphans(limit, orphanage_rng);
                    Assert(orphanage.Size() <= limit);
                    break;
                }
            }
        }

        // Set tx as potential parent to be used for future GetChildren() calls.
        if (!ptx_potential_parent || currentElement.set_potential_parent()) {
            ptx_potential_parent = tx;
        }

        const bool have_tx{orphanage.HaveTx(tx->GetWitnessHash())};
        const bool get_tx_nonnull{orphanage.GetTx(tx->GetWitnessHash()) != nullptr};
        Assert(have_tx == get_tx_nonnull);
    }
    orphanage.SanityCheck();
}
