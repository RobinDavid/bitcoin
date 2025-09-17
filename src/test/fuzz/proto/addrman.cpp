// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrdb.h>
#include <addrman.h>
#include <addrman_impl.h>
#include <chainparams.h>
#include <common/args.h>
#include <merkleblock.h>
#include <random.h>
#include <test/fuzz/proto/addrman.pb.h>
#include <test/fuzz/proto/fuzz_proto.h>
#include <test/fuzz/proto/util.h>
#include <test/fuzz/proto/util/net.h>
#include <test/util/setup_common.h>
#include <time.h>
#include <util/asmap.h>
#include <util/chaintype.h>

#include <cassert>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace {
const BasicTestingSetup* g_setup;

int32_t GetCheckRatio()
{
    return std::clamp<int32_t>(g_setup->m_node.args->GetIntArg("-checkaddrman", 0), 0, 1000000);
}
} // namespace

void initialize_addrman()
{
    static const auto testing_setup = MakeNoLogFileContext<>(ChainType::REGTEST);
    g_setup = testing_setup.get();
}

FUZZ_PROTO_TARGET(data_stream_addr_man,
                  const addrman_fuzz::Target_data_stream_addr_man& el,
                  .init = initialize_addrman) {
    SeedRandomStateForTest(SeedRand::ZEROS);
    DataStream data_stream = DataStream(ConsumeSpan(el.datastream()));
    NetGroupManager netgroupman{ConsumeNetGroupManager(el.netmanager())};
    AddrMan addr_man(netgroupman, /*deterministic=*/false, GetCheckRatio());
    try {
        ReadFromStream(addr_man, data_stream);
    } catch (const std::exception&) {
    }
}

/**
 * Generate a random address. Always returns a valid address.
 */
CNetAddr RandAddr(const addrman_fuzz::RandAddrMessage& el) {
    CNetAddr addr;
    assert(!addr.IsValid());
    addr = ConsumeNetAddr(el.address());

    // Return a dummy IPv4 5.5.5.5 if we generated an invalid address.
    if (!addr.IsValid()) {
        in_addr v4_addr = {};
        v4_addr.s_addr = 0x05050505;
        addr = CNetAddr{v4_addr};
    }

    return addr;
}

/** Fill addrman with lots of addresses from lots of sources.  */
void FillAddrman(AddrMan& addrman, const addrman_fuzz::FillAddrManMessage& el) {
    // Add a fraction of the addresses to the "tried" table.
    // 0, 1, 2, 3 corresponding to 0%, 100%, 50%, 33%
    const size_t n = ConsumeIntegralInRange<size_t>(el.fraction(), 0, 3);
    CNetAddr prev_source;

    for (size_t i = 0; i < std::min<size_t>(el.sources_size(), 50); ++i) {
        const auto& sourceEl = el.sources(i);
        const auto source = RandAddr(sourceEl.sourceaddr());
        for (const auto& addressEl : sourceEl.addresses()) {
            const auto addr = CAddress{CService{RandAddr(addressEl.address()), 8333}, NODE_NETWORK};
            const std::chrono::seconds time_penalty{ConsumeIntegralInRange<size_t>(addressEl.time_penalty(), 0, 100000000)};
            addrman.Add({addr}, source, time_penalty);

            if (n > 0 && addrman.Size() % n == 0) {
                addrman.Good(addr, Now<NodeSeconds>());
            }

            // Add 10% of the addresses from more than one source.
            if (ConsumeIntegralInRange<unsigned>(addressEl.isadd(), 0, 9) == 0 && prev_source.IsValid()) {
                addrman.Add({addr}, prev_source, time_penalty);
            }
        }
        prev_source = source;
    }
}

FUZZ_PROTO_TARGET(addrman,
                  const addrman_fuzz::Target_addrman& el,
                  .init = initialize_addrman) {

    SeedRandomStateForTest(SeedRand::ZEROS);
    SetMockTime(ConsumeTime(el.time()));
    NetGroupManager netgroupman{ConsumeNetGroupManager(el.netmanager())};
    auto addr_man_ptr = std::make_unique<AddrManDeterministic>(netgroupman, el.addrman(), GetCheckRatio());
    if (el.has_serialized_datastream()) {
        DataStream ds{ConsumeByteVector(el.serialized_datastream())};
        try {
            ds >> *addr_man_ptr;
        } catch (const std::ios_base::failure&) {
            addr_man_ptr = std::make_unique<AddrManDeterministic>(netgroupman, el.addrman2(), GetCheckRatio());
        }
    }
    AddrManDeterministic& addr_man = *addr_man_ptr;
    for (unsigned i = 0; i < std::min<unsigned>(el.actions_size(), 10000); i++) {
        const auto& currentAction = el.actions(i);
        switch (currentAction.action_type_case()) {
            default:
            case addrman_fuzz::Target_addrman_Action::kResolvConflict:
                addr_man.ResolveCollisions();
                break;
            case addrman_fuzz::Target_addrman_Action::kSelectTriedCollision:
                (void)addr_man.SelectTriedCollision();
                break;
            case addrman_fuzz::Target_addrman_Action::kAddAddresses: {
                const auto& thisAction = currentAction.addaddresses();
                std::vector<CAddress> addresses;
                for (unsigned j = 0; j < std::min<unsigned>(thisAction.addrs_size(), 10000); j++) {
                    addresses.push_back(ConsumeAddress(thisAction.addrs(j)));
                }
                auto net_addr = ConsumeNetAddr(thisAction.source());
                auto time_penalty = std::chrono::seconds{ConsumeTime(thisAction.timepenality(), 0, 100000000)};
                addr_man.Add(addresses, net_addr, time_penalty);
                break;
            }
            case addrman_fuzz::Target_addrman_Action::kGoodAddress: {
                const auto& thisAction = currentAction.goodaddress();
                auto addr = ConsumeService(thisAction.serviceaddr());
                auto time = NodeSeconds{std::chrono::seconds{ConsumeTime(thisAction.time())}};
                addr_man.Good(addr, time);
                break;
            }
            case addrman_fuzz::Target_addrman_Action::kAttemptAddress: {
                const auto& thisAction = currentAction.attemptaddress();
                auto addr = ConsumeService(thisAction.serviceaddr());
                auto count_failure = thisAction.count_failure();
                auto time = NodeSeconds{std::chrono::seconds{ConsumeTime(thisAction.time())}};
                addr_man.Attempt(addr, count_failure, time);
                break;
            }
            case addrman_fuzz::Target_addrman_Action::kConnectedAddress: {
                const auto& thisAction = currentAction.connectedaddress();
                auto addr = ConsumeService(thisAction.serviceaddr());
                auto time = NodeSeconds{std::chrono::seconds{ConsumeTime(thisAction.time())}};
                addr_man.Connected(addr, time);
                break;
            }
            case addrman_fuzz::Target_addrman_Action::kSetServices: {
                const auto& thisAction = currentAction.setservices();
                auto addr = ConsumeService(thisAction.serviceaddr());
                auto n_services = ConsumeWeakEnum(thisAction.n_service(), ALL_SERVICE_FLAGS);
                addr_man.SetServices(addr, n_services);
                break;
            }
        }
    }
    const AddrMan& const_addr_man{addr_man};
    std::optional<Network> network;
    if (el.has_network()) {
        network = PickValueInArray(el.network(), ALL_NETWORKS);
    }
    auto max_addresses = ConsumeIntegralInRange<size_t>(el.max_addresses(), 0, 4096);
    auto max_pct = ConsumeIntegralInRange<size_t>(el.max_pct(), 0, 100);
    auto filtered = el.filtered();
    (void)const_addr_man.GetAddr(max_addresses, max_pct, network, filtered);

    std::unordered_set<Network> nets;
    for (unsigned i = 0; i < std::min<unsigned>(el.networklist_size(), ALL_NETWORKS.size()); i++) {
        if (el.networklist(i).value()) {
            nets.insert(ALL_NETWORKS[i]);
        }
    }
    (void)const_addr_man.Select(el.select_new_only(), nets);

    std::optional<bool> in_new;
    if (el.has_in_new()) {
        in_new = el.in_new();
    }
    (void)const_addr_man.Size(network, in_new);
    DataStream data_stream{};
    data_stream << const_addr_man;
}

// Check that serialize followed by unserialize produces the same addrman.
FUZZ_PROTO_TARGET(addrman_serdeser,
                  const addrman_fuzz::Target_addrman_serdeser& el,
                  .init = initialize_addrman) {

    SeedRandomStateForTest(SeedRand::ZEROS);
    SetMockTime(ConsumeTime(el.time()));

    NetGroupManager netgroupman{ConsumeNetGroupManager(el.netmanager())};
    AddrManDeterministic addr_man1{netgroupman, el.addrman1(), GetCheckRatio()};
    AddrManDeterministic addr_man2{netgroupman, el.addrman2(), GetCheckRatio()};

    DataStream data_stream{};

    FillAddrman(addr_man1, el.filladdrmanmessage());
    data_stream << addr_man1;
    data_stream >> addr_man2;
    assert(addr_man1 == addr_man2);
}
