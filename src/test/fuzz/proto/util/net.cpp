// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/proto/util/net.h>

#include <compat/compat.h>
#include <netaddress.h>
#include <node/protocol_version.h>
#include <protocol.h>
#include <test/fuzz/proto/util.h>
#include <test/util/net.h>
#include <util/sock.h>
#include <util/time.h>

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

class CNode;

CNetAddr ConsumeNetAddr(const proto_fuzz_util_net::NetAddress& m) noexcept {
    struct NetAux {
        Network net;
        CNetAddr::BIP155Network bip155;
        size_t len;
    };

    static constexpr std::array<NetAux, 6> nets{
        NetAux{.net = Network::NET_IPV4, .bip155 = CNetAddr::BIP155Network::IPV4, .len = ADDR_IPV4_SIZE},
        NetAux{.net = Network::NET_IPV6, .bip155 = CNetAddr::BIP155Network::IPV6, .len = ADDR_IPV6_SIZE},
        NetAux{.net = Network::NET_ONION, .bip155 = CNetAddr::BIP155Network::TORV3, .len = ADDR_TORV3_SIZE},
        NetAux{.net = Network::NET_I2P, .bip155 = CNetAddr::BIP155Network::I2P, .len = ADDR_I2P_SIZE},
        NetAux{.net = Network::NET_CJDNS, .bip155 = CNetAddr::BIP155Network::CJDNS, .len = ADDR_CJDNS_SIZE},
        NetAux{.net = Network::NET_INTERNAL, .bip155 = CNetAddr::BIP155Network{0}, .len = 0},
    };

    const size_t nets_index = ConsumeIntegralInRange<size_t>(m.type_network(), 0, nets.size() - 1);

    const auto& aux = nets[nets_index];

    CNetAddr addr;

    if (aux.net == Network::NET_INTERNAL) {
        addr.SetInternal(m.net_internal());
        return addr;
    }

    DataStream s;

    s << static_cast<uint8_t>(aux.bip155);

    std::vector<uint8_t> addr_bytes;
    addr_bytes = ConsumeByteVector(m.addr_bytes(), aux.len);
    addr_bytes.resize(aux.len);
    if (aux.net == NET_IPV6 && addr_bytes[0] == CJDNS_PREFIX) { // Avoid generating IPv6 addresses that look like CJDNS.
        addr_bytes[0] = 0x55; // Just an arbitrary number, anything != CJDNS_PREFIX would do.
    }
    if (aux.net == NET_CJDNS) { // Avoid generating CJDNS addresses that don't start with CJDNS_PREFIX because those are !IsValid().
        addr_bytes[0] = CJDNS_PREFIX;
    }
    s << addr_bytes;

    s >> CAddress::V2_NETWORK(addr);

    return addr;
}

CAddress ConsumeAddress(const proto_fuzz_util_net::Address& m) noexcept {
    return {ConsumeService(m.cservice()), ConsumeWeakEnum(m.serviceflags(), ALL_SERVICE_FLAGS), NodeSeconds{std::chrono::seconds{m.nodesecond()}}};
}

// template <typename P>
// P ConsumeDeserializationParams(FuzzedDataProvider& fuzzed_data_provider) noexcept
// {
//     constexpr std::array ADDR_ENCODINGS{
//         CNetAddr::Encoding::V1,
//         CNetAddr::Encoding::V2,
//     };
//     constexpr std::array ADDR_FORMATS{
//         CAddress::Format::Disk,
//         CAddress::Format::Network,
//     };
//     if constexpr (std::is_same_v<P, CNetAddr::SerParams>) {
//         return P{PickValue(fuzzed_data_provider, ADDR_ENCODINGS)};
//     }
//     if constexpr (std::is_same_v<P, CAddress::SerParams>) {
//         return P{{PickValue(fuzzed_data_provider, ADDR_ENCODINGS)}, PickValue(fuzzed_data_provider, ADDR_FORMATS)};
//     }
// }
// template CNetAddr::SerParams ConsumeDeserializationParams(FuzzedDataProvider&) noexcept;
// template CAddress::SerParams ConsumeDeserializationParams(FuzzedDataProvider&) noexcept;

FuzzedSock::FuzzedSock(const proto_fuzz_util_net::FuzzSockInternal& data_provider,
                       const proto_fuzz_util_net::FuzzSockAccept* accept_provider)
    : Sock{ConsumeIntegralInRange<SOCKET>(data_provider.socket(), INVALID_SOCKET - 1, INVALID_SOCKET)},
      m_data_provider{data_provider}, m_accept_provider{accept_provider},
      m_remain_before_disconnected{data_provider.m_remain_before_disconnected()},
      m_selectable{data_provider.m_selectable()},
      m_time{MockableSteadyClock::INITIAL_MOCK_TIME}
{
    ElapseTime(std::chrono::seconds(0)); // start mocking the steady clock.
}

FuzzedSock::~FuzzedSock()
{
    // Sock::~Sock() will be called after FuzzedSock::~FuzzedSock() and it will call
    // close(m_socket) if m_socket is not INVALID_SOCKET.
    // Avoid closing an arbitrary file descriptor (m_socket is just a random very high number which
    // theoretically may concide with a real opened file descriptor).
    m_socket = INVALID_SOCKET;
}

void FuzzedSock::ElapseTime(std::chrono::milliseconds duration) const
{
    m_time += duration;
    MockableSteadyClock::SetMockTime(m_time);
}

FuzzedSock& FuzzedSock::operator=(Sock&& other)
{
    assert(false && "Move of Sock into FuzzedSock not allowed.");
    return *this;
}

ssize_t FuzzedSock::Send(const void* data, size_t len, int flags) const
{
    if (m_data_provider.sendelements_size() == 0) {
        return len;
    }
    const auto& el = m_data_provider.sendelements(nextSendElement);
    nextSendElement = (nextSendElement + 1) % m_data_provider.sendelements_size();

    constexpr std::array send_errnos{
        EACCES,
        EAGAIN,
        EALREADY,
        EBADF,
        ECONNRESET,
        EDESTADDRREQ,
        EFAULT,
        EINTR,
        EINVAL,
        EISCONN,
        EMSGSIZE,
        ENOBUFS,
        ENOMEM,
        ENOTCONN,
        ENOTSOCK,
        EOPNOTSUPP,
        EPIPE,
        EWOULDBLOCK,
    };
    if (!el.has_value()) {
        return len;
    }
    const ssize_t r = ConsumeIntegralInRange<ssize_t>(el.value(), -1, len);
    if (r == -1) {
        SetFuzzedErrNo(el.errorvalue(), send_errnos);
    }
    return r;
}

ssize_t FuzzedSock::Recv(void* buf, size_t len, int flags) const
{
    // Have a permanent error at recv_errnos[0] because when the fuzzed data is exhausted
    // SetFuzzedErrNo() will always return the first element and we want to avoid Recv()
    // returning -1 and setting errno to EAGAIN repeatedly.
    constexpr std::array recv_errnos{
        ECONNREFUSED,
        EAGAIN,
        EBADF,
        EFAULT,
        EINTR,
        EINVAL,
        ENOMEM,
        ENOTCONN,
        ENOTSOCK,
        EWOULDBLOCK,
    };
    assert(buf != nullptr || len == 0);
    bool hasError = false;
    uint32_t errorValue = 0;
    bool noData = false;
    bool latency = false;

    if (nextRecvElement >= (unsigned) m_data_provider.recvelements_size()) {
        nextRecvElement = 0;
    } else {
        const auto& el = m_data_provider.recvelements(nextRecvElement);
        nextRecvElement++;
        hasError = el.has_errorvalue();
        if (hasError) {
            errorValue = el.errorvalue();
        }
        noData = el.nodata();
        latency = el.latency();
    }

    // Do the latency before any of the "return" statements.
    if (latency && std::getenv("FUZZED_SOCKET_FAKE_LATENCY") != nullptr) {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }

    if (len == 0 || hasError || noData) {
        const ssize_t r = hasError ? 0 : -1;
        if (r == -1) {
            SetFuzzedErrNo(errorValue, recv_errnos);
        }
        return r;
    }

    size_t copied_so_far{0};

    if (!m_peek_data.empty()) {
        // MSG_PEEK was used, or a partial message was received
        const size_t copy_len{std::min(len, m_peek_data.size())};
        std::memcpy(buf, m_peek_data.data(), copy_len);
        copied_so_far += copy_len;
        if ((flags & MSG_PEEK) == 0) {
            m_peek_data.erase(m_peek_data.begin(), m_peek_data.begin() + copy_len);
        }
    }

    if (copied_so_far == len) {
        return copied_so_far;
    }

    if (nextRecvMessage >= (unsigned) m_data_provider.sockmessages_size()) return copied_so_far;

    const auto& new_message = m_data_provider.sockmessages(nextRecvMessage++);

    //auto new_data = ConsumeRandomLengthByteVector(m_fuzzed_data_provider, len - copied_so_far);
    if (new_message.empty()) return copied_so_far;

    auto new_message_used = std::min(new_message.size(), len - copied_so_far);
    std::memcpy(reinterpret_cast<uint8_t*>(buf) + copied_so_far, new_message.data(), new_message_used);
    copied_so_far += new_message_used;

    if ((flags & MSG_PEEK) != 0) {
        m_peek_data.insert(m_peek_data.end(), new_message.begin(), new_message.end());
    } else if (new_message_used < new_message.size()) {
        m_peek_data.insert(m_peek_data.end(), new_message.begin() + new_message_used, new_message.end());
    }
    return copied_so_far;

//     if (copied_so_far == len || m_fuzzed_data_provider.ConsumeBool()) {
//         return copied_so_far;
//     }
//
//     // Pad to len bytes.
//     std::memset(reinterpret_cast<uint8_t*>(buf) + copied_so_far, 0x0, len - copied_so_far);
//
//     return len;
}

int FuzzedSock::Connect(const sockaddr*, socklen_t) const
{
    // Have a permanent error at connect_errnos[0] because when the fuzzed data is exhausted
    // SetFuzzedErrNo() will always return the first element and we want to avoid Connect()
    // returning -1 and setting errno to EAGAIN repeatedly.
    constexpr std::array connect_errnos{
        ECONNREFUSED,
        EAGAIN,
        ECONNRESET,
        EHOSTUNREACH,
        EINPROGRESS,
        EINTR,
        ENETUNREACH,
        ETIMEDOUT,
    };
    if (m_data_provider.has_connecterror()) {
        SetFuzzedErrNo(m_data_provider.connecterror(), connect_errnos);
        return -1;
    }
    return 0;
}

int FuzzedSock::Bind(const sockaddr*, socklen_t) const
{
    // Have a permanent error at bind_errnos[0] because when the fuzzed data is exhausted
    // SetFuzzedErrNo() will always set the global errno to bind_errnos[0]. We want to
    // avoid this method returning -1 and setting errno to a temporary error (like EAGAIN)
    // repeatedly because proper code should retry on temporary errors, leading to an
    // infinite loop.
    constexpr std::array bind_errnos{
        EACCES,
        EADDRINUSE,
        EADDRNOTAVAIL,
        EAGAIN,
    };
    if (m_data_provider.has_binderror()) {
        SetFuzzedErrNo(m_data_provider.binderror(), bind_errnos);
        return -1;
    }
    return 0;
}

int FuzzedSock::Listen(int) const
{
    // Have a permanent error at listen_errnos[0] because when the fuzzed data is exhausted
    // SetFuzzedErrNo() will always set the global errno to listen_errnos[0]. We want to
    // avoid this method returning -1 and setting errno to a temporary error (like EAGAIN)
    // repeatedly because proper code should retry on temporary errors, leading to an
    // infinite loop.
    constexpr std::array listen_errnos{
        EADDRINUSE,
        EINVAL,
        EOPNOTSUPP,
    };
    if (m_data_provider.has_listenerror()) {
        SetFuzzedErrNo(m_data_provider.listenerror(), listen_errnos);
        return -1;
    }
    return 0;
}

std::unique_ptr<Sock> FuzzedSock::Accept(sockaddr* addr, socklen_t* addr_len) const
{
    if (m_accept_provider != nullptr && nextAcceptElement < (unsigned) m_accept_provider->acceptsocket_size()) {
        return std::make_unique<FuzzedSock>(m_accept_provider->acceptsocket(nextAcceptElement++));
    }

    constexpr std::array accept_errnos{
        ECONNABORTED,
        EINTR,
        ENOMEM,
    };
    SetFuzzedErrNo(m_data_provider.accepterrormsg(), accept_errnos);
    return std::unique_ptr<FuzzedSock>();
}

int FuzzedSock::GetSockOpt(int level, int opt_name, void* opt_val, socklen_t* opt_len) const
{
    constexpr std::array getsockopt_errnos{
        ENOMEM,
        ENOBUFS,
    };

    if (m_data_provider.getsockoptelements_size() == 0) {
        if (opt_val == nullptr) {
            return 0;
        }
        SetFuzzedErrNo(0, getsockopt_errnos);
        return -1;
    }
    const auto& el = m_data_provider.getsockoptelements(nextGetSockOptElement);
    nextGetSockOptElement = (nextGetSockOptElement + 1) % m_data_provider.getsockoptelements_size();

    if (el.has_errorvalue()) {
        SetFuzzedErrNo(el.errorvalue(), getsockopt_errnos);
        return -1;
    }
    if (opt_val == nullptr) {
        return 0;
    }
    const auto& bytes = el.optvalue();
    std::memset(opt_val, 0, *opt_len);
    std::memcpy(opt_val, bytes.data(), std::min<size_t>(*opt_len, bytes.size()));
    return 0;
}

int FuzzedSock::SetSockOpt(int, int, const void*, socklen_t) const
{
    if (m_data_provider.setsockoptelements_size() == 0) {
        return 0;
    }
    const auto& el = m_data_provider.setsockoptelements(nextSetSockOptElement);
    nextSetSockOptElement = (nextSetSockOptElement + 1) % m_data_provider.setsockoptelements_size();
    constexpr std::array setsockopt_errnos{
        ENOMEM,
        ENOBUFS,
    };
    if (el.has_errorvalue()) {
        SetFuzzedErrNo(el.errorvalue(), setsockopt_errnos);
        return -1;
    }
    return 0;
}

int FuzzedSock::GetSockName(sockaddr* name, socklen_t* name_len) const
{
    constexpr std::array getsockname_errnos{
        ECONNRESET,
        ENOBUFS,
    };
    if (m_data_provider.has_socknameerror()) {
        SetFuzzedErrNo(m_data_provider.socknameerror(), getsockname_errnos);
        return -1;
    }
    assert(name_len);
    const auto& bytes = m_data_provider.sockname();
    std::memset(name, 0, std::max<size_t>(*name_len, sizeof(sockaddr)));
    std::memcpy(name, bytes.data(), std::min<size_t>(*name_len, bytes.size()));
    *name_len = std::max<size_t>(std::min<size_t>(*name_len, bytes.size()), sizeof(sockaddr));
    return 0;
}

bool FuzzedSock::SetNonBlocking() const
{
    constexpr std::array setnonblocking_errnos{
        EBADF,
        EPERM,
    };
    if (m_data_provider.has_setnonblockingerror()) {
        SetFuzzedErrNo(m_data_provider.setnonblockingerror(), setnonblocking_errnos);
        return false;
    }
    return true;
}

bool FuzzedSock::IsSelectable() const
{
    return m_selectable;
}

bool FuzzedSock::WaitInternal(std::optional<std::chrono::milliseconds> timeout, Event requested, Event* occurred) const
{
    if (m_data_provider.waitelements_size() == 0) {
        if (occurred != nullptr) {
            *occurred = (requested & SEND);
            if (m_peek_data.size() > 0 || nextRecvMessage < (unsigned) m_data_provider.sockmessages_size()) {
                *occurred |= (requested & RECV);
            }
        }
        return true;
    }
    const auto& el = m_data_provider.waitelements(nextSetSockOptElement);
    nextWaitElement = (nextWaitElement + 1) % m_data_provider.waitelements_size();
    constexpr std::array wait_errnos{
        EBADF,
        EINTR,
        EINVAL,
    };
    if (el.has_errorvalue()) {
        SetFuzzedErrNo(el.has_errorvalue(), wait_errnos);
        return false;
    }
    if (occurred != nullptr) {
        *occurred = (requested & SEND);
        if (m_peek_data.size() > 0 || nextRecvMessage < (unsigned) m_data_provider.sockmessages_size()) {
            *occurred |= (requested & RECV);
        }
    }
    if (timeout.has_value()) ElapseTime(timeout.value());
    return true;
}

bool FuzzedSock::WaitMany(std::chrono::milliseconds timeout, EventsPerSock& events_per_sock) const
{
    for (auto& [sock, events] : events_per_sock) {
        Assert(sock->isMock());
        if (!static_cast<const FuzzedSock*>(sock.get())->WaitInternal({}, events.requested, &events.occurred)) {
            events.occurred = 0;
        }
    }
    ElapseTime(timeout);
    return true;
}

bool FuzzedSock::IsConnected(std::string& errmsg) const
{
    if (m_remain_before_disconnected > 0) {
        m_remain_before_disconnected--;
        return true;
    }
    errmsg = "disconnected at random by the fuzzer";
    return false;
}

void FillNode(const proto_fuzz_util_net::NodeInfo& m, ConnmanTestMsg& connman, CNode& node) noexcept
{
    auto successfully_connected = m.successfully_connected();
    auto remote_services = ConsumeWeakEnum(m.remote_services(), ALL_SERVICE_FLAGS);
    auto local_services = ConsumeWeakEnum(m.local_services(), ALL_SERVICE_FLAGS);
    auto version = ConsumeIntegralInRange<int32_t>(m.version(), MIN_PEER_PROTO_VERSION, std::numeric_limits<int32_t>::max());
    auto relay_txs = m.relay_txs();
    connman.Handshake(node, successfully_connected, remote_services, local_services, version, relay_txs);
}


