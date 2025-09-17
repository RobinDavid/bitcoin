#ifndef BITCOIN_TEST_FUZZ_PROTO_UTIL_H
#define BITCOIN_TEST_FUZZ_PROTO_UTIL_H

#include <test/fuzz/proto/util.pb.h>
#include <coins.h>
#include <merkleblock.h>
#include <uint256.h>
#include <util/check.h>

#include <span>
#include <string>

uint256 ConsumeUInt256(const proto_fuzz_util::uint256& val);

template<typename T>
inline std::span<const uint8_t> ConsumeSpan(const T& s) {

    static_assert(sizeof(typename T::value_type) == sizeof(uint8_t));

    return std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

template<typename T>
inline std::vector<uint8_t> ConsumeByteVector(const T& s, const std::optional<size_t>& max_length = std::nullopt) {

    static_assert(sizeof(typename T::value_type) == sizeof(uint8_t));
    const size_t targetSize = std::min(s.size(), max_length.value_or(s.size()));

    std::vector<uint8_t> ret;
    ret.resize(targetSize);
    if (targetSize > 0) {
        Assert(ret.data());
        memcpy(ret.data(), s.data(), targetSize);
    }

    return ret;
}

template<typename T>
inline std::string ConsumeString(const T& s, const std::optional<size_t>& max_length = std::nullopt) {

    static_assert(sizeof(typename T::value_type) == sizeof(uint8_t));
    const size_t targetSize = std::min(s.size(), max_length.value_or(s.size()));

    std::string ret;
    ret.resize(targetSize);
    if (targetSize > 0) {
        Assert(ret.data());
        memcpy(ret.data(), s.data(), targetSize);
    }

    return ret;
}

template<typename T>
inline std::vector<bool> ConsumeBitsVector(const T& s) {
    return BytesToBits(ConsumeByteVector(s));
}

template <typename T>
T ConsumeIntegralInRange(T value, T min = std::numeric_limits<T>::min(), T max = std::numeric_limits<T>::max()) {
  static_assert(std::is_integral_v<T>, "An integral type is required.");
  static_assert(sizeof(T) <= sizeof(uint64_t), "Unsupported integral type.");

  if (min > max)
    abort();

  // Use the biggest type possible to hold the range and the result.
  uint64_t range = static_cast<uint64_t>(max) - static_cast<uint64_t>(min);
  uint64_t result = value;

  // Avoid division by 0, in case |range + 1| results in overflow.
  if (range != std::numeric_limits<decltype(range)>::max())
    result = result % (range + 1);

  return static_cast<T>(static_cast<uint64_t>(min) + result);
}

int64_t ConsumeTime(int64_t value, const std::optional<int64_t>& min = std::nullopt, const std::optional<int64_t>& max = std::nullopt) noexcept;

template <typename Collection>
auto& PickValue(uint32_t v, Collection& col)
{
    auto sz{col.size()};
    assert(sz >= 1);
    auto it = col.begin();
    std::advance(it, ConsumeIntegralInRange<decltype(sz)>(v, 0, sz - 1));
    return *it;
}

template <typename EnumType, size_t size>
EnumType ConsumeEnum(uint32_t value, const EnumType (&all_types)[size]) noexcept
{
    return all_types[ConsumeIntegralInRange<uint32_t>(value, 0, size - 1)];
}

template <typename EnumType, size_t size>
EnumType PickValueInArray(uint32_t value, const EnumType (&all_types)[size]) noexcept
{
    return ConsumeEnum(value, all_types);
}

template <typename EnumType, size_t size>
EnumType PickValueInArray(uint32_t value, const std::array<EnumType, size>& all_types) noexcept
{
    return all_types[ConsumeIntegralInRange<uint32_t>(value, 0, size - 1)];
}

template <typename WeakEnumType, size_t size>
WeakEnumType ConsumeWeakEnum(const proto_fuzz_util::WeakEnum& m, const WeakEnumType (&all_types)[size]) noexcept
{
    if (m.has_insideenum()) {
        return ConsumeEnum(m.insideenum(), all_types);
    } else {
        return WeakEnumType(m.rawvalueenum());
    }
}

template <typename WeakEnumType, size_t size>
WeakEnumType ConsumeWeakEnum(const proto_fuzz_util::WeakEnum& m, const std::array<WeakEnumType, size>& all_types) noexcept
{
    if (m.has_insideenum()) {
        return PickValueInArray(m.insideenum(), all_types);
    } else {
        return WeakEnumType(m.rawvalueenum());
    }
}

inline CTxOut ConsumeCSimpleTxOut(const proto_fuzz_util::CSimpleTxOut& m) {
    const auto& scriptPubKey = m.scriptpubkey();
    return CTxOut(m.amount(), CScript(scriptPubKey.begin(), scriptPubKey.end()));
}

inline COutPoint ConsumeCOutPoint(const proto_fuzz_util::COutPoint& m) {
    return {Txid::FromUint256(ConsumeUInt256(m.prevhash())), m.prevn()};
}

inline CTxIn ConsumeCSimpleTxIn(const proto_fuzz_util::CSimpleTxIn& m, bool allowWitness=false) {
    const auto& scriptSig = m.scriptsig();
    CTxIn res(ConsumeCOutPoint(m.outpoint()), CScript(scriptSig.begin(), scriptSig.end()), m.nsequence());
    res.scriptWitness.stack.clear();
    if (allowWitness) {
        res.scriptWitness.stack.reserve(m.scriptwitness_size());
        for (const auto& el : m.scriptwitness()) {
            res.scriptWitness.stack.push_back({el.begin(), el.end()});
        }
    }

    return res;
}

inline CMutableTransaction ConsumeMutableSimpleTransaction(const proto_fuzz_util::CSimpleTransaction& m, bool allowWitness=true) {
    CMutableTransaction tx;
    tx.version = m.version();
    tx.nLockTime = m.nlocktime();

    tx.vin.clear();
    tx.vout.clear();
    tx.vin.reserve(m.inputs_size());
    tx.vout.reserve(m.outputs_size());
    for (const auto& el : m.inputs()) {
        tx.vin.push_back(ConsumeCSimpleTxIn(el, allowWitness));
    }
    for (const auto& el : m.outputs()) {
        tx.vout.push_back(ConsumeCSimpleTxOut(el));
    }

    return tx;
}

inline CTransaction ConsumeSimpleTransaction(const proto_fuzz_util::CSimpleTransaction& m, bool allowWitness=true) {
    return CTransaction{ConsumeMutableSimpleTransaction(m, allowWitness)};
}

inline Coin ConsumeCoin(const proto_fuzz_util::Coin& m) {
    return {ConsumeCSimpleTxOut(m.outin()), m.nheightin(), m.fcoinbasein()};
}

template <typename T, size_t size>
void SetFuzzedErrNo(uint32_t v, const std::array<T, size>& errnos) {
    errno = PickValueInArray(v, errnos);
}

[[nodiscard]] CScript ConsumeScript(const proto_fuzz_util::CScript& m, const bool maybe_p2wsh = false) noexcept;
[[nodiscard]] CAmount ConsumeMoney(uint64_t v, const std::optional<CAmount>& max = std::nullopt) noexcept;

[[nodiscard]] bool ContainsSpentInput(const CTransaction& tx, const CCoinsViewCache& inputs) noexcept;

[[nodiscard]] uint32_t ConsumeSequence(const proto_fuzz_util::Sequence& el) noexcept;

[[nodiscard]] CMutableTransaction ConsumeComplexeTransaction(const proto_fuzz_util::CComplexeTransaction& m, const std::vector<Txid>& prevout_txids, const int max_num_in = 10, const int max_num_out = 10) noexcept;


#endif // BITCOIN_TEST_FUZZ_PROTO_UTIL_H
