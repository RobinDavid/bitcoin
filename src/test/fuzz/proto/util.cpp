#include <array>
#include <pubkey.h>

#include <test/fuzz/proto/util.h>

uint256 ConsumeUInt256(const proto_fuzz_util::uint256& val) {

    std::array<unsigned char, 32> value{};

    const std::string& buf = val.value();
    if (buf.size() > 0) {
        memcpy(value.data(), buf.data(), std::min(buf.size(), value.size()));
    }

    return uint256(value);
}

int64_t ConsumeTime(int64_t value, const std::optional<int64_t>& min, const std::optional<int64_t>& max) noexcept {
    // Avoid t=0 (1970-01-01T00:00:00Z) since SetMockTime(0) disables mocktime.
    static const int64_t time_min{ParseISO8601DateTime("2000-01-01T00:00:01Z").value()};
    static const int64_t time_max{ParseISO8601DateTime("2100-12-31T23:59:59Z").value()};
    return ConsumeIntegralInRange<int64_t>(value, min.value_or(time_min), max.value_or(time_max));
}

std::vector<uint8_t> ConstructPubKeyBytes(const proto_fuzz_util::PublicKey& m) noexcept {
    std::vector<uint8_t> pk_data = ConsumeByteVector(m.data());
    if (pk_data.size() < CPubKey::COMPRESSED_SIZE) {
        pk_data.resize(CPubKey::COMPRESSED_SIZE);
    }
    static_assert(CPubKey::COMPRESSED_SIZE >= 1);

    bool isCompressed = false;
    if (pk_data[0] == 0x02 || pk_data[0] == 0x03) {
        isCompressed = true;
    } else if (pk_data[0] == 0x04 || pk_data[0] == 0x06 || pk_data[0] == 0x07) {
        isCompressed = false;
    } else {
        isCompressed = (pk_data[0] & 1);
        if (isCompressed) {
            pk_data[0] = 0x02;
        } else {
            pk_data[0] = 0x04;
        }
    }

    pk_data.resize(isCompressed ? CPubKey::COMPRESSED_SIZE : CPubKey::SIZE);
    return pk_data;
}

CAmount ConsumeMoney(uint64_t v, const std::optional<CAmount>& max) noexcept
{
    return ConsumeIntegralInRange<CAmount>(v, 0, max.value_or(MAX_MONEY));
}

CScript ConsumeScript(const proto_fuzz_util::CScript& m, const bool maybe_p2wsh) noexcept
{
    CScript r_script{};
    for (int i = 0; i < m.elements_size(); i++) {
        const auto& currentElement = m.elements(i);
        switch (currentElement.element_type_case()) {
            default:
            case proto_fuzz_util::CScript_Element::kPushInt64: { // Push an integral
                r_script << currentElement.pushint64();
                break;
            }
            case proto_fuzz_util::CScript_Element::kOpcode: { // Push an opcode
                r_script << static_cast<opcodetype>(ConsumeIntegralInRange<uint32_t>(currentElement.opcode(), 0, MAX_OPCODE));
                break;
            }
            case proto_fuzz_util::CScript_Element::kScriptNum: { // Push a scriptnum
                r_script << CScriptNum{currentElement.scriptnum()};
                break;
            }
            case proto_fuzz_util::CScript_Element::kPushByteVector: { // Push a byte vector from the buffer
                r_script << ConsumeByteVector(currentElement.pushbytevector());
                break;
            }
            case proto_fuzz_util::CScript_Element::kPushMalformatedVector: { // Insert byte vector directly to allow malformed or unparsable scripts
                auto buffer = ConsumeByteVector(currentElement.pushmalformatedvector());
                r_script.insert(r_script.end(), buffer.begin(), buffer.end());
                break;
            }
            case proto_fuzz_util::CScript_Element::kMultiSig: { // Push multisig
                                                               // There is a special case for this to aid the fuzz engine
                                                               // navigate the highly structured multisig format.
                const auto& ms = currentElement.multisig();
                r_script << ConsumeIntegralInRange<int64_t>(ms.numsig(), 0, 22);
                for (unsigned j = 0; j < std::min<unsigned>(ms.pubkeys_size(), 21); j++) {
                    r_script << ConstructPubKeyBytes(ms.pubkeys(j));
                }
                r_script << ConsumeIntegralInRange<int64_t>(ms.numkey(), 0, 22);
                break;
            }
        }
    }
    if (maybe_p2wsh && m.p2wsh()) {
        uint256 script_hash;
        CSHA256().Write(r_script.data(), r_script.size()).Finalize(script_hash.begin());
        r_script.clear();
        r_script << OP_0 << ToByteVector(script_hash);
    }
    return r_script;
}

bool ContainsSpentInput(const CTransaction& tx, const CCoinsViewCache& inputs) noexcept
{
    for (const CTxIn& tx_in : tx.vin) {
        const Coin& coin = inputs.AccessCoin(tx_in.prevout);
        if (coin.IsSpent()) {
            return true;
        }
    }
    return false;
}

