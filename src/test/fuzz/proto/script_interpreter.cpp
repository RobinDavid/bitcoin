// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <test/fuzz/proto/fuzz_proto.h>
#include <test/fuzz/proto/script_interpreter.pb.h>
#include <test/fuzz/proto/util.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

bool CastToBool(const std::vector<unsigned char>& vch);

FUZZ_PROTO_TARGET(script_interpreter, const script_interpreter_fuzz::Target& el) {

    (void)CastToBool(ConsumeByteVector(el.casttobool()));

    const CScript script_code = ConsumeScript(el.script());
    const CTransaction tx = ConsumeTransaction(el.tx0());

    if (tx.vin.size() <= 0) return;
    const unsigned int in = ConsumeIntegralInRange<unsigned int>(el.targetinput(), 0, tx.vin.size() - 1);

    int n_hash_type = el.typehash0();
    auto amount = ConsumeMoney(el.amount0());
    auto sigversion = el.iswitness0() ? SigVersion::BASE: SigVersion::WITNESS_V0;
    (void)SignatureHash(script_code, tx, in, n_hash_type, amount, sigversion, nullptr);

    const CTransaction tx_precomputed = ConsumeTransaction(el.tx1());;
    const PrecomputedTransactionData precomputed_transaction_data{tx_precomputed};
    n_hash_type = el.typehash1();
    amount = ConsumeMoney(el.amount1());
    sigversion = el.iswitness1() ? SigVersion::BASE: SigVersion::WITNESS_V0;
    (void)SignatureHash(script_code, tx, in, n_hash_type, amount, sigversion, &precomputed_transaction_data);
}
