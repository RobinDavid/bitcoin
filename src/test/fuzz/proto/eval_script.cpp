// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>
#include <script/interpreter.h>
#include <test/fuzz/proto/util.h>
#include <test/fuzz/proto/eval_script.pb.h>
#include <test/fuzz/proto/fuzz_proto.h>

#include <limits>

FUZZ_PROTO_TARGET(eval_script, const eval_script_fuzz::Target& el) {
    const unsigned int flags = el.flags();
    const CScript script = ConsumeScript(el.script(), true);

    for (const auto sig_version : {SigVersion::BASE, SigVersion::WITNESS_V0}) {
        std::vector<std::vector<unsigned char>> stack;
        (void)EvalScript(stack, script, flags, BaseSignatureChecker(), sig_version, nullptr);
    }
}
