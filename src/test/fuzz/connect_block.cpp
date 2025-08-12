// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <core_memusage.h>
#include <primitives/block.h>
#include <pubkey.h>
#include <streams.h>
#include <test/fuzz/fuzz.h>
#include <util/chaintype.h>
#include <validation.h>

#include <cassert>
#include <string>


void initialize_connect_block()
{
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

