# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

cmake_policy(PUSH)
cmake_policy(SET CMP0144 NEW)

find_package(protobuf REQUIRED)
find_package(libprotobuf-mutator REQUIRED)
cmake_policy(POP)

add_library(fuzzprotobufmsg STATIC
  addition_overflow.proto
  addrman.proto
  coins_view.proto
  coinscache_sim.proto
  connect_block.proto
  eval_script.proto
  process_messages.proto
  script_flags.proto
  script_interpreter.proto
  util.proto
  util/net.proto
  utxo_total_supply.proto
)

protobuf_generate(
  TARGET fuzzprotobufmsg
  LANGUAGE cpp
  IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(fuzzprotobufmsg PUBLIC
  protobuf::libprotobuf
)

target_include_directories(fuzzprotobufmsg PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

set(fuzzProtoSrcList
  addition_overflow.cpp
  addrman.cpp
  coins_view.cpp
  coinscache_sim.cpp
  connect_block.cpp
  eval_script.cpp
  process_messages.cpp
  script_flags.cpp
  script_interpreter.cpp
  util.cpp
  util/net.cpp
  utxo_total_supply.cpp
)

add_executable(fuzzproto
  fuzz_proto.cpp
  ${fuzzProtoSrcList}
)

target_link_libraries(fuzzproto
  fuzzprotobufmsg
  core_interface
  test_util
  fuzzer_interface
  bitcoin_cli
  bitcoin_common
  bitcoin_util
  bitcoin_node
  minisketch
  leveldb
  univalue
  secp256k1
  Boost::headers
  libevent::extra
  protobuf::libprotobuf
  libprotobuf-mutator::protobuf-mutator
  libprotobuf-mutator::protobuf-mutator-libfuzzer
)

if(NOT FUZZ_BINARY_LINKS_WITHOUT_MAIN_FUNCTION)
  target_compile_definitions(fuzzproto PRIVATE PROVIDE_FUZZ_MAIN_FUNCTION)
endif()

if (NOT SANITIZERS)
  # TODO aflmutatorproxy should be compile without afl or sanitizer
  add_library(aflmutatorproxy SHARED
    afl_proto_mutator.cpp
    ${fuzzProtoSrcList}
  )

  target_link_libraries(aflmutatorproxy
    fuzzprotobufmsg
    core_interface
    test_util
    fuzzer_interface
    bitcoin_cli
    bitcoin_common
    bitcoin_util
    bitcoin_node
    minisketch
    leveldb
    univalue
    secp256k1
    Boost::headers
    libevent::extra
    protobuf::libprotobuf
    libprotobuf-mutator::protobuf-mutator
    libprotobuf-mutator::protobuf-mutator-libfuzzer
  )
endif()
