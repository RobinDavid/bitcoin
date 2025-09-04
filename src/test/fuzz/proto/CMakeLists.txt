# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

find_package(protobuf REQUIRED)
find_package(libprotobuf-mutator REQUIRED)

add_executable(fuzzproto
  addition_overflow.cpp
  addition_overflow.proto
  fuzz_proto.cpp
)

protobuf_generate(
  TARGET fuzzproto
  LANGUAGE cpp
  IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(fuzzproto
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
