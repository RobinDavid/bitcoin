# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

find_package(protobuf REQUIRED)
find_package(libprotobuf-mutator REQUIRED)

add_executable(fuzzproto
  fuzz_proto.cpp
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
)
