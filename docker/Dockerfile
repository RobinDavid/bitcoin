FROM "debian:13"

ENV USER="docker" \
    HOME="/home/docker"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends \
        adduser \
        bash \
        binutils-dev \
        build-essential \
        ca-certificates \
        clang-19 \
        cmake \
        curl \
        gcc-14-plugin-dev \
        git \
        libboost-dev\
        libclang-rt-19-dev \
        libevent-dev \
        libfuzzer-19-dev \
        libsqlite3-dev \
        libstdc++-14-dev \
        lld-19 \
        llvm-19-dev \
        llvm-19-tools \
        ninja-build \
        pkg-config \
        python3 \
        python3-dev \
        wget \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos '' --home "$HOME" "$USER"
WORKDIR $HOME
USER $USER

ENV PATH="/usr/lib/llvm-19/bin:${PATH}" \
    LOCAL_INSTALL_PREFIX="${HOME}/local_install"

RUN mkdir $LOCAL_INSTALL_PREFIX

RUN git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git && \
    cd AFLplusplus && \
    make source-only && \
    cd ..

RUN git clone --depth 1 --branch 20250814.0 https://github.com/abseil/abseil-cpp.git && \
    cd abseil-cpp && \
    mkdir build && cd build && \
    cmake .. -G Ninja \
      -DCMAKE_C_COMPILER="clang" \
      -DCMAKE_CXX_COMPILER="clang++" \
      -DCMAKE_C_FLAGS="-fPIC" \
      -DCMAKE_CXX_FLAGS="-fPIC" \
      -DCMAKE_INSTALL_PREFIX="${LOCAL_INSTALL_PREFIX}" && \
    ninja install && \
    cd ../..

RUN git clone --depth 1 --branch v32.0 https://github.com/protocolbuffers/protobuf.git && \
    cd protobuf && \
    mkdir build && cd build && \
    cmake .. -G Ninja \
      -Dprotobuf_BUILD_TESTS=OFF \
      -DCMAKE_C_COMPILER="clang" \
      -DCMAKE_CXX_COMPILER="clang++" \
      -DCMAKE_C_FLAGS="-fPIC" \
      -DCMAKE_CXX_FLAGS="-fPIC" \
      -DABSL_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DCMAKE_INSTALL_PREFIX="${LOCAL_INSTALL_PREFIX}" && \
    ninja install && \
    cd ../..

RUN git clone --depth 1 --branch v1.5 https://github.com/google/libprotobuf-mutator.git && \
    cd libprotobuf-mutator && \
    mkdir build && cd build && \
    cmake .. -G Ninja \
      -DLIB_PROTO_MUTATOR_TESTING=OFF -DLIB_PROTO_MUTATOR_EXAMPLES=OFF \
      -DCMAKE_C_COMPILER="clang" \
      -DCMAKE_CXX_COMPILER="clang++" \
      -DCMAKE_C_FLAGS="-fPIC" \
      -DCMAKE_CXX_FLAGS="-fPIC" \
      -DABSL_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DPROTOBUF_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DCMAKE_INSTALL_PREFIX="${LOCAL_INSTALL_PREFIX}" && \
    ninja install && \
    cd ../..

USER root
# git archive -o btc.tar.gz --prefix=bitcoin/ HEAD .
ADD btc.tar.gz $HOME/
RUN chown -R $USER:$USER $HOME/bitcoin
USER $USER

WORKDIR $HOME/bitcoin

RUN mkdir docker/build && cd docker/build && \
    cmake ../.. -G Ninja \
      -DCMAKE_C_COMPILER="clang" \
      -DCMAKE_CXX_COMPILER="clang++" \
      -DABSL_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DPROTOBUF_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DLIBPROTOBUF-MUTATOR_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DCMAKE_C_FLAGS="-fPIC" \
      -DCMAKE_CXX_FLAGS="-fPIC" \
      -DBUILD_FOR_FUZZING=ON -DBUILD_FUZZ_PROTO_BINARY=ON && \
    ninja && \
    cd ..

RUN mkdir docker/build_cov_llvm && cd docker/build_cov_llvm && \
    cmake ../.. -G Ninja \
      -DCMAKE_C_COMPILER="clang" \
      -DCMAKE_CXX_COMPILER="clang++" \
      -DABSL_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DPROTOBUF_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DLIBPROTOBUF-MUTATOR_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DCMAKE_C_FLAGS="-fPIC -fprofile-instr-generate -fcoverage-mapping -fcoverage-mcdc" \
      -DCMAKE_CXX_FLAGS="-fPIC -fprofile-instr-generate -fcoverage-mapping -fcoverage-mcdc" \
      -DBUILD_FOR_FUZZING=ON -DBUILD_FUZZ_PROTO_BINARY=ON && \
    ninja && \
    cd ..

RUN mkdir docker/build_libfuzzer_asan && cd docker/build_libfuzzer_asan && \
    cmake ../.. -G Ninja \
      -DCMAKE_C_COMPILER="clang" \
      -DCMAKE_CXX_COMPILER="clang++" \
      -DABSL_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DPROTOBUF_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DLIBPROTOBUF-MUTATOR_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DBUILD_FOR_FUZZING=ON -DBUILD_FUZZ_PROTO_BINARY=ON \
      -DCMAKE_C_FLAGS="-fPIC" \
      -DCMAKE_CXX_FLAGS="-fPIC" \
      -DSANITIZERS="undefined,address,fuzzer" && \
    ninja && \
    cd ..

RUN mkdir docker/build_afl_asan && cd docker/build_afl_asan && \
    cmake ../.. -G Ninja \
      -DCMAKE_C_COMPILER="${HOME}/AFLplusplus/afl-clang-lto" \
      -DCMAKE_CXX_COMPILER="${HOME}/AFLplusplus/afl-clang-lto++" \
      -DABSL_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DPROTOBUF_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DLIBPROTOBUF-MUTATOR_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DBUILD_FOR_FUZZING=ON -DBUILD_FUZZ_PROTO_BINARY=ON \
      -DCMAKE_C_FLAGS="-fPIC" \
      -DCMAKE_CXX_FLAGS="-fPIC" \
      -DSANITIZERS="undefined,address" && \
    ninja && \
    cd ..

RUN mkdir docker/build_afl_cmp && cd docker/build_afl_cmp && \
    export AFL_LLVM_CMPLOG=1 && \
    cmake ../.. -G Ninja \
      -DCMAKE_C_COMPILER="${HOME}/AFLplusplus/afl-clang-lto" \
      -DCMAKE_CXX_COMPILER="${HOME}/AFLplusplus/afl-clang-lto++" \
      -DABSL_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DPROTOBUF_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DLIBPROTOBUF-MUTATOR_ROOT="${LOCAL_INSTALL_PREFIX}" \
      -DBUILD_FOR_FUZZING=ON -DBUILD_FUZZ_PROTO_BINARY=ON \
      -DCMAKE_C_FLAGS="-fPIC" \
      -DCMAKE_CXX_FLAGS="-fPIC" \
      -DSANITIZERS="undefined,address" && \
    ninja && \
    cd ..
