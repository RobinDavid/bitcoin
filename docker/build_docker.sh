#!/usr/bin/env bash

set -e

BASEDIR="$(cd "$(dirname "$0")" && pwd -P)"

prepare_archive (){
    pushd "$(git rev-parse --show-toplevel)" >/dev/null
    git archive -o "${BASEDIR}/btc.tar.gz" --prefix=bitcoin/ HEAD .
    popd >/dev/null
}

delete_archive() {
    rm -f "${BASEDIR}/btc.tar.gz"
}

prepare_archive

DOCKER_TAG="btc_fuzz:test"
DOCKERFILE="${BASEDIR}/Dockerfile"

prepare_archive

docker build "${BASEDIR}" -t "${DOCKER_TAG}" -f "${DOCKERFILE}"

delete_archive
