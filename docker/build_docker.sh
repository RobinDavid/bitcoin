#!/usr/bin/env bash

set -e

BASEDIR="$(cd "$(dirname "$0")" && pwd -P)"

DOCKER_TAG="btc_fuzz:test"
DOCKERFILE="${BASEDIR}/Dockerfile.deb13"

usage() {
    echo "$0 [-t TAG] [-b debian12|debian13]"
}

while getopts "ht:b:" arg "$@" ; do
    case $arg in
    : | \? )
        usage
        exit 1
        ;;
    h)
        usage
        exit 0
        ;;
    t)
        DOCKER_TAG="${OPTARG}"
        ;;
    b)
        TARGETVERSION="${OPTARG}"
        if [[ "${TARGETVERSION}" == "12" ]] || [[ "${TARGETVERSION}" == "deb12" ]] || [[ "${TARGETVERSION}" == "debian12" ]]; then
            DOCKERFILE="${BASEDIR}/Dockerfile.deb12"
        elif [[ "${TARGETVERSION}" == "13" ]] || [[ "${TARGETVERSION}" == "deb13" ]] || [[ "${TARGETVERSION}" == "debian13" ]]; then
            DOCKERFILE="${BASEDIR}/Dockerfile.deb13"
        else
            echo "Invalid base image ${TARGETVERSION}"
            usage
            exit 1
        fi
        ;;
    esac
done

prepare_archive (){
    pushd "$(git rev-parse --show-toplevel)" >/dev/null
    git archive -o "${BASEDIR}/btc.tar.gz" --prefix=bitcoin/ HEAD .
    popd >/dev/null
}

delete_archive() {
    rm -f "${BASEDIR}/btc.tar.gz"
}

prepare_archive

docker build "${BASEDIR}" -t "${DOCKER_TAG}" -f "${DOCKERFILE}"

delete_archive
