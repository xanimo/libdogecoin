#!/bin/bash
export LC_ALL=C
set -e -o pipefail

# use this script to install docker-buildx
if [ $# -eq 0 ]; then
    echo "No arguments provided"
    exit 1
fi

has_param() {
    local term="$1"
    shift
    for arg; do
        if [[ $arg == "$term" ]]; then
            return 0
        fi
    done
    return 1
}

detect_os() {
    uname_out="$(uname -s)"
    case "${uname_out}" in
        Linux*)     machine=linux;;
        Darwin*)    machine=mac;;
        CYGWIN*)    machine=cygwin;;
        MINGW*)     machine=mingw;;
        MSYS_NT*)   machine=windows;;
        *)          machine="unknown:${uname_out}"
    esac
}

OS=
detect_os
case $machine in
    "linux")    OS="linux";; 
    "mac")      OS="mac";;
esac

if ! command -v docker buildx &> /dev/null
then
    ARCH=`dpkg --print-architecture`
    VERSION="v0.8.2"
    URL_BASE=https://github.com/docker/buildx/releases/download/$VERSION
    FILENAME=buildx-$VERSION.$OS-$ARCH
    CHECKSUM=$URL_BASE/checksums.txt
    curl --location --fail $URL_BASE/$FILENAME -o $FILENAME
    curl --location --fail $CHECKSUM -o checksums.txt
    grep $FILENAME checksums.txt | sha256sum -c
    chmod +x $FILENAME
    mv $FILENAME /usr/local/lib/docker/cli-plugins/docker-buildx
    rm -rf checksums.txt
    sudo apt-get update
    sudo apt install qemu-user
    PLATFORMS=linux/amd64,linux/arm64
    docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
    if ! docker buildx ls | grep -q container-builder; then\
            docker buildx create --platform ${PLATFORMS} --name container-builder --use;\
    fi
fi

TARGET_HOST_TRIPLET=""
ALL_HOST_TRIPLETS=""
if has_param '--host' "$@"; then
    if has_param '--all' "$@"; then
        ALL_HOST_TRIPLETS=("x86_64-pc-linux-gnu" "i686-pc-linux-gnu" "aarch64-linux-gnu" "arm-linux-gnueabihf" "x86_64-apple-darwin14" "x86_64-w64-mingw32" "i686-w64-mingw32")
    else
        ALL_HOST_TRIPLETS=($2)
    fi
fi

if [[ "$TARGET_HOST_TRIPLET" == "" && "$ALL_HOST_TRIPLETS" != "" ]]; then
    docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
    if ! docker buildx ls | grep -q container-builder; then\
            docker buildx create --platform ${PLATFORMS} --name container-builder --use;\
    fi
    END=$((${#ALL_HOST_TRIPLETS[@]} - 1))
    for i in "${!ALL_HOST_TRIPLETS[@]}"
    do
    :
        TARGET_HOST_TRIPLET="${ALL_HOST_TRIPLETS[$i]}"
        case "$TARGET_HOST_TRIPLET" in
            "arm-linux-gnueabihf")
                TARGET_ARCH="armhf"
            ;;
            "aarch64-linux-gnu")
                TARGET_ARCH="arm64"
            ;;
            "x86_64-w64-mingw32")
                TARGET_ARCH="amd64"
            ;;
            "i686-w64-mingw32")
                TARGET_ARCH="i386"
            ;;
            "x86_64-apple-darwin14")
                TARGET_ARCH="amd64"
            ;;
            "x86_64-pc-linux-gnu")
                TARGET_ARCH="amd64"
            ;;
            "i686-pc-linux-gnu")
                TARGET_ARCH="i386"
            ;;
        esac
        pushd ./contrib/scripts/
            docker buildx build --platform $OS/$TARGET_ARCH --load .
        popd
    done
fi
