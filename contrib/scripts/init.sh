#!/bin/bash
export LC_ALL=C
set -e -o pipefail

# use this script to install docker buildx
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
        Darwin*)    machine=darwin;;
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
    "darwin")      OS="darwin";;
esac

detect_arch() {
    case "$1" in
        armv7l*|arm*)   arch=(arm arm32v7);;
        aarch64*)       arch=(aarch64 arm64v8);;
        i686*)          arch=(i686 i386);;
        x86_64*)        arch=(x86_64 amd64);;
        *)              arch="unknown:${uname_out}"
    esac
}

PLATFORMS=linux/amd64,linux/arm64,linux/arm/v7,linux/386

TARGET_HOST_TRIPLET=""
ALL_HOST_TRIPLETS=""
if has_param '--host' "$@"; then
    if has_param '--all' "$@"; then
        ALL_HOST_TRIPLETS=("x86_64-apple-darwin15" "x86_64-pc-linux-gnu" "i686-pc-linux-gnu" "aarch64-linux-gnu" "arm-linux-gnueabihf" "x86_64-w64-mingw32" "i686-w64-mingw32")
    else
        ALL_HOST_TRIPLETS=($2)
    fi
fi

if [ "$MEM" != "" ]; then
    MEMORY="-m $MEM"
fi

ALLOCATED_RESOURCES="$MEMORY"

build() {
    target_arch=$(./contrib/scripts/detect.sh --host=$TARGET_HOST_TRIPLET);
    echo $target_arch
    docker buildx build \
    $ALLOCATED_RESOURCES \
    --platform $IMG_ARCH \
    -t xanimo/libdogecoin:$TARGET_HOST_TRIPLET \
    -f `pwd`/contrib/scripts/Dockerfile \
    --build-arg TARGET_HOST=$TARGET_HOST_TRIPLET \
    --build-arg TARGET_ARCH=$TARGET_ARCH \
    --build-arg IMG_ARCH=$IMG_ARCH \
    --build-arg FLAVOR=$FLAVOR \
    --target artifact --output type=local,dest=./ .
}

if [[ "$TARGET_HOST_TRIPLET" == "" && "$ALL_HOST_TRIPLETS" != "" ]]; then
    END=$((${#ALL_HOST_TRIPLETS[@]} - 1))
    for i in "${!ALL_HOST_TRIPLETS[@]}"
    do
    :
        TARGET_HOST_TRIPLET="${ALL_HOST_TRIPLETS[$i]}"
        case "$TARGET_HOST_TRIPLET" in
            "arm-linux-gnueabihf")
                TARGET_ARCH="armhf"
                IMG_ARCH=linux/arm/v7
                FLAVOR="jammy"
            ;;
            "aarch64-linux-gnu")
                TARGET_ARCH="arm64"
                IMG_ARCH=linux/arm64
                FLAVOR="jammy"
            ;;
            "x86_64-w64-mingw32")
                TARGET_ARCH="amd64"
                IMG_ARCH=linux/amd64
                FLAVOR="jammy"
            ;;
            "i686-w64-mingw32")
                TARGET_ARCH="i386"
                IMG_ARCH=linux/386
                FLAVOR="focal"
            ;;
            "x86_64-apple-darwin15")
                TARGET_ARCH="amd64"
                IMG_ARCH=linux/amd64
                FLAVOR="jammy"
            ;;
            "x86_64-pc-linux-gnu")
                TARGET_ARCH="amd64"
                IMG_ARCH=linux/amd64
                FLAVOR="jammy"
            ;;
            "i686-pc-linux-gnu")
                TARGET_ARCH="i386"
                IMG_ARCH=linux/386
                FLAVOR="focal"
            ;;
        esac
        build
    done
fi
