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

PLATFORMS=linux/amd64,linux/arm64,linux/arm/v7,linux/386
if ! command -v docker &> /dev/null
then
    if [ $OS == "darwin" ]; then
        export HOMEBREW_NO_INSTALL_CLEANUP=1
        NONINTERACTIVE=1 brew install --cask docker
        export HOMEBREW_NO_INSTALL_CLEANUP=0
        if [ "$(uname -m)" == "x86_64" ]; then
            ARCH="amd64"
        fi
    else
        curl -O -L https://gist.githubusercontent.com/xanimo/5fd1e8091909f85547de8a5d8268d522/raw/9d10ff5fb1700d4adcf6038397c2638d4d950ce7/docker-init.sh
        chmod +x docker-init.sh
        ./docker-init.sh
        ARCH=`dpkg --print-architecture`
    fi
    if ! command -v docker buildx &> /dev/null
    then
        VERSION="v0.8.2"
        URL_BASE=https://github.com/docker/buildx/releases/download/$VERSION
        FILENAME=buildx-$VERSION.$OS-$ARCH
        CHECKSUM=$URL_BASE/checksums.txt
        curl -O -L $URL_BASE/$FILENAME -o $FILENAME
        if [ $OS == "darwin" ]; then
            echo "95303b8b017d6805d35768244e66b41739745f81cb3677c0aefea231e484e227  buildx-v0.8.2.darwin-amd64" | sha256sum -c
        else
            curl -O -L $CHECKSUM -o checksums.txt
            grep $FILENAME checksums.txt | sha256sum -c
        fi
        chmod +x $FILENAME
        if [ -d "/usr/local/lib/docker" ]; then
            if [ ! -d "/usr/local/lib/docker/cli-plugins" ]; then
                sudo mkdir -p /usr/local/lib/docker/cli-plugins
            fi
        fi
        sudo mv $FILENAME /usr/local/lib/docker/cli-plugins/docker-buildx
        rm -rf checksums.txt
        docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
        if ! docker buildx ls | grep -q container-builder; then
            docker buildx create --platform ${PLATFORMS} --name container-builder --use;
        fi
    else
        docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
        if ! docker buildx ls | grep -q container-builder; then
            docker buildx create --platform ${PLATFORMS} --name container-builder --node container-builder --use;
        fi
    fi
fi

TARGET_HOST_TRIPLET=""
ALL_HOST_TRIPLETS=""
if has_param '--host' "$@"; then
    if has_param '--all' "$@"; then
        ALL_HOST_TRIPLETS=("x86_64-apple-darwin14" "x86_64-pc-linux-gnu" "i686-pc-linux-gnu" "aarch64-linux-gnu" "arm-linux-gnueabihf" "x86_64-w64-mingw32" "i686-w64-mingw32")
    else
        ALL_HOST_TRIPLETS=($2)
    fi
fi

if [ "$MEM" != "" ]; then
    MEMORY="-m $MEM"
fi

ALLOCATED_RESOURCES="$MEMORY"

build() {
    pushd contrib/scripts/
        docker buildx build \
        $ALLOCATED_RESOURCES \
        --platform linux/$TARGET_ARCH \
        -t xanimo/libdogecoin:$TARGET_HOST_TRIPLET \
        --build-arg TARGET_HOST=$TARGET_HOST_TRIPLET \
        --build-arg IMG_ARCH=$IMG_ARCH \
        --build-arg FLAVOR=$FLAVOR \
        --no-cache --target artifact --output type=local,dest=../../ .
    popd
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
                FLAVOR="jammy"
            ;;
            "aarch64-linux-gnu")
                TARGET_ARCH="arm64"
                FLAVOR="jammy"
            ;;
            "x86_64-w64-mingw32")
                TARGET_ARCH="amd64"
                FLAVOR="jammy"
            ;;
            "i686-w64-mingw32")
                TARGET_ARCH="i386"
                FLAVOR="bionic"
            ;;
            "x86_64-apple-darwin14")
                TARGET_ARCH="amd64"
                FLAVOR="jammy"
            ;;
            "x86_64-pc-linux-gnu")
                TARGET_ARCH="amd64"
                FLAVOR="jammy"
            ;;
            "i686-pc-linux-gnu")
                TARGET_ARCH="i386"
                FLAVOR="bionic"
            ;;
        esac
        build
    done
fi
