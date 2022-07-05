#!/bin/bash

export LC_ALL=C
set -e -o pipefail

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

TARGET_HOST_TRIPLET=""
TARGET_PLATFORM=""
TARGET_ARCH=""
if has_param '--host' "$@"; then
    export TARGET_HOST_TRIPLET=$2
    case "$2" in
        "arm-linux-gnueabihf")
            TARGET_PLATFORM="linux"
            TARGET_ARCH="arm"
        ;;
        "aarch64-linux-gnu")
            TARGET_PLATFORM="linux"
            TARGET_ARCH="arm64"
        ;;
        "x86_64-w64-mingw32")
            TARGET_PLATFORM="windows"
            TARGET_ARCH="amd64"
        ;;
        "i686-w64-mingw32")
            TARGET_PLATFORM="windows"
            TARGET_ARCH="386"
        ;;
        "x86_64-apple-darwin14")
            TARGET_PLATFORM="darwin"
            TARGET_ARCH="amd64"
        ;;
        "x86_64-pc-linux-gnu")
            TARGET_PLATFORM="linux"
            TARGET_ARCH="amd64"
        ;;
        "i686-pc-linux-gnu")
            TARGET_PLATFORM="linux"
            TARGET_ARCH="386"
        ;;
    esac
fi

DIR_ROOT=`pwd`

pushd $DIR_ROOT/wrappers/golang/libdogecoin

if ! command -v go &> /dev/null
then
    wget https://go.dev/dl/go1.18.2.linux-amd64.tar.gz
    echo "e54bec97a1a5d230fc2f9ad0880fcbabb5888f30ed9666eca4a91c5a32e86cbc go1.18.2.linux-amd64.tar.gz" | sha256sum -c
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.18.2.linux-amd64.tar.gz
    sudo mv /usr/local/go/bin/go /usr/local/bin/go
    echo "export PATH=$PATH:/usr/local/bin/go" >> ~/.bashrc
    source ~/.bashrc
    sudo rm go1.18.2.linux-amd64.tar.gz
    if ! command -v go &> /dev/null
    then
        echo "go could not be found"
        exit
    fi
fi

export CGO_CFLAGS="-I${DIR_ROOT} -I${DIR_ROOT}/include -I${DIR_ROOT}/include/dogecoin -I${DIR_ROOT}/include/dogecoin/ -I${DIR_ROOT}/src/secp256k1/include -I${DIR_ROOT}/src/secp256k1/src -I${DIR_ROOT}/depends/${TARGET_HOST_TRIPLET}/include -fPIC ${CGO_CFLAGS}"
export CGO_LDFLAGS="-L${DIR_ROOT}/.libs -L${DIR_ROOT}/src/secp256k1/.libs -L${DIR_ROOT}/depends/${TARGET_HOST_TRIPLET}/lib -ldogecoin -levent_core -levent -lpthread -lsecp256k1 -lsecp256k1_precomputed -lm -Wl,-rpath=${DIR_ROOT}/.libs ${CGO_LDFLAGS}"
env CGO_ENABLED=1 CGO_CFLAGS="$CGO_CFLAGS" CGO_LDFLAGS="$CGO_LDFLAGS" GOOS=$TARGET_PLATFORM GOARCH=$TARGET_ARCH go build -x -work -ldflags '-linkmode external -extldflags "-static"' -o libdogecoin_$TARGET_ARCH

GOOS=$TARGET_PLATFORM GOARCH=$TARGET_ARCH go test -v

go clean -x -i -testcache

mkdir -p $DIR_ROOT/build/wrappers/golang/libdogecoin_$TARGET_ARCH
cp libdogecoin_$TARGET_ARCH $DIR_ROOT/build/wrappers/golang/libdogecoin_$TARGET_ARCH
rm libdogecoin_$TARGET_ARCH

popd