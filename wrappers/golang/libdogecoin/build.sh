#!/bin/bash

set -e

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

build() {
    env CGO_ENABLED=1 \
    CGO_CFLAGS="$CGO_CFLAGS" \
    CGO_LDFLAGS="$CGO_LDFLAGS" \
    GOOS=$TARGET_PLATFORM \
    GOARCH=$TARGET_ARCH \
    CC=$TOOLCHAIN \
    CC_FOR_${GOOS}_${GOARCH}=$(gcc -dumpmachine)-gcc \
    PKG_CONFIG_PATH=$PKG_CONFIG_PATH \
    LIBTOOL_APP_LDFLAGS=$LIBTOOL_APP_LDFLAGS \
    go build -x -ldflags '-linkmode external -extldflags "-static"' -o libdogecoin_$TARGET_ARCH
}

clean_move() {
    go clean -x -i -testcache -cache
    mkdir -p $DIR_ROOT/build/wrappers/golang/$TARGET_HOST_TRIPLET/libdogecoin_$TARGET_ARCH
    cp libdogecoin_$TARGET_ARCH $DIR_ROOT/build/wrappers/golang/$TARGET_HOST_TRIPLET/libdogecoin_$TARGET_ARCH
    rm libdogecoin_$TARGET_ARCH
}

TARGET_HOST_TRIPLET=""
TARGET_PLATFORM=""
TARGET_ARCH=""
TOOLCHAIN_ARCH=""
TOOLCHAIN_SUFFIX=""
TOOLCHAIN=""
export DIR_ROOT=`pwd`
COMMON_LIBS="-ldogecoin -levent_core -levent -lsecp256k1 -lsecp256k1_precomputed -lm"
CGO_CFLAGS="-I$DIR_ROOT -I$DIR_ROOT/include -I$DIR_ROOT/include/dogecoin -I$DIR_ROOT/include/dogecoin/ -I$DIR_ROOT/src/secp256k1/include -I$DIR_ROOT/src/secp256k1/src"
CGO_LDFLAGS="-L$DIR_ROOT/.libs -L$DIR_ROOT/src/secp256k1/.libs"
LIBTOOL_APP_LDFLAGS="-all-static"
if has_param '--host' "$@"; then
    export TARGET_HOST_TRIPLET=$2
    case "$2" in
        "arm-linux-gnueabihf")
            TARGET_PLATFORM="linux"
            TARGET_ARCH="arm"
            TOOLCHAIN_ARCH="arm"
            TOOLCHAIN_SUFFIX="gnueabihf"
            TOOLCHAIN=$2-gcc
            CGO_CFLAGS+=" -I$DIR_ROOT/depends/$2/include -fPIC"
            CGO_LDFLAGS+=" -L$DIR_ROOT/depends/$2/lib $COMMON_LIBS -lpthread -Wl,-rpath=$DIR_ROOT/.libs"
        ;;
        "aarch64-linux-gnu")
            TARGET_PLATFORM="linux"
            TARGET_ARCH="arm64"
            TOOLCHAIN_ARCH="aarch64"
            TOOLCHAIN_SUFFIX="gnu"
            TOOLCHAIN=$2-gcc
            CGO_CFLAGS+=" -I$DIR_ROOT/depends/$2/include -fPIC"
            CGO_LDFLAGS+=" -L$DIR_ROOT/depends/$2/lib $COMMON_LIBS -lpthread -Wl,-rpath=$DIR_ROOT/.libs"
        ;;
        "x86_64-w64-mingw32")
            TARGET_PLATFORM="linux"
            TARGET_ARCH="amd64"
            TOOLCHAIN_ARCH="x86_64"
            TOOLCHAIN_SUFFIX="gnu"
            TOOLCHAIN=$2-gcc
            CGO_CFLAGS+=" -I$DIR_ROOT/depends/$2/include -fPIC"
            CGO_LDFLAGS+=" -L$DIR_ROOT/depends/$2/lib $COMMON_LIBS -lpthread -lwinpthread -Wl,-rpath=$DIR_ROOT/.libs"
        ;;
        "i686-w64-mingw32")
            TARGET_PLATFORM="linux"
            TARGET_ARCH="386"
            TOOLCHAIN_ARCH="i686"
            TOOLCHAIN_SUFFIX="gnu"
            TOOLCHAIN=$2-gcc
            CGO_CFLAGS+=" -I$DIR_ROOT/depends/$2/include -fPIC"
            CGO_LDFLAGS+=" -L$DIR_ROOT/depends/$2/lib $COMMON_LIBS -lpthread -lwinpthread -Wl,-rpath=$DIR_ROOT/.libs"
        ;;
        "x86_64-apple-darwin14")
            TARGET_PLATFORM="linux"
            TARGET_ARCH="amd64"
            TOOLCHAIN_ARCH="x86_64"
            TOOLCHAIN_SUFFIX="gnu"
            TOOLCHAIN="clang"
            CGO_CFLAGS+=" -I$DIR_ROOT/depends/$2/include -fPIC"
            CGO_LDFLAGS+=" -L$DIR_ROOT/depends/$2/lib $COMMON_LIBS -lpthread -Wl,-rpath=$DIR_ROOT/.libs"
        ;;
        "x86_64-pc-linux-gnu")
            TARGET_PLATFORM="linux"
            TARGET_ARCH="amd64"
            TOOLCHAIN_ARCH="x86_64"
            TOOLCHAIN_SUFFIX="gnu"
            TOOLCHAIN=$(gcc -dumpmachine)-gcc
            CGO_CFLAGS+=" -I$DIR_ROOT/depends/$2/include -fPIC"
            CGO_LDFLAGS+=" -L$DIR_ROOT/depends/$2/lib $COMMON_LIBS -lpthread -Wl,-rpath=$DIR_ROOT/.libs"
        ;;
        "i686-pc-linux-gnu")
            TARGET_PLATFORM="linux"
            TARGET_ARCH="386"
            TOOLCHAIN_ARCH="i386"
            TOOLCHAIN_SUFFIX="gnu"
            TOOLCHAIN=$(gcc -dumpmachine)-gcc
            CGO_CFLAGS+=" -I$DIR_ROOT/depends/$2/include -fPIC"
            CGO_LDFLAGS+=" -L$DIR_ROOT/depends/$2/lib $COMMON_LIBS -lpthread -Wl,-rpath=$DIR_ROOT/.libs"
        ;;
    esac
    export TARGET_HOST_TRIPLET
    export TARGET_PLATFORM
    export TARGET_ARCH
    export TOOLCHAIN_ARCH
    export TOOLCHAIN_SUFFIX
    export TOOLCHAIN
    CGO_CFLAGS+=" ${CGO_CFLAGS}"
    CGO_LDFLAGS+=" ${CGO_LDFLAGS}"
    PKG_CONFIG_PATH="$DIR_ROOT/depends/$2/lib/pkgconfig"
fi

export CGO_CFLAGS
export CGO_LDFLAGS
pushd $DIR_ROOT/wrappers/golang/libdogecoin

if ! command -v go &> /dev/null
then
    wget https://go.dev/dl/go1.18.2.linux-amd64.tar.gz
    echo "e54bec97a1a5d230fc2f9ad0880fcbabb5888f30ed9666eca4a91c5a32e86cbc go1.18.2.linux-amd64.tar.gz" | sha256sum -c
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.18.2.linux-amd64.tar.gz
    echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc
    source ~/.bashrc
    if ! command -v go &> /dev/null
    then
        echo "go could not be found"
        exit
    fi
fi

go build -x -work -ldflags '-linkmode external -extldflags "-static"' .

go test -v

go clean -x -i -testcache

    case "$TARGET_HOST_TRIPLET" in
        "arm-linux-gnueabihf")
            build
            # GOOS=$TARGET_PLATFORM GOARCH=$TARGET_ARCH go test -v
        ;;
        "aarch64-linux-gnu")
            build
            # GOOS=$TARGET_PLATFORM GOARCH=$TARGET_ARCH go test -v
            clean_move
        ;;
        "x86_64-w64-mingw32")
            build
            # GOOS=$TARGET_PLATFORM GOARCH=$TARGET_ARCH go test -v
            clean_move
        ;;
        "i686-w64-mingw32")
            build
            GOOS=$TARGET_PLATFORM GOARCH=$TARGET_ARCH go test -v
            clean_move
        ;;
        "x86_64-apple-darwin14")
            # build
            # GOOS=$TARGET_PLATFORM GOARCH=$TARGET_ARCH go test -v
        ;;
        "x86_64-pc-linux-gnu")
            build
            GOOS=$TARGET_PLATFORM GOARCH=$TARGET_ARCH go test -v
            clean_move
        ;;
        "i686-pc-linux-gnu")
            # build
            # GOOS=$TARGET_PLATFORM GOARCH=$TARGET_ARCH go test -v
            # clean_move
        ;;
    esac
popd