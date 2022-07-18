#!/bin/bash
export LC_ALL=C
set -e -o pipefail

if [ $# -eq 0 ]; then
    echo "No arguments provided"
    exit 1
fi

check_tools() {
    for cmd in "$@"; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            echo "ERR: This script requires that '$cmd' is installed and available in your \$PATH"
            exit 1
        fi
    done
}

check_tools ar

git_root() {
    git rev-parse --show-toplevel 2> /dev/null
}

same_dir() {
    local resolved1 resolved2
    resolved1="$(git_root)"
    resolved2="$(echo `pwd`)"
    [ "$resolved1" = "$resolved2" ]
}

if ! same_dir "${PWD}" "$(git_root)"; then
cat << EOF
ERR: This script must be invoked from the top level of the git repository
Hint: This may look something like:
    contrib/scripts/combine_lib.sh
EOF
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

LIB="`pwd`/.libs/libdogecoin.a `pwd`/include/dogecoin/libdogecoin.h"
EXE=""
FILES="$LIB "
DOCS="`pwd`/doc/*.md README.md"
PREFIX=""
BUILD_PATH=""
if has_param '--host' "$@"; then
    case "$2" in
        "arm-linux-gnueabihf")
            EXE="`pwd`/such `pwd`/sendtx"
            FILES="$LIB $EXE"
        ;;
        "aarch64-linux-gnu")
            EXE="`pwd`/such `pwd`/sendtx"
            FILES="$LIB $EXE"
        ;;
        "x86_64-w64-mingw32")
            EXE="`pwd`/such.exe `pwd`/sendtx.exe"
            FILES="$LIB $EXE"
        ;;
        "i686-w64-mingw32")
            EXE="`pwd`/such.exe `pwd`/sendtx.exe"
            FILES="$LIB $EXE"
        ;;
        "x86_64-apple-darwin14")
            EXE="`pwd`/such `pwd`/sendtx"
            FILES="$LIB $EXE"
        ;;
        "x86_64-pc-linux-gnu")
            EXE="`pwd`/such `pwd`/sendtx"
            FILES="$LIB $EXE"
        ;;
        "i686-pc-linux-gnu")
            EXE="`pwd`/such `pwd`/sendtx"
            FILES="$LIB $EXE"
        ;;
    esac

    if has_param '--docker' "$@"; then
        SUDO="bash -c"
    else
        SUDO="sudo -u $(whoami) -H bash -c"
    fi

    if [ "$TAG" != "" ]; then
        PREFIX=`pwd`/build/libdogecoin-$2-$TAG
        BUILD_PATH=./build/libdogecoin-$2-$TAG
        # check if target arch build output directory exists and has known file
        FILE=$BUILD_PATH/libdogecoin.a
        if test -f "$FILE"; then
            # if so delete existing files to accomodate clean build
            $SUDO "rm -rf $BUILD_PATH/*"
        else
            # else create directory
            $SUDO "mkdir -p $BUILD_PATH"
        fi
        # copy files to build directory
        $SUDO "cp -f $FILES $BUILD_PATH"
        # output sha256 checksums to new text file
        sha256sum $PREFIX/* >> $2-$TAG-checksums.txt
        $SUDO "mkdir -p $PREFIX $BUILD_PATH/docs"
        $SUDO "cp $FILES $BUILD_PATH"
        $SUDO "cp $DOCS $BUILD_PATH/docs"
        sha256sum $BUILD_PATH/docs/* >> $2-$TAG-checksums.txt

        if has_param '--package' "$@"; then
            pushd $BUILD_PATH
                tar -czvf "$2-$TAG.tar.gz" *
            popd
        fi
    fi
fi
