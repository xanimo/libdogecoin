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
    SUDO="sudo -u $(whoami) -H bash -c"
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

        # parse repository url to fetch username
        # url="git://github.com/some-user/my-repo.git"
        # url="https://github.com/some-user/my-repo.git"
        url=`git config --get remote.origin.url`

        re="^(https|git)(:\/\/|@)([^\/:]+)[\/:]([^\/:]+)\/(.+)(.git)*$"

        if [[ $url =~ $re ]]; then    
            protocol=${BASH_REMATCH[1]}
            separator=${BASH_REMATCH[2]}
            hostname=${BASH_REMATCH[3]}
            # only need user but leaving other vars in case others find useful
            user=${BASH_REMATCH[4]}
            repo=${BASH_REMATCH[5]}
        fi

        # sign sha256 checksum file
        gpg --detach-sign --yes -o $2-$TAG-checksums.txt.sig ./$2-$TAG-checksums.txt

        # verify good signature
        gpg --verify $2-$TAG-checksums.txt.sig ./$2-$TAG-checksums.txt
        
        $SUDO "mkdir -p ./contrib/sigs/$2-$TAG/$user"
        $SUDO "chmod u=rwx,g=r,o=r ./contrib/sigs/$2-$TAG/$user"
        $SUDO "mv -u ./$2-$TAG-checksums.txt.sig ./contrib/sigs/$2-$TAG/$user/$2-$TAG-checksums.txt.sig"
        $SUDO "mv -u ./$2-$TAG-checksums.txt ./contrib/sigs/$2-$TAG/$user/$2-$TAG-checksums.txt"
    else
        PREFIX=`pwd`/build/libdogecoin-$2
        BUILD_PATH=./build/libdogecoin-$2
        $SUDO "rm -rf $BUILD_PATH"
        $SUDO "mkdir -p $BUILD_PATH $BUILD_PATH/docs"
        $SUDO "cp $FILES $BUILD_PATH"
        $SUDO "cp $DOCS $BUILD_PATH/docs"
    fi

    if has_param '--package' "$@"; then
        if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
            git tag -d $TAG
        fi
        pushd $BUILD_PATH
            tar -czvf "$2-$TAG.tar.gz" *
            gpg --armor --detach-sign --yes "$2-$TAG.tar.gz"
            gpg --verify $2-$TAG.tar.gz.asc $2-$TAG.tar.gz
            mv $2-$TAG.tar.gz ../$2-$TAG.tar.gz
            mv $2-$TAG.tar.gz.asc ../$2-$TAG.tar.gz.asc
        popd
        rm -rf $BUILD_PATH
        sha256sum ./build/$2-$TAG.tar.gz ./build/$2-$TAG.tar.gz.asc >> ./contrib/sigs/$2-$TAG/$user/$2-$TAG-checksums.txt
    fi
fi
