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

HOST=""
FILES=""
DOCS="`pwd`/doc/*.md README.md"
if has_param '--host' "$@"; then
    case "$2" in
        "arm-linux-gnueabihf")
            FILES="`pwd`/.libs/libdogecoin.a `pwd`/include/dogecoin/libdogecoin.h `pwd`/such `pwd`/sendtx"
        ;;
        "aarch64-linux-gnu")
            FILES="`pwd`/.libs/libdogecoin.a `pwd`/include/dogecoin/libdogecoin.h `pwd`/such `pwd`/sendtx"
        ;;
        "x86_64-w64-mingw32")
            FILES="`pwd`/.libs/libdogecoin.a `pwd`/include/dogecoin/libdogecoin.h `pwd`/such.exe `pwd`/sendtx.exe"
        ;;
        "i686-w64-mingw32")
            FILES="`pwd`/.libs/libdogecoin.a `pwd`/include/dogecoin/libdogecoin.h `pwd`/such.exe `pwd`/sendtx.exe"
        ;;
        "x86_64-apple-darwin14")
            FILES="`pwd`/.libs/libdogecoin.a `pwd`/include/dogecoin/libdogecoin.h `pwd`/such `pwd`/sendtx"
        ;;
        "x86_64-pc-linux-gnu") 
            FILES="`pwd`/.libs/libdogecoin.a `pwd`/include/dogecoin/libdogecoin.h `pwd`/such `pwd`/sendtx"
        ;;
        "i686-pc-linux-gnu")
            FILES="`pwd`/.libs/libdogecoin.a `pwd`/include/dogecoin/libdogecoin.h `pwd`/such `pwd`/sendtx"
        ;;
    esac
    if [ "$TAG" != "" ]; then
        sudo rm -rf ./build/*
        sudo mkdir -p ./build/libdogecoin-$2-$TAG
        sudo cp $FILES ./build/libdogecoin-$2-$TAG
        sha256sum ./build/libdogecoin-$2-$TAG/* > $2-$TAG-checksums.txt

        # url="git://github.com/some-user/my-repo.git"
        # url="https://github.com/some-user/my-repo.git"
        url=`git config --get remote.origin.url`

        re="^(https|git)(:\/\/|@)([^\/:]+)[\/:]([^\/:]+)\/(.+)(.git)*$"

        if [[ $url =~ $re ]]; then    
            protocol=${BASH_REMATCH[1]}
            separator=${BASH_REMATCH[2]}
            hostname=${BASH_REMATCH[3]}
            user=${BASH_REMATCH[4]}
            repo=${BASH_REMATCH[5]}
        fi
        gpg --detach-sign -o $user.sig ./$2-$TAG-checksums.txt
        gpg --verify $user.sig ./$2-$TAG-checksums.txt
        sudo mkdir -p ./contrib/sigs/$2-$TAG/$user
        sudo mv ./$user.sig ./contrib/sigs/$2-$TAG/$user/$user.sig
        sudo mv ./$2-$TAG-checksums.txt ./contrib/sigs/$2-$TAG/$user/$2-$TAG-checksums.txt
    else
        sudo rm -rf ./build/libdogecoin-$2
        sudo mkdir -p ./build/libdogecoin-$2
        sudo cp $FILES ./build/libdogecoin-$2
        sudo mkdir -p ./build/libdogecoin-$2/docs
        sudo cp $DOCS ./build/libdogecoin-$2/docs
    fi
fi
