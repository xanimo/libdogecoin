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

check_tools() {
    for cmd in "$@"; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            echo "ERR: This script requires that '$cmd' is installed and available in your \$PATH"
            exit 1
        fi
    done
}

detect_os() {
    uname_out="$(uname -s)"
    case "${uname_out}" in
        Linux*)     machine=linux;;
        Darwin*)    machine=mac;;
        CYGWIN*)    machine=cygwin;;
        MINGW*)     machine=mingw;;
        *)          machine="unknown:${uname_out}"
    esac
}

# clean repository
if has_param '--clean' "$@"; then
    if [ -f "`pwd`/such*" ]; then
        rm "`pwd`/such*"
    fi

    if [ -f "`pwd`/sendtx*" ]; then
        rm "`pwd`/sendtx*"
    fi

    if [ -f "`pwd`/tests*" ]; then
        rm "`pwd`/tests*"
    fi

    if [ -d "`pwd`/.libs" ]; then
        rm -rf "`pwd`/.libs"
        make clean
        make clean-local
    fi
    if has_param '--nuke' "$@"; then
        git clean -xdff --exclude='/depends/SDKs/*' --exclude='/contrib/gitian/*'
    fi
fi

DEPENDS=""
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
    END=$((${#ALL_HOST_TRIPLETS[@]} - 1))
    for i in "${!ALL_HOST_TRIPLETS[@]}"
    do
    :
        TARGET_HOST_TRIPLET="${ALL_HOST_TRIPLETS[$i]}"
        
        if [ "$DEPENDS" = "1" ]; then
            DEPENDS="--depends"
        fi

        if ! has_param '--ci' "$@"; then
            ./contrib/scripts/setup.sh --host $TARGET_HOST_TRIPLET $DEPENDS
            ./contrib/scripts/build.sh --host $TARGET_HOST_TRIPLET $DEPENDS
        fi
        ./contrib/scripts/pack.sh --host=$TARGET_HOST_TRIPLET --prefix=build    
        TARGET_DIRECTORY=`find . -maxdepth 2 -type d -regex ".*libdogecoin.*$TARGET_HOST_TRIPLET"`
        if [ "$TARGET_DIRECTORY" != "" ]; then
            IFS="/" read -ra PARTS <<< "$TARGET_DIRECTORY"
            basedir="${PARTS[1]}"
            targetdir=$( echo ${TARGET_DIRECTORY##*/} )
            case "$TARGET_HOST_TRIPLET" in
                "arm-linux-gnueabihf")
                    check_tools arm-linux-gnueabihf-gcc
                    arm-linux-gnueabihf-gcc ./$basedir/$targetdir/examples/example.c -I./$basedir/$targetdir/include -L./$basedir/$targetdir/lib -ldogecoin -o ./$basedir/$targetdir/example
                    qemu-arm -E LD_LIBRARY_PATH=/usr/arm-linux-gnueabihf/lib/ /usr/arm-linux-gnueabihf/lib/ld-linux-armhf.so.3 ./$basedir/$targetdir/example
                ;;
                "aarch64-linux-gnu")
                    check_tools aarch64-linux-gnu-gcc
                    aarch64-linux-gnu-gcc ./$basedir/$targetdir/examples/example.c -I./$basedir/$targetdir/include -L./$basedir/$targetdir/lib -ldogecoin -o ./$basedir/$targetdir/example
                    qemu-aarch64 -E LD_LIBRARY_PATH=/usr/aarch64-linux-gnu/lib/ /usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1 ./$basedir/$targetdir/example
                ;;
                "x86_64-w64-mingw32")
                    check_tools x86_64-w64-mingw32-gcc
                    x86_64-w64-mingw32-gcc ./$basedir/$targetdir/examples/example.c -I./$basedir/$targetdir/include -L./$basedir/$targetdir/lib -ldogecoin -o ./$basedir/$targetdir/example
                    ./$basedir/$targetdir/example.exe
                ;;
                "i686-w64-mingw32")
                    COMPILER=`i686-w64-mingw32-gcc`
                    check_tools i686-w64-mingw32-gcc
                    i686-w64-mingw32-gcc ./$basedir/$targetdir/examples/example.c -I./$basedir/$targetdir/include -L./$basedir/$targetdir/lib -ldogecoin -o ./$basedir/$targetdir/example
                    ./$basedir/$targetdir/example.exe
                ;;
                "x86_64-apple-darwin14")
                    detect_os
                    case $machine in
                        "linux")
                            echo "Emulation unavailable when cross compiling $TARGET_HOST_TRIPLET"
                        ;; 
                        "mac")
                            check_tools gcc
                            gcc ./$basedir/$targetdir/examples/example.c -I./$basedir/$targetdir/include -L./$basedir/$targetdir/lib -ldogecoin -o ./$basedir/$targetdir/example
                            ./$basedir/$targetdir/example
                        ;;
                    esac
                ;;
                "x86_64-pc-linux-gnu")
                    check_tools x86_64-linux-gnu-gcc
                    x86_64-linux-gnu-gcc ./$basedir/$targetdir/examples/example.c -I./$basedir/$targetdir/include -L./$basedir/$targetdir/lib -ldogecoin -o ./$basedir/$targetdir/example
                    ./$basedir/$targetdir/example
                ;;
                "i686-pc-linux-gnu")
                    check_tools i686-linux-gnu-gcc
                    i686-linux-gnu-gcc ./$basedir/$targetdir/examples/example.c -I./$basedir/$targetdir/include -L./$basedir/$targetdir/lib -ldogecoin -o ./$basedir/$targetdir/example
                    ./$basedir/$targetdir/example
                ;;
            esac
        fi
        if [ -f "`pwd`/$basedir/$targetdir/example*" ]; then
            rm "`pwd`/$basedir/$targetdir/example*"
        fi
    done
fi