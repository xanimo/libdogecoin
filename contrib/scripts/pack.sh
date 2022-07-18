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

check_error() {
    if [ "$ERROR" ]; then
        echo "Please provide a host to build and try again."
        exit $ERROR
    fi
}

BUILD_PREFIX=""
BUILD_SUFFIX=""
COMMIT=""
DOCUMENTATION="`pwd`/doc/*.md README.md `pwd`/contrib/scripts/README-scripts.md  LICENSE"
DOCKER=""
ERROR=""
HOST=""
LIB="`pwd`/.libs/libdogecoin.a `pwd`/include/dogecoin/libdogecoin.h"
SUDO="sudo -u $(whoami) -H bash -c"
SHA=sha256sum
BINARY_SUFFIX=""
for i in "$@"
do
case $i in
    -c=*|--commit=*)
        COMMIT="${i#*=}"
    ;;
    --docker)
        DOCKER=1
    ;;
    -h=*|--host=*)
        HOST="${i#*=}"
    ;;
    -p=*|--prefix=*)
        BUILD_PREFIX="${i#*=}"
    ;;
    -t=*|--tag=*)
        TAG="${i#*=}"
    ;;
    -l=*|--lib=*)
        DIR="${i#*=}"
    ;;
    *)
        ERROR=1
    ;;
esac
done

check_error

echo $SUDO before
# strip sudo if using docker
if [ "$DOCKER" ]; then
    SUDO=""
fi
echo $SUDO after

# set up build directory if it doesn't exist
if [ ! -d "$BUILD_PREFIX" ]; then
    $SUDO mkdir -p `pwd`/$BUILD_PREFIX
fi

# set binary file extension and simulataneously bounds check host
if [ "$HOST" ]; then
    case "$HOST" in
        "arm-linux-gnueabihf")
        ;;
        "aarch64-linux-gnu")
        ;;
        "x86_64-w64-mingw32")
            BINARY_SUFFIX=".exe"
        ;;
        "i686-w64-mingw32")
            BINARY_SUFFIX=".exe"
        ;;
        "x86_64-apple-darwin14")
        ;;
        "x86_64-pc-linux-gnu")
        ;;
        "i686-pc-linux-gnu")
        ;;
        *)
            ERROR=1
        ;;
    esac
    BUILD_SUFFIX="libdogecoin-$HOST"
    EXE="`pwd`/such$BINARY_SUFFIX `pwd`/sendtx$BINARY_SUFFIX"
    FILES="$LIB $EXE"
fi

echo $EXE

check_error

# allow either tag or commit for git repositories
if [ "$TAG" ] && [ "$COMMIT" ]; then
    echo "Please specify only a commit or a tag and try again."
    exit 1
else
    if [ "$TAG" ]; then
        # logic may need refining
        if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
            echo "$TAG is a legitimate commit"
            # git tag -f -s $TAG -m "$TAG"
        else
            echo "$TAG does not exist. Exiting..."
            exit 1
            # git tag -s $TAG -m "$TAG"
        fi
        BUILD_SUFFIX=$BUILD_SUFFIX-$TAG
    else 
        if [ "$COMMIT" ]; then
            BUILD_SUFFIX=$BUILD_SUFFIX-$COMMIT
        fi
    fi
fi

echo HOST = ${HOST}
echo PREFIX = ${PREFIX}
echo SEARCH PATH = ${SEARCHPATH}
echo DIRS = ${DIR}
echo $BUILD_PREFIX/$BUILD_SUFFIX
echo $BUILD_SUFFIX

if [ ! -d "output" ]; then
    $SUDO mkdir -p "`pwd`/output"
fi

if [ -d "output/$BUILD_SUFFIX" ]; then
    $SUDO rm -rf "output/$BUILD_SUFFIX"
fi

if [ ! -d "$BUILD_PREFIX/$BUILD_SUFFIX" ]; then
    $SUDO mkdir -p "$BUILD_PREFIX/$BUILD_SUFFIX"
fi

$SUDO cp -r $FILES "$BUILD_PREFIX/$BUILD_SUFFIX"
pushd $BUILD_PREFIX/$BUILD_SUFFIX
    $SHA * > checksums.txt
popd

if [ ! -d "$BUILD_PREFIX/$BUILD_SUFFIX/docs" ]; then
    $SUDO mkdir -p "$BUILD_PREFIX/$BUILD_SUFFIX/docs"
fi

$SUDO cp -r $DOCUMENTATION "$BUILD_PREFIX/$BUILD_SUFFIX/docs"

$SUDO mv `pwd`/$BUILD_PREFIX/* `pwd`/output

# clean up
# $SUDO rm -rf $BUILD_PREFIX