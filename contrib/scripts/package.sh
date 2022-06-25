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

if has_param '--host' "$@"; then
    case "$2" in
        "arm-linux-gnueabihf")
        ;;
        "aarch64-linux-gnu")
        ;;
        "x86_64-w64-mingw32")
            
        ;;
        "i686-w64-mingw32")
        ;;
        "x86_64-apple-darwin14")
        ;;
        "x86_64-pc-linux-gnu") 
        ;;
        "i686-pc-linux-gnu")
        ;;
    esac
    sudo mkdir -p ./build/libdogecoin-$2
fi
