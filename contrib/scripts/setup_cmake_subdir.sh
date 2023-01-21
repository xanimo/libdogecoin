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

if has_param '--path' "$@"; then
    echo $2
    # check if build dir exists
    if test -d $2/build; then
        echo "exists"
    else
        echo "doesn't exist"
        mkdir -p $2/build
    fi
    pushd $2/build
        cmake \
        -DEVENT_DISABLE_SHARED=ON \
        -DEVENT__DISABLE_OPENSSL=ON \
        -DEVENT__DISABLE_LIBEVENT_REGRESS=ON \
        -DEVENT__DISABLE_SAMPLES=ON \
        -DEVENT__DISABLE_DEPENDENCY_TRACKING=ON \
        -DEVENT__ENABLE_OPTION_CHECKING=ON \
        ../.
        cmake --build .
    popd
fi
