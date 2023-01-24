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

case $(uname | tr '[:upper:]' '[:lower:]') in
  linux*)
    export OS_NAME=linux
    ;;
  darwin*)
    export OS_NAME=osx
    ;;
  msys*)
    export OS_NAME=windows
    ;;
  *)
    export OS_NAME=notset
    ;;
esac

if has_param '--path' "$@"; then
    echo $2
    # check if build dir exists

    if test -d $2//build; then
        echo "exists"
    else
        echo "doesn't exist"
        mkdir -p $2//build
    fi
    if [ $OS_NAME == "windows" ]; then
        echo $OS_NAME
        config=' -DEVENT__DISABLE_SHARED=ON -DEVENT__DISABLE_LIBEVENT_REGRESS=ON -DEVENT__DISABLE_DEPENDENCY_TRACKING=ON -DEVENT__ENABLE_OPTION_CHECKING=ON'
    fi
    pushd $2//build
        cmake -DEVENT__DISABLE_OPENSSL=ON -DEVENT__DISABLE_SAMPLES=ON ${config} ..
        cmake --build .
    popd
fi
