#!/bin/bash
export LC_ALL=C
set -e -o pipefail

split_triplet() {
    c=0; ct=0;
    for i in $(echo $1 | tr "-" "\n")
    do
        host+="$(echo $i) "
        ct="$((c+=1))"
    done
    if [ $(("$ct"==4)) ]; then
        delete=pc
        host=$(echo ${host[@]/$delete})
    fi
    host=( "$host" )
    echo $host
}

detect_arch() {
    case "$1" in
        armv7l*|arm*)   arch=(arm arm32v7);;
        aarch64*)       arch=(aarch64 arm64v8);;
        i686*)          arch=(i686 i386);;
        x86_64*)        arch=(x86_64 amd64);;
        *)              arch="unknown:${uname_out}"
    esac
}

detect_os() {
    detect_arch
    uname_out="$(uname -s)"
    case "${uname_out}" in
        Linux*|linux*)
            vendor=linux
            case "${arch[0]}" in
                x86_64*|i686*)
                           vendor=pc-linux
                           os_suffix=gnu
                ;;
                arm*)      os_suffix=gnueabihf;;
                aarch64*)  os_suffix=gnu;;
            esac
            host_triplet=($arch-$vendor-$os_suffix "${arch[1]}")
        ;;
        Darwin*|darwin*)
            vendor=apple
            case "${arch[0]}" in
                *)         os_suffix=darwin;;
            esac
            host_triplet=($arch-$vendor-$os_suffix "${arch[1]}")
        ;;
        MINGW*|mingw32*)
            vendor=w64
            case "${arch[0]}" in
                x86_64*)  win_suffix=windows-"${arch[1]}";;
                i686*)    win_suffix=windows;;
                *)
            esac
            os_suffix=mingw32
            host_triplet=($arch-$vendor-$os_suffix $win_suffix)
        ;;
        *)  host_triplet=("unknown:${uname_out}" "")
    esac
}

if [[ "$@" ]]; then
    for i in "$@"
    do
    case $i in
        -h=*|--host=*)
            input="${i#*=}"
            detect_arch $(echo $(split_triplet $input))
            host_triplet=($input "${arch[1]}")
        ;;
        docker=1)
            detect_os $split_host
        ;;
        *)
            detect_os $split_host
        ;;
    esac
    done
else
    detect_os
fi

echo "${host_triplet[1]}"
