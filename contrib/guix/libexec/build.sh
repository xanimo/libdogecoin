#!/usr/bin/env bash
export LC_ALL=C
set -e -o pipefail
export TZ=UTC

# Although Guix _does_ set umask when building its own packages (in our case,
# this is all packages in manifest.scm), it does not set it for `guix
# environment`. It does make sense for at least `guix environment --container`
# to set umask, so if that change gets merged upstream and we bump the
# time-machine to a commit which includes the aforementioned change, we can
# remove this line.
#
# This line should be placed before any commands which creates files.
umask 0022

if [ -n "$V" ]; then
    # Print both unexpanded (-v) and expanded (-x) forms of commands as they are
    # read from this file.
    set -vx
    # Set VERBOSE for CMake-based builds
    export VERBOSE="$V"
fi

# Check that required environment variables are set
cat << EOF
Required environment variables as seen inside the container:
    DIST_ARCHIVE_BASE: ${DIST_ARCHIVE_BASE:?not set}
    DISTNAME: ${DISTNAME:?not set}
    HOST: ${HOST:?not set}
    SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH:?not set}
    JOBS: ${JOBS:?not set}
    DISTSRC: ${DISTSRC:?not set}
    OUTDIR: ${OUTDIR:?not set}
EOF

ACTUAL_OUTDIR="${OUTDIR}"
OUTDIR="${DISTSRC}/output"

#####################
# Environment Setup #
#####################

# The depends folder also serves as a base-prefix for depends packages for
# $HOSTs after successfully building.
BASEPREFIX="${DISTSRC}/depends"

# Given a package name and an output name, return the path of that output in our
# current guix environment
store_path() {
    grep --extended-regexp "/[^-]{32}-${1}-[^-]+${2:+-${2}}" "${GUIX_ENVIRONMENT}/manifest" \
        | head --lines=1 \
        | sed --expression='s|\x29*$||' \
              --expression='s|^[[:space:]]*"||' \
              --expression='s|"[[:space:]]*$||'
}


# Set environment variables to point the NATIVE toolchain to the right
# includes/libs
NATIVE_GCC="$(store_path gcc-toolchain)"
NATIVE_GCC_STATIC="$(store_path gcc-toolchain static)"

unset LIBRARY_PATH
unset CPATH
unset C_INCLUDE_PATH
unset CPLUS_INCLUDE_PATH
unset OBJC_INCLUDE_PATH
unset OBJCPLUS_INCLUDE_PATH

export LIBRARY_PATH="${NATIVE_GCC}/lib:${NATIVE_GCC}/lib64:${NATIVE_GCC_STATIC}/lib:${NATIVE_GCC_STATIC}/lib64"
export C_INCLUDE_PATH="${NATIVE_GCC}/include"
export CPLUS_INCLUDE_PATH="${NATIVE_GCC}/include/c++:${NATIVE_GCC}/include"
export OBJC_INCLUDE_PATH="${NATIVE_GCC}/include"
export OBJCPLUS_INCLUDE_PATH="${NATIVE_GCC}/include/c++:${NATIVE_GCC}/include"

prepend_to_search_env_var() {
    export "${1}=${2}${!1:+:}${!1}"
}

case "$HOST" in
    *darwin*)
        # zlib for native_libtapi and native_cctools. Nothing else is needed
        # here: libdogecoin builds no dmg, so there is no cdrkit/libcap/bzip2
        # to satisfy, and no libc++ store path to export -- the Xcode 12.2 SDK
        # depends/hosts/darwin.mk points at carries its own libc++ headers.
        zlib_store_path=$(store_path "zlib")
        zlib_static_store_path=$(store_path "zlib" static)

        prepend_to_search_env_var LIBRARY_PATH "${zlib_static_store_path}/lib:${zlib_store_path}/lib"
        prepend_to_search_env_var C_INCLUDE_PATH "${zlib_store_path}/include"
        prepend_to_search_env_var CPLUS_INCLUDE_PATH "${zlib_store_path}/include"
        prepend_to_search_env_var OBJC_INCLUDE_PATH "${zlib_store_path}/include"
        prepend_to_search_env_var OBJCPLUS_INCLUDE_PATH "${zlib_store_path}/include"
        ;;
esac

# guix names its cross-toolchain packages, and the directories inside them,
# after the triple its cross-base accepts. That is not the -pc- form gitian uses
# for the two linux hosts, so normalise it here. HOST keeps gitian's spelling
# everywhere else: depends, contrib/scripts and the artifact names all use it.
case "$HOST" in
    i686-pc-linux-gnu)   GUIX_TARGET=i686-linux-gnu ;;
    x86_64-pc-linux-gnu) GUIX_TARGET=x86_64-linux-gnu ;;
    *)                   GUIX_TARGET="$HOST" ;;
esac

# Set environment variables to point the CROSS toolchain to the right
# includes/libs for $HOST
case "$HOST" in
    *mingw*)
        # Determine output paths to use in CROSS_* environment variables.
        # manifest.scm provides the winpthreads matching $HOST, so the name has
        # to be derived from $HOST rather than hardcoded to one architecture.
        case "$HOST" in
            i686-w64-mingw32)   win_arch=i686 ;;
            x86_64-w64-mingw32) win_arch=x86_64 ;;
            *)                  echo "Unhandled mingw host '$HOST'... Aborting..."; exit 1 ;;
        esac
        CROSS_GLIBC="$(store_path "mingw-w64-${win_arch}-winpthreads")"
        CROSS_GCC="$(store_path "gcc-cross-${GUIX_TARGET}")"
        CROSS_GCC_LIB_STORE="$(store_path "gcc-cross-${GUIX_TARGET}" lib)"
        CROSS_GCC_LIBS=( "${CROSS_GCC_LIB_STORE}/lib/gcc/${GUIX_TARGET}"/* ) # This expands to an array of directories...
        CROSS_GCC_LIB="${CROSS_GCC_LIBS[0]}" # ...we just want the first one (there should only be one)

        # The search path ordering is generally:
        #    1. gcc-related search paths
        #    2. libc-related search paths
        #    2. kernel-header-related search paths (not applicable to mingw-w64 hosts)
        export CROSS_C_INCLUDE_PATH="${CROSS_GCC_LIB}/include:${CROSS_GCC_LIB}/include-fixed:${CROSS_GLIBC}/include"
        export CROSS_CPLUS_INCLUDE_PATH="${CROSS_GCC}/include/c++:${CROSS_GCC}/include/c++/${GUIX_TARGET}:${CROSS_GCC}/include/c++/backward:${CROSS_C_INCLUDE_PATH}"
        export CROSS_LIBRARY_PATH="${CROSS_GCC_LIB_STORE}/lib:${CROSS_GCC}/${GUIX_TARGET}/lib:${CROSS_GCC_LIB}:${CROSS_GLIBC}/lib"
        ;;
    *darwin*)
        # The CROSS toolchain for darwin uses the SDK and ignores environment variables.
        # See depends/hosts/darwin.mk for more details.
        ;;
    *linux*)
        CROSS_GLIBC="$(store_path "glibc-cross-${GUIX_TARGET}")"
        CROSS_GLIBC_STATIC="$(store_path "glibc-cross-${GUIX_TARGET}" static)"
        CROSS_KERNEL="$(store_path "linux-libre-headers-cross-${GUIX_TARGET}")"
        CROSS_GCC="$(store_path "gcc-cross-${GUIX_TARGET}")"
        CROSS_GCC_LIB_STORE="$(store_path "gcc-cross-${GUIX_TARGET}" lib)"
        CROSS_GCC_LIBS=( "${CROSS_GCC_LIB_STORE}/lib/gcc/${GUIX_TARGET}"/* ) # This expands to an array of directories...
        CROSS_GCC_LIB="${CROSS_GCC_LIBS[0]}" # ...we just want the first one (there should only be one)

        export CROSS_C_INCLUDE_PATH="${CROSS_GCC_LIB}/include:${CROSS_GCC_LIB}/include-fixed:${CROSS_GLIBC}/include:${CROSS_KERNEL}/include"
        export CROSS_CPLUS_INCLUDE_PATH="${CROSS_GCC}/include/c++:${CROSS_GCC}/include/c++/${GUIX_TARGET}:${CROSS_GCC}/include/c++/backward:${CROSS_C_INCLUDE_PATH}"
        export CROSS_LIBRARY_PATH="${CROSS_GCC_LIB_STORE}/lib:${CROSS_GCC}/${GUIX_TARGET}/lib:${CROSS_GCC_LIB}:${CROSS_GLIBC}/lib:${CROSS_GLIBC_STATIC}/lib"
        ;;
    *)
        exit 1 ;;
esac

# Sanity check CROSS_*_PATH directories
IFS=':' read -ra PATHS <<< "${CROSS_C_INCLUDE_PATH}:${CROSS_CPLUS_INCLUDE_PATH}:${CROSS_LIBRARY_PATH}"
for p in "${PATHS[@]}"; do
    if [ -n "$p" ] && [ ! -d "$p" ]; then
        echo "'$p' doesn't exist or isn't a directory... Aborting..."
        exit 1
    fi
done

# Disable Guix ld auto-rpath behavior
case "$HOST" in
    *darwin*)
        # The auto-rpath behavior is necessary for darwin builds as some native
        # tools built by depends refer to and depend on Guix-built native
        # libraries
        #
        # After the native packages in depends are built, the ld wrapper should
        # no longer affect our build, as clang would instead reach for
        # x86_64-apple-darwin18-ld from cctools
        ;;
    *) export GUIX_LD_WRAPPER_DISABLE_RPATH=yes ;;
esac

# Make /usr/bin if it doesn't exist
[ -e /usr/bin ] || mkdir -p /usr/bin

# Symlink file and env to a conventional path
[ -e /usr/bin/file ] || ln -s --no-dereference "$(command -v file)" /usr/bin/file
[ -e /usr/bin/env ]  || ln -s --no-dereference "$(command -v env)"  /usr/bin/env

# Some configure scripts invoke /bin/pwd by absolute path, which the container
# does not provide. Note that pwd is also a shell builtin, so command -v returns
# "pwd" rather than a path; use type -P to get the coreutils binary.
[ -e /bin ] || mkdir -p /bin
[ -e /bin/pwd ] || ln -s --no-dereference "$(type -P pwd)" /bin/pwd

# Every script under contrib/scripts, which the build below delegates to, is
# "#!/bin/bash" and they invoke one another, so the interpreter has to exist at
# that path rather than just on PATH.
[ -e /bin/bash ] || ln -s --no-dereference "$(command -v bash)" /bin/bash

# Determine the correct value for -Wl,--dynamic-linker for the current $HOST
case "$HOST" in
    *linux*)
        glibc_dynamic_linker=$(
            case "$GUIX_TARGET" in
                i686-linux-gnu)        echo /lib/ld-linux.so.2 ;;
                x86_64-linux-gnu)      echo /lib64/ld-linux-x86-64.so.2 ;;
                arm-linux-gnueabihf)   echo /lib/ld-linux-armhf.so.3 ;;
                aarch64-linux-gnu)     echo /lib/ld-linux-aarch64.so.1 ;;
                *)                     exit 1 ;;
            esac
        )
        ;;
esac

# Environment variables for determinism
export TAR_OPTIONS="--owner=0 --group=0 --numeric-owner --mtime='@${SOURCE_DATE_EPOCH}' --sort=name"
export TZ="UTC"
case "$HOST" in
    *darwin*)
        # cctools AR, unlike GNU binutils AR, does not have a deterministic mode
        # or a configure flag to enable determinism by default, it only
        # understands if this env-var is set or not. See:
        #
        # https://github.com/tpoechtrager/cctools-port/blob/55562e4073dea0fbfd0b20e0bf69ffe6390c7f97/cctools/ar/archive.c#L334
        export ZERO_AR_DATE=yes
        ;;
esac

###########################
# Source Tarball Building #
###########################

GIT_ARCHIVE="${DIST_ARCHIVE_BASE}/${DISTNAME}.tar.gz"

# Create the source tarball if not already there
if [ ! -e "$GIT_ARCHIVE" ]; then
    mkdir -p "$(dirname "$GIT_ARCHIVE")"
    git archive --prefix="${DISTNAME}/" --output="$GIT_ARCHIVE" HEAD
fi

mkdir -p "$OUTDIR"

############
# Building #
############

# gitian does not configure or package libdogecoin itself: every descriptor
# (contrib/gitian-descriptors/gitian-{linux,osx,win}.yml) delegates to the
# project's own scripts,
#
#   ./contrib/scripts/build.sh --host <triple> --depends
#   ./contrib/scripts/pack.sh  --host=<triple> --prefix=build --commit=<version>
#
# so do the same. Reimplementing configure and packaging here would be a second
# copy to keep in step; delegating keeps the artifacts identical by
# construction. pack.sh names both the archive and the directory inside it
# after --host, which is why HOST stays spelled the way gitian spells it.

mkdir -p "$DISTSRC"
(
    cd "$DISTSRC"

    # Extract the source tarball
    tar --strip-components=1 -xf "${GIT_ARCHIVE}"

    # Build depends here rather than in the worktree: contrib/scripts/build.sh
    # --depends and pack.sh both resolve it as `pwd`/depends/<host>, so it has
    # to sit inside this tree. gitian builds it in its source copy for the same
    # reason. SOURCES_PATH and BASE_CACHE are absolute, so nothing is refetched
    # or rebuilt between hosts.
    make -C depends --jobs="$JOBS" HOST="$HOST" \
                                       ${V:+V=1} \
                                       ${SOURCES_PATH+SOURCES_PATH="$SOURCES_PATH"} \
                                       ${BASE_CACHE+BASE_CACHE="$BASE_CACHE"} \
                                       ${SDK_PATH+SDK_PATH="$SDK_PATH"} \
                                       i686_linux_CC=i686-linux-gnu-gcc \
                                       i686_linux_CXX=i686-linux-gnu-g++ \
                                       i686_linux_AR=i686-linux-gnu-ar \
                                       i686_linux_RANLIB=i686-linux-gnu-ranlib \
                                       i686_linux_NM=i686-linux-gnu-nm \
                                       i686_linux_STRIP=i686-linux-gnu-strip \
                                       x86_64_linux_CC=x86_64-linux-gnu-gcc \
                                       x86_64_linux_CXX=x86_64-linux-gnu-g++ \
                                       x86_64_linux_AR=x86_64-linux-gnu-ar \
                                       x86_64_linux_RANLIB=x86_64-linux-gnu-ranlib \
                                       x86_64_linux_NM=x86_64-linux-gnu-nm \
                                       x86_64_linux_STRIP=x86_64-linux-gnu-strip \
                                       FORCE_USE_SYSTEM_CLANG=1

    # depends staged its native tools (cctools et al) under the prefix
    export PATH="${BASEPREFIX}/${HOST}/native/bin:${PATH}"

    # Determinism. gitian gets this from faketime wrappers; we have
    # SOURCE_DATE_EPOCH plus these flags. darwin's clang takes neither.
    case "$HOST" in
        *linux*)  export CFLAGS="-O2 -g -ffile-prefix-map=${PWD}=." ;;
        *mingw*)  export CFLAGS="-O2 -g -fno-ident" ;;
        *darwin*) export CFLAGS="-O2 -g" ;;
    esac
    export CXXFLAGS="${CFLAGS}"

    # guix-build exports DISTNAME (libdogecoin-<version>) into the container but
    # not VERSION, and pack.sh drops the component entirely when --commit is
    # empty, giving libdogecoin-<host> where gitian gives
    # libdogecoin-<version>-<host>.
    ./contrib/scripts/build.sh --host "${HOST}" --depends
    ./contrib/scripts/pack.sh --host="${HOST}" --prefix=build \
                              --commit="${DISTNAME#libdogecoin-}"

    # pack.sh writes its archives to ./output inside DISTSRC, which is exactly
    # $OUTDIR (see the top of this script), so they are already in place.
)  # $DISTSRC

####################
# Output Staging   #
####################

rm -rf "$ACTUAL_OUTDIR"
mv --no-target-directory "$OUTDIR" "$ACTUAL_OUTDIR" \
    || ( rm -rf "$ACTUAL_OUTDIR" && exit 1 )

(
    cd /outdir-base
    {
        echo "$GIT_ARCHIVE"
        find "$ACTUAL_OUTDIR" -type f
    } | xargs realpath --relative-base="$PWD" \
      | xargs sha256sum \
      | sort -k2 \
      | sponge "$ACTUAL_OUTDIR"/SHA256SUMS.part
)
