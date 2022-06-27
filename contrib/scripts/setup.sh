#!/bin/bash
export LC_ALL=C
set -e -o pipefail

# please note that this script should be ran as the current user but with sudo privileges as seen below:
# sudo -u $(whoami) -H bash -c "./contrib/scripts/setup.sh --host <host triplet> --depends"
# unless of course you are targetting docker which will not allow and should not be used with 'sudo'.

PROJECT_ROOT=$(git rev-parse --show-toplevel 2> /dev/null)
$PROJECT_ROOT/contrib/scripts/check_dir.sh

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

COMMON_PACKAGES="autoconf automake autotools-dev bison build-essential curl ca-certificates libtool libtool-bin pkg-config procps python3 python3.10-venv rsync valgrind"
ARCH_PACKAGES=""
OS_PACKAGES=""
DEPENDS=""
DOCKER=0
TARGET_HOST_TRIPLET=""
TARGET_ARCH=""

if has_param '--depends' "$@"; then
    DEPENDS=1
else
    COMMON_PACKAGES+=" libevent-dev"
fi

if has_param '--docker' "$@"; then
    DOCKER=1
    COMMON_PACKAGES+=" git"
fi

if has_param '--host' "$@"; then
    case "$2" in
        "arm-linux-gnueabihf") 
            if [ $DEPENDS ]; then
                ARCH_PACKAGES+="g++-arm-linux-gnueabihf "
            fi
            ARCH_PACKAGES+="qemu-user-static qemu-user"
            TARGET_ARCH="armhf"
        ;;
        "aarch64-linux-gnu")
            if [ $DEPENDS ]; then
                ARCH_PACKAGES+="g++-aarch64-linux-gnu "
            fi
            ARCH_PACKAGES+="qemu-user-static qemu-user"
            TARGET_ARCH="arm64"
        ;;
        "x86_64-w64-mingw32")
            if [ $DEPENDS ]; then
                ARCH_PACKAGES+="g++-mingw-w64 "
            fi
            ARCH_PACKAGES+="nsis wine64 wine-stable bc wine-binfmt"
            TARGET_ARCH="amd64"
            sudo dpkg --add-architecture $TARGET_ARCH
            sudo update-alternatives --set x86_64-w64-mingw32-gcc  /usr/bin/x86_64-w64-mingw32-gcc-posix
            sudo update-alternatives --set x86_64-w64-mingw32-g++  /usr/bin/x86_64-w64-mingw32-g++-posix
            sudo update-binfmts --import /usr/share/binfmts/wine
        ;;
        "i686-w64-mingw32")
            if [ $DEPENDS ]; then
                ARCH_PACKAGES+="g++-mingw-w64 "
            fi
            ARCH_PACKAGES+="nsis wine32 wine-stable bc wine-binfmt"
            TARGET_ARCH="i386"
            sudo dpkg --add-architecture $TARGET_ARCH
            sudo update-alternatives --set i686-w64-mingw32-gcc /usr/bin/i686-w64-mingw32-gcc-posix
            sudo update-alternatives --set i686-w64-mingw32-g++  /usr/bin/i686-w64-mingw32-g++-posix
            sudo update-binfmts --import /usr/share/binfmts/wine
        ;;
        "x86_64-apple-darwin14")
            OS_PACKAGES="cmake zlib xorriso"
            ARCH_PACKAGES+="g++ cmake libz-dev libcap-dev libtinfo5 libplist-utils librsvg2-bin libz-dev libtiff-tools libncurses-dev lld python2-minimal python-dev python-setuptools"
            TARGET_ARCH="amd64"
        ;;
        "x86_64-pc-linux-gnu") 
            ARCH_PACKAGES="python3-dev python3-dbg python2-minimal"
            TARGET_ARCH="amd64"
        ;;
        "i686-pc-linux-gnu")
            if [ $DEPENDS ]; then
                ARCH_PACKAGES+="g++-multilib "
            fi
            ARCH_PACKAGES+="bc"
            TARGET_ARCH="i386"
            sudo dpkg --add-architecture $TARGET_ARCH
        ;;
    esac
    TARGET_HOST_TRIPLET=$2
fi

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

setup_brew() {
    if ! command -v brew &> /dev/null
    then
        if [[ $EUID -ne 0 ]]; then
            # xcode-select --install
            # mkdir /usr/local/Frameworks
            # chown $(whoami):admin /usr/local/Frameworks
            NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
            echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >> /home/$USER/.profile
            eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
        fi
    fi
    brew update
    brew install automake coreutils libtool python3 $OS_PACKAGES 
}

setup_linux() {
    USE_SUDO=
    if [[ $DOCKER != 1 ]]; then
        USE_SUDO="sudo"
    fi
    $USE_SUDO apt-get update
    DEBIAN_FRONTEND=noninteractive $USE_SUDO apt-get install --no-install-recommends -y $COMMON_PACKAGES $ARCH_PACKAGES
}

OPTIONS=""
case "$TARGET_HOST_TRIPLET" in
    "x86_64-w64-mingw32")
        setup_linux
        if [[ $EUID == 0 ]] || [[ $DOCKER == 1 ]]; then
            dpkg -s mono-runtime && sudo apt-get remove mono-runtime || echo "Very nothing to uninstall."
            update-alternatives --set x86_64-w64-mingw32-gcc  /usr/bin/x86_64-w64-mingw32-gcc-posix
            update-alternatives --set x86_64-w64-mingw32-g++  /usr/bin/x86_64-w64-mingw32-g++-posix
            update-binfmts --import /usr/share/binfmts/wine
        fi
    ;;
    "i686-w64-mingw32")
        setup_linux
        if [[ $EUID == 0 ]] || [[ $DOCKER == 1 ]]; then
            dpkg -s mono-runtime && sudo apt-get remove mono-runtime || echo "Very nothing to uninstall."
            update-alternatives --set i686-w64-mingw32-gcc /usr/bin/i686-w64-mingw32-gcc-posix
            update-alternatives --set i686-w64-mingw32-g++  /usr/bin/i686-w64-mingw32-g++-posix
            update-binfmts --import /usr/share/binfmts/wine
        fi
    ;;
    "x86_64-apple-darwin14")
        detect_os
        case $machine in
            "linux")    setup_linux;; 
            "mac")      setup_brew;;
        esac
        contrib/scripts/sdk.sh
    ;;
    *)
        setup_linux
    ;;
esac

NO_X_COMPILE=("x86_64-pc-linux-gnu" "i686-pc-linux-gnu" "x86_64-apple-darwin14");
if [ "$DEPENDS" = "1" ]; then
    match=0
    for str in ${NO_X_COMPILE[@]}; do
        if [[ "$HOST" == "$str" ]]; then
            match=1
            break
        fi
    done
    if [[ $match = 0 ]]; then
        OPTIONS="CROSS_COMPILE='yes' "
    fi
    OPTIONS+="SPEED=slow V=1"
    make -C depends HOST=$TARGET_HOST_TRIPLET $OPTIONS
fi
