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

USE_SUDO=sudo
if has_param '--docker' "$@"; then
    USE_SUDO=
fi

if has_param '--prefix' "$@"; then
    PREFIX=$2
fi

check_tools() {
    for cmd in "$@"; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            echo "ERR: This script requires that '$cmd' is installed and available in your \$PATH"
            if [[ "$cmd" == "gh" ]]; then
                type -p curl >/dev/null || ($USE_SUDO apt update && $USE_SUDO apt install curl -y)
                curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | $USE_SUDO dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
                && $USE_SUDO chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
                && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | $USE_SUDO tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
                && $USE_SUDO apt update \
                && $USE_SUDO apt install gh -y
            fi
            if [[ "$cmd" == "cosign" ]]; then
                LATEST_VERSION=$(curl https://api.github.com/repos/sigstore/cosign/releases/latest | grep tag_name | cut -d : -f2 | tr -d "v\", ")
                curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign_${LATEST_VERSION}_amd64.deb"
                $USE_SUDO dpkg -i cosign_${LATEST_VERSION}_amd64.deb
            fi
        fi
    done
}

$USE_SUDO apt-get update
$USE_SUDO apt-get install --no-install-recommends -y curl
check_tools curl cosign gh

COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix=$PREFIX
