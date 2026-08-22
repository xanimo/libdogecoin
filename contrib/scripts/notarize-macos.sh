#!/bin/bash
# Notarize the signed macOS gitian tarballs.
#
# codesign alone is not enough: Gatekeeper rejects downloaded binaries that are
# signed but not notarized, even when the signature is valid and the hardened
# runtime is on.  Run this after gitian-build.sh --sign-only --codesign-macos.
#
# Nothing is stapled.  A notarization ticket cannot be stapled to a .tar.gz, so
# Gatekeeper checks the notarization online instead.
#
# usage: ./notarize-macos.sh --path=gitian/builds/<ref>
#
# Credentials come from the environment, as an App Store Connect API key:
#   APPLE_API_KEY_ID     the key identifier
#   APPLE_API_ISSUER_ID  the issuer UUID
#   APPLE_API_KEY        the .p8 private key, base64 encoded
# If any is unset the script reports and exits 0, so forks and unsigned builds
# still complete.
export LC_ALL=C
set -e -o pipefail

SEARCH_PATH=""

for arg in "$@"; do
    case "$arg" in
        -p=*|--path=*) SEARCH_PATH="${arg#*=}" ;;
        -h|--help)
            sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

if [ -z "$SEARCH_PATH" ]; then
    echo "notarize-macos.sh: --path is required" >&2
    exit 1
fi

if [ -z "${APPLE_API_KEY_ID:-}" ] || [ -z "${APPLE_API_ISSUER_ID:-}" ] || [ -z "${APPLE_API_KEY:-}" ]; then
    echo "notarization credentials not available; skipping"
    exit 0
fi

if ! command -v xcrun > /dev/null 2>&1; then
    echo "notarize-macos.sh: xcrun not found, this must run on macOS" >&2
    exit 1
fi

KEY_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$KEY_DIR"
}
trap cleanup EXIT
chmod 700 "$KEY_DIR"

KEY_FILE="${KEY_DIR}/AuthKey_${APPLE_API_KEY_ID}.p8"
OLD_UMASK="$(umask)"
umask 077
printf '%s' "$APPLE_API_KEY" | base64 --decode > "$KEY_FILE"
umask "$OLD_UMASK"

if [ ! -s "$KEY_FILE" ]; then
    echo "notarize-macos.sh: APPLE_API_KEY did not decode to anything" >&2
    exit 1
fi

found=0
while IFS= read -r tarball; do
    found=$((found + 1))
    echo "notarizing ${tarball}"
    xcrun notarytool submit "$tarball" \
        --key "$KEY_FILE" \
        --key-id "$APPLE_API_KEY_ID" \
        --issuer "$APPLE_API_ISSUER_ID" \
        --wait --timeout 30m
done < <(find "$SEARCH_PATH" -type f -name '*osx*.tar.gz' | sort)

if [ "$found" -eq 0 ]; then
    echo "no macOS tarballs found under ${SEARCH_PATH}; nothing notarized" >&2
    exit 1
fi

echo "notarized ${found} tarball(s)"
