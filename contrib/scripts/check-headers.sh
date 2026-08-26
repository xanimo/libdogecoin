#!/usr/bin/env bash
# Assert the headers the release actually ships can compile on their own.
#
# contrib/scripts/pack.sh carries its own hardcoded list of headers to put in
# the tarball, separate from include_HEADERS and from the CMake install list.
# When a public header gains an #include of something that list does not carry,
# every build succeeds and the packaged tarball is the only thing that breaks,
# on its first #include. That is the failure this catches.
set -euo pipefail

cd "$(dirname "$0")/../.."

pack="contrib/scripts/pack.sh"
if [ ! -f "$pack" ]; then
    echo "check-headers: $pack not found" >&2
    exit 1
fi

# The LIB= line names the headers that go in the tarball.
mapfile -t shipped < <(grep -m1 '^LIB=' "$pack" | grep -oE 'include/dogecoin/[A-Za-z0-9_-]+\.h')
if [ "${#shipped[@]}" -eq 0 ]; then
    echo "check-headers: no headers found in $pack LIB=" >&2
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/dogecoin"

echo "shipped by pack.sh:"
for h in "${shipped[@]}"; do
    if [ ! -f "$h" ]; then
        echo "  $h  <-- listed in pack.sh but not in the tree" >&2
        exit 1
    fi
    printf '  %s\n' "${h#include/dogecoin/}"
    cp "$h" "$tmp/dogecoin/"
done

# A consumer sees only those headers, and defines no build-time macros.
cat > "$tmp/consumer.c" <<'EOF'
#include <dogecoin/libdogecoin.h>
int main(void) { return 0; }
EOF

if "${CC:-cc}" -I "$tmp" -c "$tmp/consumer.c" -o "$tmp/consumer.o" 2> "$tmp/err"; then
    echo "the packed header set compiles standalone"
    exit 0
fi

echo >&2
echo "the packed header set does NOT compile standalone:" >&2
sed 's/^/  /' "$tmp/err" >&2
echo >&2
echo "add the missing header to LIB= in $pack, or stop including it from a public header." >&2
exit 1
