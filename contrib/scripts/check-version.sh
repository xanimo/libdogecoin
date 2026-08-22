#!/usr/bin/env bash
# Assert every place that names the package version agrees with configure.ac.
#
# configure.ac is the single source of truth.  The autotools and CMake builds
# both read it, so they cannot drift.  Package.swift cannot: a SwiftPM manifest
# is evaluated in a sandbox and is not a good place to parse a sibling file, so
# it carries a literal and this script is what keeps it honest.
set -euo pipefail

cd "$(dirname "$0")/../.."

fail=0
note() { printf '  %-28s %s\n' "$1" "$2"; }
bad()  { printf '  %-28s %s  <-- expected %s\n' "$1" "$2" "$3"; fail=1; }

m4_define() {
    sed -n "s/^define(_PKG_VERSION_$1, \(.*\))\$/\1/p" configure.ac | head -1
}

major=$(m4_define MAJOR)
minor=$(m4_define MINOR)
build=$(m4_define BUILD)
is_release=$(m4_define IS_RELEASE)
suffix=$(m4_define SUFFIX | sed 's/^\[//; s/\]$//')

for v in "$major" "$minor" "$build" "$is_release"; do
    if [ -z "$v" ]; then
        echo "cannot read the version macros out of configure.ac" >&2
        exit 1
    fi
done

if [ "$is_release" = "true" ]; then
    expected="${major}.${minor}.${build}${suffix}"
else
    expected="${major}.${minor}.${build}-dev"
fi

echo "configure.ac declares ${expected}"

# Package.swift carries a literal.
swift_version=$(sed -n 's/.*\.define("PACKAGE_VERSION", to: "\\"\(.*\)\\"").*/\1/p' Package.swift | head -1)
if [ -z "$swift_version" ]; then
    bad "Package.swift" "(not found)" "$expected"
elif [ "$swift_version" = "$expected" ]; then
    note "Package.swift" "$swift_version"
else
    bad "Package.swift" "$swift_version" "$expected"
fi

# CMake derives its version, so this checks the derivation rather than a literal.
if command -v cmake >/dev/null 2>&1; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    if cmake -S . -B "$tmp" > "$tmp/log" 2>&1; then
        cmake_version=$(sed -n 's/^-- libdogecoin version: //p' "$tmp/log" | head -1)
        if [ "$cmake_version" = "$expected" ]; then
            note "CMakeLists.txt" "$cmake_version"
        else
            bad "CMakeLists.txt" "${cmake_version:-(not reported)}" "$expected"
        fi
    else
        note "CMakeLists.txt" "(configure failed, skipped)"
        tail -5 "$tmp/log" >&2
    fi
else
    note "CMakeLists.txt" "(cmake not installed, skipped)"
fi

# The gitian descriptors must not name a version at all; they read it from the
# configure run inside the build.
if grep -nE '[0-9]+\.[0-9]+\.[0-9]+' contrib/gitian-descriptors/*.yml; then
    echo "  gitian descriptors must not hardcode a version" >&2
    fail=1
else
    note "gitian descriptors" "derived at build time"
fi

exit $fail
