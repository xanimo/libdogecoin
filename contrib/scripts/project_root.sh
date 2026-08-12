# Shared project-root check for contrib/scripts. Not executable; source it:
#
#     . "$(dirname "$0")/project_root.sh"
#     require_project_root "contrib/scripts/pack.sh --host=... --prefix=build"
#
# The project root is where configure.ac sits. Testing for a git checkout
# instead rejects an exported source tarball, which is what a release build
# unpacks and builds from, and which carries no .git.

at_project_root() {
    [ -f "${PWD}/configure.ac" ] && [ -d "${PWD}/contrib/scripts" ]
}

# require_project_root <example invocation shown in the hint>
require_project_root() {
    if at_project_root; then
        return 0
    fi
cat << EOF
ERR: This script must be invoked from the top level of the project
Hint: This may look something like:
    $1
EOF
    exit 1
}
