#!/bin/bash
export LC_ALL=C
set -e -o pipefail

if [ $# -eq 0 ]; then
    echo "No arguments provided (sign)"
    exit 1
fi

check_tools() {
    for cmd in "$@"; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            echo "ERR: This script requires that '$cmd' is installed and available in your \$PATH"
            exit 1
        fi
    done
}

check_tools gpg

git_root() {
    git rev-parse --show-toplevel 2> /dev/null
}

same_dir() {
    local resolved1 resolved2
    resolved1="$(git_root)"
    resolved2="$(echo `pwd`)"
    [ "$resolved1" = "$resolved2" ]
}

if ! same_dir "${PWD}" "$(git_root)"; then
cat << EOF
ERR: This script must be invoked from the top level of the git repository
Hint: This may look something like:
    contrib/scripts/combine_lib.sh
EOF
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

help() {
    echo "Usage: sign 
               [ -i | --input ]
               [ -o | --output ]
               [ -h | --help  ]"
    exit 2
}


SHORT=i:,o:,h:
LONG=input:,output:,host:,help
OPTS=$(getopt -a -n sign --options $SHORT --longoptions $LONG -- "$@")

VALID_ARGUMENTS=$# # Returns the count of arguments that are in short or long options

if [ "$VALID_ARGUMENTS" -eq 0 ]; then
  help
fi

eval set -- "$OPTS"

while :
do
  case "$1" in
    --host )
      export host="$2"
      shift 2
      ;;
    -i | --input )
      export input="$2"
      shift 2
      ;;
    -o | --output )
      export output="$2"
      shift 2
      ;;
    -h | --help)
      help
      ;;
    --)
      shift;
      break
      ;;
    *)
      echo "Unexpected option: $1"
      help
      ;;
  esac
done

SIGN="$armor --detach-sign --yes $output $input"

if [ ! $input ]; then
    echo "Please provide an input to sign."
    exit 1
fi

if [ ! $output ]; then
    echo "Please provide a file name to output."
    exit 1
fi

gpg --detach-sign --yes -o "$output.sig" $input
gpg --verify "$output.sig" $output
gpg --armor --detach-sign --yes -o "$output.asc" $input
gpg --verify "$output.asc" $output


