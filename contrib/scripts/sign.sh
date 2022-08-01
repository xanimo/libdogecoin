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

ERROR=""
TARGET_HOST_TRIPLET=""
if has_param '--host' "$@"; then
    case "$2" in
        "arm-linux-gnueabihf")
            TARGET_HOST_TRIPLET=$2
            shift 2
        ;;
        "aarch64-linux-gnu")
            TARGET_HOST_TRIPLET=$2
            shift 2
        ;;
        "x86_64-w64-mingw32")
            TARGET_HOST_TRIPLET=$2
            shift 2
        ;;
        "i686-w64-mingw32")
            TARGET_HOST_TRIPLET=$2
            shift 2
        ;;
        "x86_64-apple-darwin14")
            TARGET_HOST_TRIPLET=$2
            shift 2
        ;;
        "x86_64-pc-linux-gnu")
            TARGET_HOST_TRIPLET=$2
            shift 2
        ;;
        "i686-pc-linux-gnu")
            TARGET_HOST_TRIPLET=$2
            shift 2
        ;;
        *)
            ERROR=1
        ;;
    esac
fi

if [ "$ERROR" == 1 ]; then
    echo "Unrecognized host. Please provide a known host and try again."
    exit 1
fi


help() {
    echo "Usage: ./sign.sh --input such
               [ -i | --input ]
               [ -h | --help  ]"
    exit 2
}


SHORT=i:,h:
LONG=input:,help
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

if [ ! $input ]; then
    echo "Please provide an input to sign."
    exit 1
else
  if [ ! -f "$input" ]; then
    echo "Input is not valid."
    exit 1
  fi
fi

filename=$(basename -- "$input")
# extract file extension after first .
extension="${input#*.}"
# extract file name before first .
filename="${input%%.*}"

# if archive then gpg sign .asc
if [ "$extension" == "tar.gz" ] || [ "$extension" == "zip" ]; then
  gpg --armor --detach-sign --yes -o "$input.asc" $input
  gpg --verify "$input.asc" $input
else
  gpg --detach-sign --yes -o $input.sig $input
  gpg --verify "$input.sig" $input
fi
