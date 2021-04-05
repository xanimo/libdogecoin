#!/usr/bin/env sh
update_subtree() {
    # set parameters
    REMOTE="$1"
    LOCAL_SUBDIR="$2"
    REMOTE_SUBDIR="$3"

    # get content from repository
    git fetch "$REMOTE"
    FETCH_HEAD="$(git describe --always FETCH_HEAD)"
    SOURCE_HEAD="$FETCH_HEAD"

    # if a remote subdir is set, split the content to only have that subdir
    if test "x$REMOTE_SUBDIR" != "x"
    then
        touch "$REMOTE_SUBDIR" # this hack lets git-subtree split a non-worktree branch
        SOURCE_HEAD="$(git subtree split --prefix "$REMOTE_SUBDIR" "$FETCH_HEAD")"
    fi

    MESSAGE="Merge subtree $LOCAL_SUBDIR from $REMOTE $REMOTE_SUBDIR $FETCH_HEAD"

    # merge or add the subtree into the worktree
    git subtree merge --squash --prefix src/"$LOCAL_SUBDIR" "$SOURCE_HEAD" --message "$MESSAGE" ||
        git subtree add --squash --prefix src/"$LOCAL_SUBDIR" "$SOURCE_HEAD" --message "$MESSAGE"
}

copy_headers()
{
    # set single parameter
    SRCDIR="src/$1"
    DSTDIR="include/btc"
    shift 1

    # for each header, mutate it to be like libbtc, and copy it in with a commit
    for HEADER in "$@"
    do
        HEADERNAME=$(basename "$HEADER")
        { sed -f /dev/stdin "$SRCDIR"/"$HEADER" > "$DSTDIR"/"$HEADERNAME" <<HEADER_MUTATION_END
            # prefix ifndef/define guard symbols with LIBBTC_ and add LIBBTCL_BEGIN_DECL
            s/^\(#ifndef _\)_*\([^_]*.*[^_]\)_*_$/\1_LIBBTC_\2__/
            s/^\(#define _\)_*\([^_]*.*[^_]\)_*_\(\s.*$\|$\)/\1_LIBBTC_\2__\n&\n\n#include "btc.h"\n\nLIBBTC_BEGIN_DECL/

            # prefix functions with LIBBTC_API
            s/^\(int\|void\|char\|bool\)/LIBBTC_API \1/

            # add LIBBTC_END_DECL before end
            $ s/^\(#endif\)$/LIBBTC_END_DECL\n\n\1/
HEADER_MUTATION_END
        } &&
        git add "$DSTDIR"/"$HEADERNAME" &&
        git commit -m "Update $DSTDIR/$HEADERNAME from $SRCDIR/$HEADER"
    done
}

# subtrees
update_subtree https://github.com/bitcoin-core/secp256k1 secp256k1
update_subtree https://github.com/trezor/trezor-firmware trezor-crypto crypto

# headers copied from subtrees
copy_headers trezor-crypto hmac.h sha2.h segwit_addr.h
