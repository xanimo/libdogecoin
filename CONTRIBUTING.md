# Contributing

## Branch naming

**Put `-dev` in your branch name, and do not use `/` in it.**

Use the development branch you are targeting as the prefix:

```
0.1.5-dev-fix-net-checksum
0.1.5-dev-fix-cmake-liboqs-link
0.1.5-dev-bip157
```

This is not a style preference. The workflows in `.github/workflows/` filter on
the branch name, so a branch that does not match simply never gets built.

### What the filters actually are

`ci.yml`:

```yaml
on:
  push:
    branches: [ "*-dev*" ]
    tags: [ "v*" ]
  pull_request:
    branches: [ "*" ]
```

`ql.yml` (CodeQL):

```yaml
on:
  push:
    branches:
      - '*-dev*'
      - 'main'
  pull_request:
    branches:
      - '*'
```

Two consequences catch people out:

1. **No `-dev` in the name means no CI on push.** You can push a branch, see a
   clean branch list with an empty check-status column, and reasonably assume
   nothing is wrong — when in fact nothing ever ran. Builds, the test suite, the
   ASan+UBSAN gate and the sanitizer legs are all skipped.

2. **`*` does not match `/` in a GitHub branch filter.** A single-star pattern
   only matches within one path segment, so `fix/my-change` and
   `feature/my-change` can never match `*-dev*` no matter what else is in the
   name. Slash-prefixed branches are silently excluded from push-triggered CI.

Note that `pull_request` filters match the **base** branch, not your branch. Once
a PR is open, both workflows run regardless of what your branch is called — so a
badly named branch looks fine the moment you open a PR, which is usually *after*
you wanted the feedback. Naming the branch correctly is what gets you a build on
every push, before review.

### Checking before you push

```sh
# does this name get push-triggered CI?
case "$(git rev-parse --abbrev-ref HEAD)" in
  */*)    echo "no: slashes never match a single-star filter" ;;
  *-dev*) echo "yes" ;;
  *)      echo "no: needs -dev in the name" ;;
esac
```

If you have already pushed under the wrong name:

```sh
git branch -m old-name 0.1.5-dev-new-name
git push -u origin 0.1.5-dev-new-name
git push origin --delete old-name
```
