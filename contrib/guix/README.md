# Bootstrappable libdogecoin builds

`contrib/guix` builds libdogecoin release artifacts in an isolated
[Guix](https://guix.gnu.org/) container, one per host triple, from an exported
copy of the source rather than from your working tree.

It targets the same seven hosts the gitian descriptors build, produces the same
artifact names, and delegates the actual configure and packaging to the
project's own `contrib/scripts`, so it cannot drift from what gitian ships.

## Requirements

* Guix, with `guix-daemon` running. Guix 1.3.0 or newer is enough; the build
  pins its own toolchain regardless of which version you invoke it with.
* Roughly 512 MiB of free space per host, plus space for the Guix store.
  `guix-build` refuses to start if the target filesystem is short. A full
  seven-host build measured 712 MiB of build trees and 62 MiB of output.
* For `x86_64-apple-darwin15` only, the macOS SDK. See [SDK](#sdk).

## Usage

From the top of a clean checkout:

```sh
./contrib/guix/guix-build
```

That builds every host. To build a subset, set `HOSTS`:

```sh
HOSTS="x86_64-pc-linux-gnu x86_64-w64-mingw32" ./contrib/guix/guix-build
```

Artifacts land in `guix-build-<commit>/output/<host>/`, alongside a
`SHA256SUMS.part` per host and the source archive in `output/dist-archive/`.

The worktree must have no modified tracked files: the build archives `HEAD`, so
uncommitted changes would not be in the result and the mismatch would be
invisible.

### Hosts and artifacts

| Host | Artifact |
|---|---|
| `x86_64-pc-linux-gnu` | `libdogecoin-<version>-x86_64-pc-linux-gnu.tar.gz` |
| `i686-pc-linux-gnu` | `libdogecoin-<version>-i686-pc-linux-gnu.tar.gz` |
| `arm-linux-gnueabihf` | `libdogecoin-<version>-arm-linux-gnueabihf.tar.gz` |
| `aarch64-linux-gnu` | `libdogecoin-<version>-aarch64-linux-gnu.tar.gz` |
| `i686-w64-mingw32` | `libdogecoin-<version>-i686-w64-mingw32.zip` |
| `x86_64-w64-mingw32` | `libdogecoin-<version>-x86_64-w64-mingw32.zip` |
| `x86_64-apple-darwin15` | `libdogecoin-<version>-x86_64-apple-darwin15.tar.gz` |

`arm64-apple-darwin` is deliberately absent. `contrib/scripts` and CI build it;
no gitian descriptor does, so it is out of scope here.

### Environment variables

| Variable | Meaning |
|---|---|
| `HOSTS` | Space-separated host triples to build. Defaults to all seven. |
| `JOBS` | Parallelism. Defaults to `nproc`. |
| `SOURCES_PATH` | Shared depends *source* cache. Worth setting; survives cleans. |
| `BASE_CACHE` | Shared depends *built package* cache. Likewise. |
| `SDK_PATH` | Where macOS SDKs live. Defaults to `depends/SDKs`. |
| `V` | Set to a non-empty value for verbose depends output. |
| `SUBSTITUTE_URLS` | Extra substitute servers, if you trust them. |
| `GUIX_CHANNEL_URL` | Where to fetch Guix itself from. See [the pin](#the-pin). |

Because the container has no network, depends sources must already be present.
Setting `SOURCES_PATH` and `BASE_CACHE` to paths outside the tree keeps them
across builds:

```sh
env SOURCES_PATH="$HOME/guix-cache/sources" \
    BASE_CACHE="$HOME/guix-cache/base" \
    ./contrib/guix/guix-build
```

## SDK

The darwin host needs the same SDK gitian uses, an Xcode 12.2 extraction that
bundles the libc++ headers. `depends/hosts/darwin.mk` targets macOS 10.15
against the 11.0 SDK, and `.github/workflows/ci.yml` pins the exact tarball:

```sh
mkdir -p depends/SDKs
curl -L -O https://bitcoincore.org/depends-sources/sdks/Xcode-12.2-12B45b-extracted-SDK-with-libcxx-headers.tar.gz
echo "df75d30ecafc429e905134333aeae56ac65fac67cb4182622398fd717df77619  Xcode-12.2-12B45b-extracted-SDK-with-libcxx-headers.tar.gz" | sha256sum -c
tar -C depends/SDKs -xf Xcode-12.2-12B45b-extracted-SDK-with-libcxx-headers.tar.gz
```

No Xcode installation is required; the tarball is a published extraction.

## The pin

Guix itself is pinned to tag `v1.4.0`, commit
`8e2f32cee982d42a79e53fc1e9aa7b8ff0514714`, via `guix time-machine`. Two
consequences worth knowing:

* The first run authenticates tens of thousands of commits and takes a long
  time. Later runs reuse that work.
* Upstream is Savannah. The GitHub mirror is gone. Savannah also trips a libgit2
  redirect bug in some Guix versions, which fails before any building starts:

  ```
  guix time-machine: error: Git error: cannot redirect from 'git.savannah.gnu.org' to ...
  ```

  Point `GUIX_CHANNEL_URL` somewhere that does not redirect. Codeberg carries the
  same pinned commit:

  ```sh
  GUIX_CHANNEL_URL=https://codeberg.org/guix/guix.git ./contrib/guix/guix-build
  ```

  Or clone once and build from the local copy, which also helps when Savannah is
  merely slow:

  ```sh
  git clone --bare https://git.savannah.gnu.org/git/guix.git $HOME/guix-repo.git
  GUIX_CHANNEL_URL=file://$HOME/guix-repo.git ./contrib/guix/guix-build
  ```

  Changing the URL does not weaken anything. `--commit` pins the revision and
  Guix authenticates it against the keyring either way, so any source carrying
  that commit yields the same Guix.

## How it relates to gitian

The gitian descriptors do not configure or package libdogecoin themselves; each
one calls `contrib/scripts/build.sh --host <triple> --depends` and then
`contrib/scripts/pack.sh --host=<triple> --prefix=build --commit=<version>`.
This build does the same, so packaging changes reach both systems at once.

Two details follow from that:

* depends is built inside the exported tree, not the worktree, because those
  scripts resolve it as `` `pwd`/depends/<host> ``.
* `HOST` keeps gitian's spelling throughout, including the `-pc-` linux triples,
  because `pack.sh` names both the archive and the directory inside it after it.
  Guix's `cross-base` rejects that spelling, so `manifest.scm` and
  `libexec/build.sh` normalise it to a Guix triple purely for toolchain lookups.
  Anything resolving a Guix package or a path inside the toolchain uses the
  normalised form; everything else uses `HOST`.

Determinism comes from `SOURCE_DATE_EPOCH`, taken from the commit date, plus
`-ffile-prefix-map` on linux and `-fno-ident` on mingw, where gitian uses
`faketime` wrappers instead.

## Cleaning

```sh
./contrib/guix/guix-clean
```

removes build trees while preserving the caches, the SDK directory, the output
directory and the Guix profile roots.

A killed build leaves its `distsrc-<commit>-<host>` behind and `guix-build` then
refuses to start for that commit. Removing that one directory is enough;
`guix-clean` is heavier than the situation needs.

## When it fails

* Read the failing `config.log` before reasoning about compiler flags. It
  records the exact invocation, which is usually the answer.
* `guix build --keep-failed` leaves the tree of a failed *Guix package* build
  under `/tmp`; that is separate from a failed libdogecoin build, whose tree
  stays in `guix-build-<commit>/distsrc-<commit>-<host>`.
* Watch progress with `tail -F` on the log you redirected to, piped through
  `tr '\r' '\n'` so carriage-return progress lines do not hide the output.
