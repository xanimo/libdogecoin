# Release Process

## Versioning

`configure.ac` is the only place the version is written down:

```m4
define(_PKG_VERSION_MAJOR, 0)
define(_PKG_VERSION_MINOR, 1)
define(_PKG_VERSION_BUILD, 5)
define(_PKG_VERSION_IS_RELEASE, true)
define(_PKG_VERSION_SUFFIX, [])
```

Note it is `_PKG_VERSION_BUILD`, not `_PKG_VERSION_PATCH`. `_PKG_VERSION_IS_RELEASE`
selects between the suffix and `-dev`:

| `IS_RELEASE` | `SUFFIX` | version string |
|---|---|---|
| `false` | anything | `0.1.5-dev` |
| `true` | `[]` | `0.1.5` |
| `true` | `[-pre]` | `0.1.5-pre` |
| `true` | `[-dogebox-pre]` | `0.1.5-dogebox-pre` |

A `-dev` branch keeps `IS_RELEASE` at `false`. A pre-release sets it `true` and
puts its marker in `SUFFIX`. A final release sets it `true` with an empty
`SUFFIX`.

Everything else derives from those macros:

* the CMake build parses them out of `configure.ac`, so `PACKAGE_VERSION` matches
  the autotools build
* the gitian descriptors read `PACKAGE_VERSION` back out of the `Makefile` that
  the in-build `./configure` generates, and use it for the tarball name, the
  archive prefix and `pack.sh --commit`. They do not name a version anywhere
* `Package.swift` cannot parse a sibling file from inside the SwiftPM manifest
  sandbox, so it carries a literal

`contrib/scripts/check-version.sh` asserts all of these agree, and CI runs it on
every push. It fails if `Package.swift` drifts, if the CMake derivation stops
matching, or if a gitian descriptor grows a hardcoded version again.

`_LIB_VERSION_{CURRENT,REVISION,AGE}` are separate: they are the libtool ABI
numbers, not the package version, and follow the
[libtool rules](https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html).
Bump `CURRENT` and reset `REVISION` when the ABI changes incompatibly.

## Cutting a release

1. Open a PR to `main` that
   1. adds the release notes to `doc/changelog.md`, and
   2. if this is **not** a patch release, updates `_PKG_VERSION_{MAJOR,MINOR}` and
      `_LIB_VERSION_*` in `configure.ac`

   Generate the notes in the same format the previous entries use:

   ```sh
   gh api repos/dogecoinfoundation/libdogecoin/releases/generate-notes \
     -f tag_name=vMAJOR.MINOR.BUILD \
     -f target_commitish=MAJOR.MINOR-dev \
     -f previous_tag_name=vPREVIOUS \
     --jq '.body'
   ```

2. After the PR is merged,
   * if this is **not** a patch release, create a release branch named
     `MAJOR.MINOR`, check it contains the right commits, and commit
     `_PKG_VERSION_IS_RELEASE` as `true` with the intended `_PKG_VERSION_SUFFIX`
     on that branch. Do not set it on a `-dev` branch
   * if this **is** a patch release, open a PR with the bugfixes against the
     `MAJOR.MINOR` branch, including the changelog commit and the
     `_PKG_VERSION_BUILD` and `_LIB_VERSION_*` bumps

3. Run `./contrib/scripts/check-version.sh` and confirm it reports the version
   you intend to ship.

4. Tag the commit with `git tag -s vMAJOR.MINOR.BUILD`. The tag name and the
   version string must match: at `v0.1.4-pre` they did not, because the tag said
   `-pre` while the built library reported `0.1.4-dogebox-pre`.

5. Push the branch and the tag with `git push origin --tags`. Pushing a `v*` tag
   is what triggers the gitian build, the signing jobs and the release asset
   upload in `.github/workflows/ci.yml`.

6. Create a GitHub release linking the matching entry in `doc/changelog.md`.
   Mark it a pre-release if `_PKG_VERSION_SUFFIX` is non-empty.

## Reproducible builds

`./contrib/gitian-build.sh` drives the three descriptors in
`contrib/gitian-descriptors/`, producing linux, windows and macOS artifacts. CI
runs it on `v*` tags. See `--help` for the signing flags.

A guix build is not available on this branch yet; the port is in flight.

## Signing

Windows artifacts are signed inside the gitian build via `--codesign-win`,
using `LIBDOGECOIN_DEV_WINDOWS_CERT_DATA` and
`LIBDOGECOIN_DEV_WINDOWS_CERT_PASSWORD`.

macOS artifacts cannot be signed inside a linux gitian container, so the
`sign-gitian-macos` job downloads them onto a macOS runner and re-runs
`gitian-build.sh --sign-only --codesign-macos`. It signs with `/usr/bin/codesign`
under a hardened runtime and needs `LIBDOGECOIN_DEV_MACOS_CERT_DATA`,
`LIBDOGECOIN_DEV_MACOS_CERT_PASSWORD` and `LIBDOGECOIN_DEV_APPLE_TEAM_ID`. All
of the signing steps skip rather than fail when their secrets are absent, so a
fork build still completes.

Notarization runs after signing and needs `LIBDOGECOIN_DEV_APPLE_API_KEY_ID`,
`LIBDOGECOIN_DEV_APPLE_API_ISSUER_ID` and `LIBDOGECOIN_DEV_APPLE_API_KEY`, a
base64 App Store Connect `.p8`. Without notarization Gatekeeper refuses
downloaded binaries on current macOS even though they are validly signed. This
step has not been exercised against real credentials.

## Releases and dates

GitHub stamps `published_at` when a draft is published and the API will not
accept a value for it, so a draft cannot be back-dated. The underlying tag keeps
its own date. Publishing an old draft today puts it at the top of the release
list; keep `prerelease` set so it does not take the "Latest" badge.
