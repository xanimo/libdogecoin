### Usage

To build dependencies for the current arch+OS:

    make

To build for another arch/OS:

    make HOST=host-platform-triplet

For example:

    make HOST=x86_64-w64-mingw32 -j4

A prefix will be generated that's suitable for plugging into libdogecoin's
configure. In the above example, a dir named x86_64-w64-mingw32 will be
created. To use it for libdogecoin:

    ./configure --prefix=`pwd`/depends/x86_64-w64-mingw32

Common `host-platform-triplets` for cross compilation are:

- `i686-w64-mingw32` for Win32
- `x86_64-w64-mingw32` for Win64
- `x86_64-apple-darwin15` for MacOSX
- `arm-linux-gnueabihf` for Linux ARM 32 bit
- `aarch64-linux-gnu` for Linux ARM 64 bit
- `x86_64-linux-gnu` for Linux 64 bit
- `armv7a-linux-android` for Android ARM 32 bit
- `aarch64-linux-android` for Android ARM 64 bit
- `x86_64-linux-android` for Android x86 64 bit

No other options are needed, the paths are automatically configured.

Dependency Options:
The following can be set when running make: make FOO=bar

    SOURCES_PATH: downloaded sources will be placed here
    BASE_CACHE: built packages will be placed here
    SDK_PATH: Path where sdk's can be found (used by OSX and Android)
    ANDROID_TOOLCHAIN_BIN: Path to Android toolchain if installed via Android SDK Manager
    ANDROID_API_LEVEL: API level corresponding to the Android version targeted
    FALLBACK_DOWNLOAD_PATH: If a source file can't be fetched, try here before giving up
    NO_LIBOQS: set to skip building liboqs (PQC library). Leave empty to include it (e.g. NO_LIBOQS=)
    RACCOON_G: set to 'y' to build GMP and MPFR for the in-tree Raccoon-G
               implementation (--enable-raccoon-g). MPFR is the C analogue of
               Python's mpmath and is required to make the Raccoon-G Gaussian
               sampler byte-exact against the upstream Python reference.
    ZK_CARRIER: set to '1' to vendor herumi/mcl for native Groth16
                verification in the ZK carrier module.  When unset,
                Groth16 verification is delegated to off-box snarkjs.
    DEBUG: disable some optimizations and enable more runtime checking
    HOST_ID_SALT: Optional salt to use when generating host package ids
    BUILD_ID_SALT: Optional salt to use when generating build package ids
    YUBIKEY: set to 'y' to include yubikey packages for the enclave hosts
    NASM: set to 1 to build native_nasm (for --enable-intel-avx2/--enable-intel-sse or -DUSE_AVX2=ON/-DUSE_SSE=ON). Default: off.

If some packages are not built, the appropriate
options will be passed to libdogecoin's configure. In this case, `--disable-net`.

Additional targets:

    download: run 'make download' to fetch all sources without building them
    download-osx: run 'make download-osx' to fetch all sources needed for osx builds
    download-win: run 'make download-win' to fetch all sources needed for win builds
    download-linux: run 'make download-linux' to fetch all sources needed for linux builds

### Other documentation

- [description.md](description.md): General description of the depends system
- [packages.md](packages.md): Steps for adding packages
