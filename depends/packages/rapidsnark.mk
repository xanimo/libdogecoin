# rapidsnark — iden3/rapidsnark v0.0.8 Groth16 verifier+prover static library.
#
# Source build (no prebuilt blobs).  The upstream v0.0.8 source tarball is a
# git-archive that ships empty `depends/{ffiasm,json,...}` submodule
# directories; we therefore fetch the matching ffiasm and nlohmann/json
# tarballs as `extra_sources` and stage them into the same paths the upstream
# CMakeLists.txt expects.  Only the verifier-only library targets
# (rapidsnarkStatic + fr + fq) are built — we don't need the prover server,
# pistache, or circom_runtime submodules.
#
# Built with USE_ASM=NO so the verifier doesn't require NASM (the verifier is
# not perf-critical for libdogecoin's mobile-friendly use case), and against
# the system libgmp / libgmp-dev (Ubuntu) / libgmp (brew on macOS).

package=rapidsnark
$(package)_version=0.0.8
$(package)_download_path=https://github.com/iden3/rapidsnark/archive/refs/tags
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=633f0e520ffaad35665eb50b0106bfd6d1414c10d273390357c8ab89592be4ac

# Pinned submodule SHAs read from `git ls-tree v0.0.8 depends/` on the upstream
# rapidsnark repo (https://github.com/iden3/rapidsnark/tree/v0.0.8/depends).
# Update these together with $(package)_version.
$(package)_ffiasm_sha=aa90166dc4c5a075b835a398e15cc1e06ac90e95
$(package)_ffiasm_file=ffiasm-$($(package)_ffiasm_sha).tar.gz
$(package)_ffiasm_sha256=bc6956ad661dc4a75adae544cd2b0e426a8dbb8b30d810e3e002029421141688

$(package)_json_sha=350ff4f7ced7c4117eae2fb93df02823c8021fcb
$(package)_json_file=nlohmann-json-$($(package)_json_sha).tar.gz
$(package)_json_sha256=1ac51d0c2c8456d73f4cbfa29b460a15a29f7ba5759bc6f1b9a01a8766bfc7a8

$(package)_extra_sources=$($(package)_ffiasm_file) $($(package)_json_file)

$(package)_dependencies=

define $(package)_set_vars
  $(package)_config_opts =
endef

# Custom fetch: pull the main rapidsnark tarball plus the two submodule
# tarballs (each from its own GitHub archive URL).  The fetch_file helper
# verifies each SHA-256 hash against the constants above; on mismatch the
# stamp file is removed and the build aborts at the next step.
define $(package)_fetch_cmds
  $(call fetch_file,$(package),$(subst \:,:,$($(package)_download_path_fixed)),$($(package)_file_name),$($(package)_file_name),$($(package)_sha256_hash)) && \
  $(call fetch_file,$(package),https://github.com/iden3/ffiasm/archive,$($(package)_ffiasm_sha).tar.gz,$($(package)_ffiasm_file),$($(package)_ffiasm_sha256)) && \
  $(call fetch_file,$(package),https://github.com/nlohmann/json/archive,$($(package)_json_sha).tar.gz,$($(package)_json_file),$($(package)_json_sha256))
endef

# Custom extract: verify all three SHA-256 hashes, untar the main rapidsnark
# tree (--strip-components=1 like the default extract), then stage the
# ffiasm/json submodules under depends/ exactly where upstream's CMakeLists.txt
# expects to find them (../depends/ffiasm/c/* and ../depends/json/single_include).
define $(package)_extract_cmds
  mkdir -p $($(package)_extract_dir) && \
  echo "$($(package)_sha256_hash)  $($(package)_source_dir)/$($(package)_file_name)" > $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_ffiasm_sha256)  $($(package)_source_dir)/$($(package)_ffiasm_file)" > $($(package)_extract_dir)/.$($(package)_ffiasm_file).hash && \
  echo "$($(package)_json_sha256)  $($(package)_source_dir)/$($(package)_json_file)" > $($(package)_extract_dir)/.$($(package)_json_file).hash && \
  $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_ffiasm_file).hash && \
  $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_json_file).hash && \
  tar --strip-components=1 -xf $($(package)_source_dir)/$($(package)_file_name) && \
  rm -rf depends/ffiasm depends/json && \
  mkdir -p depends/ffiasm depends/json && \
  tar --strip-components=1 -xf $($(package)_source_dir)/$($(package)_ffiasm_file) -C depends/ffiasm && \
  tar --strip-components=1 -xf $($(package)_source_dir)/$($(package)_json_file)   -C depends/json
endef

# Configure with cmake against the system libgmp; verifier-only library so we
# turn off OpenMP and the (NASM-requiring) assembly paths.  BUILD_TESTS is
# disabled to avoid the `test_public_size` target that wants `circuit_final.zkey`
# in testdata/.
define $(package)_config_cmds
  rm -rf build_verifier && mkdir build_verifier && cd build_verifier && \
  cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=OFF \
    -DUSE_OPENMP=OFF \
    -DUSE_ASM=NO \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_C_COMPILER='$(firstword $(host_CC))' \
    -DCMAKE_C_FLAGS='$(wordlist 2,1000,$(host_CC)) $(host_CFLAGS) -O2' \
    -DCMAKE_CXX_COMPILER='$(firstword $(host_CXX))' \
    -DCMAKE_CXX_FLAGS='$(wordlist 2,1000,$(host_CXX)) $(host_CXXFLAGS) -O2'
endef

# Only build the verifier-side static libraries (rapidsnarkStatic, fr, fq).
# The shared library, prover/verifier executables, and the BUILD_TESTS target
# are not needed by libdogecoin and pull in extra dependencies.
define $(package)_build_cmds
  $(MAKE) -C build_verifier -j$(JOBS) rapidsnarkStatic fr fq
endef

# Install the three static libraries plus the public C ABI headers
# (verifier.h, prover.h) under the host_prefix.  configure.ac picks them up
# via -L$prefix/lib and -I$prefix/include as set by depends/config.site.in.
define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/lib && \
  mkdir -p $($(package)_staging_prefix_dir)/include/rapidsnark && \
  cp build_verifier/src/librapidsnark.a $($(package)_staging_prefix_dir)/lib/ && \
  cp build_verifier/src/libfr.a         $($(package)_staging_prefix_dir)/lib/ && \
  cp build_verifier/src/libfq.a         $($(package)_staging_prefix_dir)/lib/ && \
  cp src/verifier.h                     $($(package)_staging_prefix_dir)/include/rapidsnark/ && \
  cp src/prover.h                       $($(package)_staging_prefix_dir)/include/rapidsnark/
endef
