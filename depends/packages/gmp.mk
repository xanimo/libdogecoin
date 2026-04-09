package=gmp

$(package)_version=6.3.0
$(package)_download_path=https://ftp.gnu.org/gnu/gmp
$(package)_file_name=$(package)-$($(package)_version).tar.bz2
$(package)_sha256_hash=ac28211a7cfb609bae2e2c8d6058d66c8fe96434f740cf6fe2e47b000d1c20cb

# GMP is pulled in only for the experimental Raccoon-G build (--enable-raccoon-g).
# It is the dependency of MPFR, which provides the mpmath-equivalent
# arbitrary-precision FP arithmetic that the Raccoon-G Gaussian sampler needs
# in order to be byte-exact against the upstream Python reference.

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --enable-static --with-pic
  $(package)_config_opts += --disable-dependency-tracking --enable-option-checking
  $(package)_config_opts += --enable-cxx=no --disable-assembly
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -f lib/*.la
endef
