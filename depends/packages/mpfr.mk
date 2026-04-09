package=mpfr

$(package)_version=4.2.1
$(package)_download_path=https://ftp.gnu.org/gnu/mpfr
$(package)_file_name=$(package)-$($(package)_version).tar.bz2
$(package)_sha256_hash=b9df93635b20e4089c29623b19420c4ac848a1b29df1cfd59f26cab0d2666aa0
$(package)_dependencies=gmp

# MPFR is the C analogue of Python's mpmath: arbitrary-precision floating-point
# arithmetic with correct rounding (IEEE 754-2008). Raccoon-G's Gaussian sampler
# operates at sigma = 2^7 / 2^40 with mpmath in the upstream reference; matching
# that byte-for-byte requires correctly-rounded FP at user-controlled precision.
# Pulled in only for --enable-raccoon-g.

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --enable-static --with-pic
  $(package)_config_opts += --disable-dependency-tracking --enable-option-checking
  $(package)_config_opts += --with-gmp=$(host_prefix)
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
