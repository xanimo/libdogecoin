package=libmpfr
$(package)_version=4.1.0
$(package)_download_path=https://www.mpfr.org/mpfr-current/
$(package)_file_name=mpfr-4.1.0.tar.xz
$(package)_sha256_hash=0c98a3f1732ff6ca4ea690552079da9c597872d30e96ec28414ee23c95558a7f
$(package)_dependencies=libgmp
$(package)_config_opts=--enable-static --disable-shared

define $(package)_preprocess_cmds
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install ; echo '=== staging find for $(package):' ; find $($(package)_staging_dir)
endef