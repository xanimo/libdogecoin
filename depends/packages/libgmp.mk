package=libgmp
$(package)_version=6.3.0
$(package)_download_path=https://ftp.gnu.org/gnu/gmp/
$(package)_file_name=gmp-6.3.0.tar.gz
$(package)_sha256_hash=e56fd59d76810932a0555aa15a14b61c16bed66110d3c75cc2ac49ddaa9ab24c
$(package)_dependencies=
$(package)_config_opts=--enable-cxx --enable-static --disable-shared

define $(package)_preprocess_cmds
endef

define $(package)_config_cmds
  $($(package)_autoconf) --host=$(host) --build=$(build)
endef

define $(package)_build_cmds
  $(MAKE) CPPFLAGS='-fPIC'
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install ; echo '=== staging find for $(package):' ; find $($(package)_staging_dir)
endef
