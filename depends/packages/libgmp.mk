package=libgmp
$(package)_version=6.2.1
$(package)_download_path=https://ftp.gnu.org/gnu/gmp/
$(package)_file_name=gmp-6.2.1.tar.lz
$(package)_sha256_hash=2c7f4f0d370801b2849c48c9ef3f59553b5f1d3791d070cffb04599f9fc67b41
$(package)_dependencies=

define $(package)_set_vars
$(package)_config_opts=--enable-static --disable-shared --with-gnu-ld
$(package)_config_opts_mingw32=--enable-mingw
$(package)_config_opts_darwin=--enable-clang
$(package)_config_opts_linux=--with-pic
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