package=libmpfr
$(package)_version=4.2.1
$(package)_download_path=https://ftp.gnu.org/gnu/mpfr/
$(package)_file_name=mpfr-4.2.1.tar.gz
$(package)_sha256_hash=116715552bd966c85b417c424db1bbdf639f53836eb361549d1f8d6ded5cb4c6
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
