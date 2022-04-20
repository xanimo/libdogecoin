package=libevent
$(package)_version=2.1.12
$(package)_download_path=https://github.com/libevent/libevent/releases/download/release-$($(package)_version)-stable/
$(package)_file_name=libevent-$($(package)_version)-stable.tar.gz
$(package)_sha256_hash=92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --disable-openssl --disable-libevent-regress --disable-samples
  $(package)_config_opts += --disable-dependency-tracking --enable-option-checking
  $(package)_config_opts_release=--disable-debug-mode
  $(package)_config_opts_linux=--with-pic
  $(package)_cppflags_mingw32=-D_WIN32_WINNT=0x0601
endef

define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub build-aux
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

ifneq (,$(build_os), mingw32)
  define $(package)_postprocess_cmds
    rm lib/*.la && \
    rm include/ev*.h
  endef
endif