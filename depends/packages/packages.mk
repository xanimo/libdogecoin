packages:=libevent
native_packages := native_ccache

# NASM=1 builds native_nasm for Intel AVX2/SSE assembly (src/intel).
ifeq ($(NASM),1)
native_packages += native_nasm
endif

wallet_packages=

upnp_packages=

darwin_native_packages =

yubikey_packages = libyubikey libusb ykpers
liboqs_packages = liboqs
raccoon_g_packages = gmp mpfr
zk_carrier_packages = gmp mcl rapidsnark

ifneq ($(build_os),darwin)
darwin_native_packages += native_cctools native_libtapi

ifeq ($(strip $(FORCE_USE_SYSTEM_CLANG)),)
darwin_native_packages+= native_clang
endif

endif
