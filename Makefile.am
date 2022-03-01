ACLOCAL_AMFLAGS = -I build-aux/m4
AUTOMAKE_OPTIONS = serial-tests
.PHONY: gen
.INTERMEDIATE: $(GENBIN)

DIST_SUBDIRS = src/secp256k1

LIBSECP256K1=src/secp256k1/libsecp256k1.la

$(LIBSECP256K1): $(wildcard src/secp256k1/src/*) $(wildcard src/secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

lib_LTLIBRARIES = libdogecoin.la
libdogecoinincludedir = $(includedir)/dogecoin
libdogecoininclude_HEADERS = \
    include/dogecoin/address.h \
    include/dogecoin/crypto/aes.h \
    include/dogecoin/crypto/base58.h \
    include/dogecoin/bip32.h \
    include/dogecoin/block.h \
    include/dogecoin/blockchain.h \
    include/dogecoin/buffer.h \
    include/dogecoin/compat/byteswap.h \
    include/dogecoin/chainparams.h \
    include/dogecoin/cstr.h \
    include/dogecoin/crypto/ctaes/ctaes.h \
    include/dogecoin/dogecoin.h \
    include/dogecoin/crypto/ecc.h \
    include/dogecoin/crypto/hash.h \
    include/dogecoin/crypto/key.h \
    include/dogecoin/mem.h \
    include/dogecoin/compat/portable_endian.h \
    include/dogecoin/crypto/random.h \
    include/dogecoin/crypto/rmd160.h \
    include/dogecoin/script.h \
    include/dogecoin/crypto/segwit_addr.h \
    include/dogecoin/serialize.h \
    include/dogecoin/crypto/sha2.h \
    include/dogecoin/tool.h \
    include/dogecoin/tx.h \
    include/dogecoin/utils.h \
    include/dogecoin/vector.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libdogecoin.pc

libdogecoin_la_SOURCES = \
    src/address.c \
    src/crypto/aes.c \
    src/crypto/base58.c \
    src/bip32.c \
    src/block.c \
    src/buffer.c \
    src/chainparams.c \
    src/cli/tool.c \
    src/cstr.c \
    src/crypto/ctaes/ctaes.c \
    src/crypto/ecc.c \
    src/crypto/key.c \
    src/mem.c \
    src/crypto/random.c \
    src/crypto/rmd160.c \
    src/script.c \
    src/crypto/segwit_addr.c \
    src/serialize.c \
    src/crypto/sha2.c \
    src/tx.c \
    src/utils.c \
    src/vector.c

libdogecoin_la_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src/logdb/include
libdogecoin_la_LIBADD = $(LIBSECP256K1)

if USE_TESTS
noinst_PROGRAMS = tests
tests_LDADD = libdogecoin.la
tests_SOURCES = \
    test/address_tests.c \
    test/aes_tests.c \
    test/base58_tests.c \
    test/bip32_tests.c \
    test/block_tests.c \
    test/buffer_tests.c \
    test/cstr_tests.c \
    test/ecc_tests.c \
    test/hash_tests.c \
    test/key_tests.c \
    test/mem_tests.c \
    test/random_tests.c \
    test/rmd160_tests.c \
    test/serialize_tests.c \
    test/sha2_tests.c \
    test/tx_tests.c \
    test/utest.h \
    test/unittester.c \
    test/utils_tests.c \
    test/vector_tests.c

tests_CFLAGS = $(libdogecoin_la_CFLAGS)
tests_CPPFLAGS = -I$(top_srcdir)/src
tests_LDFLAGS = -static
TESTS = tests
endif

if WITH_LOGDB
libdogecoin_la_SOURCES += \
    src/logdb/logdb_core.c \
    src/logdb/logdb_memdb_llist.c \
    src/logdb/logdb_memdb_rbtree.c \
    src/logdb/logdb_rec.c \
    src/logdb/misc.c \
    src/logdb/red_black_tree.c \
    src/logdb/stack.c

logdbincludedir = $(includedir)/logdb
logdbinclude_HEADERS = \
    src/logdb/include/logdb/logdb_base.h \
    src/logdb/include/logdb/logdb_core.h \
    src/logdb/include/logdb/logdb_memdb_llist.h \
    src/logdb/include/logdb/logdb_memdb_rbtree.h \
    src/logdb/include/logdb/logdb_rec.h \
    src/logdb/include/logdb/logdb.h \
    src/logdb/include/logdb/misc.h \
    src/logdb/include/logdb/red_black_tree.h \
    src/logdb/include/logdb/stack.h

if USE_TESTS
tests_SOURCES += \
    src/logdb/test/logdb_tests.c \
    src/logdb/test/tests_red_black_tree.c \
    src/logdb/test/logdb_tests_sample.h
endif
endif

if WITH_WALLET
libdogecoininclude_HEADERS += \
    include/dogecoin/wallet.h

libdogecoin_la_SOURCES += \
    src/wallet.c

if USE_TESTS
tests_SOURCES += \
    test/wallet_tests.c
endif
endif

if WITH_NET
libdogecoininclude_HEADERS += \
    include/dogecoin/headersdb.h \
    include/dogecoin/headersdb_file.h \
    include/dogecoin/net/protocol.h \
    include/dogecoin/net/net.h \
    include/dogecoin/net/spv.h

libdogecoin_la_SOURCES += \
    src/headersdb_file.c \
    src/net/net.c \
    src/net/protocol.c \
    src/net/spv.c

libdogecoin_la_LIBADD += $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS)
libdogecoin_la_CFLAGS += $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)

if USE_TESTS
tests_SOURCES += \
    test/net_tests.c \
    test/netspv_tests.c \
    test/protocol_tests.c
tests_LDADD += $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS)
endif
endif

if WITH_TOOLS
if USE_TESTS
tests_SOURCES += \
    test/tool_tests.c
endif
instdir=$(prefix)/bin
inst_PROGRAMS = such
such_LDADD = libdogecoin.la
such_SOURCES = \
    src/cli/such.c
such_CFLAGS = $(libdogecoin_la_CFLAGS)
such_CPPFLAGS = -I$(top_srcdir)/src
such_LDFLAGS = -static

if WITH_NET
inst_PROGRAMS += sendtx
sendtx_LDADD = libdogecoin.la $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS)
sendtx_SOURCES = \
    src/cli/sendtx.c
sendtx_CFLAGS = $(libdogecoin_la_CFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
sendtx_CPPFLAGS = -I$(top_srcdir)/src
sendtx_LDFLAGS = -static

inst_PROGRAMS += spvnode
spvnode_LDADD = libdogecoin.la
spvnode_SOURCES = \
    src/cli/spvnode.c
spvnode_CFLAGS = $(libdogecoin_la_CFLAGS)
spvnode_CPPFLAGS = -I$(top_srcdir)/src
spvnode_LDFLAGS = -static
endif
endif

clean-local:
	-$(MAKE) -C src/secp256k1 clean
