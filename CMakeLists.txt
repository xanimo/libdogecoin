CMAKE_MINIMUM_REQUIRED(VERSION 3.13) # 3.13: concise relative source paths
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")

SET(CMAKE_C_STANDARD 99)
SET(CMAKE_C_STANDARD_REQUIRED TRUE)

SET(LIBDOGECOIN_NAME dogecoin)
PROJECT(lib${LIBDOGECOIN_NAME} VERSION 0.1)

IF(WIN32)
    set(CMAKE_SYSTEM_NAME Windows)
    set(CMAKE_SYSTEM_VERSION 10.0)
    set(CMAKE_SYSTEM_PROCESSOR AMD64)

    set(CMAKE_C_COMPILER "/mnt/c/Program\ Files\ \(x86\)/Microsoft\ Visual\ Studio/2022/BuildTools/VC/Tools/Llvm/bin/clang-cl")
    set(CMAKE_CXX_COMPILER "/mnt/c/Program\ Files\ \(x86\)/Microsoft\ Visual\ Studio/2022/BuildTools/VC/Tools/Llvm/bin/clang-cl")
    set(CMAKE_LINKER "/mnt/c/Program\ Files\ \(x86\)/Microsoft\ Visual\ Studio/2022/BuildTools/VC/Tools/Llvm/bin/lld-link")

    set(MSVC_BASE "/mnt/c/Program\ Files\ \(x86\)/Microsoft\ Visual\ Studio/2022/BuildTools/VC/Tools/MSVC/14.33.31629")
    set(MSVC_INCLUDE "${MSVC_BASE}/include")
    set(MSVC_LIB "${MSVC_BASE}/lib")

    set(WINSDK_BASE "/mnt/c/Program\ Files\ \(x86\)/Windows\ Kits/10")
    set(WINSDK_VER "10.0.19041.0")
    set(WINSDK_INCLUDE "${WINSDK_BASE}/Include/${WINSDK_VER}")
    set(WINSDK_LIB "${WINSDK_BASE}/Lib/${WINSDK_VER}")

    set(COMPILE_FLAGS
        -D_CRT_SECURE_NO_WARNINGS
        -imsvc "'${MSVC_INCLUDE}'"
        -imsvc "'${WINSDK_INCLUDE}/cppwinrt'"
        -imsvc "'${WINSDK_INCLUDE}/ucrt'"
        -imsvc "'${WINSDK_INCLUDE}/shared'"
        -imsvc "'${WINSDK_INCLUDE}/um'"
        -imsvc "'${WINSDK_INCLUDE}/winrt'"
    )

    set(LINK_FLAGS
        /manifest:no
        -libpath:"${MSVC_LIB}/x64"
        -libpath:"${WINSDK_LIB}/ucrt/x64"
        -libpath:"${WINSDK_LIB}/ucrt_enclave/x64"
        -libpath:"${WINSDK_LIB}/um/x64"
    )

    string(REPLACE ";" " " LINK_FLAGS "${LINK_FLAGS}")

    set(_CMAKE_EXE_LINKER_FLAGS_INITIAL "${CMAKE_EXE_LINKER_FLAGS}" CACHE STRING "")
    set(CMAKE_EXE_LINKER_FLAGS "${_CMAKE_EXE_LINKER_FLAGS_INITIAL} ${LINK_FLAGS}" CACHE STRING "" FORCE)

    set(_CMAKE_MODULE_LINKER_FLAGS_INITIAL "${CMAKE_MODULE_LINKER_FLAGS}" CACHE STRING "")
    set(CMAKE_MODULE_LINKER_FLAGS "${_CMAKE_MODULE_LINKER_FLAGS_INITIAL} ${LINK_FLAGS}" CACHE STRING "" FORCE)

    set(_CMAKE_SHARED_LINKER_FLAGS_INITIAL "${CMAKE_SHARED_LINKER_FLAGS}" CACHE STRING "")
    set(CMAKE_SHARED_LINKER_FLAGS "${_CMAKE_SHARED_LINKER_FLAGS_INITIAL} ${LINK_FLAGS}" CACHE STRING "" FORCE)

    set(CMAKE_C_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
    set(CMAKE_CXX_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)

    set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_NO_WARNINGS ON)
ENDIF()

INCLUDE(CTest)
SET(USE_TESTS ${CMAKE_TESTING_ENABLED})
SET(WITH_TOOLS TRUE CACHE BOOL "enable dogecoin tool cli application")
SET(WITH_NET TRUE CACHE BOOL "enable net functions")
SET(RANDOM_DEVICE "/dev/urandom" CACHE STRING "set the device to read random data from")

IF(WITH_NET)
    IF(WIN32)
        FIND_LIBRARY(LIBEVENT NAMES event libevent HINTS "${CMAKE_PREFIX_PATH}")
        #FIND_LIBRARY(LIBEVENT_PTHREADS event_pthreads REQUIRED)
        FIND_LIBRARY(WINPTHREADS NAMES pthreadVC2 pthreadwin32 pthreads pthread HINTS "${CMAKE_PREFIX_PATH};${CMAKE_PREFIX_PATH}/contrib/winpthreads/include/lib/x64/")
    ELSE()
        execute_process(COMMAND ${PROJECT_SOURCE_DIR}/contrib/scripts/setup_cmake_subdir.sh --path ${PROJECT_SOURCE_DIR}/src/libevent)
        set(LIBEVENT_EXTRA_PREFIXES ./src/libevent)
        foreach(prefix ${LIBEVENT_EXTRA_PREFIXES})
        list(APPEND LIBEVENT_INCLUDE_PATHS "${prefix}/include/event2" "${prefix}/build/include/event2")
        list(APPEND LIBEVENT_PATHS "${prefix}/build/lib")
        endforeach()

        find_path(LIBEVENT_INCLUDE_DIR event.h PATHS ${LIBEVENT_INCLUDE_PATHS})
        find_library(LIBEVENT event PATHS ${LIBEVENT_PATHS} REQUIRED)
        find_library(LIBEVENT_CORE event_core PATHS ${LIBEVENT_PATHS} REQUIRED)

        set(LIBUNISTRING_PREFIXES ${PROJECT_SOURCE_DIR}/depends/${HOST})
        MESSAGE(STATUS "LIBUNISTRING_PREFIXES: ${LIBUNISTRING_PREFIXES}")
        foreach(prefix ${LIBUNISTRING_PREFIXES})
        MESSAGE(STATUS "prefix: ${prefix}")
        list(APPEND LIBUNISTRING_INCLUDE_PATHS "${prefix}/include" "${prefix}/include/unistring")
        MESSAGE(STATUS "LIBUNISTRING_INCLUDE_PATHS: ${LIBUNISTRING_INCLUDE_PATHS}")
        list(APPEND LIBUNISTRING_PATHS "${prefix}/lib")
        endforeach()

        find_path(LIBUNISTRING_INCLUDE_DIR uninorm.h PATHS ${LIBUNISTRING_INCLUDE_PATHS} REQUIRED)
        execute_process(COMMAND cp -r ${PROJECT_SOURCE_DIR}/depends/${HOST}/include ${PROJECT_SOURCE_DIR})
        find_library(LIBUNISTRING unistring PATHS ${LIBUNISTRING_PATHS} REQUIRED)
    ENDIF()
ENDIF()

MESSAGE(STATUS "${HOST}")
MESSAGE(STATUS "")
MESSAGE(STATUS "Options used to compile and link:")
MESSAGE(STATUS "  WITH_TOOLS    = ${WITH_TOOLS}")
MESSAGE(STATUS "  WITH_NET      = ${WITH_NET}")
MESSAGE(STATUS "")

ADD_DEFINITIONS(
    -DPACKAGE_NAME="${PROJECT_NAME}"
    -DPACKAGE_VERSION="${PROJECT_VERSION}"
    -DRANDOM_DEVICE="${RANDOM_DEVICE}"
)
IF(USE_TESTS)
    ADD_DEFINITIONS(-DUSE_TESTS=1)
ENDIF()
IF(WITH_TOOLS)
    ADD_DEFINITIONS(-DWITH_TOOLS=1)
ENDIF()
IF(WITH_NET)
    ADD_DEFINITIONS(-DWITH_NET=1)
ENDIF()
FILE(TOUCH src/libdogecoin-config.h)


ADD_LIBRARY(${LIBDOGECOIN_NAME})

INSTALL(FILES
    include/dogecoin/address.h
    include/dogecoin/aes.h
    include/dogecoin/base58.h
    include/dogecoin/bip32.h
    include/dogecoin/block.h
    include/dogecoin/buffer.h
    include/dogecoin/byteswap.h
    include/dogecoin/chainparams.h
    include/dogecoin/cstr.h
    include/dogecoin/ctaes.h
    include/dogecoin/dogecoin.h
    include/dogecoin/ecc.h
    include/dogecoin/hash.h
    include/dogecoin/key.h
    include/dogecoin/koinu.h
    include/dogecoin/mem.h
    include/dogecoin/portable_endian.h
    include/dogecoin/random.h
    include/dogecoin/rmd160.h
    include/dogecoin/script.h
    include/dogecoin/serialize.h
    include/dogecoin/sha2.h
    include/dogecoin/tool.h
    include/dogecoin/transaction.h
    include/dogecoin/tx.h
    include/uthash/uthash.h
    include/dogecoin/utils.h
    include/dogecoin/vector.h
    include/dogecoin/wow.h
    DESTINATION include/dogecoin
)

IF(WIN32)
INSTALL(FILES
    contrib/getopt/wingetopt.h
    contrib/wintime/wingettime.h
    DESTINATION include/dogecoin
)
ENDIF()

TARGET_SOURCES(${LIBDOGECOIN_NAME} PRIVATE
    src/address.c
    src/aes.c
    src/base58.c
    src/bip32.c
    src/block.c
    src/buffer.c
    src/chainparams.c
    src/cstr.c
    src/ctaes.c
    src/ecc.c
    src/key.c
    src/koinu.c
    src/mem.c
    src/random.c
    src/rmd160.c
    src/script.c
    src/serialize.c
    src/sha2.c
    src/cli/tool.c
    src/transaction.c
    src/tx.c
    src/utils.c
    src/vector.c
    src/bip44.c
    src/bip39.c
)

IF(WIN32)
TARGET_SOURCES(${LIBDOGECOIN_NAME} PRIVATE
    contrib/getopt/wingetopt.c
    contrib/wintime/wingettime.c
)
ENDIF()

FILE(GLOB SECP256K1 RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    src/secp256k1/src/*.c)
LIST(REMOVE_ITEM SECP256K1
    src/secp256k1/src/tests.c
    src/secp256k1/src/tests_exhaustive.c
    src/secp256k1/src/bench_ecdh.c
    src/secp256k1/src/bench_ecmult.c
    src/secp256k1/src/bench_recover.c
    src/secp256k1/src/bench_sign.c
    src/secp256k1/src/bench_verify.c
    src/secp256k1/src/bench_ecdh.c
    src/secp256k1/src/bench_internal.c
    src/secp256k1/src/bench_schnorr_verify.c
    src/secp256k1/src/valgrind_ctime_test.c)
ADD_DEFINITIONS(
    -DUSE_NUM_GMP
    -DUSE_FIELD_10X26
    -DUSE_FIELD_INV_BUILTIN
    -DUSE_SCALAR_8X32
    -DUSE_SCALAR_INV_BUILTIN
    -DENABLE_MODULE_RECOVERY
    -DECMULT_WINDOW_SIZE=15
    -DECMULT_GEN_PREC_BITS=4)
TARGET_SOURCES(${LIBDOGECOIN_NAME} PRIVATE ${SECP256K1} ${LIBUNISTRING})

INCLUDE_DIRECTORIES(
    include
    src/secp256k1
    src/secp256k1/include
    ${GMP_INSTALL_DIR}/include)

IF(USE_TESTS)
    ADD_EXECUTABLE(tests)
    TARGET_SOURCES(tests PRIVATE
        test/address_tests.c
        test/aes_tests.c
        test/base58_tests.c
        test/bip32_tests.c
        test/block_tests.c
        test/buffer_tests.c
        test/cstr_tests.c
        test/ecc_tests.c
        test/hash_tests.c
        test/key_tests.c
        test/koinu_tests.c
        test/mem_tests.c
        test/opreturn_tests.c
        test/random_tests.c
        test/rmd160_tests.c
        test/serialize_tests.c
        test/sha2_tests.c
        test/transaction_tests.c
        test/tx_tests.c
        test/utest.h
        test/unittester.c
        test/utils_tests.c
        test/vector_tests.c
        test/bip39_tests.c
        test/bip44_tests.c
)
    TARGET_LINK_LIBRARIES(tests ${LIBDOGECOIN_NAME} ${LIBUNISTRING})
    ADD_TEST(NAME ${LIBDOGECOIN_NAME}_tests COMMAND tests)
ENDIF()

IF(WITH_NET)
    INCLUDE_DIRECTORIES(
        src/libevent
        src/libevent/include)
    INSTALL(FILES
        include/dogecoin/protocol.h
        include/dogecoin/net.h
        DESTINATION include/dogecoin
    )
    TARGET_SOURCES(${LIBDOGECOIN_NAME} PRIVATE
        src/net.c
        src/protocol.c
    )

    TARGET_LINK_LIBRARIES(${LIBDOGECOIN_NAME} ${LIBEVENT} ${LIBEVENT_PTHREADS} ${LIBUNISTRING})

    IF(USE_TESTS)
        TARGET_SOURCES(tests PRIVATE
            test/net_tests.c
            test/protocol_tests.c
        )
    ENDIF()
ENDIF()

IF(WITH_TOOLS)
    IF(USE_TESTS)
        TARGET_SOURCES(tests PRIVATE
            test/tool_tests.c
        )
    ENDIF()

    ADD_EXECUTABLE(such src/cli/such.c)
    INSTALL(TARGETS such RUNTIME)
    TARGET_LINK_LIBRARIES(such ${LIBDOGECOIN_NAME} ${LIBUNISTRING} )

    TARGET_INCLUDE_DIRECTORIES(such PRIVATE src)

    IF(WITH_NET)
        ADD_EXECUTABLE(sendtx src/cli/sendtx.c)
        INSTALL(TARGETS sendtx RUNTIME)
        TARGET_LINK_LIBRARIES(sendtx ${LIBDOGECOIN_NAME} ${LIBUNISTRING} )

        TARGET_INCLUDE_DIRECTORIES(sendtx PRIVATE src)
    ENDIF()
ENDIF()
