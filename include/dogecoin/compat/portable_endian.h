/* "License": Public Domain
// I, Mathias Panzenböck, place this file hereby into the public domain. Use it at your own risk for whatever you like.
// In case there are jurisdictions that don't support putting things in the public domain you can also consider it to
// be "dual licensed" under the BSD, MIT and Apache licenses, if you want to. This code is trivial anyway. Consider it
// an example on how to get the endian conversion functions on different platforms.
//
// Copyright (c) 2022 bluezr
// Copyright (c) 2022 The Dogecoin Foundation
*/

#ifndef __LIBDOGECOIN_COMPAT_PORTABLE_ENDIAN_H__
#define __LIBDOGECOIN_COMPAT_PORTABLE_ENDIAN_H__

LIBDOGECOIN_BEGIN_DECL

#if defined(HAVE_CONFIG_H)
#include <src/libdogecoin-config.h>
#endif

#include <stdint.h>

#include <dogecoin/compat/byteswap.h>

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)

#define __WINDOWS__

#endif

#if defined(__linux__) || defined(__CYGWIN__)

#if defined(HAVE_ENDIAN_H)
#include <endian.h>
#endif

#elif defined(__APPLE__)

#include <libkern/OSByteOrder.h>

/* Swapping the byte order of the 16-bit integer `x` from host byte order to big endian byte order. */
#define htobe16(x) OSSwapHostToBigInt16(x)
/* Swapping the byte order of the 16-bit integer `x` from host byte order to little endian byte order. */
#define htole16(x) OSSwapHostToLittleInt16(x)
/* Swapping the byte order of the 16-bit integer `x` from big endian byte order to host byte order. */
#define be16toh(x) OSSwapBigToHostInt16(x)
/* Swapping the byte order of the 16-bit integer `x` from little endian byte order to host byte order. */
#define le16toh(x) OSSwapLittleToHostInt16(x)

/* Swapping the byte order of the 32-bit integer `x` from host byte order to big endian byte order. */
#define htobe32(x) OSSwapHostToBigInt32(x)
/* Swapping the byte order of the 32-bit integer `x` from host byte order to little endian byte order. */
#define htole32(x) OSSwapHostToLittleInt32(x)
/* Swapping the byte order of the 32-bit integer `x` from big endian byte order to host byte order. */
#define be32toh(x) OSSwapBigToHostInt32(x)
/* Swapping the byte order of the 32-bit integer `x` from little endian byte order to host byte order. */
#define le32toh(x) OSSwapLittleToHostInt32(x)

/* Swapping the byte order of the 64-bit integer `x` from host byte order to big endian byte order. */
#define htobe64(x) OSSwapHostToBigInt64(x)
/* Swapping the byte order of the 64-bit integer `x` from host byte order to little endian byte order. */
#define htole64(x) OSSwapHostToLittleInt64(x)
/* Swapping the byte order of the 64-bit integer `x` from big endian byte order to host byte order. */
#define be64toh(x) OSSwapBigToHostInt64(x)
/* Swapping the byte order of the 64-bit integer `x` from little endian byte order to host byte order. */
#define le64toh(x) OSSwapLittleToHostInt64(x)

#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __PDP_ENDIAN PDP_ENDIAN

#elif defined(__OpenBSD__)

#if defined(HAVE_SYS_ENDIAN_H)
#include <sys/endian.h>
#endif

#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)

#if defined(HAVE_SYS_ENDIAN_H)
#include <sys/endian.h>
#endif

/* A macro that swaps the byte order of the 16-bit integer `x` from big endian byte order to host byte
order. */
#define be16toh(x) betoh16(x)
/* A macro that swaps the byte order of the 16-bit integer `x` from little endian byte order to host
byte order. */
#define le16toh(x) letoh16(x)

/* Swapping the byte order of the 32-bit integer `x` from big endian byte order to host byte order. */
#define be32toh(x) betoh32(x)
/* A macro that swaps the byte order of the 32-bit integer `x` from little endian byte order to host
byte order. */
#define le32toh(x) letoh32(x)

/* Swapping the byte order of the 64-bit integer `x` from big endian byte order to host byte order. */
#define be64toh(x) betoh64(x)
/* A macro that swaps the byte order of the 64-bit integer `x` from little endian byte order to host
byte order. */
#define le64toh(x) letoh64(x)

#elif defined(__WINDOWS__)

#include <winsock2.h>
#include <sys/param.h>

#if BYTE_ORDER == LITTLE_ENDIAN

#define htobe16(x) htons(x)
#define htole16(x) (x)
#define be16toh(x) ntohs(x)
#define le16toh(x) (x)

#define htobe32(x) htonl(x)
#define htole32(x) (x)
#define be32toh(x) ntohl(x)
#define le32toh(x) (x)

#define htobe64(x) htonll(x)
#define htole64(x) (x)
#define be64toh(x) ntohll(x)
#define le64toh(x) (x)

#if HAVE_DECL_HTOLE16 == 0
/**
 * Convert a 16-bit integer from host-endian to little-endian
 * 
 * @param host_16bits the host-native value to be converted to little-endian.
 * 
 * @return the host-byte-order 16-bit value converted to little-endian byte order.
 */
LIBDOGECOIN_API static inline uint16_t htole16(uint16_t host_16bits)
{
    return bswap_16(host_16bits);
}
#endif // HAVE_DECL_HTOLE16

#if HAVE_DECL_LE16TOH == 0
/**
 * Convert a little endian 16 bits value to a big endian 16 bits value
 * 
 * @param little_endian_16bits the little-endian 16-bit value to convert to host byte order
 * 
 * @return the value of the 16-bit integer in host byte order.
 */
LIBDOGECOIN_API static inline uint16_t le16toh(uint16_t little_endian_16bits)
{
    return bswap_16(little_endian_16bits);
}
#endif // HAVE_DECL_LE16TOH

#if HAVE_DECL_HTOLE32 == 0
LIBDOGECOIN_API static inline uint32_t htole32(uint32_t host_32bits)
/* Swapping the bytes of a 32-bit integer. */
{
    return bswap_32(host_32bits);
}
#endif // HAVE_DECL_HTOLE32

#if HAVE_DECL_LE32TOH == 0
/**
 * Convert a 32-bit little-endian integer to a 32-bit big-endian integer
 * 
 * @param little_endian_32bits the little-endian 32-bit value to convert to big-endian
 * 
 * @return the value of the 32-bit integer in host (CPU) byte order.
 */
LIBDOGECOIN_API static inline uint32_t le32toh(uint32_t little_endian_32bits)
{
    return bswap_32(little_endian_32bits);
}
#endif // HAVE_DECL_LE32TOH

#if HAVE_DECL_HTOLE64 == 0
/**
 * Convert a 64-bit integer from host byte order to little-endian byte order
 * 
 * @param host_64bits the 64-bit integer to be converted to little-endian.
 * 
 * @return the host to little endian conversion of the host 64-bit unsigned integer.
 */
LIBDOGECOIN_API static inline uint64_t htole64(uint64_t host_64bits)
{
    return bswap_64(host_64bits);
}
#endif // HAVE_DECL_HTOLE64

#if HAVE_DECL_LE64TOH == 0
/**
 * Convert a 64-bit little endian integer to a 64-bit big endian integer.
 * 
 * @param little_endian_64bits the value to be converted
 * 
 * @return the value of the variable little_endian_64bits
 */
LIBDOGECOIN_API static inline uint64_t le64toh(uint64_t little_endian_64bits)
{
    return bswap_64(little_endian_64bits);
}
#endif // HAVE_DECL_LE64TOH

#if HAVE_DECL_HTOLE16 == 0
LIBDOGECOIN_API static inline uint16_t htole16(uint16_t host_16bits)
{
    return host_16bits;
}
#endif // HAVE_DECL_HTOLE16

#if HAVE_DECL_LE16TOH == 0
LIBDOGECOIN_API static inline uint16_t le16toh(uint16_t little_endian_16bits)
{
    return little_endian_16bits;
}
#endif // HAVE_DECL_LE16TOH

#if HAVE_DECL_HTOLE32 == 0
LIBDOGECOIN_API static inline uint32_t htole32(uint32_t host_32bits)
{
    return host_32bits;
}
#endif // HAVE_DECL_HTOLE32

#if HAVE_DECL_LE32TOH == 0
/**
 * Converts a little endian 32 bit integer to a big endian 32 bit integer
 * 
 * @param little_endian_32bits The little endian 32 bits value to convert to big endian.
 * 
 * @return the value of the 32-bit integer passed to it.
 */
LIBDOGECOIN_API static inline uint32_t le32toh(uint32_t little_endian_32bits)
{
    return little_endian_32bits;
}
#endif // HAVE_DECL_LE32TOH

#if HAVE_DECL_HTOLE64 == 0
LIBDOGECOIN_API static inline uint64_t htole64(uint64_t host_64bits)
{
    return host_64bits;
}
#endif // HAVE_DECL_HTOLE64

#if HAVE_DECL_LE64TOH == 0
/**
 * Convert a 64-bit little-endian integer to a 64-bit big-endian integer.
 * 
 * @param little_endian_64bits the value to be converted
 * 
 * @return the value of the 64-bit integer passed to it.
 */
LIBDOGECOIN_API static inline uint64_t le64toh(uint64_t little_endian_64bits)
{
    return little_endian_64bits;
}
#endif // HAVE_DECL_LE64TOH


#elif BYTE_ORDER == BIG_ENDIAN


/* that would be xbox 360 */
#define htobe16(x) (x)
#define htole16(x) bswap_16(x)
#define be16toh(x) (x)
#define le16toh(x) bswap_16(x)

#define htobe32(x) (x)
#define htole32(x) bswap_32(x)
#define be32toh(x) (x)
#define le32toh(x) bswap_32(x)

#define htobe64(x) (x)
#define htole64(x) bswap_64(x)
#define be64toh(x) (x)
#define le64toh(x) bswap_64(x)

#if HAVE_DECL_HTOBE16 == 0
/**
 * It converts a 16-bit integer from host-byte order to big-endian byte order.
 * 
 * @param host_16bits the host-endian representation of a 16-bit unsigned integer.
 * 
 * @return The host byte order version of the 16-bit value.
 */
LIBDOGECOIN_API static inline uint16_t htobe16(uint16_t host_16bits)
{
    return host_16bits;
}
#endif // HAVE_DECL_HTOBE16

#if HAVE_DECL_BE16TOH == 0
/**
 * Convert a big endian 16 bits value to a host endian 16 bits value
 * 
 * @param big_endian_16bits The 16-bit value to be converted to little-endian.
 * 
 * @return The value of the 16-bit integer in host byte order.
 */
LIBDOGECOIN_API static inline uint16_t be16toh(uint16_t big_endian_16bits)
{
    return big_endian_16bits;
}
#endif // HAVE_DECL_BE16TOH

#if HAVE_DECL_HTOBE32 == 0
/**
 * It converts a 32-bit integer from host byte order to big-endian byte order.
 * 
 * @param host_32bits the 32-bit integer to be converted to big-endian.
 * 
 * @return The host_32bits value.
 */
LIBDOGECOIN_API static inline uint32_t htobe32(uint32_t host_32bits)
{
    return host_32bits;
}
#endif // HAVE_DECL_HTOBE32

#if HAVE_DECL_BE32TOH == 0
/**
 * Converts a big endian 32 bit integer to a host byte order 32 bit integer
 * 
 * @param big_endian_32bits The 32-bit integer to convert to little-endian.
 * 
 * @return The value of the 32-bit integer in host byte order.
 */
LIBDOGECOIN_API static inline uint32_t be32toh(uint32_t big_endian_32bits)
{
    return big_endian_32bits;
}
#endif // HAVE_DECL_BE32TOH

#if HAVE_DECL_HTOBE64 == 0
/**
 * It converts a 64-bit integer from host-byte order to big-endian byte order.
 * 
 * @param host_64bits the 64-bit integer to be converted to big-endian.
 * 
 * @return The host 64-bit integer in network byte order.
 */
LIBDOGECOIN_API static inline uint64_t htobe64(uint64_t host_64bits)
{
    return host_64bits;
}
#endif // HAVE_DECL_HTOBE64

#if HAVE_DECL_BE64TOH == 0
LIBDOGECOIN_API static inline uint64_t be64toh(uint64_t big_endian_64bits)
{
    return big_endian_64bits;
}
#endif // HAVE_DECL_BE64TOH

#if HAVE_DECL_HTOBE16 == 0
/**
 * Convert a 16-bit integer from host-byte order to network-byte order
 * 
 * @param host_16bits the host-endian version of the 16-bit value
 * 
 * @return the host-byte-order converted value of the host-byte-order value passed in.
 */
LIBDOGECOIN_API static inline uint16_t htobe16(uint16_t host_16bits)
{
    return bswap_16(host_16bits);
}
#endif // HAVE_DECL_HTOBE16

#if HAVE_DECL_BE16TOH == 0
/**
 * Convert a big endian 16 bits value to a little endian 16 bits value
 * 
 * @param big_endian_16bits The 16-bit value to be converted to little-endian.
 * 
 * @return the value of the 16-bit integer in host byte order.
 */
LIBDOGECOIN_API static inline uint16_t be16toh(uint16_t big_endian_16bits)
{
    return bswap_16(big_endian_16bits);
}
#endif // HAVE_DECL_BE16TOH

#if HAVE_DECL_HTOBE32 == 0
/**
 * Convert a 32-bit integer from host byte order to big-endian byte order
 * 
 * @param host_32bits the 32-bit integer to convert to big-endian
 * 
 * @return the host to big endian conversion of the host 32 bit integer.
 */
LIBDOGECOIN_API static inline uint32_t htobe32(uint32_t host_32bits)
{
    return bswap_32(host_32bits);
}
#endif // HAVE_DECL_HTOBE32

#if HAVE_DECL_BE32TOH == 0
/**
 * Convert a 32-bit big-endian integer to a 32-bit little-endian integer
 * 
 * @param big_endian_32bits The 32-bit integer to convert to little-endian.
 * 
 * @return the value of the 32-bit integer in host byte order.
 */
LIBDOGECOIN_API static inline uint32_t be32toh(uint32_t big_endian_32bits)
{
    return bswap_32(big_endian_32bits);
}
#endif // HAVE_DECL_BE32TOH

#if HAVE_DECL_HTOBE64 == 0
/**
 * Convert a 64-bit unsigned integer from host byte order to big-endian.
 * 
 * @param host_64bits the 64-bit integer to convert to big-endian
 * 
 * @return the host to big endian conversion of the host 64 bit integer.
 */
LIBDOGECOIN_API static inline uint64_t htobe64(uint64_t host_64bits)
{
    return bswap_64(host_64bits);
}
#endif // HAVE_DECL_HTOBE64

#if HAVE_DECL_BE64TOH == 0
/**
 * Convert a 64-bit big-endian integer to a 64-bit little-endian integer
 * 
 * @param big_endian_64bits The 64-bit big-endian value to convert to host byte order.
 * 
 * @return the value of the variable big_endian_64bits
 */
LIBDOGECOIN_API static inline uint64_t be64toh(uint64_t big_endian_64bits)
{
    return bswap_64(big_endian_64bits);
}
#endif // HAVE_DECL_BE64TOH

#else

#error byte order not supported

#endif

#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __PDP_ENDIAN PDP_ENDIAN

#else

#error platform not supported

#endif

LIBDOGECOIN_END_DECL

#endif // __LIBDOGECOIN_COMPAT_PORTABLE_ENDIAN_H__
