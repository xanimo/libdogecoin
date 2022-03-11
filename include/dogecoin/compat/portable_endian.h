/* "License": Public Domain
// I, Mathias Panzenböck, place this file hereby into the public domain. Use it at your own risk for whatever you like.
// In case there are jurisdictions that don't support putting things in the public domain you can also consider it to
// be "dual licensed" under the BSD, MIT and Apache licenses, if you want to. This code is trivial anyway. Consider it
// an example on how to get the endian conversion functions on different platforms.
*/
#ifndef __LIBDOGECOIN_COMPAT_PORTABLE_ENDIAN_H__
#define __LIBDOGECOIN_COMPAT_PORTABLE_ENDIAN_H__

#include <stdint.h>

#include <dogecoin/compat/byteswap.h>

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)

#define __WINDOWS__

#endif

#if defined(__linux__) || defined(__CYGWIN__)

#include <endian.h>

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

#include <sys/endian.h>

#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)

#include <sys/endian.h>

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

#ifndef _MSC_VER
#include <sys/param.h>
#endif
#include <winsock2.h>

#if BYTE_ORDER == LITTLE_ENDIAN

/* Swapping the byte order of the 16-bit integer `x` from host byte order to big endian byte order. */
#define htobe16(x) htons(x)
/* A macro that swaps the byte order of the 16-bit integer `x` from host byte order to little endian
byte order. */
#define htole16(x) (x)
/* Swapping the byte order of the 16-bit integer `x` from big endian byte order to host byte order. */
#define be16toh(x) ntohs(x)
/* A macro that swaps the byte order of the 16-bit integer `x` from little endian byte order to host
byte order. */
#define le16toh(x) (x)

/* Swapping the byte order of the 32-bit integer `x` from host byte order to big endian byte order. */
#define htobe32(x) htonl(x)
/* A macro that swaps the byte order of the 32-bit integer `x` from host byte order to little endian
byte order. */
#define htole32(x) (x)
/* Swapping the byte order of the 32-bit integer `x` from little endian byte order to host byte order. */
#define be32toh(x) ntohl(x)
/* A macro that swaps the byte order of the 32-bit integer `x` from little endian byte order to host
byte order. */
#define le32toh(x) (x)

/* Swapping the byte order of the 64-bit integer `x` from host byte order to big endian byte order. */
#define htobe64(x) htonll(x)
/* A macro that swaps the byte order of the 64-bit integer `x` from host byte order to little endian
byte order. */
#define htole64(x) (x)
/* Swapping the byte order of the 64-bit integer `x` from little endian byte order to host byte order. */
#define be64toh(x) ntohll(x)
/* A macro that swaps the byte order of the 64-bit integer `x` from little endian byte order to host
byte order. */
#define le64toh(x) (x)

#elif BYTE_ORDER == BIG_ENDIAN

/* that would be xbox 360 */
/* A trick to make the code compile on both Linux and Windows. */
#define htobe16(x) (x)
/* Swapping the byte order of the 16-bit integer `x` from host byte order to little endian byte order. */
#define htole16(x) bswap_16(x)
/* A trick to make the code compile on both Linux and Windows. */
#define be16toh(x) (x)
/* Swapping the byte order of the 16-bit integer `x` from little endian byte order to host byte order. */
#define le16toh(x) bswap_16(x)

/* A trick to make the code compile on both Linux and Windows. */
#define htobe32(x) (x)
/* Swapping the byte order of the 32-bit integer `x` from host byte order to little endian byte order. */
#define htole32(x) bswap_32(x)
/* A trick to make the code compile on both Linux and Windows. */
#define be32toh(x) (x)
/* Swapping the byte order of the 32-bit integer `x` from little endian byte order to host byte order. */
#define le32toh(x) bswap_32(x)

/* A trick to make the code compile on both Linux and Windows. */
#define htobe64(x) (x)
/* Swapping the byte order of the 64-bit integer `x` from host byte order to little endian byte order. */
#define htole64(x) bswap_64(x)
/* A trick to make the code compile on both Linux and Windows. */
#define be64toh(x) (x)

/* Swapping the byte order of the 64-bit integer `x` from little endian byte order to host byte order. */
#define le64toh(x) bswap_64(x)

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

#endif // __LIBDOGECOIN_COMPAT_PORTABLE_ENDIAN_H__
