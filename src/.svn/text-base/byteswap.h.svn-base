/* $Id: byteswap.h 210 2008-08-22 14:04:36Z roe $ */

#ifndef BYTESWAP_H
#define BYTESWAP_H

#include <sys/param.h>

/*
 * These are safe to use with prefix/postfix ++ (e.g. htolel(sz++)).
 */

static inline unsigned short
bswap_16(unsigned short x)
{
	return (x >> 8) | (x << 8);
}

static inline unsigned long
bswap_32(unsigned long x)
{
	return (bswap_16(x & 0xffff) << 16) | (bswap_16(x >> 16));
}

static inline unsigned long long
bswap_64(unsigned long long x)
{
	return (((unsigned long long)bswap_32(x & 0xffffffffull)) << 32) |
		(bswap_32(x >> 32));
}

#if BYTE_ORDER == LITTLE_ENDIAN
#define htoles(x) (x)
#define htolel(x) (x)
#define htolell(x) (x)
#else
#define htoles(x) bswap_16(x)
#define htolel(x) bswap_32(x)
#define htolell(x) bswap_64(x)
#endif

#if BYTE_ORDER == BIG_ENDIAN
#define htobes(x) (x)
#define htobel(x) (x)
#define htobell(x) (x)
#else
#define htobes(x) bswap_16(x)
#define htobel(x) bswap_32(x)
#define htobell(x) bswap_64(x)
#endif

#endif /* BYTESWAP_H */

