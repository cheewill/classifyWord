/* $Id: strconv.c 211 2008-08-22 14:12:06Z roe $ */

#include <sys/types.h>
#include <stdint.h>
#include <wchar.h>
#include <string.h>

/*
 * These conversions are not 
 */

/*
 * Dirty hack which works most of the time and is significantly
 * faster than using libiconv.  Calculates the string size in
 * bytes for free.
 */
size_t
ucs2_from_wcs(uint8_t *dst, size_t dstsz, wchar_t *src)
{
	wchar_t *sp = src;
	int i;

	for (i = 0; i < dstsz && *sp; i += 2) {
		dst[i]   = (uint8_t)((*sp) & 0x000000ff);
		dst[i+1] = (uint8_t)(((*sp++) & 0x0000ff00) >> 8);
	}

	return i;
}

/*
 * Convert a UCS2 string of sz bytes into a NULL-terminated
 * wchar_t string.
 */
void
ucs2_to_wcs(uint8_t *src, size_t srcsz, wchar_t *dst)
{
	wchar_t *dp = dst;

	for (int i = 0; i < srcsz; i += 2) {
		*dp++ = (wchar_t)( (uint32_t)(src[i]) |
		                  ((uint32_t)(src[i+1]) << 8));
	}
	*dp = 0;
}

int
is_same_name(const uint16_t *name1, size_t size1,
             const uint16_t *name2, size_t size2)
{
	if (size1 != size2)
	{
		return 0;
	}

	if (0 == memcmp(name1, name2, size1 * sizeof(uint16_t)))
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

