/* $Id: compat.c 221 2008-08-22 14:59:28Z roe $ */

#include <stdlib.h>
#include <wchar.h>

#ifdef COMPAT_WCSDUP
wchar_t *
wcsdup(const wchar_t *s)
{
	wchar_t *copy;
	size_t len;

	len = wcslen(s) + 1;
	if ((copy = malloc(len * sizeof(wchar_t))) == NULL)
		return (NULL);
	return (wmemcpy(copy, s, len));
}
#endif

void dummy()
{
	return;
}

