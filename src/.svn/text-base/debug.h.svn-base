/* $Id: debug.h 194 2008-08-22 06:41:47Z roe $ */

#ifndef DEBUG_H
#define DEBUG_H

#ifdef DEBUG
# include <sys/types.h>
# define HD(x,y,z)	hd((x),(y),(z))
void hd(const char *, void *, size_t);
# define DPRINTF(...)	fprintf(stderr, __VA_ARGS__)
#else
# define HD(x,y,z)
# define DPRINTF(...)
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif

#include <assert.h>

#endif /* DEBUG_H */

