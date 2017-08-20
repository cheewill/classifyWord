/* $Id: memeq.h 215 2008-08-22 14:23:14Z roe $ */

#ifndef MEMEQ_H
#define MEMEQ_H

/* unsupported internal interfaces, do not use */
#define memeq1x32(x,nx,y,ny) (((uint32_t*)(x))[nx] == ((uint32_t*)(y))[ny])
#define memeq1x64(x,nx,y,ny) (((uint64_t*)(x))[nx] == ((uint64_t*)(y))[ny])
#define memeq2x32(x,y) ( \
		memeq1x32((x), 0, (y), 0) && \
		memeq1x32((x), 1, (y), 1))
#define memeq2x64(x,y) ( \
		memeq1x64((x), 0, (y), 0) && \
		memeq1x64((x), 1, (y), 1))
#define memeq2x64a1x32(x,y) ( \
		memeq1x64((x), 0, (y), 0) && \
		memeq1x64((x), 1, (y), 1) && \
		memeq1x32((x), 4, (y), 4))
#define memeq3x64(x,y) ( \
		memeq1x64((x), 0, (y), 0) && \
		memeq1x64((x), 1, (y), 1) && \
		memeq1x64((x), 2, (y), 2))
#define memeq4x32(x,y) ( \
		memeq1x32((x), 0, (y), 0) && \
		memeq1x32((x), 1, (y), 1) && \
		memeq1x32((x), 2, (y), 2) && \
		memeq1x32((x), 3, (y), 3))
#define memeq5x32(x,y) ( \
		memeq1x32((x), 0, (y), 0) && \
		memeq1x32((x), 1, (y), 1) && \
		memeq1x32((x), 2, (y), 2) && \
		memeq1x32((x), 3, (y), 3) && \
		memeq1x32((x), 4, (y), 4))
#define memeq6x32(x,y) ( \
		memeq1x32((x), 0, (y), 0) && \
		memeq1x32((x), 1, (y), 1) && \
		memeq1x32((x), 2, (y), 2) && \
		memeq1x32((x), 3, (y), 3) && \
		memeq1x32((x), 4, (y), 4) && \
		memeq1x32((x), 5, (y), 5))

/* supported interfaces */
#if defined(__LP64__)
# define memeq128(x,y) memeq2x64(x,y)
# define memeq160(x,y) memeq2x64a1x32(x,y)
# define memeq192(x,y) memeq3x64(x,y)
#else
# define memeq128(x,y) memeq4x32(x,y)
# define memeq160(x,y) memeq5x32(x,y)
# define memeq192(x,y) memeq6x32(x,y)
#endif

#endif /* MEMEQ_H */

