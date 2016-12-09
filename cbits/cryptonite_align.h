#ifndef CRYPTONITE_ALIGN_H
#define CRYPTONITE_ALIGN_H

#include "cryptonite_bitfn.h"

#if (defined(__i386__))
# define UNALIGNED_ACCESS_OK
#elif defined(__x86_64__)
# define UNALIGNED_ACCESS_OK
#else
# define UNALIGNED_ACCESS_FAULT
#endif

/* n need to be power of 2.
 * IS_ALIGNED(p,8) */
#define IS_ALIGNED(p,alignment) (((uintptr_t) (p)) & ((alignment)-1))

#ifdef WITH_ASSERT_ALIGNMENT
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
# define ASSERT_ALIGNMENT(up, alignment) \
	do { if (IS_ALIGNED(up, alignment)) \
	{ printf("ALIGNMENT-ASSERT-FAILURE: %s:%d: ptr=%p alignment=%d\n", __FILE__, __LINE__, (void *) up, (alignment)); \
	  exit(99); \
	}; } while (0)
#else
# define ASSERT_ALIGNMENT(p, n) do {} while (0)
#endif

#ifdef UNALIGNED_ACCESS_OK
#define need_alignment(p,n) (0)
#else
#define need_alignment(p,n) IS_ALIGNED(p,n)
#endif

static inline uint32_t load_le32_aligned(const uint8_t *p)
{
	return le32_to_cpu(*((uint32_t *) p));		
}

#ifdef UNALIGNED_ACCESS_OK
#define load_le32(a) load_le32_aligned(a)
#else
static inline uint32_t load_le32(const uint8_t *p)
{
	return ((uint32_t)p[0]) | ((uint32_t)p[1] <<  8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
#endif

#endif
