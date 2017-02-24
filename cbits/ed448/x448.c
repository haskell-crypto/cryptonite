/* Copyright (c) 2015 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/**
 * @file decaf.c
 * @author Mike Hamburg
 * @brief Decaf high-level functions.
 */

#include <stdint.h>
#include "x448.h"

#ifdef ARCH_X86_64
#define WBITS 64
#else
#define WBITS 32
#endif

#define LBITS (WBITS * 7 / 8)
#define X448_LIMBS (448/LBITS)

#if WBITS == 64
typedef uint64_t decaf_word_t;
typedef int64_t decaf_sword_t;
typedef __uint128_t decaf_dword_t;
typedef __int128_t decaf_sdword_t;
#elif WBITS == 32
typedef uint32_t decaf_word_t;
typedef int32_t decaf_sword_t;
typedef uint64_t decaf_dword_t;
typedef int64_t decaf_sdword_t;
#else
#error "WBITS must be 32 or 64"
#endif

typedef struct { decaf_word_t limb[X448_LIMBS]; } gf_s, gf[1];

static const unsigned char X448_BASE_POINT[X448_BYTES] = {5};

static const gf ZERO = {{{0}}}, ONE = {{{1}}};

#define LMASK ((((decaf_word_t)1)<<LBITS)-1)
#if WBITS == 64
static const gf P = {{{ LMASK, LMASK, LMASK, LMASK, LMASK-1, LMASK, LMASK, LMASK }}};
#else
static const gf P = {{{ LMASK,   LMASK, LMASK, LMASK, LMASK, LMASK, LMASK, LMASK,
		      LMASK-1, LMASK, LMASK, LMASK, LMASK, LMASK, LMASK, LMASK }}};
#endif
static const int EDWARDS_D = -39081;

#if (defined(__OPTIMIZE__) && !defined(__OPTIMIZE_SIZE__)) || defined(DECAF_FORCE_UNROLL)
    #if X448_LIMBS==8
    #define FOR_LIMB_U(i,op) { unsigned int i=0; \
       op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; \
    }
    #elif X448_LIMBS==16
    #define FOR_LIMB_U(i,op) { unsigned int i=0; \
       op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; \
       op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; \
    }
    #else
    #define FOR_LIMB_U(i,op) { unsigned int i=0; for (i=0; i<X448_LIMBS; i++)  { op; }}
    #endif
#else
#define FOR_LIMB_U(i,op) { unsigned int i=0; for (i=0; i<X448_LIMBS; i++)  { op; }}
#endif

#define FOR_LIMB(i,op) { unsigned int i=0; for (i=0; i<X448_LIMBS; i++)  { op; }}

/** Copy x = y */
static void gf_cpy(gf x, const gf y) {
    FOR_LIMB_U(i, x->limb[i] = y->limb[i]);
}

/** Mostly-unoptimized multiply (PERF), but at least it's unrolled. */
static void
gf_mul (gf c, const gf a, const gf b) {
    gf aa;
    gf_cpy(aa,a);

    decaf_dword_t accum[X448_LIMBS] = {0};
    FOR_LIMB_U(i, {
        FOR_LIMB_U(j,{ accum[(i+j)%X448_LIMBS] += (decaf_dword_t)b->limb[i] * aa->limb[j]; });
        aa->limb[(X448_LIMBS-1-i)^(X448_LIMBS/2)] += aa->limb[X448_LIMBS-1-i];
    });

    accum[X448_LIMBS-1] += accum[X448_LIMBS-2] >> LBITS;
    accum[X448_LIMBS-2] &= LMASK;
    accum[X448_LIMBS/2] += accum[X448_LIMBS-1] >> LBITS;
    FOR_LIMB_U(j,{
        accum[j] += accum[(j-1)%X448_LIMBS] >> LBITS;
        accum[(j-1)%X448_LIMBS] &= LMASK;
    });
    FOR_LIMB_U(j, c->limb[j] = accum[j] );
}

/** No dedicated square (PERF) */
#define gf_sqr(c,a) gf_mul(c,a,a)

/** Inverse square root using addition chain. */
static void
gf_isqrt(gf y, const gf x) {
    int i;
#define STEP(s,m,n) gf_mul(s,m,c); gf_cpy(c,s); for (i=0;i<n;i++) gf_sqr(c,c);
    gf a, b, c;
    gf_sqr ( c,   x );
    STEP(b,x,1);
    STEP(b,x,3);
    STEP(a,b,3);
    STEP(a,b,9);
    STEP(b,a,1);
    STEP(a,x,18);
    STEP(a,b,37);
    STEP(b,a,37);
    STEP(b,a,111);
    STEP(a,b,1);
    STEP(b,x,223);
    gf_mul(y,a,c);
}

static void
gf_inv(gf y, const gf x) {
    gf z,w;
    gf_sqr(z,x); /* x^2 */
    gf_isqrt(w,z); /* +- 1/sqrt(x^2) = +- 1/x */
    gf_sqr(z,w); /* 1/x^2 */
    gf_mul(w,x,z); /* 1/x */
    gf_cpy(y,w);
}

/** Weak reduce mod p. */
static void
gf_reduce(gf x) {
    x->limb[X448_LIMBS/2] += x->limb[X448_LIMBS-1] >> LBITS;
    FOR_LIMB_U(j,{
        x->limb[j] += x->limb[(j-1)%X448_LIMBS] >> LBITS;
        x->limb[(j-1)%X448_LIMBS] &= LMASK;
    });
}

/** Add mod p.  Conservatively always weak-reduce. (PERF) */
static void
gf_add ( gf x, const gf y, const gf z ) {
    FOR_LIMB_U(i, x->limb[i] = y->limb[i] + z->limb[i] );
    gf_reduce(x);
}

/** Subtract mod p.  Conservatively always weak-reduce. (PERF) */
static void
gf_sub ( gf x, const gf y, const gf z ) {
    FOR_LIMB_U(i, x->limb[i] = y->limb[i] - z->limb[i] + 2*P->limb[i] );
    gf_reduce(x);
}

/** Constant time, if (swap) (x,y) = (y,x); */
static void
cond_swap(gf x, gf_s *__restrict__ y, decaf_word_t swap) {
    FOR_LIMB_U(i, {
        decaf_word_t s = (x->limb[i] ^ y->limb[i]) & swap;
        x->limb[i] ^= s;
        y->limb[i] ^= s;
    });
}

/**
 * Mul by signed int.  Not constant-time WRT the sign of that int.
 * Just uses a full mul (PERF)
 */
static inline void
gf_mlw(gf a, const gf b, int w) {
    if (w>0) {
        gf ww = {{{w}}};
        gf_mul(a,b,ww);
    } else {
        gf ww = {{{-w}}};
        gf_mul(a,b,ww);
        gf_sub(a,ZERO,a);
    }
}

/** Canonicalize */
static void gf_canon ( gf a ) {
    gf_reduce(a);

    /* subtract p with borrow */
    decaf_sdword_t carry = 0;
    FOR_LIMB(i, {
        carry = carry + a->limb[i] - P->limb[i];
        a->limb[i] = carry & LMASK;
        carry >>= LBITS;
    });

    decaf_word_t addback = carry;
    carry = 0;

    /* add it back */
    FOR_LIMB(i, {
        carry = carry + a->limb[i] + (P->limb[i] & addback);
        a->limb[i] = carry & LMASK;
        carry >>= LBITS;
    });
}

/* Deserialize */
static decaf_word_t
gf_deser(gf s, const unsigned char ser[X448_BYTES]) {
    unsigned int i, k=0, bits=0;
    decaf_dword_t buf=0;
    for (i=0; i<X448_BYTES; i++) {
        buf |= (decaf_dword_t)ser[i]<<bits;
        for (bits += 8; (bits>=LBITS || i==X448_BYTES-1) && k<X448_LIMBS; bits-=LBITS, buf>>=LBITS) {
            s->limb[k++] = buf & LMASK;
        }
    }

    decaf_sdword_t accum = 0;
    FOR_LIMB(i, accum = (accum + s->limb[i] - P->limb[i]) >> WBITS );
    return accum;
}

/* Serialize */
static void
gf_ser(uint8_t ser[X448_BYTES], gf a) {
    gf_canon(a);
    int k=0, bits=0;
    decaf_dword_t buf=0;
    FOR_LIMB(i, {
        buf |= (decaf_dword_t)a->limb[i]<<bits;
        for (bits += LBITS; (bits>=8 || i==X448_LIMBS-1) && k<X448_BYTES; bits-=8, buf>>=8) {
            ser[k++]=buf;
        }
    });
}

int __attribute__((visibility("default"))) cryptonite_x448 (
    unsigned char out[X448_BYTES],
    const unsigned char scalar[X448_BYTES],
    const unsigned char base[X448_BYTES]
) {
    gf x1, x2, z2, x3, z3, t1, t2;
    gf_deser(x1,base);
    gf_cpy(x2,ONE);
    gf_cpy(z2,ZERO);
    gf_cpy(x3,x1);
    gf_cpy(z3,ONE);

    int t;
    decaf_word_t swap = 0;

    for (t = 448-1; t>=0; t--) {
        uint8_t sb = scalar[t/8];

        /* Scalar conditioning */
        if (t/8==0) sb &= 0xFC;
        else if (t/8 == X448_BYTES-1) sb |= 0x80;

        decaf_word_t k_t = (sb>>(t%8)) & 1;
        k_t = -k_t; /* set to all 0s or all 1s */

        swap ^= k_t;
        cond_swap(x2,x3,swap);
        cond_swap(z2,z3,swap);
        swap = k_t;

        gf_add(t1,x2,z2); /* A = x2 + z2 */
        gf_sub(t2,x2,z2); /* B = x2 - z2 */
        gf_sub(z2,x3,z3); /* D = x3 - z3 */
        gf_mul(x2,t1,z2); /* DA */
        gf_add(z2,z3,x3); /* C = x3 + z3 */
        gf_mul(x3,t2,z2); /* CB */
        gf_sub(z3,x2,x3); /* DA-CB */
        gf_sqr(z2,z3);    /* (DA-CB)^2 */
        gf_mul(z3,x1,z2); /* z3 = x1(DA-CB)^2 */
        gf_add(z2,x2,x3); /* (DA+CB) */
        gf_sqr(x3,z2);    /* x3 = (DA+CB)^2 */

        gf_sqr(z2,t1);    /* AA = A^2 */
        gf_sqr(t1,t2);    /* BB = B^2 */
        gf_mul(x2,z2,t1); /* x2 = AA*BB */
        gf_sub(t2,z2,t1); /* E = AA-BB */

        gf_mlw(t1,t2,-EDWARDS_D); /* E*-d = a24*E */
        gf_add(t1,t1,z2); /* AA + a24*E */
        gf_mul(z2,t2,t1); /* z2 = E(AA+a24*E) */
    }

    /* Finish */
    cond_swap(x2,x3,swap);
    cond_swap(z2,z3,swap);
    gf_inv(z2,z2);
    gf_mul(x1,x2,z2);
    gf_ser(out,x1);

    decaf_sword_t nz = 0;
    for (t=0; t<X448_BYTES; t++) {
        nz |= out[t];
    }
    nz = (nz-1)>>8; /* 0 = succ, -1 = fail */

    /* return value: 0 = succ, -1 = fail */
    return nz;
}

int __attribute__((visibility("default")))
cryptonite_x448_base (
    unsigned char out[X448_BYTES],
    const unsigned char scalar[X448_BYTES]
) {
    return cryptonite_x448(out,scalar,X448_BASE_POINT);
}
