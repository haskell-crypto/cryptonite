/*
 * Copyright 2013 The Android Open Source Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Google Inc. nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Google Inc. ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL Google Inc. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// This is an implementation of the P256 elliptic curve group. It's written to
// be portable 32-bit, although it's still constant-time.
//
// WARNING: Implementing these functions in a constant-time manner is far from
//          obvious. Be careful when touching this code.
//
// See http://www.imperialviolet.org/2010/12/04/ecc.html ([1]) for background.

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "p256/p256.h"

const cryptonite_p256_int cryptonite_SECP256r1_n =  // curve order
  {{0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, -1, -1, 0, -1}};

const cryptonite_p256_int cryptonite_SECP256r1_p =  // curve field size
  {{-1, -1, -1, 0, 0, 0, 1, -1 }};

const cryptonite_p256_int cryptonite_SECP256r1_b =  // curve b
  {{0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0,
    0x769886bc, 0xb3ebbd55, 0xaa3a93e7, 0x5ac635d8}};

void cryptonite_p256_init(cryptonite_p256_int* a) {
  memset(a, 0, sizeof(*a));
}

void cryptonite_p256_clear(cryptonite_p256_int* a) { cryptonite_p256_init(a); }

int cryptonite_p256_get_bit(const cryptonite_p256_int* scalar, int bit) {
  return (P256_DIGIT(scalar, bit / P256_BITSPERDIGIT)
              >> (bit & (P256_BITSPERDIGIT - 1))) & 1;
}

int cryptonite_p256_is_zero(const cryptonite_p256_int* a) {
  int i, result = 0;
  for (i = 0; i < P256_NDIGITS; ++i) result |= P256_DIGIT(a, i);
  return !result;
}

// top, c[] += a[] * b
// Returns new top
static cryptonite_p256_digit mulAdd(const cryptonite_p256_int* a,
                         cryptonite_p256_digit b,
                         cryptonite_p256_digit top,
                         cryptonite_p256_digit* c) {
  int i;
  cryptonite_p256_ddigit carry = 0;

  for (i = 0; i < P256_NDIGITS; ++i) {
    carry += *c;
    carry += (cryptonite_p256_ddigit)P256_DIGIT(a, i) * b;
    *c++ = (cryptonite_p256_digit)carry;
    carry >>= P256_BITSPERDIGIT;
  }
  return top + (cryptonite_p256_digit)carry;
}

// top, c[] -= top_a, a[]
static cryptonite_p256_digit subTop(cryptonite_p256_digit top_a,
                         const cryptonite_p256_digit* a,
                         cryptonite_p256_digit top_c,
                         cryptonite_p256_digit* c) {
  int i;
  cryptonite_p256_sddigit borrow = 0;

  for (i = 0; i < P256_NDIGITS; ++i) {
    borrow += *c;
    borrow -= *a++;
    *c++ = (cryptonite_p256_digit)borrow;
    borrow >>= P256_BITSPERDIGIT;
  }
  borrow += top_c;
  borrow -= top_a;
  top_c = (cryptonite_p256_digit)borrow;
  assert((borrow >> P256_BITSPERDIGIT) == 0);
  return top_c;
}

// top, c[] -= MOD[] & mask (0 or -1)
// returns new top.
static cryptonite_p256_digit subM(const cryptonite_p256_int* MOD,
                       cryptonite_p256_digit top,
                       cryptonite_p256_digit* c,
                       cryptonite_p256_digit mask) {
  int i;
  cryptonite_p256_sddigit borrow = 0;
  for (i = 0; i < P256_NDIGITS; ++i) {
    borrow += *c;
    borrow -= P256_DIGIT(MOD, i) & mask;
    *c++ = (cryptonite_p256_digit)borrow;
    borrow >>= P256_BITSPERDIGIT;
  }
  return top + (cryptonite_p256_digit)borrow;
}

// top, c[] += MOD[] & mask (0 or -1)
// returns new top.
static cryptonite_p256_digit addM(const cryptonite_p256_int* MOD,
                       cryptonite_p256_digit top,
                       cryptonite_p256_digit* c,
                       cryptonite_p256_digit mask) {
  int i;
  cryptonite_p256_ddigit carry = 0;
  for (i = 0; i < P256_NDIGITS; ++i) {
    carry += *c;
    carry += P256_DIGIT(MOD, i) & mask;
    *c++ = (cryptonite_p256_digit)carry;
    carry >>= P256_BITSPERDIGIT;
  }
  return top + (cryptonite_p256_digit)carry;
}

// c = a * b mod MOD. c can be a and/or b.
void cryptonite_p256_modmul(const cryptonite_p256_int* MOD,
                 const cryptonite_p256_int* a,
                 const cryptonite_p256_digit top_b,
                 const cryptonite_p256_int* b,
                 cryptonite_p256_int* c) {
  cryptonite_p256_digit tmp[P256_NDIGITS * 2 + 1] = { 0 };
  cryptonite_p256_digit top = 0;
  int i;

  // Multiply/add into tmp.
  for (i = 0; i < P256_NDIGITS; ++i) {
    if (i) tmp[i + P256_NDIGITS - 1] = top;
    top = mulAdd(a, P256_DIGIT(b, i), 0, tmp + i);
  }

  // Multiply/add top digit
  tmp[i + P256_NDIGITS - 1] = top;
  top = mulAdd(a, top_b, 0, tmp + i);

  // Reduce tmp, digit by digit.
  for (; i >= 0; --i) {
    cryptonite_p256_digit reducer[P256_NDIGITS] = { 0 };
    cryptonite_p256_digit top_reducer;

    // top can be any value at this point.
    // Guestimate reducer as top * MOD, since msw of MOD is -1.
    top_reducer = mulAdd(MOD, top, 0, reducer);

    // Subtract reducer from top | tmp.
    top = subTop(top_reducer, reducer, top, tmp + i);

    // top is now either 0 or 1. Make it 0, fixed-timing.
    assert(top <= 1);

    top = subM(MOD, top, tmp + i, ~(top - 1));

    assert(top == 0);

    // We have now reduced the top digit off tmp. Fetch new top digit.
    top = tmp[i + P256_NDIGITS - 1];
  }

  // tmp might still be larger than MOD, yet same bit length.
  // Make sure it is less, fixed-timing.
  addM(MOD, 0, tmp, subM(MOD, 0, tmp, -1));

  memcpy(c, tmp, P256_NBYTES);
}
int cryptonite_p256_is_odd(const cryptonite_p256_int* a) { return P256_DIGIT(a, 0) & 1; }
int cryptonite_p256_is_even(const cryptonite_p256_int* a) { return !(P256_DIGIT(a, 0) & 1); }

cryptonite_p256_digit cryptonite_p256_shl(const cryptonite_p256_int* a, int n, cryptonite_p256_int* b) {
  int i;
  cryptonite_p256_digit top = P256_DIGIT(a, P256_NDIGITS - 1);

  n %= P256_BITSPERDIGIT;
  for (i = P256_NDIGITS - 1; i > 0; --i) {
    cryptonite_p256_digit accu = (P256_DIGIT(a, i) << n);
    accu |= (P256_DIGIT(a, i - 1) >> (P256_BITSPERDIGIT - n));
    P256_DIGIT(b, i) = accu;
  }
  P256_DIGIT(b, i) = (P256_DIGIT(a, i) << n);

  top = (cryptonite_p256_digit)((((cryptonite_p256_ddigit)top) << n) >> P256_BITSPERDIGIT);

  return top;
}

void cryptonite_p256_shr(const cryptonite_p256_int* a, int n, cryptonite_p256_int* b) {
  int i;

  n %= P256_BITSPERDIGIT;
  for (i = 0; i < P256_NDIGITS - 1; ++i) {
    cryptonite_p256_digit accu = (P256_DIGIT(a, i) >> n);
    accu |= (P256_DIGIT(a, i + 1) << (P256_BITSPERDIGIT - n));
    P256_DIGIT(b, i) = accu;
  }
  P256_DIGIT(b, i) = (P256_DIGIT(a, i) >> n);
}

static void cryptonite_p256_shr1(const cryptonite_p256_int* a, int highbit, cryptonite_p256_int* b) {
  int i;

  for (i = 0; i < P256_NDIGITS - 1; ++i) {
    cryptonite_p256_digit accu = (P256_DIGIT(a, i) >> 1);
    accu |= (P256_DIGIT(a, i + 1) << (P256_BITSPERDIGIT - 1));
    P256_DIGIT(b, i) = accu;
  }
  P256_DIGIT(b, i) = (P256_DIGIT(a, i) >> 1) |
      (highbit << (P256_BITSPERDIGIT - 1));
}

// Return -1, 0, 1 for a < b, a == b or a > b respectively.
int cryptonite_p256_cmp(const cryptonite_p256_int* a, const cryptonite_p256_int* b) {
  int i;
  cryptonite_p256_sddigit borrow = 0;
  cryptonite_p256_digit notzero = 0;

  for (i = 0; i < P256_NDIGITS; ++i) {
    borrow += (cryptonite_p256_sddigit)P256_DIGIT(a, i) - P256_DIGIT(b, i);
    // Track whether any result digit is ever not zero.
    // Relies on !!(non-zero) evaluating to 1, e.g., !!(-1) evaluating to 1.
    notzero |= !!((cryptonite_p256_digit)borrow);
    borrow >>= P256_BITSPERDIGIT;
  }
  return (int)borrow | notzero;
}

// c = a - b. Returns borrow: 0 or -1.
int cryptonite_p256_sub(const cryptonite_p256_int* a, const cryptonite_p256_int* b, cryptonite_p256_int* c) {
  int i;
  cryptonite_p256_sddigit borrow = 0;

  for (i = 0; i < P256_NDIGITS; ++i) {
    borrow += (cryptonite_p256_sddigit)P256_DIGIT(a, i) - P256_DIGIT(b, i);
    if (c) P256_DIGIT(c, i) = (cryptonite_p256_digit)borrow;
    borrow >>= P256_BITSPERDIGIT;
  }
  return (int)borrow;
}

// c = a + b. Returns carry: 0 or 1.
int cryptonite_p256_add(const cryptonite_p256_int* a, const cryptonite_p256_int* b, cryptonite_p256_int* c) {
  int i;
  cryptonite_p256_ddigit carry = 0;

  for (i = 0; i < P256_NDIGITS; ++i) {
    carry += (cryptonite_p256_ddigit)P256_DIGIT(a, i) + P256_DIGIT(b, i);
    if (c) P256_DIGIT(c, i) = (cryptonite_p256_digit)carry;
    carry >>= P256_BITSPERDIGIT;
  }
  return (int)carry;
}

// b = a + d. Returns carry, 0 or 1.
int cryptonite_p256_add_d(const cryptonite_p256_int* a, cryptonite_p256_digit d, cryptonite_p256_int* b) {
  int i;
  cryptonite_p256_ddigit carry = d;

  for (i = 0; i < P256_NDIGITS; ++i) {
    carry += (cryptonite_p256_ddigit)P256_DIGIT(a, i);
    if (b) P256_DIGIT(b, i) = (cryptonite_p256_digit)carry;
    carry >>= P256_BITSPERDIGIT;
  }
  return (int)carry;
}

// b = 1/a mod MOD, binary euclid.
void cryptonite_p256_modinv_vartime(const cryptonite_p256_int* MOD,
                         const cryptonite_p256_int* a,
                         cryptonite_p256_int* b) {
  cryptonite_p256_int R = P256_ZERO;
  cryptonite_p256_int S = P256_ONE;
  cryptonite_p256_int U = *MOD;
  cryptonite_p256_int V = *a;

  for (;;) {
    if (cryptonite_p256_is_even(&U)) {
      cryptonite_p256_shr1(&U, 0, &U);
      if (cryptonite_p256_is_even(&R)) {
        cryptonite_p256_shr1(&R, 0, &R);
      } else {
        // R = (R+MOD)/2
        cryptonite_p256_shr1(&R, cryptonite_p256_add(&R, MOD, &R), &R);
      }
    } else if (cryptonite_p256_is_even(&V)) {
      cryptonite_p256_shr1(&V, 0, &V);
      if (cryptonite_p256_is_even(&S)) {
        cryptonite_p256_shr1(&S, 0, &S);
      } else {
        // S = (S+MOD)/2
        cryptonite_p256_shr1(&S, cryptonite_p256_add(&S, MOD, &S) , &S);
      }
    } else {  // U,V both odd.
      if (!cryptonite_p256_sub(&V, &U, NULL)) {
        cryptonite_p256_sub(&V, &U, &V);
        if (cryptonite_p256_sub(&S, &R, &S)) cryptonite_p256_add(&S, MOD, &S);
        if (cryptonite_p256_is_zero(&V)) break;  // done.
      } else {
        cryptonite_p256_sub(&U, &V, &U);
        if (cryptonite_p256_sub(&R, &S, &R)) cryptonite_p256_add(&R, MOD, &R);
      }
    }
  }

  cryptonite_p256_mod(MOD, &R, b);
}

void cryptonite_p256_mod(const cryptonite_p256_int* MOD,
              const cryptonite_p256_int* in,
              cryptonite_p256_int* out) {
  if (out != in) *out = *in;
  addM(MOD, 0, P256_DIGITS(out), subM(MOD, 0, P256_DIGITS(out), -1));
}

// Verify y^2 == x^3 - 3x + b mod p
// and 0 < x < p and 0 < y < p
int cryptonite_p256_is_valid_point(const cryptonite_p256_int* x, const cryptonite_p256_int* y) {
  cryptonite_p256_int y2, x3;

  if (cryptonite_p256_cmp(&cryptonite_SECP256r1_p, x) <= 0 ||
      cryptonite_p256_cmp(&cryptonite_SECP256r1_p, y) <= 0 ||
      cryptonite_p256_is_zero(x) ||
      cryptonite_p256_is_zero(y)) return 0;

  cryptonite_p256_modmul(&cryptonite_SECP256r1_p, y, 0, y, &y2);  // y^2

  cryptonite_p256_modmul(&cryptonite_SECP256r1_p, x, 0, x, &x3);  // x^2
  cryptonite_p256_modmul(&cryptonite_SECP256r1_p, x, 0, &x3, &x3);  // x^3
  if (cryptonite_p256_sub(&x3, x, &x3)) cryptonite_p256_add(&x3, &cryptonite_SECP256r1_p, &x3);  // x^3 - x
  if (cryptonite_p256_sub(&x3, x, &x3)) cryptonite_p256_add(&x3, &cryptonite_SECP256r1_p, &x3);  // x^3 - 2x
  if (cryptonite_p256_sub(&x3, x, &x3)) cryptonite_p256_add(&x3, &cryptonite_SECP256r1_p, &x3);  // x^3 - 3x
  if (cryptonite_p256_add(&x3, &cryptonite_SECP256r1_b, &x3))  // x^3 - 3x + b
    cryptonite_p256_sub(&x3, &cryptonite_SECP256r1_p, &x3);

  return cryptonite_p256_cmp(&y2, &x3) == 0;
}

void cryptonite_p256_from_bin(const uint8_t src[P256_NBYTES], cryptonite_p256_int* dst) {
  int i;
  const uint8_t* p = &src[0];

  for (i = P256_NDIGITS - 1; i >= 0; --i) {
    P256_DIGIT(dst, i) =
        (p[0] << 24) |
        (p[1] << 16) |
        (p[2] << 8) |
        p[3];
    p += 4;
  }
}

void cryptonite_p256_to_bin(const cryptonite_p256_int* src, uint8_t dst[P256_NBYTES])
{
	int i;
	uint8_t* p = &dst[0];

	for (i = P256_NDIGITS -1; i >= 0; --i) {
		const cryptonite_p256_digit dig = P256_DIGIT(src, i);
		p[0] = dig >> 24;
		p[1] = dig >> 16;
		p[2] = dig >> 8;
		p[3] = dig;
		p += 4;
	}
}
