/*
 * Copyright (c) 2012 Vincent Hanquez <vincent@snarc.org>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of his contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdint.h>
#include <cryptonite_cpu.h>
#include <aes/gf.h>
#include <aes/x86ni.h>

/* this is a really inefficient way to GF multiply.
 * the alternative without hw accel is building small tables
 * to speed up the multiplication.
 * TODO: optimise with tables
 */
void cryptonite_gf_mul(block128 *a, block128 *b)
{
	uint64_t a0, a1, v0, v1;
	int i, j;

	a0 = a1 = 0;
	v0 = cpu_to_be64(a->q[0]);
	v1 = cpu_to_be64(a->q[1]);

	for (i = 0; i < 16; i++)
		for (j = 0x80; j != 0; j >>= 1) {
			uint8_t x = b->b[i] & j;
			a0 ^= x ? v0 : 0;
			a1 ^= x ? v1 : 0;
			x = (uint8_t) v1 & 1;
			v1 = (v1 >> 1) | (v0 << 63);
			v0 = (v0 >> 1) ^ (x ? (0xe1ULL << 56) : 0);
		}
	a->q[0] = cpu_to_be64(a0);
	a->q[1] = cpu_to_be64(a1);
}

/* inplace GFMUL for xts mode */
void cryptonite_gf_mulx(block128 *a)
{
	const uint64_t gf_mask = cpu_to_le64(0x8000000000000000ULL);
	uint64_t r = ((a->q[1] & gf_mask) ? cpu_to_le64(0x87) : 0);
	a->q[1] = cpu_to_le64((le64_to_cpu(a->q[1]) << 1) | (a->q[0] & gf_mask ? 1 : 0));
	a->q[0] = cpu_to_le64(le64_to_cpu(a->q[0]) << 1) ^ r;
}

