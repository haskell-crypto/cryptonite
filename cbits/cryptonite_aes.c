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

#include <string.h>
#include <stdio.h>

#include <cryptonite_cpu.h>
#include <cryptonite_aes.h>
#include <cryptonite_bitfn.h>

#include <aes/generic.h>
#include <aes/gf.h>
#include <aes/x86ni.h>

void cryptonite_aes_generic_encrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks);
void cryptonite_aes_generic_decrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks);
void cryptonite_aes_generic_encrypt_cbc(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks);
void cryptonite_aes_generic_decrypt_cbc(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks);
void cryptonite_aes_generic_encrypt_ctr(uint8_t *output, aes_key *key, aes_block *iv, uint8_t *input, uint32_t length);
void cryptonite_aes_generic_encrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                             uint32_t spoint, aes_block *input, uint32_t nb_blocks);
void cryptonite_aes_generic_decrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                             uint32_t spoint, aes_block *input, uint32_t nb_blocks);
void cryptonite_aes_generic_gcm_encrypt(uint8_t *output, aes_gcm *gcm, aes_key *key, uint8_t *input, uint32_t length);
void cryptonite_aes_generic_gcm_decrypt(uint8_t *output, aes_gcm *gcm, aes_key *key, uint8_t *input, uint32_t length);
void cryptonite_aes_generic_ocb_encrypt(uint8_t *output, aes_ocb *ocb, aes_key *key, uint8_t *input, uint32_t length);
void cryptonite_aes_generic_ocb_decrypt(uint8_t *output, aes_ocb *ocb, aes_key *key, uint8_t *input, uint32_t length);

enum {
	/* init */
	INIT_128, INIT_192, INIT_256,
	/* single block */
	ENCRYPT_BLOCK_128, ENCRYPT_BLOCK_192, ENCRYPT_BLOCK_256,
	DECRYPT_BLOCK_128, DECRYPT_BLOCK_192, DECRYPT_BLOCK_256,
	/* ecb */
	ENCRYPT_ECB_128, ENCRYPT_ECB_192, ENCRYPT_ECB_256,
	DECRYPT_ECB_128, DECRYPT_ECB_192, DECRYPT_ECB_256,
	/* cbc */
	ENCRYPT_CBC_128, ENCRYPT_CBC_192, ENCRYPT_CBC_256,
	DECRYPT_CBC_128, DECRYPT_CBC_192, DECRYPT_CBC_256,
	/* ctr */
	ENCRYPT_CTR_128, ENCRYPT_CTR_192, ENCRYPT_CTR_256,
	/* xts */
	ENCRYPT_XTS_128, ENCRYPT_XTS_192, ENCRYPT_XTS_256,
	DECRYPT_XTS_128, DECRYPT_XTS_192, DECRYPT_XTS_256,
	/* gcm */
	ENCRYPT_GCM_128, ENCRYPT_GCM_192, ENCRYPT_GCM_256,
	DECRYPT_GCM_128, DECRYPT_GCM_192, DECRYPT_GCM_256,
	/* ocb */
	ENCRYPT_OCB_128, ENCRYPT_OCB_192, ENCRYPT_OCB_256,
	DECRYPT_OCB_128, DECRYPT_OCB_192, DECRYPT_OCB_256,
};

void *cryptonite_aes_branch_table[] = {
	/* INIT */
	[INIT_128]          = cryptonite_aes_generic_init,
	[INIT_192]          = cryptonite_aes_generic_init,
	[INIT_256]          = cryptonite_aes_generic_init,
	/* BLOCK */
	[ENCRYPT_BLOCK_128] = cryptonite_aes_generic_encrypt_block,
	[ENCRYPT_BLOCK_192] = cryptonite_aes_generic_encrypt_block,
	[ENCRYPT_BLOCK_256] = cryptonite_aes_generic_encrypt_block,
	[DECRYPT_BLOCK_128] = cryptonite_aes_generic_decrypt_block,
	[DECRYPT_BLOCK_192] = cryptonite_aes_generic_decrypt_block,
	[DECRYPT_BLOCK_256] = cryptonite_aes_generic_decrypt_block,
	/* ECB */
	[ENCRYPT_ECB_128]   = cryptonite_aes_generic_encrypt_ecb,
	[ENCRYPT_ECB_192]   = cryptonite_aes_generic_encrypt_ecb,
	[ENCRYPT_ECB_256]   = cryptonite_aes_generic_encrypt_ecb,
	[DECRYPT_ECB_128]   = cryptonite_aes_generic_decrypt_ecb,
	[DECRYPT_ECB_192]   = cryptonite_aes_generic_decrypt_ecb,
	[DECRYPT_ECB_256]   = cryptonite_aes_generic_decrypt_ecb,
	/* CBC */
	[ENCRYPT_CBC_128]   = cryptonite_aes_generic_encrypt_cbc,
	[ENCRYPT_CBC_192]   = cryptonite_aes_generic_encrypt_cbc,
	[ENCRYPT_CBC_256]   = cryptonite_aes_generic_encrypt_cbc,
	[DECRYPT_CBC_128]   = cryptonite_aes_generic_decrypt_cbc,
	[DECRYPT_CBC_192]   = cryptonite_aes_generic_decrypt_cbc,
	[DECRYPT_CBC_256]   = cryptonite_aes_generic_decrypt_cbc,
	/* CTR */
	[ENCRYPT_CTR_128]   = cryptonite_aes_generic_encrypt_ctr,
	[ENCRYPT_CTR_192]   = cryptonite_aes_generic_encrypt_ctr,
	[ENCRYPT_CTR_256]   = cryptonite_aes_generic_encrypt_ctr,
	/* XTS */
	[ENCRYPT_XTS_128]   = cryptonite_aes_generic_encrypt_xts,
	[ENCRYPT_XTS_192]   = cryptonite_aes_generic_encrypt_xts,
	[ENCRYPT_XTS_256]   = cryptonite_aes_generic_encrypt_xts,
	[DECRYPT_XTS_128]   = cryptonite_aes_generic_decrypt_xts,
	[DECRYPT_XTS_192]   = cryptonite_aes_generic_decrypt_xts,
	[DECRYPT_XTS_256]   = cryptonite_aes_generic_decrypt_xts,
	/* GCM */
	[ENCRYPT_GCM_128]   = cryptonite_aes_generic_gcm_encrypt,
	[ENCRYPT_GCM_192]   = cryptonite_aes_generic_gcm_encrypt,
	[ENCRYPT_GCM_256]   = cryptonite_aes_generic_gcm_encrypt,
	[DECRYPT_GCM_128]   = cryptonite_aes_generic_gcm_decrypt,
	[DECRYPT_GCM_192]   = cryptonite_aes_generic_gcm_decrypt,
	[DECRYPT_GCM_256]   = cryptonite_aes_generic_gcm_decrypt,
	/* OCB */
	[ENCRYPT_OCB_128]   = cryptonite_aes_generic_ocb_encrypt,
	[ENCRYPT_OCB_192]   = cryptonite_aes_generic_ocb_encrypt,
	[ENCRYPT_OCB_256]   = cryptonite_aes_generic_ocb_encrypt,
	[DECRYPT_OCB_128]   = cryptonite_aes_generic_ocb_decrypt,
	[DECRYPT_OCB_192]   = cryptonite_aes_generic_ocb_decrypt,
	[DECRYPT_OCB_256]   = cryptonite_aes_generic_ocb_decrypt,
};

typedef void (*init_f)(aes_key *, uint8_t *, uint8_t);
typedef void (*ecb_f)(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks);
typedef void (*cbc_f)(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks);
typedef void (*ctr_f)(uint8_t *output, aes_key *key, aes_block *iv, uint8_t *input, uint32_t length);
typedef void (*xts_f)(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit, uint32_t spoint, aes_block *input, uint32_t nb_blocks);
typedef void (*gcm_crypt_f)(uint8_t *output, aes_gcm *gcm, aes_key *key, uint8_t *input, uint32_t length);
typedef void (*ocb_crypt_f)(uint8_t *output, aes_ocb *ocb, aes_key *key, uint8_t *input, uint32_t length);
typedef void (*block_f)(aes_block *output, aes_key *key, aes_block *input);

#ifdef HAVE_AESNI_INTRINSICS
#define GET_INIT(strength) \
	((init_f) (cryptonite_aes_branch_table[INIT_128 + strength]))
#define GET_ECB_ENCRYPT(strength) \
	((ecb_f) (cryptonite_aes_branch_table[ENCRYPT_ECB_128 + strength]))
#define GET_ECB_DECRYPT(strength) \
	((ecb_f) (cryptonite_aes_branch_table[DECRYPT_ECB_128 + strength]))
#define GET_CBC_ENCRYPT(strength) \
	((cbc_f) (cryptonite_aes_branch_table[ENCRYPT_CBC_128 + strength]))
#define GET_CBC_DECRYPT(strength) \
	((cbc_f) (cryptonite_aes_branch_table[DECRYPT_CBC_128 + strength]))
#define GET_CTR_ENCRYPT(strength) \
	((ctr_f) (cryptonite_aes_branch_table[ENCRYPT_CTR_128 + strength]))
#define GET_XTS_ENCRYPT(strength) \
	((xts_f) (cryptonite_aes_branch_table[ENCRYPT_XTS_128 + strength]))
#define GET_XTS_DECRYPT(strength) \
	((xts_f) (cryptonite_aes_branch_table[DECRYPT_XTS_128 + strength]))
#define GET_GCM_ENCRYPT(strength) \
	((gcm_crypt_f) (cryptonite_aes_branch_table[ENCRYPT_GCM_128 + strength]))
#define GET_GCM_DECRYPT(strength) \
	((gcm_crypt_f) (cryptonite_aes_branch_table[DECRYPT_GCM_128 + strength]))
#define GET_OCB_ENCRYPT(strength) \
	((ocb_crypt_f) (cryptonite_aes_branch_table[ENCRYPT_OCB_128 + strength]))
#define GET_OCB_DECRYPT(strength) \
	((ocb_crypt_f) (cryptonite_aes_branch_table[DECRYPT_OCB_128 + strength]))
#define cryptonite_aes_encrypt_block(o,k,i) \
	(((block_f) (cryptonite_aes_branch_table[ENCRYPT_BLOCK_128 + k->strength]))(o,k,i))
#define cryptonite_aes_decrypt_block(o,k,i) \
	(((block_f) (cryptonite_aes_branch_table[DECRYPT_BLOCK_128 + k->strength]))(o,k,i))
#else
#define GET_INIT(strenght) cryptonite_aes_generic_init
#define GET_ECB_ENCRYPT(strength) cryptonite_aes_generic_encrypt_ecb
#define GET_ECB_DECRYPT(strength) cryptonite_aes_generic_decrypt_ecb
#define GET_CBC_ENCRYPT(strength) cryptonite_aes_generic_encrypt_cbc
#define GET_CBC_DECRYPT(strength) cryptonite_aes_generic_decrypt_cbc
#define GET_CTR_ENCRYPT(strength) cryptonite_aes_generic_encrypt_ctr
#define GET_XTS_ENCRYPT(strength) cryptonite_aes_generic_encrypt_xts
#define GET_XTS_DECRYPT(strength) cryptonite_aes_generic_decrypt_xts
#define GET_GCM_ENCRYPT(strength) cryptonite_aes_generic_gcm_encrypt
#define GET_GCM_DECRYPT(strength) cryptonite_aes_generic_gcm_decrypt
#define GET_OCB_ENCRYPT(strength) cryptonite_aes_generic_ocb_encrypt
#define GET_OCB_DECRYPT(strength) cryptonite_aes_generic_ocb_decrypt
#define cryptonite_aes_encrypt_block(o,k,i) cryptonite_aes_generic_encrypt_block(o,k,i)
#define cryptonite_aes_decrypt_block(o,k,i) cryptonite_aes_generic_decrypt_block(o,k,i)
#endif

#if defined(ARCH_X86) && defined(HAVE_AESNI_INTRINSICS)
static void initialize_table_ni(int aesni, int pclmul)
{
	if (!aesni)
		return;
	cryptonite_aes_branch_table[INIT_128] = cryptonite_aesni_init;
	cryptonite_aes_branch_table[INIT_256] = cryptonite_aesni_init;

	cryptonite_aes_branch_table[ENCRYPT_BLOCK_128] = cryptonite_aesni_encrypt_block128;
	cryptonite_aes_branch_table[DECRYPT_BLOCK_128] = cryptonite_aesni_decrypt_block128;
	cryptonite_aes_branch_table[ENCRYPT_BLOCK_256] = cryptonite_aesni_encrypt_block256;
	cryptonite_aes_branch_table[DECRYPT_BLOCK_256] = cryptonite_aesni_decrypt_block256;
	/* ECB */
	cryptonite_aes_branch_table[ENCRYPT_ECB_128] = cryptonite_aesni_encrypt_ecb128;
	cryptonite_aes_branch_table[DECRYPT_ECB_128] = cryptonite_aesni_decrypt_ecb128;
	cryptonite_aes_branch_table[ENCRYPT_ECB_256] = cryptonite_aesni_encrypt_ecb256;
	cryptonite_aes_branch_table[DECRYPT_ECB_256] = cryptonite_aesni_decrypt_ecb256;
	/* CBC */
	cryptonite_aes_branch_table[ENCRYPT_CBC_128] = cryptonite_aesni_encrypt_cbc128;
	cryptonite_aes_branch_table[DECRYPT_CBC_128] = cryptonite_aesni_decrypt_cbc128;
	cryptonite_aes_branch_table[ENCRYPT_CBC_256] = cryptonite_aesni_encrypt_cbc256;
	cryptonite_aes_branch_table[DECRYPT_CBC_256] = cryptonite_aesni_decrypt_cbc256;
	/* CTR */
	cryptonite_aes_branch_table[ENCRYPT_CTR_128] = cryptonite_aesni_encrypt_ctr128;
	cryptonite_aes_branch_table[ENCRYPT_CTR_256] = cryptonite_aesni_encrypt_ctr256;
	/* XTS */
	cryptonite_aes_branch_table[ENCRYPT_XTS_128] = cryptonite_aesni_encrypt_xts128;
	cryptonite_aes_branch_table[ENCRYPT_XTS_256] = cryptonite_aesni_encrypt_xts256;
	/* GCM */
	cryptonite_aes_branch_table[ENCRYPT_GCM_128] = cryptonite_aesni_gcm_encrypt128;
	cryptonite_aes_branch_table[ENCRYPT_GCM_256] = cryptonite_aesni_gcm_encrypt256;
	/* OCB */
	/*
	cryptonite_aes_branch_table[ENCRYPT_OCB_128] = cryptonite_aesni_ocb_encrypt128;
	cryptonite_aes_branch_table[ENCRYPT_OCB_256] = cryptonite_aesni_ocb_encrypt256;
	*/
}
#endif

void cryptonite_aes_initkey(aes_key *key, uint8_t *origkey, uint8_t size)
{
	switch (size) {
	case 16: key->nbr = 10; key->strength = 0; break;
	case 24: key->nbr = 12; key->strength = 1; break;
	case 32: key->nbr = 14; key->strength = 2; break;
	}
#if defined(ARCH_X86) && defined(HAVE_AESNI_INTRINSICS)
	cryptonite_aesni_initialize_hw(initialize_table_ni);
#endif
	init_f _init = GET_INIT(key->strength);
	_init(key, origkey, size);
}

void cryptonite_aes_encrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	ecb_f e = GET_ECB_ENCRYPT(key->strength);
	e(output, key, input, nb_blocks);
}

void cryptonite_aes_decrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	ecb_f d = GET_ECB_DECRYPT(key->strength);
	d(output, key, input, nb_blocks);
}

void cryptonite_aes_encrypt_cbc(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks)
{
	cbc_f e = GET_CBC_ENCRYPT(key->strength);
	e(output, key, iv, input, nb_blocks);
}

void cryptonite_aes_decrypt_cbc(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks)
{
	cbc_f d = GET_CBC_DECRYPT(key->strength);
	d(output, key, iv, input, nb_blocks);
}

void cryptonite_aes_gen_ctr(aes_block *output, aes_key *key, const aes_block *iv, uint32_t nb_blocks)
{
	aes_block block;

	/* preload IV in block */
	block128_copy(&block, iv);

	for ( ; nb_blocks-- > 0; output++, block128_inc_be(&block)) {
		cryptonite_aes_encrypt_block(output, key, &block);
	}
}

void cryptonite_aes_gen_ctr_cont(aes_block *output, aes_key *key, aes_block *iv, uint32_t nb_blocks)
{
	aes_block block;

	/* preload IV in block */
	block128_copy(&block, iv);

	for ( ; nb_blocks-- > 0; output++, block128_inc_be(&block)) {
		cryptonite_aes_encrypt_block(output, key, &block);
	}

	/* copy back the IV */
	block128_copy(iv, &block);
}

void cryptonite_aes_encrypt_ctr(uint8_t *output, aes_key *key, aes_block *iv, uint8_t *input, uint32_t len)
{
	ctr_f e = GET_CTR_ENCRYPT(key->strength);
	e(output, key, iv, input, len);
}

void cryptonite_aes_encrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                     uint32_t spoint, aes_block *input, uint32_t nb_blocks)
{
	xts_f e = GET_XTS_ENCRYPT(k1->strength);
	e(output, k1, k2, dataunit, spoint, input, nb_blocks);
}

void cryptonite_aes_decrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                     uint32_t spoint, aes_block *input, uint32_t nb_blocks)
{
	cryptonite_aes_generic_decrypt_xts(output, k1, k2, dataunit, spoint, input, nb_blocks);
}

void cryptonite_aes_gcm_encrypt(uint8_t *output, aes_gcm *gcm, aes_key *key, uint8_t *input, uint32_t length)
{
	gcm_crypt_f e = GET_GCM_ENCRYPT(key->strength);
	e(output, gcm, key, input, length);
}

void cryptonite_aes_gcm_decrypt(uint8_t *output, aes_gcm *gcm, aes_key *key, uint8_t *input, uint32_t length)
{
	gcm_crypt_f d = GET_GCM_DECRYPT(key->strength);
	d(output, gcm, key, input, length);
}

void cryptonite_aes_ocb_encrypt(uint8_t *output, aes_ocb *ocb, aes_key *key, uint8_t *input, uint32_t length)
{
	ocb_crypt_f e = GET_OCB_ENCRYPT(key->strength);
	e(output, ocb, key, input, length);
}

void cryptonite_aes_ocb_decrypt(uint8_t *output, aes_ocb *ocb, aes_key *key, uint8_t *input, uint32_t length)
{
	ocb_crypt_f d = GET_OCB_DECRYPT(key->strength);
	d(output, ocb, key, input, length);
}

static void gcm_ghash_add(aes_gcm *gcm, block128 *b)
{
	block128_xor(&gcm->tag, b);
	cryptonite_gf_mul(&gcm->tag, &gcm->h);
}

void cryptonite_aes_gcm_init(aes_gcm *gcm, aes_key *key, uint8_t *iv, uint32_t len)
{
	gcm->length_aad = 0;
	gcm->length_input = 0;

	block128_zero(&gcm->h);
	block128_zero(&gcm->tag);
	block128_zero(&gcm->iv);

	/* prepare H : encrypt_K(0^128) */
	cryptonite_aes_encrypt_block(&gcm->h, key, &gcm->h);

	if (len == 12) {
		block128_copy_bytes(&gcm->iv, iv, 12);
		gcm->iv.b[15] = 0x01;
	} else {
		uint32_t origlen = len << 3;
		int i;
		for (; len >= 16; len -= 16, iv += 16) {
			block128_xor(&gcm->iv, (block128 *) iv);
			cryptonite_gf_mul(&gcm->iv, &gcm->h);
		}
		if (len > 0) {
			block128_xor_bytes(&gcm->iv, iv, len);
			cryptonite_gf_mul(&gcm->iv, &gcm->h);
		}
		for (i = 15; origlen; --i, origlen >>= 8)
			gcm->iv.b[i] ^= (uint8_t) origlen;
		cryptonite_gf_mul(&gcm->iv, &gcm->h);
	}

	block128_copy(&gcm->civ, &gcm->iv);
}

void cryptonite_aes_gcm_aad(aes_gcm *gcm, uint8_t *input, uint32_t length)
{
	gcm->length_aad += length;
	for (; length >= 16; input += 16, length -= 16) {
		gcm_ghash_add(gcm, (block128 *) input);
	}
	if (length > 0) {
		aes_block tmp;
		block128_zero(&tmp);
		block128_copy_bytes(&tmp, input, length);
		gcm_ghash_add(gcm, &tmp);
	}

}

void cryptonite_aes_gcm_finish(uint8_t *tag, aes_gcm *gcm, aes_key *key)
{
	aes_block lblock;
	int i;

	/* tag = (tag-1 xor (lenbits(a) | lenbits(c)) ) . H */
	lblock.q[0] = cpu_to_be64(gcm->length_aad << 3);
	lblock.q[1] = cpu_to_be64(gcm->length_input << 3);
	gcm_ghash_add(gcm, &lblock);

	cryptonite_aes_encrypt_block(&lblock, key, &gcm->iv);
	block128_xor(&gcm->tag, &lblock);

	for (i = 0; i < 16; i++) {
		tag[i] = gcm->tag.b[i];
	}
}

static inline void ocb_block_double(block128 *d, block128 *s)
{
	unsigned int i;
	uint8_t tmp = s->b[0];

	for (i=0; i<15; i++)
		d->b[i] = (s->b[i] << 1) | (s->b[i+1] >> 7);
	d->b[15] = (s->b[15] << 1) ^ ((tmp >> 7) * 0x87);
}

static void ocb_get_L_i(block128 *l, block128 *lis, unsigned int i)
{
#define L_CACHED 4
	i = bitfn_ntz(i);
	if (i < L_CACHED) {
		block128_copy(l, &lis[i]);
	} else {
		i -= (L_CACHED - 1);
		block128_copy(l, &lis[L_CACHED - 1]);
		while (i--) {
			ocb_block_double(l, l);
		}
	}
#undef L_CACHED
}

void cryptonite_aes_ocb_init(aes_ocb *ocb, aes_key *key, uint8_t *iv, uint32_t len)
{
	block128 tmp, nonce, ktop;
	unsigned char stretch[24];
	unsigned bottom, byteshift, bitshift, i;

	/* we don't accept more than 15 bytes, any bytes higher will be ignored. */
	if (len > 15) {
		len = 15;
	}

	/* create L*, and L$,L0,L1,L2,L3 */
	block128_zero(&tmp);
	cryptonite_aes_encrypt_block(&ocb->lstar, key, &tmp);

	ocb_block_double(&ocb->ldollar, &ocb->lstar);
	ocb_block_double(&ocb->li[0], &ocb->ldollar);
	ocb_block_double(&ocb->li[1], &ocb->li[0]);
	ocb_block_double(&ocb->li[2], &ocb->li[1]);
	ocb_block_double(&ocb->li[3], &ocb->li[2]);

	/* create strech from the nonce */
	block128_zero(&nonce);
	memcpy(nonce.b + 4, iv, 12);
	nonce.b[0] = (unsigned char)(((16 * 8) % 128) << 1);
	nonce.b[16-12-1] |= 0x01;
	bottom = nonce.b[15] & 0x3F;
	nonce.b[15] &= 0xC0;
	cryptonite_aes_encrypt_block(&ktop, key, &nonce);
	memcpy(stretch, ktop.b, 16);

	memcpy(tmp.b, ktop.b + 1, 8);
	block128_xor(&tmp, &ktop);
	memcpy(stretch + 16, tmp.b, 8);

	/* initialize the encryption offset from stretch */
	byteshift = bottom / 8;
	bitshift = bottom % 8;
	if (bitshift != 0)
		for (i = 0; i < 16; i++)
			ocb->offset_enc.b[i] = (stretch[i+byteshift] << bitshift)
			                     | (stretch[i+byteshift+1] >> (8-bitshift));
	else
		for (i = 0; i < 16; i++)
			ocb->offset_enc.b[i] = stretch[i+byteshift];
	/* initialize checksum for aad and encryption, and the aad offset */
	block128_zero(&ocb->sum_aad);
	block128_zero(&ocb->sum_enc);
	block128_zero(&ocb->offset_aad);
}

void cryptonite_aes_ocb_aad(aes_ocb *ocb, aes_key *key, uint8_t *input, uint32_t length)
{
	block128 tmp;
	unsigned int i;

	for (i=1; i<= length/16; i++, input=input+16) {
		ocb_get_L_i(&tmp, ocb->li, i);
		block128_xor(&ocb->offset_aad, &tmp);

		block128_vxor(&tmp, &ocb->offset_aad, (block128 *) input);
		cryptonite_aes_encrypt_block(&tmp, key, &tmp);
		block128_xor(&ocb->sum_aad, &tmp);
	}

	length = length % 16; /* Bytes in final block */
	if (length > 0) {
		block128_xor(&ocb->offset_aad, &ocb->lstar);
		block128_zero(&tmp);
		block128_copy_bytes(&tmp, input, length);
		tmp.b[length] = 0x80;
		block128_xor(&tmp, &ocb->offset_aad);
		cryptonite_aes_encrypt_block(&tmp, key, &tmp);
		block128_xor(&ocb->sum_aad, &tmp);
	}
}

void cryptonite_aes_ocb_finish(uint8_t *tag, aes_ocb *ocb, aes_key *key)
{
	block128 tmp;

	block128_vxor(&tmp, &ocb->sum_enc, &ocb->offset_enc);
	block128_xor(&tmp, &ocb->ldollar);
	cryptonite_aes_encrypt_block((block128 *) tag, key, &tmp);
	block128_xor((block128 *) tag, &ocb->sum_aad);
}

void cryptonite_aes_generic_encrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	for ( ; nb_blocks-- > 0; input++, output++) {
		cryptonite_aes_generic_encrypt_block(output, key, input);
	}
}

void cryptonite_aes_generic_decrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	for ( ; nb_blocks-- > 0; input++, output++) {
		cryptonite_aes_generic_decrypt_block(output, key, input);
	}
}

void cryptonite_aes_generic_encrypt_cbc(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks)
{
	aes_block block;

	/* preload IV in block */
	block128_copy(&block, iv);
	for ( ; nb_blocks-- > 0; input++, output++) {
		block128_xor(&block, (block128 *) input);
		cryptonite_aes_generic_encrypt_block(&block, key, &block);
		block128_copy((block128 *) output, &block);
	}
}

void cryptonite_aes_generic_decrypt_cbc(aes_block *output, aes_key *key, aes_block *ivini, aes_block *input, uint32_t nb_blocks)
{
	aes_block block, blocko;
	aes_block iv;

	/* preload IV in block */
	block128_copy(&iv, ivini);
	for ( ; nb_blocks-- > 0; input++, output++) {
		block128_copy(&block, (block128 *) input);
		cryptonite_aes_generic_decrypt_block(&blocko, key, &block);
		block128_vxor((block128 *) output, &blocko, &iv);
		block128_copy(&iv, &block);
	}
}

void cryptonite_aes_generic_encrypt_ctr(uint8_t *output, aes_key *key, aes_block *iv, uint8_t *input, uint32_t len)
{
	aes_block block, o;
	uint32_t nb_blocks = len / 16;
	int i;

	/* preload IV in block */
	block128_copy(&block, iv);

	for ( ; nb_blocks-- > 0; block128_inc_be(&block), output += 16, input += 16) {
		cryptonite_aes_encrypt_block(&o, key, &block);
		block128_vxor((block128 *) output, &o, (block128 *) input);
	}

	if ((len % 16) != 0) {
		cryptonite_aes_encrypt_block(&o, key, &block);
		for (i = 0; i < (len % 16); i++) {
			*output = ((uint8_t *) &o)[i] ^ *input;
			output++;
			input++;
		}
	}
}

void cryptonite_aes_generic_encrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                             uint32_t spoint, aes_block *input, uint32_t nb_blocks)
{
	aes_block block, tweak;

	/* load IV and encrypt it using k2 as the tweak */
	block128_copy(&tweak, dataunit);
	cryptonite_aes_encrypt_block(&tweak, k2, &tweak);

	/* TO OPTIMISE: this is really inefficient way to do that */
	while (spoint-- > 0)
		cryptonite_gf_mulx(&tweak);

	for ( ; nb_blocks-- > 0; input++, output++, cryptonite_gf_mulx(&tweak)) {
		block128_vxor(&block, input, &tweak);
		cryptonite_aes_encrypt_block(&block, k1, &block);
		block128_vxor(output, &block, &tweak);
	}
}

void cryptonite_aes_generic_decrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                             uint32_t spoint, aes_block *input, uint32_t nb_blocks)
{
	aes_block block, tweak;

	/* load IV and encrypt it using k2 as the tweak */
	block128_copy(&tweak, dataunit);
	cryptonite_aes_encrypt_block(&tweak, k2, &tweak);

	/* TO OPTIMISE: this is really inefficient way to do that */
	while (spoint-- > 0)
		cryptonite_gf_mulx(&tweak);

	for ( ; nb_blocks-- > 0; input++, output++, cryptonite_gf_mulx(&tweak)) {
		block128_vxor(&block, input, &tweak);
		cryptonite_aes_decrypt_block(&block, k1, &block);
		block128_vxor(output, &block, &tweak);
	}
}

void cryptonite_aes_generic_gcm_encrypt(uint8_t *output, aes_gcm *gcm, aes_key *key, uint8_t *input, uint32_t length)
{
	aes_block out;

	gcm->length_input += length;
	for (; length >= 16; input += 16, output += 16, length -= 16) {
		block128_inc_be(&gcm->civ);

		cryptonite_aes_encrypt_block(&out, key, &gcm->civ);
		block128_xor(&out, (block128 *) input);
		gcm_ghash_add(gcm, &out);
		block128_copy((block128 *) output, &out);
	}
	if (length > 0) {
		aes_block tmp;
		int i;

		block128_inc_be(&gcm->civ);
		/* create e(civ) in out */
		cryptonite_aes_encrypt_block(&out, key, &gcm->civ);
		/* initialize a tmp as input and xor it to e(civ) */
		block128_zero(&tmp);
		block128_copy_bytes(&tmp, input, length);
		block128_xor_bytes(&tmp, out.b, length);

		gcm_ghash_add(gcm, &tmp);

		for (i = 0; i < length; i++) {
			output[i] = tmp.b[i];
		}
	}
}

void cryptonite_aes_generic_gcm_decrypt(uint8_t *output, aes_gcm *gcm, aes_key *key, uint8_t *input, uint32_t length)
{
	aes_block out;

	gcm->length_input += length;
	for (; length >= 16; input += 16, output += 16, length -= 16) {
		block128_inc_be(&gcm->civ);

		cryptonite_aes_encrypt_block(&out, key, &gcm->civ);
		gcm_ghash_add(gcm, (block128 *) input);
		block128_xor(&out, (block128 *) input);
		block128_copy((block128 *) output, &out);
	}
	if (length > 0) {
		aes_block tmp;
		int i;

		block128_inc_be(&gcm->civ);

		block128_zero(&tmp);
		block128_copy_bytes(&tmp, input, length);
		gcm_ghash_add(gcm, &tmp);

		cryptonite_aes_encrypt_block(&out, key, &gcm->civ);
		block128_xor_bytes(&tmp, out.b, length);

		for (i = 0; i < length; i++) {
			output[i] = tmp.b[i];
		}
	}
}

static void ocb_generic_crypt(uint8_t *output, aes_ocb *ocb, aes_key *key,
                              uint8_t *input, uint32_t length, int encrypt)
{
	block128 tmp, pad;
	unsigned int i;

	for (i = 1; i <= length/16; i++, input += 16, output += 16) {
		/* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
		ocb_get_L_i(&tmp, ocb->li, i);
		block128_xor(&ocb->offset_enc, &tmp);

		block128_vxor(&tmp, &ocb->offset_enc, (block128 *) input);
		if (encrypt) {
			cryptonite_aes_encrypt_block(&tmp, key, &tmp);
			block128_vxor((block128 *) output, &ocb->offset_enc, &tmp);
			block128_xor(&ocb->sum_enc, (block128 *) input);
		} else {
			cryptonite_aes_decrypt_block(&tmp, key, &tmp);
			block128_vxor((block128 *) output, &ocb->offset_enc, &tmp);
			block128_xor(&ocb->sum_enc, (block128 *) output);
		}
	}

	/* process the last partial block if any */
	length = length % 16;
	if (length > 0) {
		block128_xor(&ocb->offset_enc, &ocb->lstar);
		cryptonite_aes_encrypt_block(&pad, key, &ocb->offset_enc);

		if (encrypt) {
			block128_zero(&tmp);
			block128_copy_bytes(&tmp, input, length);
			tmp.b[length] = 0x80;
			block128_xor(&ocb->sum_enc, &tmp);
			block128_xor(&pad, &tmp);
			memcpy(output, pad.b, length);
			output += length;
		} else {
			block128_copy(&tmp, &pad);
			block128_copy_bytes(&tmp, input, length);
			block128_xor(&tmp, &pad);
			tmp.b[length] = 0x80;
			memcpy(output, tmp.b, length);
			block128_xor(&ocb->sum_enc, &tmp);
			input += length;
		}
	}
}

void cryptonite_aes_generic_ocb_encrypt(uint8_t *output, aes_ocb *ocb, aes_key *key, uint8_t *input, uint32_t length)
{
	ocb_generic_crypt(output, ocb, key, input, length, 1);
}

void cryptonite_aes_generic_ocb_decrypt(uint8_t *output, aes_ocb *ocb, aes_key *key, uint8_t *input, uint32_t length)
{
	ocb_generic_crypt(output, ocb, key, input, length, 0);
}
