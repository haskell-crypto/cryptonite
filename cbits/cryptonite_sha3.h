/*
 * Copyright (C) 2012 Vincent Hanquez <vincent@snarc.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef CRYPTOHASH_SHA3_H
#define CRYPTOHASH_SHA3_H

#include <stdint.h>

struct sha3_ctx
{
	uint32_t bufindex;
	uint32_t bufsz;
	uint64_t state[25];
	uint8_t  buf[0]; /* maximum SHAKE128 is 168 bytes, otherwise buffer can be decreased */
};

#define SHA3_CTX_SIZE		sizeof(struct sha3_ctx)

void cryptonite_sha3_init(struct sha3_ctx *ctx, uint32_t hashlen);
void cryptonite_sha3_update(struct sha3_ctx *ctx, const uint8_t *data, uint32_t len);
void cryptonite_sha3_finalize(struct sha3_ctx *ctx, uint32_t hashlen, uint8_t *out);

void cryptonite_sha3_finalize_shake(struct sha3_ctx *ctx);
void cryptonite_sha3_output(struct sha3_ctx *ctx, uint8_t *out, uint32_t len);

#endif
