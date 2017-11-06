/*
    Public domain by Olivier Chéron <olivier.cheron@gmail.com>

    Arithmetic extensions to Ed25519-donna
*/


/*
    Scalar functions
*/

void
ED25519_FN(ed25519_scalar_encode) (unsigned char out[32], const bignum256modm in) {
    contract256_modm(out, in);
}

void
ED25519_FN(ed25519_scalar_decode_long) (bignum256modm out, const unsigned char *in, size_t len) {
    expand256_modm(out, in, len);
}

int
ED25519_FN(ed25519_scalar_eq) (const bignum256modm a, const bignum256modm b) {
    bignum256modm_element_t e = 0;

    for (int i = 0; i < bignum256modm_limb_size; i++) {
        e |= a[i] ^ b[i];
    }

    return (int) (1 & ((e - 1) >> bignum256modm_bits_per_limb));
}

void
ED25519_FN(ed25519_scalar_add) (bignum256modm r, const bignum256modm x, const bignum256modm y) {
    add256_modm(r, x, y);
}

void
ED25519_FN(ed25519_scalar_mul) (bignum256modm r, const bignum256modm x, const bignum256modm y) {
    mul256_modm(r, x, y);
}


/*
    Point functions
*/

void
ED25519_FN(ed25519_point_encode) (unsigned char r[32], const ge25519 *p) {
    ge25519_pack(r, p);
}

int
ED25519_FN(ed25519_point_decode_vartime) (ge25519 *r, const unsigned char p[32]) {
    unsigned char p_neg[32];

    // invert parity bit of X coordinate so the point is negated twice
    // (once here, once in ge25519_unpack_negative_vartime)
    for (int i = 0; i < 31; i++) {
        p_neg[i] = p[i];
    }
    p_neg[31] = p[31] ^ 0x80;

    return ge25519_unpack_negative_vartime(r, p_neg);
}

int
ED25519_FN(ed25519_point_eq) (const ge25519 *p, const ge25519 *q) {
    bignum25519 a, b;
    unsigned char contract_a[32], contract_b[32];
    int eq;

    // pX * qZ = qX * pZ
    curve25519_mul(a, p->x, q->z);
    curve25519_contract(contract_a, a);
    curve25519_mul(b, q->x, p->z);
    curve25519_contract(contract_b, b);
    eq = ed25519_verify(contract_a, contract_b, 32);

    // pY * qZ = qY * pZ
    curve25519_mul(a, p->y, q->z);
    curve25519_contract(contract_a, a);
    curve25519_mul(b, q->y, p->z);
    curve25519_contract(contract_b, b);
    eq &= ed25519_verify(contract_a, contract_b, 32);

    return eq;
}

void
ED25519_FN(ed25519_point_negate) (ge25519 *r, const ge25519 *p) {
    curve25519_neg(r->x, p->x);
    curve25519_copy(r->y, p->y);
    curve25519_copy(r->z, p->z);
    curve25519_neg(r->t, p->t);
}

void
ED25519_FN(ed25519_point_add) (ge25519 *r, const ge25519 *p, const ge25519 *q) {
    ge25519_add(r, p, q);
}

void
ED25519_FN(ed25519_point_double) (ge25519 *r, const ge25519 *p) {
    ge25519_double(r, p);
}

void
ED25519_FN(ed25519_point_base_scalarmul) (ge25519 *r, const bignum256modm s) {
    ge25519_scalarmult_base_niels(r, ge25519_niels_base_multiples, s);
}

void
ED25519_FN(ed25519_point_scalarmul) (ge25519 *r, const ge25519 *p, const bignum256modm s) {
    ge25519 tmp;
    uint32_t scalar_bit;
    unsigned char ss[32];

    // transform scalar as little-endian number
    contract256_modm(ss, s);

    // initialize r to identity
    memset(r, 0, sizeof(ge25519));
    r->y[0] = 1;
    r->z[0] = 1;

    // double-add-always
    for (int i = 31; i >= 0; i--) {
        for (int j = 7; j >= 0; j--) {
            ge25519_double(r, r);

            ge25519_add(&tmp, r, p);
            scalar_bit = (ss[i] >> j) & 1;
            curve25519_swap_conditional(r->x, tmp.x, scalar_bit);
            curve25519_swap_conditional(r->y, tmp.y, scalar_bit);
            curve25519_swap_conditional(r->z, tmp.z, scalar_bit);
            curve25519_swap_conditional(r->t, tmp.t, scalar_bit);
        }
    }
}
