
#define X448_BYTES (448/8)

/* The base point (5) */
extern const unsigned char X448_BASE_POINT[X448_BYTES];

/* Returns 0 on success, -1 on failure */
int __attribute__((visibility("default")))
cryptonite_x448 (
    unsigned char out[X448_BYTES],
    const unsigned char scalar[X448_BYTES],
    const unsigned char base[X448_BYTES]
);

/* Returns 0 on success, -1 on failure
 *
 * Same as x448(out,scalar,X448_BASE_POINT), except that
 * an implementation may optimize it.
 */
int __attribute__((visibility("default")))
cryptonite_x448_base (
    unsigned char out[X448_BYTES],
    const unsigned char scalar[X448_BYTES]
);

