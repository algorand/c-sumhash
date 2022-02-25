#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fips202.h"
#include "include/sumhash512.h"
#include "src/matrix.h"

static inline uint64_t
load64_le(const uint8_t src[8])
{
    uint64_t w = (uint64_t) src[0];
    w |= (uint64_t) src[1] <<  8;
    w |= (uint64_t) src[2] << 16;
    w |= (uint64_t) src[3] << 24;
    w |= (uint64_t) src[4] << 32;
    w |= (uint64_t) src[5] << 40;
    w |= (uint64_t) src[6] << 48;
    w |= (uint64_t) src[7] << 56;
    return w;
}

static void randomize_matrix(matrix A, void *ctx, void (*read_rand)(void *ctx, uint8_t *out, size_t outlen)) {
    uint8_t w[8];
    for (int i = 0; i < SUMHASH512_N_ROWS; i++) {
        for (int j = 0; j < SUMHASH512_M_BITS; j++) {
            // Each byte read from rand is interpreted as an 8-bit string in LE/LSB
            // encoding, consistent with SHA-3 (NIST FIPS 202, Appendix B). See also:
            // https://keccak.team/keccak_bits_and_bytes.html
            read_rand(ctx, w, 8);
            A[i][j] = load64_le(w);
        }
    }
}

static void read_shake(void *ctx, uint8_t *out, size_t outlen) {
    keccak_state *state = ctx;
    shake256_squeeze(out, outlen, state);
} 

static void randomize_matrix_from_seed(matrix A, const uint8_t *seed, int seedlen) {
    keccak_state state;
    shake256_init(&state);
    uint8_t p[6] = {64, 0, (uint8_t)SUMHASH512_N_ROWS, SUMHASH512_N_ROWS>>8, (uint8_t)SUMHASH512_M_BITS, SUMHASH512_M_BITS>>8};
    // SHAKE treats bytes as LSB-first 8-bit strings, so this conforms to the sumhash spec.
    shake256_absorb(&state, p, 6);
    shake256_absorb(&state, seed, seedlen);
    shake256_finalize(&state);
    randomize_matrix(A, &state, read_shake);
}



int main() {
    matrix algorand_matrix;
    randomize_matrix_from_seed(algorand_matrix, (uint8_t*)"Algorand", 8);
    printf("{ ");
    for (int i = 0; i < SUMHASH512_N_ROWS; i++) {
        printf("{ ");
        for (int j = 0; j < SUMHASH512_M_BITS; j++) {
            printf("0x%llx, ",algorand_matrix[i][j]);
        }
        printf("},\n ");
    }
    printf("};\n ");
    return 0;
}
