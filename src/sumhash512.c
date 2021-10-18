#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fips202.h"
#include "util.h"
#include "include/sumhash512.h"

#define Q_t uint64_t
typedef Q_t matrix[SUMHASH512_N_ROWS][SUMHASH512_M_BITS];

static void randomize_matrix(matrix A, void *ctx, void (*read_rand)(void *ctx, uint8_t *out, size_t outlen)) {
    uint8_t w[8];
    for (int i = 0; i < SUMHASH512_N_ROWS; i++) {
        for (int j = 0; j < SUMHASH512_M_BITS; j++) {
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
    shake256_absorb(&state, p, 6);
    shake256_absorb(&state, seed, seedlen);
    shake256_finalize(&state);
    randomize_matrix(A, &state, read_shake);
}

static void hash_bytes(const matrix A, const uint8_t *msg, Q_t *result) { 
    uint64_t t[SUMHASH512_N_ROWS];
    for (int i = 0; i < 8; i ++) {
        t[i] = 0; 
    }
    for (int i = 0; i < SUMHASH512_M_BITS / 8; i ++) {
        uint64_t b = msg[i];
        for (int j = 0; j < 8; j ++) {
            uint64_t w = -((b >> j) & 1);
            for (int k = 0; k < SUMHASH512_N_ROWS; k ++) {
                t[k] += w & A[k][(i << 3) + j];
            }
        }
    }
    for (int i = 0; i < 8; i ++) { 
        result[i] = t[i];
    }
}

static matrix algorandMatrix;

__attribute__((constructor))
static void init_algorand_matrix() {
    randomize_matrix_from_seed(algorandMatrix, (uint8_t*)"Algorand", 8);
}

void sumhash512_init(sumhash512_state *state) {
    memset(state, 0, sizeof(sumhash512_state));
}

void sumhash512_init_salted(sumhash512_state *state, const uint8_t salt[SUMHASH512_BLOCK_SIZE]) {
    sumhash512_init(state);
    // Must come after sumhash512_init, which set use_salt to 0.
    memcpy(state->salt, salt, SUMHASH512_BLOCK_SIZE);
    state->use_salt = 1;

    uint8_t zeros[SUMHASH512_BLOCK_SIZE];
    memset(zeros, 0, SUMHASH512_BLOCK_SIZE);
    sumhash512_update(state, zeros, SUMHASH512_BLOCK_SIZE);
}

static void sumhash_compress(sumhash512_state *state, const uint8_t *block, uint8_t *msg_buf) {
    le64enc_vect(msg_buf, state->state, SUMHASH512_N_ROWS*8);
    if (!state->use_salt) {
        memcpy(msg_buf+SUMHASH512_N_ROWS*8, block, SUMHASH512_BLOCK_SIZE);
    } else {
        uint8_t *x = msg_buf+SUMHASH512_N_ROWS*8;
        for (int i = 0; i < SUMHASH512_BLOCK_SIZE; i++) {
            x[i] = state->salt[i] ^ block[i];
        }
    }
    hash_bytes((const Q_t (*)[SUMHASH512_M_BITS])algorandMatrix, msg_buf, state->state);
}

// This code is based on hash_sha512_cp.c from libsodium.
void sumhash512_update(sumhash512_state *state, const uint8_t *in, size_t inlen) {
    uint64_t           bitlen[2];
    size_t i;
    size_t r;

    uint8_t msg_buf[SUMHASH512_M_BITS/8];
    unsigned int b = SUMHASH512_BLOCK_SIZE;

    if (inlen <= 0U) {
        return;
    }
    r = (size_t) ((state->count[1] >> 3) % b);

    // count[0] are the high bits
    bitlen[1] = ((uint64_t) inlen) << 3;
    bitlen[0] = ((uint64_t) inlen) >> 61;
    if ((state->count[1] += bitlen[1]) < bitlen[1]) {
        state->count[0]++;
    }
    state->count[0] += bitlen[0];

    if (inlen < b - r) {
        for (i = 0; i < inlen; i++) {
            state->buf[r + i] = in[i];
        }
        return;
    }

    for (i = 0; i < b - r; i++) {
        state->buf[r + i] = in[i];
    }
    sumhash_compress(state, state->buf, msg_buf);
    in += b - r;
    inlen -= b - r;

    while (inlen >= b) {
        sumhash_compress(state, in, msg_buf);
        in += b;
        inlen -= b;
    }
    inlen %= b;
    memcpy(state->buf, in, inlen);
}

void sumhash512_final(sumhash512_state *state, uint8_t *out) {
    unsigned int r;
    unsigned int i;

    uint8_t msg_buf[SUMHASH512_M_BITS/8];
    unsigned int b = SUMHASH512_BLOCK_SIZE;

    // Add padding.
    r = (unsigned int) ((state->count[1] >> 3) % b);
    state->buf[r] = 0x80;
    if (r < b - 16) {
        for (i = 1; i < b - 16 - r; i++) {
            state->buf[r + i] = 0;
        }
    } else {
        for (i = 1; i < b - r; i++) {
            state->buf[r + i] = 0;
        }
        sumhash_compress(state, state->buf, msg_buf);
        memset(&state->buf[0], 0, b-16);
    }
    // Encode bit length in the final block in little endian.
    // Note that state->count is "big endian."
    store64_le(&state->buf[b-16], state->count[1]);
    store64_le(&state->buf[b-8], state->count[0]);
    sumhash_compress(state, state->buf, msg_buf);

    le64enc_vect(out, state->state, SUMHASH512_N_ROWS*8);

}

void sumhash512(uint8_t *out, const uint8_t *in, size_t inlen) {
    sumhash512_state st;
    sumhash512_init(&st);
    sumhash512_update(&st, in, inlen);
    sumhash512_final(&st, out);
}

void sumhash512_salted(uint8_t *out, const uint8_t *in, size_t inlen, const uint8_t salt[SUMHASH512_BLOCK_SIZE]) {
    sumhash512_state st;
    sumhash512_init_salted(&st, salt);
    sumhash512_update(&st, in, inlen);
    sumhash512_final(&st, out);
}
